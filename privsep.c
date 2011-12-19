/*	$OpenBSD: privsep.c,v 1.34 2008/11/23 04:29:42 brad Exp $	*/

/*
 * Copyright (c) 2003 Anil Madhavapeddy <anil@recoil.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define _BSD_SOURCE
#define _GNU_SOURCE
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/wait.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <grp.h>
#include "mlvpn.h"

/*
 * mlvpn can only go forward in these states; each state should represent
 * less privilege.   After STATE_INIT, the child is allowed to parse its
 * config file once, and communicate the information regarding what logfiles
 * it needs access to back to the parent.  When that is done, it sends a
 * message to the priv parent revoking this access, moving to STATE_RUNNING.
 * In this state, any log-files not in the access list are rejected.
 *
 * This allows a HUP signal to the child to reopen its log files, and
 * the config file to be parsed if it hasn't been changed (this is still
 * useful to force resolution of remote syslog servers again).
 * If the config file has been modified, then the child dies, and
 * the priv parent restarts itself.
 */
enum priv_state {
	STATE_INIT,		/* just started up */
	STATE_CONFIG,		/* parsing config file for first time */
	STATE_RUNNING,		/* running and accepting network traffic */
	STATE_QUIT		/* shutting down */
};

enum cmd_types {
	PRIV_OPEN_LOG,		/* open logfile for appending */
	PRIV_OPEN_CONFIG,	/* open config file for reading only */
	PRIV_OPEN_TUN,
	PRIV_DONE_CONFIG_PARSE	/* signal that the initial config parse is done */
};

static int priv_fd = -1;
static volatile pid_t child_pid = -1;
static char config_file[MAXPATHLEN];
static struct stat cf_info;
static volatile sig_atomic_t cur_state = STATE_INIT;

/* Queue for the allowed logfiles */
struct logname {
	char path[MAXPATHLEN];
	TAILQ_ENTRY(logname) next;
};
static TAILQ_HEAD(, logname) lognames;

static void check_log_name(char *, size_t);
static int open_file(char *);
static void increase_state(int);
//static void sig_pass_to_chld(int);
static void sig_got_chld(int);
static void must_read(int, void *, size_t);
static void must_write(int, void *, size_t);
static int  may_read(int, void *, size_t);

int
priv_init(char *conf, char *argv[])
{
	int i, fd, socks[2], cmd, restart;
	size_t path_len;
	char path[MAXPATHLEN];
	struct ifreq ifr;
	struct passwd *pw;
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = SIG_DFL;
	for (i = 1; i < _NSIG; i++)
		sigaction(i, &sa, NULL);

	/* Create sockets */
	if (socketpair(AF_LOCAL, SOCK_STREAM, PF_UNSPEC, socks) == -1)
		err(1, "socketpair() failed");

	pw = getpwnam("mlvpn");
	if (pw == NULL)
		errx(1, "unknown user mlvpn");

	child_pid = fork();
	if (child_pid < 0)
		err(1, "fork() failed");

	if (!child_pid) {
		/* Child - drop privileges and return */
		if (chroot(pw->pw_dir) != 0)
			err(1, "unable to chroot");
		if (chdir("/") != 0)
			err(1, "unable to chdir");

		if (setgroups(1, &pw->pw_gid) == -1)
			err(1, "setgroups() failed");
		if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1)
			err(1, "setresgid() failed");
		if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
			err(1, "setresuid() failed");
		close(socks[0]);
		priv_fd = socks[1];
		return 0;
	}

	/* PHIL: TODO */
	/*
	if (!Debug) {
		close(lockfd);
		dup2(nullfd, STDIN_FILENO);
		dup2(nullfd, STDOUT_FILENO);
		dup2(nullfd, STDERR_FILENO);
	}
	*/

	//if (nullfd > 2)
	//close(nullfd);

	/* Father */
	/* Pass TERM/HUP/INT/QUIT through to child, and accept CHLD */
	//sa.sa_handler = sig_pass_to_chld;
	//sigaction(SIGTERM, &sa, NULL);
	//sigaction(SIGHUP, &sa, NULL);
	//sigaction(SIGINT, &sa, NULL);
	//sigaction(SIGQUIT, &sa, NULL);
	sa.sa_handler = sig_got_chld;
	sa.sa_flags |= SA_NOCLDSTOP;
	sigaction(SIGCHLD, &sa, NULL);

	//setproctitle("[priv]");
	close(socks[1]);

	/* Save the config file specified by the child process */
	strncpy(config_file, conf, sizeof config_file);

	if (stat(config_file, &cf_info) < 0)
		err(1, "stat config file failed");

	TAILQ_INIT(&lognames);
	increase_state(STATE_CONFIG);
	restart = 0;

	while (cur_state < STATE_QUIT) {
		if (may_read(socks[0], &cmd, sizeof(int)))
			break;
		switch (cmd) {
		case PRIV_OPEN_LOG:
			//dprintf("[priv]: msg PRIV_OPEN_LOG received\n")
			/* Expecting: length, path */
			must_read(socks[0], &path_len, sizeof(size_t));
			if (path_len == 0 || path_len > sizeof(path))
				_exit(0);
			must_read(socks[0], &path, path_len);
			path[path_len - 1] = '\0';
			check_log_name(path, path_len);
			fd = open_file(path);
			send_fd(socks[0], fd);
			if (fd < 0)
				warnx("priv_open_log failed");
			else
				close(fd);
			break;

		case PRIV_OPEN_CONFIG:
			//dprintf("[priv]: msg PRIV_OPEN_CONFIG received\n");
			stat(config_file, &cf_info);
			fd = open(config_file, O_RDONLY|O_NONBLOCK, 0);
			send_fd(socks[0], fd);
			if (fd < 0)
				warnx("priv_open_config failed");
			else
				close(fd);
			break;

		case PRIV_OPEN_TUN:
			must_read(socks[0], &path_len, sizeof(size_t));

			if (path_len > sizeof(path))
				_exit(0);
			else if (path_len > 0) {
				must_read(socks[0], &path, path_len);
				path[path_len-1] = '\0';
			} else {
				path[0] = '\0';
			}

			fd = open("/dev/net/tun", O_RDWR);

			if (fd < 0) {
				warnx("priv_open_tun failed");
				must_write(socks[0], 0, sizeof(size_t));
			} else {
				memset(&ifr, 0, sizeof(ifr));
				/* We do not want kernel packet info */
				ifr.ifr_flags = IFF_TUN | IFF_NO_PI; 
				/* Allocate with specified name, otherwise the kernel
				 * will find a name for us. */
				if (path_len)
					strncpy(ifr.ifr_name, path, IFNAMSIZ);

				/* ioctl to create the if */
				if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0)
					warn("priv_open_tun failed");

				path_len = strlen(ifr.ifr_name);
				/* The kernel is the only one able to "name" the if.
				 * so we reread it to get the real name set by the kernel. */

				must_write(socks[0], &path_len, sizeof(path_len));
				must_write(socks[0], ifr.ifr_name, path_len);
			}
			send_fd(socks[0], fd);
			if (fd >= 0)
				close(fd);
			break;

		case PRIV_DONE_CONFIG_PARSE:
			//dprintf("[priv]: msg PRIV_DONE_CONFIG_PARSE received\n");
			increase_state(STATE_RUNNING);
			break;

		default:
			errx(1, "unknown command %d", cmd);
			break;
		}
	}

	close(socks[0]);

	if (restart) {
		int r;

		wait(&r);
		execvp(argv[0], argv);
	}
	_exit(1);
}

static int
open_file(char *path)
{
	/* must not start with | */
	if (path[0] == '|')
		return (-1);

	return (open(path, O_WRONLY|O_APPEND|O_NONBLOCK, 0));
}

/* If we are in the initial configuration state, accept a logname and add
 * it to the list of acceptable logfiles.  Otherwise, check against this list
 * and rewrite to /dev/null if it's a bad path.
 */
static void
check_log_name(char *lognam, size_t loglen)
{
	struct logname *lg;
	char *p;

	/* Any path containing '..' is invalid.  */
	for (p = lognam; *p && (p - lognam) < loglen; p++)
		if (*p == '.' && *(p + 1) == '.')
			goto bad_path;

	switch (cur_state) {
	case STATE_CONFIG:
		lg = malloc(sizeof(struct logname));
		if (!lg)
			err(1, "check_log_name() malloc");
		strncpy(lg->path, lognam, MAXPATHLEN);
		TAILQ_INSERT_TAIL(&lognames, lg, next);
		break;
	case STATE_RUNNING:
		TAILQ_FOREACH(lg, &lognames, next)
			if (!strcmp(lg->path, lognam))
				return;
		goto bad_path;
		break;
	default:
		/* Any other state should just refuse the request */
		goto bad_path;
		break;
	}
	return;

bad_path:
	warnx("%s: invalid attempt to open %s: rewriting to /dev/null",
	    "check_log_name", lognam);
	strncpy(lognam, "/dev/null", loglen);
}

/* Crank our state into less permissive modes */
static void
increase_state(int state)
{
	if (state <= cur_state)
		errx(1, "attempt to decrease or match current state");
	if (state < STATE_INIT || state > STATE_QUIT)
		errx(1, "attempt to switch to invalid state");
	cur_state = state;
}

/* Open log-file */
FILE *
priv_open_log(const char *lognam)
{
	char path[MAXPATHLEN];
	int cmd, fd;
	size_t path_len;
	FILE *fp;

	if (priv_fd < 0)
		errx(1, "%s: called from privileged child", "priv_open_log");

	strncpy(path, lognam, sizeof path);
	path_len = strlen(path) + 1;

	cmd = PRIV_OPEN_LOG;
	must_write(priv_fd, &cmd, sizeof(int));
	must_write(priv_fd, &path_len, sizeof(size_t));
	must_write(priv_fd, path, path_len);
	fd = receive_fd(priv_fd);

	if (fd < 0)
		return NULL;

	fp = fdopen(fd, "a");
	if (!fp) {
		warn("priv_open_log: fdopen() failed");
		close(fd);
		return NULL;
	}

	return fp;
}

/* Open mlvpn config file for reading */
FILE *
priv_open_config(void)
{
	int cmd, fd;
	FILE *fp;

	if (priv_fd < 0)
		errx(1, "%s: called from privileged portion", "priv_open_config");

	cmd = PRIV_OPEN_CONFIG;
	must_write(priv_fd, &cmd, sizeof(int));
	fd = receive_fd(priv_fd);
	if (fd < 0)
		return NULL;

	fp = fdopen(fd, "r");
	if (!fp) {
		warn("priv_open_config: fdopen() failed");
		close(fd);
		return NULL;
	}

	return fp;
}

/* Open tun */
int priv_open_tun(char *devname)
{
	char path[IFNAMSIZ];
	int cmd, fd;
	size_t path_len;

	if (priv_fd < 0)
		errx(1, "priv_open_tun: called from privileged portion");

	strncpy(path, devname, sizeof path);
	path_len = strlen(path) + 1;

	cmd = PRIV_OPEN_TUN;
	must_write(priv_fd, &cmd, sizeof(int));
	must_write(priv_fd, &path_len, sizeof(size_t));
	must_write(priv_fd, path, path_len);
	must_read(priv_fd, &path_len, sizeof(size_t));

	if (path_len > 0) {
		must_read(priv_fd, devname, path_len);
	}

	devname[path_len] = '\0';
	fd = receive_fd(priv_fd);
	return fd;
}

/* Child can signal that its initial parsing is done, so that parent
 * can revoke further logfile permissions.  This call only works once. */
void
priv_config_parse_done(void)
{
	int cmd;

	if (priv_fd < 0)
		errx(1, "%s: called from privileged portion",
		    "priv_config_parse_done");

	cmd = PRIV_DONE_CONFIG_PARSE;
	must_write(priv_fd, &cmd, sizeof(int));
}

/* When child dies, move into the shutdown state */
/* ARGSUSED */
static void
sig_got_chld(int sig)
{
	int save_errno = errno;
	pid_t	pid;

	do {
		pid = waitpid(WAIT_ANY, NULL, WNOHANG);
		if (pid == child_pid && cur_state < STATE_QUIT)
			cur_state = STATE_QUIT;
	} while (pid > 0 || (pid == -1 && errno == EINTR));
	errno = save_errno;
}

/* Read all data or return 1 for error.  */
static int
may_read(int fd, void *buf, size_t n)
{
	char *s = buf;
	ssize_t res, pos = 0;

	while (n > pos) {
		res = read(fd, s + pos, n - pos);
		switch (res) {
		case -1:
			if (errno == EINTR || errno == EAGAIN)
				continue;
		case 0:
			return (1);
		default:
			pos += res;
		}
	}
	return (0);
}

/* Read data with the assertion that it all must come through, or
 * else abort the process.  Based on atomicio() from openssh. */
static void
must_read(int fd, void *buf, size_t n)
{
	char *s = buf;
	ssize_t res, pos = 0;

	while (n > pos) {
		res = read(fd, s + pos, n - pos);
		switch (res) {
		case -1:
			if (errno == EINTR || errno == EAGAIN)
				continue;
		case 0:
			_exit(0);
		default:
			pos += res;
		}
	}
}

/* Write data with the assertion that it all has to be written, or
 * else abort the process.  Based on atomicio() from openssh. */
static void
must_write(int fd, void *buf, size_t n)
{
	char *s = buf;
	ssize_t res, pos = 0;

	while (n > pos) {
		res = write(fd, s + pos, n - pos);
		switch (res) {
		case -1:
			if (errno == EINTR || errno == EAGAIN)
				continue;
		case 0:
			_exit(0);
		default:
			pos += res;
		}
	}
}
