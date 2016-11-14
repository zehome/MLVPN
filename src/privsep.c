/*
 * Copyright (c) 2003 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2015 Laurent Coustet <ed@zehome.com>
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

#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include "includes.h"

#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <grp.h>

#if defined(HAVE_FREEBSD) || defined(HAVE_OPENBSD)
 #include <signal.h>
#endif
#ifdef HAVE_FREEBSD
 #define _NSIG _SIG_MAXSIG
#elif defined(HAVE_DARWIN)
 #define _NSIG NSIG
#endif

#include "privsep.h"
#include "mlvpn.h"
#include "tuntap_generic.h"

/*
 * mlvpn can only go forward in these states; each state should represent
 * less privilege.   After STATE_INIT, the child is allowed to parse its
 * config file once, and communicate the information regarding what logfile
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
    STATE_INIT,       /* just started up */
    STATE_CONFIG,     /* parsing config file for first time */
    STATE_RUNNING,    /* running and accepting network traffic */
    STATE_QUIT        /* shutting down */
};

enum cmd_types {
    PRIV_OPEN_CONFIG,   /* open config file for reading only */
    PRIV_INIT_SCRIPT,   /* set allowed status script path */
    PRIV_OPEN_TUN,      /* open tun/tap device */
    PRIV_RUN_SCRIPT,    /* run status script */
    PRIV_RELOAD_RESOLVER,
    PRIV_GETADDRINFO,
    PRIV_SET_RUNNING_STATE /* ready for maximum security */
};

/* Error message for some communication between processes */
#define ERRMSGSIZ 1024

static int priv_fd = -1;
static volatile pid_t child_pid = -1;
static volatile sig_atomic_t cur_state = STATE_INIT;

/* No-change runtime file path */
static char allowed_configfile[MAXPATHLEN] = {0};

static int root_open_file(char *, int);
int root_tuntap_open(int tuntapmode, char *devname, int mtu);
static int root_launch_script(char *, int, char **, char **);
static void increase_state(int);
static void sig_got_chld(int);
static void sig_pass_to_chld(int);
static void must_read(int, void *, size_t);
static void must_write(int, void *, size_t);
static int  may_read(int, void *, size_t);
static void reset_default_signals();

int
priv_init(char *argv[], char *username)
{
    int i, fd, socks[2], cmd;
    int nullfd;
    int mtu;
    int tuntapmode;
    int env_len;
    size_t len;
    size_t hostname_len, servname_len, addrinfo_len;
    char path[MAXPATHLEN];
    struct passwd *pw = NULL;
    struct sigaction sa;
    struct addrinfo hints, *res0, *res;
    char hostname[MLVPN_MAXHNAMSTR], servname[MLVPN_MAXHNAMSTR];
    char *phostname, *pservname;
    char script_path[MAXPATHLEN] = {0};
    char tuntapname[MLVPN_IFNAMSIZ];
    char **script_argv;
    char **script_env;
    char errormessage[ERRMSGSIZ];
    int script_argc;
    struct stat st;

    /* LC: TODO: Better way to check for root ! */
    int is_root = getuid() == 0;

    reset_default_signals();
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    /* Create sockets */
    if (socketpair(AF_LOCAL, SOCK_STREAM, PF_UNSPEC, socks) == -1)
        err(1, "socketpair() failed");

    /* Safe enough ? */
    if (username && *username)
    {
        pw = getpwnam(username);
        if (pw == NULL)
            errx(1, "unknown user %s", username);
    }

    child_pid = fork();
    if (child_pid < 0)
        err(1, "fork() failed");

    if (!child_pid)
    {
        if (RUNNING_ON_VALGRIND) {
            warnx("running on valgrind, keep privileges");
        } else {
            /* Child - drop privileges and return */
            if (is_root && pw)
            {
                if (chroot(pw->pw_dir) != 0)
                    err(1, "unable to chroot");
            }

            /* May be usefull to chose chdir directory ? */
            if (chdir("/") != 0)
                err(1, "unable to chdir");

            if (is_root && pw)
            {
                if (setgroups(1, &pw->pw_gid) == -1)
                    err(1, "setgroups() failed");
/* NetBSD does not have thoses */
#ifdef HAVE_SETRESGID
                if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1)
                    err(1, "setresgid() failed");
#else
                if (setregid(pw->pw_gid, pw->pw_gid) == -1)
                    err(1, "setregid() failed");
#endif
#ifdef HAVE_SETRESUID
                if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
                    err(1, "setresuid() failed");
#else
                if (setreuid(pw->pw_uid, pw->pw_uid) == -1)
                    err(1, "setreuid() failed");
#endif
            }
        }
        close(socks[0]);
        priv_fd = socks[1];
#ifdef HAVE_PLEDGE
        if (pledge("stdio inet unix recvfd", NULL) != 0) {
            err(1, "pledge");
        }
#endif
        return 0;
    }
    /* Father */
    /* Pass TERM/HUP/INT/QUIT through to child, and accept CHLD */
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = sig_pass_to_chld;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    /* mlvpn (unpriv) died */
    sa.sa_handler = sig_got_chld;
    sa.sa_flags = SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    close(socks[1]);

    nullfd = open("/dev/null", O_RDONLY);
    if (nullfd < 0)
    {
        perror("/dev/null");
        _exit(1);
    }
    dup2(nullfd, 0);
    dup2(nullfd, 1);
    //dup2(nullfd, 2);
    if (nullfd > 2)
        close(nullfd);

    increase_state(STATE_CONFIG);

    while (cur_state < STATE_QUIT)
    {
        if (may_read(socks[0], &cmd, sizeof(cmd)))
            break;
        switch (cmd) {

        case PRIV_OPEN_CONFIG:
            must_read(socks[0], &len, sizeof(len));
            if (len == 0 || len > sizeof(path) || len > MAXPATHLEN)
                _exit(0);
            must_read(socks[0], &path, len);
            path[len - 1] = '\0';

            if (cur_state == STATE_CONFIG)
                strlcpy(allowed_configfile, path, len);
            if (! *allowed_configfile)
                fatalx("empty configuration file path");

            fd = root_open_file(allowed_configfile, O_RDONLY|O_NONBLOCK);
            send_fd(socks[0], fd);
            if (fd < 0)
                log_warnx("privsep", "priv_open_config `%s' failed",
                    allowed_configfile);
            else
                close(fd);
            break;

        case PRIV_OPEN_TUN:
            /* we should not re-open the tuntap device ever! */
            if (cur_state != STATE_CONFIG)
                _exit(0);

            must_read(socks[0], &tuntapmode, sizeof(tuntapmode));
            if (tuntapmode != MLVPN_TUNTAPMODE_TUN &&
                    tuntapmode != MLVPN_TUNTAPMODE_TAP)
                _exit(0);

            must_read(socks[0], &len, sizeof(len));
            if (len > MLVPN_IFNAMSIZ)
                _exit(0);
            else if (len > 0) {
                must_read(socks[0], &tuntapname, len);
                tuntapname[len - 1] = '\0';
            } else {
                tuntapname[0] = '\0';
            }
            must_read(socks[0], &mtu, sizeof(mtu));
            if (mtu < 0 || mtu > 1500) {
                fatalx("priv_open_tun: wrong mtu.");
            }

            /* see tuntap_*.c . That's where this is defined. */
            fd = root_tuntap_open(tuntapmode, tuntapname, mtu);
            if (fd < 0)
            {
                len = 0;
                must_write(socks[0], &len, sizeof(len));
                break;
            }

            len = strlen(tuntapname) + 1;
            must_write(socks[0], &len, sizeof(len));
            must_write(socks[0], tuntapname, len);
            send_fd(socks[0], fd);
            if (fd >= 0)
                close(fd);
            break;

        case PRIV_INIT_SCRIPT:
            /* Not allowed to change script path when running
             * for security reasons
             */
            if (cur_state != STATE_CONFIG)
                _exit(0);

            must_read(socks[0], &len, sizeof(len));
            if (len == 0 || len > sizeof(script_path))
                _exit(0);
            must_read(socks[0], &path, len);

            path[len - 1] = '\0';

            /* Basic permission checking.
             * basically, the script must be 0700 owned by root
             */
            *errormessage = '\0';
            if (stat(path, &st) < 0)
            {
                snprintf(errormessage, ERRMSGSIZ, "Unable to open file %s:%s",
                         path, strerror(errno));
            } else if (st.st_mode & (S_IRWXG|S_IRWXO)) {
                snprintf(errormessage, ERRMSGSIZ,
                         "%s is group/other accessible",
                         path);
            } else if (!(st.st_mode & S_IXUSR)) {
                snprintf(errormessage, ERRMSGSIZ,
                         "%s is not executable",
                         path);
            } else {
                strlcpy(script_path, path, len);
            }
            len = strlen(errormessage) + 1;
            must_write(socks[0], &len, sizeof(len));
            must_write(socks[0], errormessage, len);
            break;

        case PRIV_GETADDRINFO:
            /* Expecting: len, hostname, len, servname, hints */
            must_read(socks[0], &hostname_len, sizeof(hostname_len));
            if (hostname_len > sizeof(hostname))
                _exit(0);
            else if (hostname_len > 0) {
                must_read(socks[0], &hostname, hostname_len);
                hostname[hostname_len - 1] = '\0';
                phostname = hostname;
            } else {
                phostname = NULL;
            }

            must_read(socks[0], &servname_len, sizeof(servname_len));
            if (servname_len > sizeof(servname))
                _exit(0);
            if (servname_len > 0) {
                must_read(socks[0], &servname, servname_len);
                servname[servname_len - 1] = '\0';
                pservname = servname;
            } else {
                pservname = NULL;
            }

            memset(&hints, '\0', sizeof(struct addrinfo));
            must_read(socks[0], &hints, sizeof(struct addrinfo));

            addrinfo_len = 0;
            i = getaddrinfo(phostname, pservname, &hints, &res0);
            if (i != 0 || res0 == NULL) {
                must_write(socks[0], &addrinfo_len, sizeof(addrinfo_len));
            } else {
                res = res0;
                while (res)
                {
                    addrinfo_len++;
                    res = res->ai_next;
                }
                must_write(socks[0], &addrinfo_len, sizeof(addrinfo_len));

                res = res0;
                while (res)
                {
                    must_write(socks[0], &res->ai_flags, sizeof(res->ai_flags));
                    must_write(socks[0], &res->ai_family, sizeof(res->ai_family));
                    must_write(socks[0], &res->ai_socktype, sizeof(res->ai_socktype));
                    must_write(socks[0], &res->ai_protocol, sizeof(res->ai_protocol));
                    must_write(socks[0], &res->ai_addrlen, sizeof(res->ai_addrlen));
                    must_write(socks[0], res->ai_addr, res->ai_addrlen);
                    res = res->ai_next;
                }
                freeaddrinfo(res0);
            }
            break;

        case PRIV_RUN_SCRIPT:
            must_read(socks[0], &script_argc, sizeof(script_argc));
            if (script_argc <= 0)
                _exit(0);

            if ((script_argv = calloc(script_argc + 1, sizeof(char *))) == NULL)
                _exit(0);

            /* read script argumuments */
            for(i = 0; i < script_argc; i++) {
                must_read(socks[0], &len, sizeof(len));
                if (len <= 0)
                    _exit(0);
                if ((script_argv[i] = malloc(len)) == NULL)
                    _exit(0);
                must_read(socks[0], script_argv[i], len);
                script_argv[i][len-1] = '\0';
            }
            script_argv[i] = NULL;

            /* Read environment */
            must_read(socks[0], &env_len, sizeof(env_len));
            if (env_len <= 0)
                _exit(0);
            if ((script_env = calloc(env_len + 1, sizeof(char *))) == NULL)
                _exit(0);
            for(i = 0; i < env_len; i++) {
                must_read(socks[0], &len, sizeof(len));
                if (len <= 0)
                    _exit(0);
                if ((script_env[i] = malloc(len)) == NULL)
                    _exit(0);
                must_read(socks[0], script_env[i], len);
                script_env[i][len - 1] = '\0';
            }

            if (! *script_path)
                i = -1;
            else
                i = root_launch_script(script_path,
                    script_argc, script_argv, script_env);
            must_write(socks[0], &i, sizeof(i));
            for(i = 0; i < script_argc && script_argv[i]; i++)
                free(script_argv[i]);
            free(script_argv);
            for(i = 0; i < env_len && script_env[i]; i++)
                free(script_env[i]);
            free(script_env);
            break;
        case PRIV_RELOAD_RESOLVER:
#ifdef HAVE_DECL_RES_INIT
            res_init();
#endif
            break;

        case PRIV_SET_RUNNING_STATE:
            increase_state(STATE_RUNNING);
#ifdef HAVE_PLEDGE
            if (pledge("rpath stdio dns sendfd exec proc", NULL) != 0) {
                err(1, "pledge");
            }
#endif
            break;

        default:
            errx(1, "unknown command %d", cmd);
            break;
        }
    }

    close(socks[0]);
    _exit(1);
}

static int
root_open_file(char *path, int flags)
{
    /* must not start with | */
    if (path[0] == '|')
        return (-1);
    return (open(path, flags, 0));
}

static int
root_launch_script(char *setup_script, int argc, char **argv, char **env)
{
    sigset_t oldmask, mask;
    int pid, status = -1;
    int i;
    char **newargs;
    char **envp = env;

    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, &oldmask);

    /* try to launch network script */
    pid = fork();
    if (pid == 0)
    {
        /* Reset all signals is required because after fork
         * the child process inherits all signal dispositions
         * of the parent
         */
        reset_default_signals();
        closefrom(3);
        newargs = calloc(argc + 2, sizeof(char *));
        if (! newargs)
            err(1, "memory allocation failed");
        newargs[0] = setup_script;
        for(i = 0; i < argc; i++)
            newargs[i+1] = argv[i];
        newargs[i+1] = NULL;

        while (*envp) {
            putenv(*envp);
            envp++;
        }

        if(chdir("/") != 0)
            errx(1, "chdir failed.");
        execv(setup_script, newargs);
        _exit(1);
    } else if (pid > 0) {
        while (waitpid(pid, &status, 0) != pid) {
            /* loop */
        }
        sigprocmask(SIG_SETMASK, &oldmask, NULL);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            return status;
        } else if (WIFSIGNALED(status)) {
            log_warnx("privsep", "network script %s killed by signal %d",
                setup_script,
                WTERMSIG(status));
        } else {
            log_warnx("privsep", "network script %s exit status %d",
                setup_script,
                WEXITSTATUS(status));
        }
    } else
        log_warn("privsep",
            "%s: could not launch network script", setup_script);
    return status;
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

/* Open mlvpn config file for reading */
int
priv_open_config(char *config_path)
{
    int cmd, fd;
    size_t len;

    if (priv_fd < 0)
        errx(1, "%s: called from privileged portion", "priv_open_config");

    len = strlen(config_path) + 1;

    cmd = PRIV_OPEN_CONFIG;
    must_write(priv_fd, &cmd, sizeof(cmd));

    must_write(priv_fd, &len, sizeof(len));
    must_write(priv_fd, config_path, len);

    fd = receive_fd(priv_fd);
    return fd;
}

/* Open tun from unpriviled code
 * Scope: public
 */
int priv_open_tun(int tuntapmode, char *devname, int mtu)
{
    int cmd, fd;
    size_t len;

    if (priv_fd < 0)
        errx(1, "%s: called from privileged portion", "priv_open_tun");

    if (devname == NULL)
        len = 0;
    else
        len = strlen(devname) + 1;

    cmd = PRIV_OPEN_TUN;
    must_write(priv_fd, &cmd, sizeof(cmd));
    must_write(priv_fd, &tuntapmode, sizeof(tuntapmode));

    must_write(priv_fd, &len, sizeof(len));
    if (len > 0 && devname != NULL)
        must_write(priv_fd, devname, len);
    must_write(priv_fd, &mtu, sizeof(mtu));

    must_read(priv_fd, &len, sizeof(len));
    if (len > 0 && len < MLVPN_IFNAMSIZ && devname != NULL)
    {
        must_read(priv_fd, devname, len);
        devname[len-1] = '\0';
        fd = receive_fd(priv_fd);
    } else if (len <= 0) {
        fd = len;
    } else {
        /* Too big ! */
        errx(1, "%s: device name returned by privileged "
             "service is too long.",
             "priv_open_tun");
    }
    return fd;
}


/* Name/service to address translation.  Response is placed into addr, and
 * the length is returned (zero on error) */
int
priv_getaddrinfo(char *host, char *serv, struct addrinfo **addrinfo,
                 struct addrinfo *hints)
{
    char hostcpy[MLVPN_MAXHNAMSTR], servcpy[MLVPN_MAXHNAMSTR];
    int cmd;
    size_t i, hostname_len, servname_len, ret_len;
    struct addrinfo *new, *last = NULL;

    if (priv_fd < 0)
        errx(1, "%s: called from privileged portion", "priv_getaddrinfo");

    if (host) {
        strlcpy(hostcpy, host, sizeof(hostcpy));
        hostname_len = strlen(hostcpy) + 1;
    } else {
        hostname_len = 0;
    }

    if (serv) {
        strlcpy(servcpy, serv, sizeof(servcpy));
        servname_len = strlen(servcpy) + 1;
    } else {
        servname_len = 0;
    }
    cmd = PRIV_GETADDRINFO;
    must_write(priv_fd, &cmd, sizeof(cmd));
    must_write(priv_fd, &hostname_len, sizeof(hostname_len));
    if (hostname_len)
        must_write(priv_fd, hostcpy, hostname_len);
    must_write(priv_fd, &servname_len, sizeof(servname_len));
    if (servname_len)
        must_write(priv_fd, servcpy, servname_len);
    must_write(priv_fd, hints, sizeof(struct addrinfo));

    /* How much addrinfo we have */
    must_read(priv_fd, &ret_len, sizeof(ret_len));

    /* Check there was no error (indicated by a return of 0) */
    if (!ret_len)
        return 0;

    for (i=0; i < ret_len; i++)
    {
        new = malloc(sizeof(struct addrinfo));
        must_read(priv_fd, &new->ai_flags, sizeof(new->ai_flags));
        must_read(priv_fd, &new->ai_family, sizeof(new->ai_family));
        must_read(priv_fd, &new->ai_socktype, sizeof(new->ai_socktype));
        must_read(priv_fd, &new->ai_protocol, sizeof(new->ai_protocol));
        must_read(priv_fd, &new->ai_addrlen, sizeof(new->ai_addrlen));
        new->ai_addr = (struct sockaddr *)malloc(new->ai_addrlen);
        must_read(priv_fd, new->ai_addr, new->ai_addrlen);
        new->ai_canonname = NULL;
        new->ai_next = NULL;

        if (i == 0)
            *addrinfo = new;
        if (last)
            last->ai_next = new;
        last = new;
    }

    return ret_len;
}

/* init script path */
int
priv_init_script(char *path)
{
    int cmd;
    size_t len;
    char errormessage[ERRMSGSIZ];

    if (priv_fd < 0)
        errx(1, "%s: called from privileged portion",
             "priv_init_script");

    cmd = PRIV_INIT_SCRIPT;
    must_write(priv_fd, &cmd, sizeof(cmd));
    len = strlen(path) + 1;
    must_write(priv_fd, &len, sizeof(len));
    must_write(priv_fd, path, len);

    must_read(priv_fd, &len, sizeof(len));

    if (len <= 0)
    {
        errx(1, "priv_init_script: invalid answer from server");
    } else if (len > ERRMSGSIZ) {
        log_warnx("privsep", "priv_init_script: error message truncated");
        len = ERRMSGSIZ;
    }
    must_read(priv_fd, errormessage, len);
    errormessage[len-1] = 0;

    if (*errormessage)
    {
        log_warnx("privsep", "error from priv server: %s",
            errormessage);
        return -1;
    }
    return 0;
}

/* run script */
int
priv_run_script(int argc, char **argv, int env_len, char **env)
{
    int cmd, retval;
    int i;
    size_t len;

    if (priv_fd < 0)
        errx(1, "%s: called from privileged portion",
             "priv_run_script");

    cmd = PRIV_RUN_SCRIPT;
    must_write(priv_fd, &cmd, sizeof(cmd));

    must_write(priv_fd, &argc, sizeof(argc));
    for (i=0; i < argc; i++)
    {
        len = strlen(argv[i]) + 1;
        must_write(priv_fd, &len, sizeof(len));
        must_write(priv_fd, argv[i], len);
    }
    must_write(priv_fd, &env_len, sizeof(env_len));
    for (i=0; i < env_len; i++) {
        len = strlen(env[i]) + 1;
        must_write(priv_fd, &len, sizeof(len));
        must_write(priv_fd, env[i], len);
    }

    must_read(priv_fd, &retval, sizeof(retval));
    return retval;
}

void priv_reload_resolver(void)
{
    int cmd;
    if (priv_fd < 0)
        errx(1, "%s: called from privileged portion",
             "priv_reload_resolver");
    cmd = PRIV_RELOAD_RESOLVER;
    must_write(priv_fd, &cmd, sizeof(cmd));
}

/* Child can signal that its initial parsing is done, so that parent
 * can revoke further logfile permissions.  This call only works once. */
void
priv_set_running_state(void)
{
    int cmd;
    if (priv_fd < 0)
        errx(1, "%s: called from privileged portion",
             "priv_set_running_state");
    cmd = PRIV_SET_RUNNING_STATE;
    must_write(priv_fd, &cmd, sizeof(cmd));
}

/* When child dies, move into the shutdown state */
/* ARGSUSED */
static void
sig_got_chld(int sig)
{
    int save_errno = errno;
    pid_t    pid;

    do {
        pid = waitpid(WAIT_ANY, NULL, WNOHANG);
        if (pid == child_pid && cur_state < STATE_QUIT)
            cur_state = STATE_QUIT;
    } while (pid > 0 || (pid == -1 && errno == EINTR));
    errno = save_errno;
}

static void
sig_pass_to_chld(int sig)
{
    int save_errno = errno;
    if (child_pid != -1)
    {
        kill(child_pid, sig);
        errno = save_errno;
    }
}

/* Read all data or return 1 for error.  */
static int
may_read(int fd, void *buf, size_t n)
{
    char *s = buf;
    ssize_t res, pos = 0;

    while (n > pos)
    {
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

    while (n > pos)
    {
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

    while (n > pos)
    {
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

static void
reset_default_signals()
{
    int i;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = SIG_DFL;
    for (i = 1; i < _NSIG; i++)
        sigaction(i, &sa, NULL);
}
