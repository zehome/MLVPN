#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <time.h>

#include "strlcpy.h"
#include "debug.h"
#include "control.h"
#include "mlvpn.h"
    
void
mlvpn_control_init(struct mlvpn_control *ctrl)
{
    if (ctrl->mode == MLVPN_CONTROL_DISABLED)
        return;

    struct sockaddr_un un_addr;
    struct addrinfo hints, *res, *bak;
    int ret;
    int val;

    res = bak = NULL;

    ctrl->fifofd = -1;
    ctrl->sockfd = -1;
    ctrl->clientfd = -1;
    *ctrl->rbuf = '\0';
    *ctrl->wbuf = '\0';

    /* UNIX domain socket */
    if (*ctrl->fifo_path)
    {
        ctrl->fifofd = socket(AF_LOCAL, SOCK_STREAM, 0);
        if (ctrl->fifofd < 0)
            _ERROR("Unable to create unix socket.\n");
        else {
            memset(&un_addr, 0, sizeof(un_addr));
            un_addr.sun_family = AF_UNIX;
            strlcpy(un_addr.sun_path, ctrl->fifo_path, strlen(ctrl->fifo_path)+1);
            /* remove existing sock if exists! (bad stop) */
            /* TODO: handle proper "at_exit" removal of this socket */
            unlink(un_addr.sun_path);
            if (bind(ctrl->fifofd, (struct sockaddr *) &un_addr,
                sizeof(un_addr)) < 0)
            {
                _ERROR("Error binding socket %s: %s\n", un_addr.sun_path,
                    strerror(errno));
                close(ctrl->fifofd);
                ctrl->fifofd = -1;
            }
        }
    }


    /* INET socket */
    if (*ctrl->bindaddr && *ctrl->bindport)
    {
        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_PASSIVE;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        ret = priv_getaddrinfo(ctrl->bindaddr, ctrl->bindport,
            &res, &hints);
        bak = res;
        if (ret < 0 || ! res)
        {
            _ERROR("_getaddrinfo(%s,%s) failed: %s\n",
                ctrl->bindaddr, ctrl->bindport,
                gai_strerror(ret));
        }

        while(res)
        {
            if ( (ctrl->sockfd = socket(res->ai_family,
                            res->ai_socktype,
                            res->ai_protocol)) < 0)
            {
                _ERROR("Socket creation error (%s:%s): %s\n",
                    ctrl->bindaddr, ctrl->bindport, strerror(errno));
            } else {
                val = 1;
                setsockopt(ctrl->sockfd, SOL_SOCKET, SO_REUSEADDR,
                    &val, sizeof(int));
                setsockopt(ctrl->sockfd, IPPROTO_TCP, TCP_NODELAY,
                    &val, sizeof(int));
                if (bind(ctrl->sockfd, res->ai_addr, res->ai_addrlen) < 0)
                {
                    _ERROR("Bind error on %d: %s\n", ctrl->sockfd, strerror(errno));
                    close(ctrl->sockfd);
                    ctrl->sockfd = -1;
                }
                break;
            }
            res = res->ai_next;
        }
    }
    if (bak)
        freeaddrinfo(bak);

    /* bind */
    if (ctrl->fifofd >= 0)
    {
        if (mlvpn_sock_set_nonblocking(ctrl->fifofd) < 0)
        {
            close(ctrl->fifofd);
            ctrl->fifofd = -1;
        } else {
            if (listen(ctrl->fifofd, 1) < 0)
            {
                _ERROR("Error listening: %s\n", strerror(errno));
                close(ctrl->fifofd);
                ctrl->fifofd = -1;
            }
        }
    }
    if (ctrl->sockfd >= 0)
    {
        if (mlvpn_sock_set_nonblocking(ctrl->sockfd) < 0)
        {
            close(ctrl->sockfd);
            ctrl->sockfd = -1;
        } else {
            if (listen(ctrl->sockfd, 1) < 0)
            {
                _ERROR("Error listening: %s\n", strerror(errno));
                close(ctrl->sockfd);
                ctrl->sockfd = -1;
            }
        }
    }

    return;
}

int
mlvpn_control_accept(struct mlvpn_control *ctrl, int fd)
{
    /* Early exit */
    if (fd < 0 || ctrl->mode == MLVPN_CONTROL_DISABLED)
        return 0;

    int cfd;
    int accepted = 0;
    struct sockaddr_storage clientaddr;
    socklen_t addrlen = sizeof(clientaddr);

    cfd = accept(fd, (struct sockaddr *)&clientaddr, &addrlen);
    if (cfd < 0)
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            _ERROR("Error during accept: %s\n", strerror(errno));
    } else {
        if (ctrl->clientfd != -1)
        {
            _DEBUG("Remote control already connected on fd %d.\n",
                ctrl->clientfd);
            send(cfd, "ERR: Already connected.\n", 24, 0);
            close(cfd);
        }
        accepted++;
        ctrl->clientfd = cfd;
        ctrl->rbufpos = 0;
        ctrl->wbufpos = 0;
        ctrl->last_activity = time((time_t *) NULL);
    }
    return accepted;
}

int
mlvpn_control_timeout(struct mlvpn_control *ctrl)
{
    if (ctrl->mode != MLVPN_CONTROL_DISABLED &&
        ctrl->clientfd >= 0)
    {
        if (ctrl->last_activity + MLVPN_CTRL_TIMEOUT <=
            time((time_t *)NULL))
        {
            _INFO("Control socket %d timeout.\n", ctrl->clientfd);
            close(ctrl->clientfd);
            ctrl->clientfd = -1;
            return 1;
        }
    }
    return 0;
}

/* Parse a message received from the client.
 * Example messages:
 * STATS
 * UPTIME
 * START tunX
 * STOP tunX
 * RESTART tunX
 */
void
mlvpn_control_parse(struct mlvpn_control *ctrl, char *line)
{
    char *cmd, *arg;
    char cline[MLVPN_CTRL_BUFSIZ];
    int argpos = 0;
    int i, j;

    /* Cleanup \r */
    for (i = 0, j = 0; i <= strlen(line); i++)
        if (line[i] != '\r')
            cline[j++] = line[i];
    printf("Line before: `%s' len: %d After: `%s' len:%d (j=%d)\n",
        line, strlen(line), cline, strlen(cline), j);

    cmd = strtok(cline, " ");
    if (! cmd)
        return;
    else
        printf("Command: %s\n", cmd);

    while( (arg = strtok(NULL, " ")) != NULL)
    {
        printf("ARG[%d]: `%s'\n", argpos, arg);
        argpos++;
    }
}

/* Returns 1 if a valid line is found. 0 otherwise. */
int
mlvpn_control_read_check(struct mlvpn_control *ctrl)
{
    char line[MLVPN_CTRL_BUFSIZ];
    char c;
    int i;
    for (i = 0; i < ctrl->rbufpos; i++)
    {
        c = ctrl->rbuf[i];
        if (c == MLVPN_CTRL_EOF)
        {
            _DEBUG("Received EOF from client %d.\n", ctrl->clientfd);
            close(ctrl->clientfd);
            ctrl->clientfd = -1;
            break;
        }

        if (c == MLVPN_CTRL_TERMINATOR)
        {
            memcpy(line, ctrl->rbuf, i);
            line[i] = '\0';
            /* Shift the actual buffer */
            memmove(ctrl->rbuf, ctrl->rbuf+i,
                MLVPN_CTRL_BUFSIZ - i);
            ctrl->rbufpos -= i+1;
            mlvpn_control_parse(ctrl, line);
            return 1;
        }
    }
    return 0;
}

/* Read from the socket to rbuf */
int
mlvpn_control_read(struct mlvpn_control *ctrl)
{
    int len;

    len = read(ctrl->clientfd, ctrl->rbuf + ctrl->rbufpos,
        MLVPN_CTRL_BUFSIZ - ctrl->rbufpos);
    if (len < 0)
    {
        _ERROR("Read error on Md: %s\n", ctrl->clientfd,
            strerror(errno));
        close(ctrl->clientfd);
        ctrl->clientfd = -1;
    } else if (len > 0) {
        ctrl->last_activity = time((time_t *)NULL);
        _DEBUG("Read %d bytes on control fd.\n", len);
        ctrl->rbufpos += len;
        if (ctrl->rbufpos >= MLVPN_CTRL_BUFSIZ)
        {
            _ERROR("Buffer overflow on control read buffer.\n");
            close(ctrl->clientfd);
            ctrl->clientfd = -1;
            return -1;
        }

        /* Parse the message */
        while (mlvpn_control_read_check(ctrl) != 0);
    }

    return 0;
}

/* Flush the control client wbuf */
int
mlvpn_control_write(struct mlvpn_control *ctrl)
{
    return 0;
}

