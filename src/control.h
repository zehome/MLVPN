#ifndef MLVPN_CONTROL_H
#define MLVPN_CONTROL_H

#include <ev.h>

#define MLVPN_CTRL_EOF 0x04
#define MLVPN_CTRL_TERMINATOR '\n'
/* Control socket (mkfifo and/or AF_INET6?) */
#define MLVPN_CTRL_BUFSIZ 1024
/* Control timeout in seconds */
#define MLVPN_CTRL_TIMEOUT 5
struct mlvpn_control
{
    int mode;
    /* TODO: PATHMAX */
    char fifo_path[1024];
    mode_t fifo_mode;
    int fifofd;
    char *bindaddr;
    char *bindport;
    int sockfd;
    /* Client part */
    int clientfd; /* Only supports one client for now */
    time_t last_activity;
    char rbuf[MLVPN_CTRL_BUFSIZ];
    int rbufpos;
    char *wbuf;
    int wbuflen;
    int wbufpos;
    int http; /* HTTP mode ? 1 for inet socket */
    int close_after_write;
    ev_io fifo_watcher;
    ev_io sock_watcher;
    ev_io client_io_read;
    ev_io client_io_write;
    ev_timer timeout_watcher;
};

enum {
    MLVPN_CONTROL_DISABLED,
    MLVPN_CONTROL_READONLY,
    MLVPN_CONTROL_READWRITE
};

void
mlvpn_control_init(struct mlvpn_control *ctrl);

int
mlvpn_control_accept(struct mlvpn_control *ctrl, int fd);

int
mlvpn_control_timeout(struct mlvpn_control *ctrl);

void
mlvpn_control_parse(struct mlvpn_control *ctrl, char *line);

int
mlvpn_control_read_check(struct mlvpn_control *ctrl);

/* inside control, write to buffer */
int
mlvpn_control_write(struct mlvpn_control *ctrl, void *buf, size_t len);

/* From main loop */
int
mlvpn_control_read(struct mlvpn_control *ctrl);

/* From main loop */
int
mlvpn_control_send(struct mlvpn_control *ctrl);

#endif
