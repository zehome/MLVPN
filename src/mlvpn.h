#ifndef _MLVPN_H
#define _MLVPN_H

#include "includes.h"

#include <stdint.h>
#include <stdio.h>
#include <sys/queue.h>
#include <ev.h>

#ifdef HAVE_OPENBSD
#include <netinet/in.h>
#endif

/* Many thanks Fabien Dupont! */
#ifdef HAVE_LINUX
/* Absolutely essential to have it there for IFNAMSIZ */
#include <sys/types.h>
#include <netdb.h>
#include <linux/if.h>
#endif

#include <arpa/inet.h>

#include "pkt.h"
#include "buffer.h"

#define MLVPN_MAXHNAMSTR 1024
#define MLVPN_MAXPORTSTR 5

/* Number of packets in the queue. Each pkt is ~ 1520 */
/* 1520 * 128 ~= 24 KBytes of data maximum per channel VMSize */
#define PKTBUFSIZE 128

/* tuntap interface name size */
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif
#define MLVPN_IFNAMSIZ IFNAMSIZ

#define NEXT_KEEPALIVE(now, t) (now + (t->timeout / 2))

struct mlvpn_options
{
    /* use ps_status or not ? */
    int change_process_title;
    /* process name if set */
    char process_name[1024];
    /* where is the config file */
    /* TODO: PATHMAX */
    char config[1024];
    int config_fd;
    /* verbose mode */
    int verbose;
    /* background */
    int background;
    /* pidfile */
    char pidfile[1024];
    /* User change if running as root */
    char unpriv_user[128];
    int root_allowed;
};

enum encap_proto {
    ENCAP_PROTO_UDP
};

enum chap_status {
    MLVPN_CHAP_DISCONNECTED,
    MLVPN_CHAP_AUTHSENT,
    MLVPN_CHAP_AUTHOK
};

LIST_HEAD(rtunhead, mlvpn_tunnel_s) rtuns;

typedef struct mlvpn_tunnel_s
{
    LIST_ENTRY(mlvpn_tunnel_s) entries;
    char *name;           /* tunnel name */
    char *bindaddr;       /* packets source */
    char *bindport;       /* packets port source (or NULL) */
    char *destaddr;       /* remote server ip (can be hostname) */
    char *destport;       /* remote server port */
    int fd;               /* socket file descriptor */
    int server_mode;      /* server or client */
    int disconnects;      /* is it stable ? */
    int conn_attempts;    /* connection attempts */
    double weight;        /* For weight round robin */
    uint64_t sentpackets; /* 64bit packets sent counter */
    uint64_t recvpackets; /* 64bit packets recv counter */
    uint64_t sentbytes;   /* 64bit bytes sent counter */
    uint64_t recvbytes;   /* 64bit bytes recv counter */
    uint32_t timeout;     /* configured timeout in seconds */
    uint32_t bandwidth;   /* bandwidth in bytes per second */
    circular_buffer_t *sbuf;    /* send buffer */
    circular_buffer_t *hpsbuf;  /* high priority buffer */
    circular_buffer_t *rbuf;    /* receive buffer */
    enum encap_proto encap_prot;
    struct addrinfo *addrinfo;
    enum chap_status status;    /* Auth status */
    ev_tstamp last_activity;
    ev_tstamp last_connection_attempt;
    ev_tstamp next_keepalive;
    ev_io io_read;
    ev_io io_write;
    ev_timer io_timeout;
} mlvpn_tunnel_t;

int mlvpn_config(int config_file_fd, int first_time);
int mlvpn_sock_set_nonblocking(int fd);


/* wrr */
int mlvpn_rtun_wrr_init(struct rtunhead *head);
mlvpn_tunnel_t *mlvpn_rtun_wrr_choose();
mlvpn_tunnel_t *mlvpn_rtun_choose();
mlvpn_tunnel_t *mlvpn_rtun_new(const char *name,
    const char *bindaddr, const char *bindport,
    const char *destaddr, const char *destport,
    int server_mode, uint32_t timeout);
void mlvpn_rtun_drop(mlvpn_tunnel_t *t);
void mlvpn_rtun_status_down(mlvpn_tunnel_t *t);

/* privsep */
#include "privsep.h"

/* hook system */
enum mlvpn_hook {
    MLVPN_HOOK_TUNTAP,
    MLVPN_HOOK_RTUN
};

int mlvpn_hook(enum mlvpn_hook, int argc, char **argv);

/* log.c */
void log_init(int);
void log_verbose(int);
void log_warn(const char *, ...) __attribute__((__format__ (printf, 1, 2)));
void log_warnx(const char *, ...) __attribute__((__format__ (printf, 1, 2)));
void log_info(const char *, ...) __attribute__((__format__ (printf, 1, 2)));
void log_debug(const char *, ...) __attribute__((__format__ (printf, 1, 2)));
void logit(int, const char *, ...) __attribute__((__format__ (printf, 2, 3)));
void vlog(int, const char *, va_list) __attribute__((__format__ (printf, 2, 0)));
__attribute__((noreturn)) void fatal(const char *);
__attribute__((noreturn)) void fatalx(const char *);

#endif
