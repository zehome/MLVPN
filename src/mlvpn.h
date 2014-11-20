#ifndef _MLVPN_H
#define _MLVPN_H

#include "config.h"

#include <stdint.h>
#include <stdio.h>
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

typedef struct mlvpn_tunnel_s
{
    char *name;           /* tunnel name */
    char *bindaddr;       /* packets source */
    char *bindport;       /* packets port source (or NULL) */
    char *destaddr;       /* remote server ip (can be hostname) */
    char *destport;       /* remote server port */
    int fd;               /* socket file descriptor */
    int server_mode;      /* server or client */
    int disconnects;      /* is it stable ? */
    int conn_attempts;    /* connection attempts */
    time_t next_attempt;  /* next connection attempt */
    double weight;        /* For weight round robin */
    uint64_t sentpackets; /* 64bit packets sent counter */
    uint64_t recvpackets; /* 64bit packets recv counter */
    uint64_t sentbytes;   /* 64bit bytes sent counter */
    uint64_t recvbytes;   /* 64bit bytes recv counter */
    uint32_t latency_increase; /* 32bit latency increase counter in ms */
    circular_buffer_t *sbuf;    /* send buffer */
    circular_buffer_t *hpsbuf;  /* high priority buffer */
    circular_buffer_t *rbuf;    /* receive buffer */
    struct mlvpn_tunnel_s *next; /* chained list to next element */
    enum encap_proto encap_prot;
    struct addrinfo *addrinfo;
    enum chap_status status;     /* Auth status */
    time_t last_packet_time; /* Used to timeout the link */
    time_t timeout;
    time_t next_keepalive; /* when to send the "next" keepalive packet */
    ev_io io_read;
    ev_io io_write;
    ev_timer io_timeout;
} mlvpn_tunnel_t;

int mlvpn_config(int config_file_fd, int first_time);

int mlvpn_sock_set_nonblocking(int fd);

void mlvpn_rtun_status_up(mlvpn_tunnel_t *t);
void mlvpn_rtun_status_down(mlvpn_tunnel_t *t);
void mlvpn_rtun_tick(mlvpn_tunnel_t *t);
void mlvpn_rtun_tick_connect(mlvpn_tunnel_t *t);
void mlvpn_rtun_keepalive(time_t now, mlvpn_tunnel_t *t);
void mlvpn_rtun_check_timeout(struct ev_loop *loop, ev_timer *w, int revents);
void mlvpn_rtun_recalc_weight();
int mlvpn_rtun_bind(mlvpn_tunnel_t *t);
int mlvpn_rtun_connect(mlvpn_tunnel_t *t);
mlvpn_tunnel_t *mlvpn_rtun_last();
mlvpn_tunnel_t *mlvpn_rtun_choose();
mlvpn_tunnel_t *
mlvpn_rtun_new(const char *name,
               const char *bindaddr, const char *bindport,
               const char *destaddr, const char *destport,
               int server_mode);

int mlvpn_server_accept();

/* wrr */
int mlvpn_rtun_wrr_init(mlvpn_tunnel_t *start);
mlvpn_tunnel_t *mlvpn_rtun_wrr_choose();

/* privsep */
#include "privsep.h"

/* hook system */
enum mlvpn_hook {
    MLVPN_HOOK_TUNTAP,
    MLVPN_HOOK_RTUN
};

int mlvpn_hook(enum mlvpn_hook, int argc, char **argv);

#endif
