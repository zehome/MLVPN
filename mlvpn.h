#ifndef _MLVPN_H
#define _MLVPN_H

#include <stdint.h>
#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <linux/if.h>

#include "pkt.h"
#include "buffer.h"

#define MLVPN_ETH_IP4 0x0800
#define MLVPN_ETH_IP6 0x86DD
#define MLVPN_ETH_ARP 0x0806

#define MLVPN_MAXHNAMSTR 1024
#define MLVPN_MAXPORTSTR 5
#define MLVPN_MAGIC 0xFFEEDD00

/* 4 Kbytes re-assembly buffer */
#define BUFSIZE 1024 * 4
/* Number of packets in the queue. Each pkt is ~ 1520 */
/* 1520 * 128 ~= 24 KBytes of data maximum per channel VMSize */
#define PKTBUFSIZE 128
/* Maximum channels */
#define MAXTUNNELS 128

struct tuntap_s
{
    int fd;
    int mtu;
    char devname[IFNAMSIZ];
};


struct mlvpn_ether
{
    uint8_t src[6];
    uint8_t dst[6];
    uint16_t proto;
};

struct mlvpn_ipv4
{
    uint8_t version_and_length;
    uint8_t tos;
    uint16_t length;
    uint16_t id;
    uint16_t frag;
    uint8_t ttl;
    uint8_t proto;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
};

struct mlvpn_buffer
{
    size_t len;
    char data[BUFSIZE];
};

typedef struct mlvpn_tunnel_s
{
    char *bindaddr;       /* packets source */
    char *bindport;       /* packets port source (or NULL) */
    char *destaddr;       /* remote server ip (can be hostname) */
    char *destport;       /* remote server port */
    int fd;               /* socket file descriptor */
    int server_fd;        /* server socket (used to accept) */
    int server_mode;      /* server or client */
    int disconnects;      /* is it stable ? */
    int conn_attempts;    /* connection attempts */
    time_t next_attempt;  /* next connection attempt */
    uint8_t weight;       /* For weight round robin */
    uint64_t sendpackets; /* 64bit packets send counter */
    pktbuffer_t *sbuf;    /* send buffer */
    pktbuffer_t *hpsbuf;  /* high priority buffer */
    struct mlvpn_buffer rbuf;    /* receive buffer */
    struct mlvpn_tunnel_s *next; /* chained list to next element */
    int encap_prot;       /* ENCAP_PROTO_UDP or ENCAP_PROTO_TCP */
    struct addrinfo *addrinfo;
    int activated;
    time_t last_packet_time; /* Used to timeout the link */
    time_t timeout;
} mlvpn_tunnel_t;

enum {
    ENCAP_PROTO_UDP,
    ENCAP_PROTO_TCP
};

int mlvpn_config(char *filename);
void init_buffers();

uint64_t mlvpn_millis();


/* Should be elsewhere ! */
void print_ether(struct mlvpn_ether *ether);
void print_ip4(struct mlvpn_ipv4 *ip4);
struct mlvpn_ether *
decap_ethernet_frame(struct mlvpn_ether *ether, const void *buffer);
struct mlvpn_ipv4 *
decap_ip4_frame(struct mlvpn_ipv4 *ip4, const void *buffer);
void print_frame(const char *frame);

int mlvpn_tuntap_read();
int mlvpn_tuntap_write();
int mlvpn_taptun_alloc();

void mlvpn_rtun_reset_counters();
void mlvpn_rtun_close(mlvpn_tunnel_t *tun);
void mlvpn_rtun_tick(mlvpn_tunnel_t *t);
void mlvpn_rtun_tick_connect();
int mlvpn_rtun_bind(mlvpn_tunnel_t *t);
int mlvpn_rtun_connect(mlvpn_tunnel_t *t);
int mlvpn_rtun_tick_rbuf(mlvpn_tunnel_t *tun);
int mlvpn_rtun_read(mlvpn_tunnel_t *tun);
int mlvpn_rtun_write(mlvpn_tunnel_t *tun);
int mlvpn_rtun_write_pkt(mlvpn_tunnel_t *tun, pktbuffer_t *pktbuf);
int mlvpn_rtun_timer_write(mlvpn_tunnel_t *t);
mlvpn_tunnel_t *mlvpn_rtun_last();
mlvpn_tunnel_t *mlvpn_rtun_choose();
mlvpn_tunnel_t *
mlvpn_rtun_new(const char *bindaddr, const char *bindport,
               const char *destaddr, const char *destport,
               int server_mode);

int mlvpn_server_accept();

#endif
