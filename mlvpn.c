/* ML-VPN is a project which intends to allow the use of multiple
 * links to another point.
 * 
 * Usefull for example for xDSL aggregation.
 * (c) 2011 Laurent Coustet http://ed.zehome.com/
 * Laurent Coustet <ed@zehome.com>
 */

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <linux/if.h>

#define MLVPN_ETH_IP4 0x0800
#define MLVPN_ETH_IP6 0x86DD
#define MLVPN_ETH_ARP 0x0806

#define MLVPN_MAXHNAMSTR 1024
#define MLVPN_MAXPORTSTR 5

/* Only 5 Kbytes */
#define BUFSIZE 1024 * 5
#define PKTBUFSIZE 32
#define MAXTUNNELS 128

struct tuntap_s
{
    int fd;
    int mtu;
    char devname[IFNAMSIZ];
};

#define MLVPN_MAGIC 0xFFEEDD00EDDEAD42
#define ETHER_MAX_PKT 1448
typedef struct mlvpn_pkt
{
    uint64_t magic;
    uint32_t len;
    char data[ETHER_MAX_PKT];
} mlvpn_pkt_t;

/* TCP overhead = 66 Bytes on the wire */
#define TCP_OVERHEAD 66
#define DEFAULT_MTU 1500
#define TUNTAP_RW_MAX DEFAULT_MTU
#define RTUN_RW_MAX (DEFAULT_MTU - TCP_OVERHEAD)
#define MAX_PKT_LEN (RTUN_RW_MAX - sizeof(mlvpn_pkt_t))

typedef struct pktbuffer_s
{
    mlvpn_pkt_t pkts[PKTBUFSIZE];
    int len;
} pktbuffer_t;

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

typedef struct mlvpn_tunnel_s
{
    int fd;               /* socket file descriptor */
    int server_fd;        /* server socket (used to accept) */
    int server_mode;      /* server or client */
    char *bindaddr;       /* packets source */
    char *bindport;       /* packets port source (or NULL) */
    char *destaddr;       /* remote server ip (can be hostname) */
    char *destport;       /* remote server port */
    int disconnects;      /* is it stable ? */
    int conn_attempts;    /* connection attempts */
    time_t next_attempt;  /* enxt connection attempt */
    uint8_t weight;       /* For weight round robin */
    uint64_t sendpackets; /* 64bit packets send counter */
    pktbuffer_t *sbuf;    /* send buffer */
    pktbuffer_t *rbuf;    /* receive buffer */
    struct mlvpn_tunnel_s *next; /* chained list to next element */
} mlvpn_tunnel_t;

/* GLOBALS */
static struct tuntap_s tuntap;
static pktbuffer_t *tap_send;
static mlvpn_tunnel_t *rtun_start = NULL;

/* Build a new pkt and insert into pktbuffer */
int
mlvpn_put_pkt(pktbuffer_t *buf, const void *data, int len)
{
    mlvpn_pkt_t pkt;
    if (len > ETHER_MAX_PKT)
    {
        fprintf(stderr, "Packet len %d overlimit!\n", len);
        return -1;
    }
    pkt.magic = MLVPN_MAGIC;
    pkt.len = len;
    memmove(pkt.data, data, len);
    memcpy(&buf->pkts[buf->len], &pkt, sizeof(mlvpn_pkt_t));
    return ++buf->len;
}

void
mlvpn_pop_pkt(pktbuffer_t *buf)
{
    int i;
    for (i = 0; i < buf->len-1; i++)
        memmove(&buf->pkts[i], &buf->pkts[i+1], sizeof(mlvpn_pkt_t));
    buf->len -= 1;
}

mlvpn_tunnel_t *
mlvpn_rtun_last()
{
    mlvpn_tunnel_t *t = rtun_start;
    if (t == NULL)
        return NULL;
    while (t->next)
        t = t->next;
    return t;
}

mlvpn_tunnel_t *
mlvpn_rtun_new(const char *bindaddr, const char *bindport,
               const char *destaddr, const char *destport,
               int server_mode)
{
    mlvpn_tunnel_t *last = rtun_start;
    mlvpn_tunnel_t *new;
    int i;

    /* Some basic checks */
    if (server_mode)
    {
        if (bindaddr == NULL || bindport == NULL)
        {
            fprintf(stderr, "Can initialize socket with null bindaddr:bindport.\n");
            return NULL;
        }
    } else {
        if (destaddr == NULL || destport == NULL)
        {
            fprintf(stderr, "Can initialize socket with null destaddr:destport.\n");
            return NULL;
        }
    }

    new = (mlvpn_tunnel_t *)calloc(1, sizeof(mlvpn_tunnel_t));
    /* other values are enforced by calloc to 0/NULL */

    new->fd = -1;
    new->server_mode = server_mode;
    new->server_fd = -1;
    new->weight = 1;

    if (bindaddr)
    {
        new->bindaddr = malloc(MLVPN_MAXHNAMSTR+1);
        strncpy(new->bindaddr, bindaddr, MLVPN_MAXHNAMSTR);
    }

    if (bindport)
    {
        new->bindport = malloc(MLVPN_MAXPORTSTR+1);
        strncpy(new->bindport, bindport, MLVPN_MAXPORTSTR);
    }

    if (destaddr)
    {
        new->destaddr = malloc(MLVPN_MAXHNAMSTR+1);
        strncpy(new->destaddr, destaddr, MLVPN_MAXHNAMSTR);
    }

    if (destport)
    {
        new->destport = malloc(MLVPN_MAXPORTSTR+1);
        strncpy(new->destport, destport, MLVPN_MAXPORTSTR);
    }

    new->sbuf = (pktbuffer_t *)calloc(1, sizeof(pktbuffer_t));
    new->sbuf->len = 0;
    new->rbuf = (pktbuffer_t *)calloc(1, sizeof(pktbuffer_t));
    new->rbuf->len = 0;

    /* insert into chained list */
    last = mlvpn_rtun_last();
    if (last) {
        last->next = new;
    } else {
        /* First element */
        rtun_start = new; 
    }
    return new;
}

int
mlvpn_rtun_bind(mlvpn_tunnel_t *t)
{
    struct addrinfo hints, *res;
    int n, fd;
    memset(&hints, 0, sizeof(struct addrinfo));
    /* AI_PASSIVE flag: the resulting address is used to bind
       to a socket for accepting incoming connections.
       So, when the hostname==NULL, getaddrinfo function will
       return one entry per allowed protocol family containing
       the unspecified address for that family. */
    hints.ai_flags    = AI_PASSIVE;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    n = getaddrinfo(t->bindaddr, t->bindport, &hints, &res);
    if (n < 0)
    {
        fprintf(stderr, "getaddrinfo error: [%s]\n", gai_strerror(n));
        return -1;
    }
    /* Try open socket with each address getaddrinfo returned,
       until getting a valid listening socket. */
    if (t->server_mode)
        fd = t->server_fd;
    else
        fd = t->fd;

    printf("Binding socket %d to %s\n", fd, t->bindaddr);
    n = bind(fd, res->ai_addr, res->ai_addrlen);
    if (n < 0)
    {
        perror("bind");
        return -1;
    }
    return 0;
}

int mlvpn_rtun_connect(mlvpn_tunnel_t *t)
{
    int ret, fd;
    char *addr, *port;
    struct addrinfo hints, *res, *back;

    if (t->server_mode)
    {
        addr = t->bindaddr;
        port = t->bindport;
        fd = t->server_fd;
        printf("server_rtun_connect %s %s\n", addr, port);
    } else {
        addr = t->destaddr;
        port = t->destport;
        fd = t->fd;
        printf("client_rtun_connect %s %s\n", addr, port);
    }

    /* Initialize hints */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET; /* Prefer IPv4 */
    hints.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo(addr, port, &hints, &res);
    if (ret < 0)
    {
        fprintf(stderr, "Connection to [%s]:%s failed. getaddrinfo: [%s]\n", addr, port, gai_strerror(ret));
        return -1;
    }
    back = res;
    while (res)
    {
        /* creation de la socket(2) */
        if ( (fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
        {
            fprintf(stderr, "Socket creation error while connecting to [%s]: %s\n", addr, port);
        } else {
            fprintf(stderr, "Created socket %d.\n", fd);
            if (t->server_mode)
                t->server_fd = fd;
            else
                t->fd = fd;

            /* setup non blocking sockets */
            int val = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(int));
            setsockopt(t->fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(int));
            if (t->bindaddr)
            {
                if (mlvpn_rtun_bind(t) < 0)
                {
                    fprintf(stderr, "Unable to bind socket %d.\n", fd);
                    if (t->server_mode)
                        goto error;
                }
            }
            if (t->server_mode)
            {
                /* listen, only allow 1 socket in accept() queue */
                if ((ret = listen(fd, 1)) < 0)
                {
                    fprintf(stderr, "Unable to listen on socket %d.\n", fd);
                    goto error;
                }
            } else {
                /* client mode */
                fprintf(stderr, "Connecting to [%s]:%s\n", addr, port);
                /* connect(2) */
                if (connect(fd, res->ai_addr, res->ai_addrlen) == 0)
                {
                    fprintf(stderr, "Successfully connected to [%s]:%s.\n", addr, port);
                    break;
                } else {
                    fprintf(stderr, "Connection to [%s]:%s failed.\n", addr, port);
                    perror("connect");
                    close(fd);
                    t->fd = -1;
                }
            }
            /* set non blocking after connect... May lockup the entiere process */
            long fl = fcntl(fd, F_GETFL);
            if (fl < 0)
            {
                fprintf(stderr, "Error during fcntl.\n");
                perror("fcntl F_GETFL");
            } else {
                fl |= O_NONBLOCK;
                if (fcntl(fd, F_SETFL, fl) < 0)
                {
                    fprintf(stderr, "Unable to set socket %d non blocking.\n", fd);
                    perror("fcntl F_SETFL");
                }
            }
        }
        res = res->ai_next;
    }
    
    freeaddrinfo(back);
    return 0;
error:
    freeaddrinfo(back);
    return -1;
}

void mlvpn_tick_connect_rtun()
{
    mlvpn_tunnel_t *t = rtun_start;
    int ret, fd;
    time_t now;

    while (t)
    {
        if (t->server_mode)
            fd = t->server_fd;
        else
            fd = t->fd;
        if (fd < 0)
        {
            now = time((time_t *)NULL);
            if (t->next_attempt <= 0 || now >= t->next_attempt)
            {
                t->conn_attempts += 1;
                ret = mlvpn_rtun_connect(t);
                if (ret < 0)
                {
                    t->next_attempt = now + t->conn_attempts * 10;
                } else {
                    t->next_attempt = 0;
                    t->conn_attempts = 0;
                }
            }
        }
        t = t->next;
    }
}

int mlvpn_server_accept()
{
    mlvpn_tunnel_t *t = rtun_start;
    int fd;
    char clienthost[NI_MAXHOST];
    char clientservice[NI_MAXSERV];

    struct sockaddr_storage clientaddr;
    socklen_t addrlen = sizeof(clientaddr);

    int accepted = 0;

    while (t)
    {
        if (t->server_fd > 0)
        {
            fd = accept(t->server_fd, (struct sockaddr *)&clientaddr, &addrlen);
            if (fd < 0)
            {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    perror("accept");
            } else {
                accepted++;

                memset(clienthost, 0, sizeof(clienthost));
                memset(clientservice, 0, sizeof(clientservice));

                getnameinfo((struct sockaddr *)&clientaddr, addrlen,
                            clienthost, sizeof(clienthost),
                            clientservice, sizeof(clientservice),
                            NI_NUMERICHOST);
                fprintf(stderr, "Connection attempt from [%s]:%s.\n", 
                    clienthost, clientservice);
                if (t->fd >= 0)
                {
                    fprintf(stderr, "Overwritting already existing connection.\n");
                    close(t->fd);
                    t->fd = -1;
                }
                t->fd = fd;

                long fl = fcntl(t->fd, F_GETFL);
                if (fl < 0)
                {
                    fprintf(stderr, "Error during fcntl.\n");
                    perror("fcntl F_GETFL");
                } else {
                    fl |= O_NONBLOCK;
                    if (fcntl(t->fd, F_SETFL, fl) < 0)
                    {
                        fprintf(stderr, "Unable to set socket %d non blocking.\n", t->fd);
                        perror("fcntl F_SETFL");
                    }
                }
            }
        }
        t = t->next;
    }
    return accepted;
}

int mlvpn_taptun_alloc()
{
    struct ifreq ifr;
    int fd, err;

    if ( (fd = open("/dev/net/tun", O_RDWR)) < 0 )
    {
        fprintf(stderr, "Unable to open /dev/net/tun RW. Check permissions.\n");
        return fd;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; /* We do not want kernel packet info */

    /* Allocate with specified name, otherwise the kernel
     * will find a name for us.
     */
    if (tuntap.devname)
    {
        strncpy(ifr.ifr_name, tuntap.devname, IFNAMSIZ);
    }

    /* ioctl to create the if */
    if ( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0)
    {
        fprintf(stderr, "Unable to create the device. Kernel returned %d.\n", err);
        perror("ioctl");
        close(fd);
        return err;
    }

    /* The kernel is the only one able to "name" the if.
     * so we reread it to get the real name set by the kernel.
     */
    if (tuntap.devname)
        strncpy(tuntap.devname, ifr.ifr_name, IFNAMSIZ);

    tuntap.fd = fd;
    return fd;
}

void print_ether(struct mlvpn_ether *ether)
{
    int i;

    printf("ether ");

    for (i = 0; i < 6; i++)
    {
        printf("%02x", ether->src[i]);
        if (i<5) printf(":");
    }

    printf(" > ");

    for (i = 0; i < 6; i++)
    {
        printf("%02x", ether->dst[i]);
        if (i<5) printf(":");
    }

    printf(" proto ");
    uint16_t proto = ntohs(ether->proto);

    if (proto == MLVPN_ETH_IP4)
        printf("IPv4");
    else if (proto == MLVPN_ETH_IP6)
        printf("IPv6");
    else if (proto == MLVPN_ETH_ARP)
        printf("ARP");
    else
        printf("%04x", proto);
}

void
print_ip4(struct mlvpn_ipv4 *ip4)
{
    char src[INET_ADDRSTRLEN+1];
    char dst[INET_ADDRSTRLEN+1];

    memset(src, 0, INET_ADDRSTRLEN+1);
    memset(dst, 0, INET_ADDRSTRLEN+1);

    printf(" tos: %03d ", ip4->tos);
    printf(" len: %05d ", ntohs(ip4->length));

    struct in_addr src_addr;
    struct in_addr dst_addr;

    src_addr.s_addr = ip4->src;
    dst_addr.s_addr = ip4->dst;

    inet_ntop(AF_INET, (const struct in_addr*)&src_addr, src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, (const struct in_addr*)&dst_addr, dst, INET_ADDRSTRLEN);

    printf("%s > %s", src, dst);
}

struct mlvpn_ether *
decap_ethernet_frame(struct mlvpn_ether *ether, const void *buffer)
{
    memcpy(ether, buffer, sizeof(struct mlvpn_ether));
    return ether;
}

struct mlvpn_ipv4 *
decap_ip4_frame(struct mlvpn_ipv4 *ip4, const void *buffer)
{
    memcpy(ip4, buffer, sizeof(struct mlvpn_ipv4));
    return ip4;
}

void print_frame(const char *frame)
{
    /* decap packet to get TOS */
    //struct mlvpn_ether ether;
    struct mlvpn_ipv4 ip4;
    //decap_ethernet_frame(&ether, frame);
    //print_ether(&ether);
    //if (ntohs(ether.proto) == MLVPN_ETH_IP4)
    //{
    //    //decap_ip4_frame(&ip4, frame+sizeof(struct mlvpn_ether));
        decap_ip4_frame(&ip4, frame);
        print_ip4(&ip4);
    //}
}

mlvpn_tunnel_t *
mlvpn_choose_least_packets_rtun()
{
    mlvpn_tunnel_t *t = rtun_start;
    mlvpn_tunnel_t *lpt = t;
    uint64_t least = 0-1; /* max value */
    uint64_t tmp;

    while (t)
    {
        if (t->fd > 0)
        {
            tmp = (t->sendpackets * t->weight);
            if (tmp <= least)
            {
                least = tmp;
                lpt = t;
            }
        }
        t = t->next;
    }
    lpt->sendpackets++;
    return lpt;
}

int mlvpn_read_tap()
{
    int len;
    char buffer[DEFAULT_MTU];

    /* least packets tunnel */
    mlvpn_tunnel_t *lpt = mlvpn_choose_least_packets_rtun();

    len = read(tuntap.fd, buffer, DEFAULT_MTU);
    if (len < 0)
    {
        perror("read");
    } else if (len > 0) {
        if (lpt->sbuf->len + 1 > PKTBUFSIZE)
        {
            fprintf(stderr, "Tun %d buffer overrun.\n", lpt->fd);
            lpt->sbuf->len = 0;
        }

        /* Horrible debug */
        printf("< TAP\t");
        print_frame(buffer);

        if (! lpt)
        {
            printf(" [ERR]\n");
            return 0;
        } else {
            printf("\n");
        }

        mlvpn_put_pkt(lpt->sbuf, buffer, len);
    }
    return len;
}

int mlvpn_write_tap()
{
    int len;
    mlvpn_pkt_t *pkt;
    pktbuffer_t *buf = tap_send;

    if (buf->len <= 0)
    {
        fprintf(stderr, 
            "Nothing to write on tap! (%d) PROGRAMMING ERROR.\n", buf->len);
        return -1;
    }
    pkt = &buf->pkts[0];
    len = write(tuntap.fd, pkt->data, pkt->len);
    if (len < 0)
    {
        fprintf(stderr, "Write error on tuntap.\n");
        perror("write");
    } else {
        if (len != pkt->len)
        {
            fprintf(stderr, "Error writing to tap device: written %d bytes out of %d.\n", len, pkt->len);
        } else {
            printf("> Written %d bytes on TAP (%d pkts left).\n", len, buf->len);
        }
    }
    mlvpn_pop_pkt(buf);
    return len;
}

/* read from the rtunnel => write directly to the tap send buffer */
int mlvpn_read_rtun(mlvpn_tunnel_t *tun)
{
    int len;
    mlvpn_pkt_t pkt;

    if (tap_send->len+1 > PKTBUFSIZE)
    {
        fprintf(stderr, "TAP buffer overrun.\n");
        tap_send->len = 0;
    }

    len = read(tun->fd, &pkt, sizeof(pkt));
    if (len < 0)
    {
        perror("read");
        close(tun->fd);
        tun->fd = -1;
    } else if (len != 0) {

        if (len != sizeof(pkt)) {
            fprintf(stderr, "Wrong len, get %ld need %ld\n", len, sizeof(pkt));
            return len;
        }

        if (pkt.magic != MLVPN_MAGIC)
        {
            fprintf(stderr, "Invalid mlvpn pkt. %llx != %llx\n", pkt.magic, (uint64_t)MLVPN_MAGIC);
            fprintf(stderr, "len = %ld\n", len);
            return -1;
        }
        printf("< TUN %d read %d bytes.\n", tun->fd, pkt.len);
        mlvpn_put_pkt(tap_send, pkt.data, pkt.len);
    }
    return len;
}

int mlvpn_write_rtun(mlvpn_tunnel_t *tun)
{
    int len;
    mlvpn_pkt_t *pkt = &tun->sbuf->pkts[0];

    len = write(tun->fd, pkt, sizeof(*pkt));
    if (len < 0)
    {
        fprintf(stderr, "Write error on tunnel fd=%d\n", tun->fd);
        perror("write");
        close(tun->fd);
        tun->fd = -1;
    } else {
        if (sizeof(*pkt) != len)
        {
            fprintf(stderr, "Error writing on TUN %d: written %d bytes over %d.\n",
                tun->fd, len, sizeof(*pkt));
        } else {
            printf("> TUN %d written %d bytes (%d pkts left).\n", tun->fd, len, tun->sbuf->len - 1);
        }
    }
    mlvpn_pop_pkt(tun->sbuf);
    return len;
}

void init_buffers()
{
    tap_send = (pktbuffer_t *)calloc(1, sizeof(pktbuffer_t));
    tap_send->len = 0;
}

int main(int argc, char **argv)
{
    int ret;
    mlvpn_tunnel_t *tmptun;

    printf("ML-VPN (c) 2011 Laurent Coustet\n");

    init_buffers();

    memset(&tuntap, 0, sizeof(tuntap));

    snprintf(tuntap.devname, IFNAMSIZ, "mlvpn%d", 0);
    tuntap.mtu = 1500;
    ret = mlvpn_taptun_alloc();
    if (ret <= 0)
    {
        fprintf(stderr, "Unable to create tunnel device.\n");
        return 1;
    } else {
        fprintf(stderr, "Created tap interface %s\n", tuntap.devname);
    }
    
    /* client */
    /*
    for (i = 0; i < 4; i++)
    {
        char port[6];
        memset(port, 0, 6);
        snprintf(port, 5, "%d", 5080+i);
        tmptun = mlvpn_rtun_new(NULL, NULL, "192.168.6.2", port, 0);
    }
    */
    tmptun = mlvpn_rtun_new(NULL, NULL, "chp.zehome.com", "5080", 0);
    tmptun = mlvpn_rtun_new(NULL, NULL, "chp1.zehome.com", "5081", 0);
    tmptun = mlvpn_rtun_new(NULL, NULL, "chp2.zehome.com", "5082", 0);

    /* srv */
    /*
    for (i = 0; i < 4; i++)
    {
        char port[6];
        memset(port, 0, 6);
        snprintf(port, 5, "%d", 5080+i);
        tmptun = mlvpn_rtun_new("0.0.0.0", port, NULL, NULL, 1);
    }
    */

    while ( 1 ) 
    {
        /* Connect rtun if not connected. tick if connected */
        mlvpn_tick_connect_rtun();
        mlvpn_server_accept();

        int maxfd = 0;
        struct timeval timeout;
        fd_set rfds, wfds;
        
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_SET(tuntap.fd, &rfds);
        if (tuntap.fd > maxfd)
            maxfd = tuntap.fd;

        if (tap_send->len > 0)
            FD_SET(tuntap.fd, &wfds);

        /* set rfds/wfds for rtunnels */
        tmptun = rtun_start;
        while (tmptun)
        {
            if (tmptun->fd > 0)
            {
                if (tmptun->sbuf->len > 0)
                    FD_SET(tmptun->fd, &wfds);
                FD_SET(tmptun->fd, &rfds);
                if (tmptun->fd > maxfd)
                    maxfd = tmptun->fd;
            }
            tmptun = tmptun->next;
        }

        timeout.tv_sec = 1;
        timeout.tv_usec = 50000;

        ret = select(maxfd+1, &rfds, &wfds, NULL, &timeout);
        if (ret > 0)
        {
            if (FD_ISSET(tuntap.fd, &rfds))
                mlvpn_read_tap();
            if (FD_ISSET(tuntap.fd, &wfds))
                mlvpn_write_tap();
            tmptun = rtun_start;
            while (tmptun)
            {
                if (tmptun->fd > 0)
                {
                    if (FD_ISSET(tmptun->fd, &rfds))
                        mlvpn_read_rtun(tmptun);
                    if (FD_ISSET(tmptun->fd, &wfds))
                        mlvpn_write_rtun(tmptun);
                }
                tmptun = tmptun->next;
            }
        } else if (ret < 0) {
            /* Error */
            perror("select");
            return 2;
        }
    }

    return 0;
}
