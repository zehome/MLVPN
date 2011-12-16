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
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>

#include "debug.h"
#include "mlvpn.h"

/* GLOBALS */
static struct tuntap_s tuntap;
static pktbuffer_t *tap_send;
static mlvpn_tunnel_t *rtun_start = NULL;

uint64_t mlvpn_millis()
{
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0)
    {
        perror("gettimeofday");
        return 1;
    }
    return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
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

    /* Some basic checks */
    if (server_mode)
    {
        if (bindaddr == NULL || bindport == NULL)
        {
            _ERROR("Can initialize socket with null bindaddr:bindport.\n");
            return NULL;
        }
    } else {
        if (destaddr == NULL || destport == NULL)
        {
            _ERROR("Can initialize socket with null destaddr:destport.\n");
            return NULL;
        }
    }

    new = (mlvpn_tunnel_t *)calloc(1, sizeof(mlvpn_tunnel_t));
    /* other values are enforced by calloc to 0/NULL */

    new->fd = -1;
    new->server_mode = server_mode;
    new->server_fd = -1;
    new->weight = 1;
    new->activated = 0;
    new->encap_prot = ENCAP_PROTO_UDP;
    new->addrinfo = (struct addrinfo *)malloc(sizeof(struct addrinfo));
    memset(new->addrinfo, 0, sizeof(struct addrinfo));

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
    new->sbuf->bandwidth = 0;

    new->hpsbuf = (pktbuffer_t *)calloc(1, sizeof(pktbuffer_t));
    new->hpsbuf->len = 0;
    new->hpsbuf->bandwidth = 0;

    memset(new->rbuf.data, 0, BUFSIZE);
    new->rbuf.len = 0;
    
    new->sbuf->pkts = (mlvpn_pkt_t *)calloc(PKTBUFSIZE, sizeof(mlvpn_pkt_t));
    new->hpsbuf->pkts = (mlvpn_pkt_t *)calloc(PKTBUFSIZE, sizeof(mlvpn_pkt_t));

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
    fd = t->fd;
    if (t->encap_prot == ENCAP_PROTO_TCP)
    {
        hints.ai_socktype = SOCK_STREAM;
        if (t->server_mode)
            fd = t->server_fd;
    } else {
        hints.ai_socktype = SOCK_DGRAM;
    }
    n = getaddrinfo(t->bindaddr, t->bindport, &hints, &res);
    if (n < 0)
    {
        _ERROR("getaddrinfo error: [%s]\n", gai_strerror(n));
        return -1;
    }

    /* Try open socket with each address getaddrinfo returned,
       until getting a valid listening socket. */
    _INFO("Binding socket %d to %s\n", fd, t->bindaddr);
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
    struct addrinfo hints, *res;

    fd = t->fd;
    if (t->server_mode)
    {
        if (t->encap_prot == ENCAP_PROTO_TCP)
            fd = t->server_fd;
        addr = t->bindaddr;
        port = t->bindport;
        _INFO("server_rtun_connect %s %s\n", addr, port);
    } else {
        addr = t->destaddr;
        port = t->destport;
        _INFO("client_rtun_connect %s %s\n", addr, port);
    }

    /* Initialize hints */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; /* Prefer IPv4 */
    if (t->encap_prot == ENCAP_PROTO_TCP)
    {
        hints.ai_socktype = SOCK_STREAM;
    } else {
        hints.ai_socktype = SOCK_DGRAM;
    }

    ret = getaddrinfo(addr, port, &hints, &t->addrinfo);
    if (ret < 0)
    {
        _ERROR("Connection to [%s]:%s failed. getaddrinfo: [%s]\n", addr, port, gai_strerror(ret));
        return -1;
    }
    res = t->addrinfo;

    while (res)
    {
        /* creation de la socket(2) */
        if ( (fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
        {
            _ERROR("Socket creation error while connecting to [%s]: %s\n", addr, port);
        } else {
            _ERROR("Created socket %d.\n", fd);
            if (t->server_mode && t->encap_prot == ENCAP_PROTO_TCP)
                t->server_fd = fd;
            else
                t->fd = fd;

            /* setup non blocking sockets */
            int val = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(int));
            if (t->encap_prot == ENCAP_PROTO_TCP)
                setsockopt(t->fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(int));
            if (t->bindaddr)
            {
                if (mlvpn_rtun_bind(t) < 0)
                {
                    _ERROR("Unable to bind socket %d.\n", fd);
                    if (t->server_mode)
                        goto error;
                }
            }
            if (t->encap_prot == ENCAP_PROTO_TCP)
            {
                if (t->server_mode)
                {
                    /* listen, only allow 1 socket in accept() queue */
                    if ((ret = listen(fd, 1)) < 0)
                    {
                        _ERROR("Unable to listen on socket %d.\n", fd);
                        goto error;
                    }
                } else {
                    /* client mode */
                    _ERROR("Connecting to [%s]:%s\n", addr, port);
                    /* connect(2) */
                    if (connect(fd, res->ai_addr, res->ai_addrlen) == 0)
                    {
                        _ERROR("Successfully connected to [%s]:%s.\n", addr, port);
                        break;
                    } else {
                        _ERROR("Connection to [%s]:%s failed.\n", addr, port);
                        perror("connect");
                        close(fd);
                        t->fd = -1;
                    }
                }
            }
            /* set non blocking after connect... May lockup the entiere process */
            long fl = fcntl(fd, F_GETFL);
            if (fl < 0)
            {
                _ERROR("Error during fcntl.\n");
                perror("fcntl F_GETFL");
            } else {
                fl |= O_NONBLOCK;
                if (fcntl(fd, F_SETFL, fl) < 0)
                {
                    _ERROR("Unable to set socket %d non blocking.\n", fd);
                    perror("fcntl F_SETFL");
                }
            }
        }
        res = res->ai_next;
    }
    
    return 0;
error:
    return -1;
}

void mlvpn_tick_connect_rtun()
{
    mlvpn_tunnel_t *t = rtun_start;
    int ret, fd;
    time_t now;

    while (t)
    {
        if (t->server_mode && t->encap_prot == ENCAP_PROTO_TCP)
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
        if (t->server_fd > 0 && t->encap_prot == ENCAP_PROTO_TCP)
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
                            NI_NUMERICHOST|NI_NUMERICSERV);
                _ERROR("Connection attempt from [%s]:%s.\n", 
                    clienthost, clientservice);
                if (t->fd >= 0)
                {
                    _ERROR("Overwritting already existing connection.\n");
                    close(t->fd);
                    t->fd = -1;
                    t->activated = 1;
                }
                t->fd = fd;

                long fl = fcntl(t->fd, F_GETFL);
                if (fl < 0)
                {
                    _ERROR("Error during fcntl.\n");
                    perror("fcntl F_GETFL");
                } else {
                    fl |= O_NONBLOCK;
                    if (fcntl(t->fd, F_SETFL, fl) < 0)
                    {
                        _ERROR("Unable to set socket %d non blocking.\n", t->fd);
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
        _ERROR("Unable to open /dev/net/tun RW. Check permissions.\n");
        return fd;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; /* We do not want kernel packet info */

    /* Allocate with specified name, otherwise the kernel
     * will find a name for us.
     */
    if (tuntap.devname)
        strncpy(ifr.ifr_name, tuntap.devname, IFNAMSIZ);

    /* ioctl to create the if */
    if ( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0)
    {
        _ERROR("Unable to create the device. Kernel returned %d.\n", err);
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
    struct mlvpn_ether ether;
    struct mlvpn_ipv4 ip4;
    decap_ethernet_frame(&ether, frame);
    print_ether(&ether);
    if (ntohs(ether.proto) == MLVPN_ETH_IP4)
    {
        decap_ip4_frame(&ip4, frame+sizeof(struct mlvpn_ether));
        decap_ip4_frame(&ip4, frame);
        print_ip4(&ip4);
    }
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
        if (t->fd > 0 && t->activated)
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
    if (lpt)
        lpt->sendpackets++;
    return lpt;
}

int mlvpn_read_tap()
{
    int len;
    char buffer[DEFAULT_MTU];
    pktbuffer_t *sbuf;
    mlvpn_tunnel_t *lpt;

    /* least packets tunnel */
    lpt = mlvpn_choose_least_packets_rtun();
    if (! lpt)
        return 0;

    sbuf = lpt->sbuf;

    len = read(tuntap.fd, buffer, DEFAULT_MTU);
    if (len < 0)
    {
        perror("read");
    } else if (len > 0) {
        struct mlvpn_ipv4 ip4;
        decap_ip4_frame(&ip4, buffer);

        /* icmp ? */
        if (ip4.proto & 0x01 || ip4.tos & 0x10)
            sbuf = lpt->hpsbuf;

        if (sbuf->len+1 > PKTBUFSIZE)
        {
            _WARNING("TUN %d buffer overrun.\n", lpt->fd);
            sbuf->len = 0;
        }
        mlvpn_put_pkt(sbuf, buffer, len);
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
        _ERROR( 
            "Nothing to write on tap! (%d) PROGRAMMING ERROR.\n", (int)buf->len);
        return -1;
    }
    pkt = &buf->pkts[0]; /* First pkt in queue */
    len = write(tuntap.fd, pkt->pktdata.data, pkt->pktdata.len);
    if (len < 0)
    {
        _ERROR("Write error on tuntap.\n");
        perror("write");
    } else {
        if (len != pkt->pktdata.len)
        {
            _ERROR("Error writing to tap device: written %d bytes out of %d.\n", len, pkt->pktdata.len);
        } else {
            _DEBUG("> Written %d bytes on TAP (%d pkts left).\n", len, (int)buf->len);
        }
    }
    mlvpn_pop_pkt(buf);
    return len;
}

/* Pass thru the mlvpn_rbuf to find packets received
 * from the TCP/UDP channel and prepare packets for TUN/TAP device. */
int mlvpn_tick_rtun_rbuf(mlvpn_tunnel_t *tun)
{
    struct mlvpn_pktdata pktdata;
    int i;
    int pkts = 0;
    int last_shift = -1;

    for (i = 0; i < tun->rbuf.len - (PKTHDRSIZ(pktdata)) ; i++)
    {
        void *rbuf = tun->rbuf.data + i;
        /* Finding the magic and re-assemble valid pkt */
        memcpy(&pktdata, rbuf, PKTHDRSIZ(pktdata));
        if (pktdata.magic == MLVPN_MAGIC)
        {
            if (tun->rbuf.len - i >= pktdata.len+PKTHDRSIZ(pktdata))
            {
                /* Valid packet, copy the rest */
                memcpy(&pktdata, rbuf, PKTHDRSIZ(pktdata)+pktdata.len);
                if (tap_send->len+1 > PKTBUFSIZE)
                {
                    _ERROR("TAP buffer overrun.\n");
                    tap_send->len = 0;
                }
                mlvpn_put_pkt(tap_send, pktdata.data, pktdata.len);

                /* shift read buffer to the right */
                /* -1 because of i++ in the loop */
                i += (PKTHDRSIZ(pktdata) + pktdata.len - 1); 
                last_shift = i;
                /* Overkill */
                memset(&pktdata, 0, sizeof(pktdata));
                pkts++;
            } else {
                _DEBUG("Found pkt but not enough data. Len=%d available=%d\n", (int)pktdata.len, (int)(tun->rbuf.len - i));
            }
        }
    }
    if (last_shift > 0)
    {
        int rest_len = tun->rbuf.len - last_shift;
        if (rest_len > 0)
        {
            memmove(tun->rbuf.data,
                tun->rbuf.data + last_shift,
                rest_len);
        }
        tun->rbuf.len -= last_shift;
    }

    return pkts;
}

/* read from the rtunnel => write directly to the tap send buffer */
int mlvpn_read_rtun(mlvpn_tunnel_t *tun)
{
    int len;
    int rlen;
    struct sockaddr_storage clientaddr;
    socklen_t addrlen = sizeof(clientaddr);

    /* how much data we can handle right now ? */
    rlen = BUFSIZE - tun->rbuf.len;
    if (rlen <= 0)
    {
        _WARNING("Tun %d receive buffer overrun.\n", tun->fd);
        tun->rbuf.len = 0;
    }
    
    if (tun->encap_prot == ENCAP_PROTO_TCP)
    {
        len = read(tun->fd, tun->rbuf.data + tun->rbuf.len, rlen);
    } else {
        len = recvfrom(tun->fd, tun->rbuf.data+tun->rbuf.len, rlen, 
            MSG_DONTWAIT, (struct sockaddr *)&clientaddr, &addrlen);
    }
    if (len < 0)
    {
        perror("read");
        tun->rbuf.len = 0;
        close(tun->fd);
        tun->fd = -1;
    } else if (len > 0) {
        if (tun->encap_prot == ENCAP_PROTO_TCP)
        {
            _DEBUG("< TUN %d read %d bytes.\n", tun->fd, len);
        } else {
            char clienthost[NI_MAXHOST];
            char clientport[NI_MAXSERV];
            getnameinfo((struct sockaddr *)&clientaddr, addrlen,
                clienthost, sizeof(clienthost),
                clientport, sizeof(clientport),
                NI_NUMERICHOST|NI_NUMERICSERV);
            _DEBUG("< TUN %d read %d bytes from %s:%s.\n", tun->fd, len, 
                clienthost, clientport);
            if (! tun->addrinfo->ai_addrlen)
                tun->addrinfo->ai_addrlen = addrlen;
            if (memcmp(tun->addrinfo->ai_addr, &clientaddr, addrlen) != 0)
            {
                tun->activated = 1;
                _DEBUG("New UDP connection detected.\n");
                memcpy(tun->addrinfo->ai_addr, &clientaddr, addrlen);
            }
        }
        tun->rbuf.len += len;
        mlvpn_tick_rtun_rbuf(tun);
    }
    return len;
}

int mlvpn_write_rtun_pkt(mlvpn_tunnel_t *tun, pktbuffer_t *pktbuf)
{
    int len;
    int wlen;
    mlvpn_pkt_t *pkt = &pktbuf->pkts[0];

    wlen = PKTHDRSIZ(pkt->pktdata) + pkt->pktdata.len;

    if (tun->encap_prot == ENCAP_PROTO_TCP)
    {
        len = write(tun->fd, &pkt->pktdata, wlen);
    } else {
        len = sendto(tun->fd, &pkt->pktdata, wlen, MSG_DONTWAIT,
            tun->addrinfo->ai_addr, tun->addrinfo->ai_addrlen);
    }
    if (len < 0)
    {
        _ERROR("Write error on tunnel fd=%d\n", tun->fd);
        perror("write");
        close(tun->fd);
        tun->fd = -1;
    } else {
        if (wlen != len)
        {
            _ERROR("Error writing on TUN %d: written %d bytes over %d.\n",
                tun->fd, len, wlen);
        } else {
            _DEBUG("> TUN %d written %d bytes (%d pkts left).\n", tun->fd, len, (int)pktbuf->len - 1);
        }
    }
    mlvpn_pop_pkt(pktbuf);
    return len;
}

int mlvpn_write_rtun(mlvpn_tunnel_t *tun)
{
    int bytes = 0;
    if (tun->hpsbuf->len > 0)
        bytes += mlvpn_write_rtun_pkt(tun, tun->hpsbuf);

    if (tun->sbuf->len > 0)
        bytes += mlvpn_write_rtun_pkt(tun, tun->sbuf);

    return bytes;
}

int
mlvpn_timer_rtun_send(mlvpn_tunnel_t *t)
{
    int bytesent = -1;
    uint64_t now;
    mlvpn_pkt_t *pkt;

    /* Send high priority buffer as soon as possible */
    if (t->hpsbuf->len > 0)
    {
        bytesent = mlvpn_write_rtun_pkt(t, t->hpsbuf);
    }

    if (t->sbuf->len <= 0)
        return bytesent;

    pkt = &t->sbuf->pkts[0];
    now = mlvpn_millis();
    if (now >= pkt->next_packet_send || pkt->next_packet_send == 0)
    {
        bytesent += mlvpn_write_rtun_pkt(t, t->sbuf);
        if (t->sbuf->len > 0)
        {
            pkt = &t->sbuf->pkts[0];
            if (t->sbuf->bandwidth > 0 && pkt->pktdata.len > 0)
            {
                pkt->next_packet_send = mlvpn_millis() + 
                    1000/(t->sbuf->bandwidth/pkt->pktdata.len);
            }
        }
    } else {
        /* need some sleep to avoid 100% cpu */
        usleep(500);
    }
    return bytesent;
}

void init_buffers()
{
    tap_send = (pktbuffer_t *)calloc(1, sizeof(pktbuffer_t));
    tap_send->len = 0;
    tap_send->pkts = calloc(PKTBUFSIZE, sizeof(mlvpn_pkt_t));
    tap_send->bandwidth = 0;
}

int main(int argc, char **argv)
{
    int ret;
    mlvpn_tunnel_t *tmptun;

    printf("ML-VPN (c) 2011 Laurent Coustet\n");

    memset(&tuntap, 0, sizeof(tuntap));

    snprintf(tuntap.devname, IFNAMSIZ, "mlvpn%d", 0);
    tuntap.mtu = 1500;
    ret = mlvpn_taptun_alloc();
    if (ret <= 0)
    {
        _ERROR("Unable to create tunnel device.\n");
        return 1;
    } else {
        _INFO("Created tap interface %s\n", tuntap.devname);
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
    tmptun = mlvpn_rtun_new("192.168.6.2", NULL, "chp.zehome.com", "5080", 0);
    tmptun->sbuf->bandwidth = 60*1024; /* 30KB/s bandwidth */
    //tmptun = mlvpn_rtun_new("192.168.6.2", NULL, "chp1.zehome.com", "5081", 0);
    //tmptun = mlvpn_rtun_new("192.168.6.2", NULL, "chp2.zehome.com", "5082", 0);

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
    
    init_buffers();

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
                if (tmptun->sbuf->len > 0 || tmptun->hpsbuf->len > 0)
                    FD_SET(tmptun->fd, &wfds);
                FD_SET(tmptun->fd, &rfds);
                if (tmptun->fd > maxfd)
                    maxfd = tmptun->fd;
            }
            tmptun = tmptun->next;
        }

        timeout.tv_sec = 1;
        timeout.tv_usec = 1000;

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
                        mlvpn_timer_rtun_send(tmptun);
                }
                tmptun = tmptun->next;
            }
        } else if (ret == 0) {
            /* timeout, check for "normalize sending" */

        } else if (ret < 0) {
            /* Error */
            perror("select");
            return 2;
        }
    }

    return 0;
}
