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
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <pwd.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>

/* TODO: Linux specific */
#include <sys/prctl.h>

#include "debug.h"
#include "mlvpn.h"
#include "tool.h"
#include "configlib.h"
#include "ps_status.h"
#include "config.h"
#include "control.h"
#include "strlcpy.h"

/* GLOBALS */
struct tuntap_s tuntap;
mlvpn_tunnel_t *rtun_start = NULL;
char *progname;
char *tundevname = NULL;

/* "private" */
static char *status_command = NULL;
static pktbuffer_t *tap_send;

/* Statistics */
time_t start_time;
time_t last_reload;

/* Triggered by signal if sigint is raised */
static int global_exit = 0;
static char *optstr = "bc:n:p:u:vV";
static struct option long_options[] = {
    {"background",    no_argument,       0, 'b' },
    {"config",        required_argument, 0, 'c' },
    {"name",          required_argument, 0, 'n' },
    {"natural-title", no_argument,       0,  1  },
    {"help",          no_argument,       0, 'h' },
    {"pidfile",       required_argument, 0, 'p' },
    {"user",          required_argument, 0, 'u' },
    {"verbose",       no_argument,       0, 'v' },
    {"version",       no_argument,       0, 'V' },
    {"yes-run-as-root",no_argument,      0, 'r' },
    {0,               0,                 0, 0 }
};
static struct mlvpn_options mlvpn_options;

static char mlvpn_priv_process_name[2048] = {0};
static char mlvpn_process_name[2048] = {0};

static void
usage(char **argv)
{
    fprintf(stderr,
        "usage: %s [options]\n\n"
        "Options:\n"
        " -b, --background      launch as a daemon (fork)\n"
        " -c, --config [path]   path to config file (ex. /etc/mlvpn.conf)\n"
        " --natural-title       do not change process title\n"
        " -n, --name            change process-title and include 'name'\n"
        " -h, --help            this help\n"
        " -p, --pidfile [path]  path to pidfile (ex. /var/run/mlvpn.pid)\n"
        " -u, --user [username] drop privileges to user 'username'\n"
        " -v, --verbose         more debug messages on stdout\n"
        " --yes-run-as-root     ! please do not use !\n"
        " -V, --version         output version information and exit\n"
        "\n"
        "For more details see mlvpn(1) and mlvpn.conf(5).\n", argv[0]);
    exit(2);
}

uint64_t mlvpn_millis()
{
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0)
    {
        _ERROR("Error in gettimeofday: %s\n", strerror(errno));
        return 1;
    }
    return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

int
mlvpn_sock_set_nonblocking(int fd)
{
    int ret = 0;

    long fl = fcntl(fd, F_GETFL);
    if (fl < 0)
    {
        _ERROR("Error during fcntl: %s\n", strerror(errno));
        ret = -1;
    } else {
        fl |= O_NONBLOCK;
        if ( (ret = fcntl(fd, F_SETFL, fl)) < 0)
        {
            _ERROR("Unable to set socket %d non blocking: %s.\n",
                fd, strerror(errno));
        }
    }
    return ret;
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

void
mlvpn_rtun_tick(mlvpn_tunnel_t *t)
{
    int now = time((time_t *)NULL);
    _DEBUG("mlvpn_rtun_tick(%d)\n", t->fd);
    t->last_packet_time = now;
}


mlvpn_tunnel_t *
mlvpn_rtun_new(const char *name,
               const char *bindaddr, const char *bindport,
               const char *destaddr, const char *destport,
               int server_mode)
{
    mlvpn_tunnel_t *last;
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

    new->name = strdup(name);
    new->fd = -1;
    new->server_mode = server_mode;
    new->server_fd = -1;
    new->weight = 1;
    new->status = MLVPN_CHAP_DISCONNECTED;
    new->encap_prot = ENCAP_PROTO_UDP;
    new->addrinfo = NULL;
    new->sentpackets = 0;
    new->sentbytes = 0;
    new->recvbytes = 0;

    if (bindaddr)
    {
        new->bindaddr = calloc(1, MLVPN_MAXHNAMSTR+1);
        strlcpy(new->bindaddr, bindaddr, MLVPN_MAXHNAMSTR);
    }

    if (bindport)
    {
        new->bindport = calloc(1, MLVPN_MAXPORTSTR+1);
        strlcpy(new->bindport, bindport, MLVPN_MAXPORTSTR);
    }

    if (destaddr)
    {
        new->destaddr = calloc(1, MLVPN_MAXHNAMSTR+1);
        strlcpy(new->destaddr, destaddr, MLVPN_MAXHNAMSTR);
    }

    if (destport)
    {
        new->destport = calloc(1, MLVPN_MAXPORTSTR+1);
        strlcpy(new->destport, destport, MLVPN_MAXPORTSTR);
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

    mlvpn_rtun_tick(new);

    /* Default to 60s timeout */
    new->timeout = 60;
    new->next_keepalive = 0;

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

/* Based on tunnel bandwidth, compute a "weight" value
 * to balance correctly the round robin rtun_choose.
 */
void mlvpn_rtun_recalc_weight()
{
    mlvpn_tunnel_t *t = rtun_start;
    int bandwidth_total = 0;
    int warned = 0;
    int tunnels = 0;

    /* If the bandwidth limit is not set on all interfaces, then
     * it's impossible to balance correctly! */
    while (t)
    {
        if (t->sbuf->bandwidth == 0)
        {
            _WARNING("MLVPN can't balance correctly the traffic on"
                " tunnels if bandwidth limit is disabled! (tun '%s')\n",
                t->name);
            warned++;
        }
        bandwidth_total += t->sbuf->bandwidth;
        t = t->next;
        tunnels++;
    }

    if (warned == 0)
    {
        t = rtun_start;
        while (t)
        {
            /* useless, but we want to be sure not to divide by 0 ! */
            if (t->sbuf->bandwidth > 0 && bandwidth_total > 0)
            {
                t->weight = (((double)t->sbuf->bandwidth/(double)bandwidth_total) * 100.0);
                _DEBUG("tun %s weight = %f (%d %d)\n", t->name, t->weight,
                    t->sbuf->bandwidth, bandwidth_total);
            }
            t = t->next;
        }
    }
}

int
mlvpn_rtun_bind(mlvpn_tunnel_t *t)
{
    struct addrinfo hints, *res;
    char *bindaddr, *bindport;
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

    bindaddr = t->bindaddr;
    bindport = t->bindport;

    if (t->bindaddr == NULL)
        bindaddr = "0.0.0.0";
    if (t->bindport == NULL)
        bindport = "0";

    n = priv_getaddrinfo(bindaddr, bindport, &res, &hints);
    if (n < 0)
    {
        _ERROR("getaddrinfo error.\n");
        return -1;
    }

    /* Try open socket with each address getaddrinfo returned,
       until getting a valid listening socket. */
    _INFO("Binding socket %d to %s\n", fd, t->bindaddr);
    n = bind(fd, res->ai_addr, res->ai_addrlen);
    if (n < 0)
    {
        _ERROR("Bind error on %d: %s\n", fd, strerror(errno));
        return -1;
    }
    return 0;
}

int mlvpn_rtun_connect(mlvpn_tunnel_t *t)
{
    int ret, fd = -1;
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

    ret = priv_getaddrinfo(addr, port, &t->addrinfo, &hints);
    if (ret < 0 || !t->addrinfo)
    {
        _ERROR("getaddrinfo(%s,%d) failed: %s\n",
            addr, port, gai_strerror(ret));
        return -1;
    }

    res = t->addrinfo;
    while (res)
    {
        /* creation de la socket(2) */
        if ( (fd = socket(t->addrinfo->ai_family,
                        t->addrinfo->ai_socktype,
                        t->addrinfo->ai_protocol)) < 0)
        {
            _ERROR("Socket creation error while connecting to %s:%s: %s\n",
                addr, port, strerror(fd));
        } else {
            _DEBUG("Created socket %d.\n", fd);
            if (t->server_mode && t->encap_prot == ENCAP_PROTO_TCP)
                t->server_fd = fd;
            else
                t->fd = fd;
            break;
        }
        res = res->ai_next;
    }

    if (fd < 0)
    {
        _ERROR("Connection failed. Check DNS?\n");
        return 1;
    }

    /* setup non blocking sockets */
    int val = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
        &val, sizeof(int));
    if (t->encap_prot == ENCAP_PROTO_TCP)
        setsockopt(t->fd, IPPROTO_TCP, TCP_NODELAY,
            &val, sizeof(int));
    if (t->bindaddr)
    {
        if (mlvpn_rtun_bind(t) < 0)
        {
            _ERROR("Unable to bind socket %d.\n", fd);
            if (t->server_mode)
                return -2;
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
                return -3;
            }
        } else {
            /* client mode */
            _ERROR("Connecting to [%s]:%s\n", addr, port);
            /* connect(2) */
            if (connect(fd, t->addrinfo->ai_addr, t->addrinfo->ai_addrlen) == 0)
            {
                _ERROR("Successfully connected to [%s]:%s.\n",
                    addr, port);
            } else {
                _ERROR("Connection to [%s]:%s failed: %s\n",
                    addr, port, strerror(errno));
                t->fd = -1;
                t->status = 0;
                return -4;
            }
        }
    }

    /* set non blocking after connect... May lockup the entiere process */
    mlvpn_sock_set_nonblocking(fd);

    mlvpn_rtun_tick(t);
    return 0;
}

void
mlvpn_rtun_status_up(mlvpn_tunnel_t *t)
{
    char *cmdargs[4] = {tuntap.devname, "rtun_up", t->name, NULL};
    t->status = MLVPN_CHAP_AUTHOK;

    mlvpn_rtun_wrr_init(rtun_start);
    if (! t->server_mode)
        mlvpn_rtun_keepalive(time((time_t *)NULL), t);

    priv_run_script(3, cmdargs);
}

void mlvpn_rtun_status_down(mlvpn_tunnel_t *t)
{
    int old_status = t->status;

    if (t->fd > 0)
        close(t->fd);
    t->fd = -1;
    t->status = MLVPN_CHAP_DISCONNECTED;
    t->rbuf.len = 0;
    t->sbuf->len = 0;
    t->hpsbuf->len = 0;
    t->next_keepalive = 0;
    if (old_status >= MLVPN_CHAP_AUTHOK)
    {
        char *cmdargs[4] = {tuntap.devname, "rtun_down", t->name, NULL};
        priv_run_script(3, cmdargs);

        /* Re-initialize weight round robin */
        mlvpn_rtun_wrr_init(rtun_start);
    }
}


void mlvpn_rtun_challenge_send(mlvpn_tunnel_t *t)
{
    char pkt[2] = {'A','U'};
    if (t->hpsbuf->len+1 > PKTBUFSIZE)
    {
        _WARNING("TUN %d buffer overflow.\n", t->fd);
        t->hpsbuf->len = 0;
    }
    mlvpn_put_pkt(t->hpsbuf, pkt, sizeof(pkt));
    t->status = MLVPN_CHAP_AUTHSENT;
    _DEBUG("mlvpn_rtun_challenge_send %d\n", t->fd);
}

/* when tun->status is != MLVPN_CHAP_AUTHOK,
 * then we must be in "handshake" mode.
 *
 * The client is the initiator of the handshake,
 * it will send a first packet with a challenge.
 *
 * The server then sends back the {OK} answer.
 * The client checks if that's the expected result.
 * If yes, client sends a "keepalive" (0 length) packet
 * and the connection is "established."
 */

/* This function is called when a valid MLVPN packet is received
 * but tun->status != MLVPN_CHAP_AUTHOK
 */
void mlvpn_rtun_chap_dispatch(mlvpn_tunnel_t *t, char *buffer, int len)
{
    char pkt[2];
    if (t->server_mode)
    {
        /* server side */
        _DEBUG("chap_dispatch(tunnel=%s status=%d\n", t->name, t->status);
        if (t->status == MLVPN_CHAP_DISCONNECTED)
        {
            if (len != 2)
            {
                _WARNING("Invalid query len from client.\n");
                return;
            }
            if (buffer[0] == 'A' && buffer[1] == 'U')
            {
                pkt[0] = 'O';
                pkt[1] = 'K';
            } else {
                _WARNING("Invalid query from client.\n");
                return;
            }

            if (t->hpsbuf->len+1 > PKTBUFSIZE)
            {
                _WARNING("TUN %d buffer overflow.\n", t->fd);
                t->hpsbuf->len = 0;
            }

            _DEBUG("Sending 'OK' packet to client.\n");
            mlvpn_put_pkt(t->hpsbuf, pkt, 2);
            t->status = MLVPN_CHAP_AUTHSENT;
        } else if (t->status == MLVPN_CHAP_AUTHSENT) {
            _INFO("TUN %d authenticated.\n", t->fd);
            mlvpn_rtun_status_up(t);
        }
    } else {
        /* client side */
        if (t->status == MLVPN_CHAP_AUTHSENT)
        {
            if (len != 2)
            {
                _WARNING("Invalid answer from server (len=%d != 2).\n", len);
                return;
            }
            if (buffer[0] == 'O' && buffer[1] == 'K')
            {
                 mlvpn_rtun_status_up(t);
            } else {
                _WARNING("Not OK answer from server.\n");
                mlvpn_rtun_status_down(t);
            }
        }
    }
}

void mlvpn_rtun_tick_connect()
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

        if (! t->server_mode &&
            (t->fd > 0 && t->status == MLVPN_CHAP_DISCONNECTED))
        {
            mlvpn_rtun_challenge_send(t);
        }

        t = t->next;
    }
}

int mlvpn_server_accept()
{
    int fd;
    char clienthost[NI_MAXHOST];
    char clientservice[NI_MAXSERV];
    struct sockaddr_storage clientaddr;

    int accepted = 0;
    mlvpn_tunnel_t *t = rtun_start;

    socklen_t addrlen = sizeof(clientaddr);

    while (t)
    {
        if (t->server_fd > 0 && t->encap_prot == ENCAP_PROTO_TCP)
        {
            fd = accept(t->server_fd, (struct sockaddr *)&clientaddr,
                &addrlen);
            if (fd < 0)
            {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    /* TODO: Disable server_fd ! */
                    _ERROR("Error during accept: %s\n", strerror(errno));
                }
            } else {
                accepted++;

                memset(clienthost, 0, sizeof(clienthost));
                memset(clientservice, 0, sizeof(clientservice));

                getnameinfo((struct sockaddr *)&clientaddr, addrlen,
                            clienthost, sizeof(clienthost),
                            clientservice, sizeof(clientservice),
                            NI_NUMERICHOST|NI_NUMERICSERV);
                _INFO("Connection attempt from [%s]:%s.\n",
                    clienthost, clientservice);
                if (t->fd >= 0)
                {
                    _ERROR("Overwritting already existing connection.\n");
                    mlvpn_rtun_status_down(t);
                }
                t->fd = fd;

                mlvpn_sock_set_nonblocking(t->fd);
            }
        }
        t = t->next;
    }
    return accepted;
}

int mlvpn_tuntap_alloc()
{
    int fd;

    if ((fd = priv_open_tun(tuntap.type, tuntap.devname)) < 0 )
    {
        _ERROR("Unable to open /dev/net/tun RW. Check permissions.\n");
        return fd;
    }
    tuntap.fd = fd;
    {
        char *args[3] = {tuntap.devname, "tuntap_up", NULL};
        priv_run_script(2, args);
    }
    return fd;
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

mlvpn_tunnel_t *mlvpn_rtun_choose()
{
    mlvpn_tunnel_t *tun;
    tun = mlvpn_rtun_wrr_choose();
    if (tun)
        tun->sentpackets++;
    return tun;
}

void mlvpn_rtun_keepalive(time_t now, mlvpn_tunnel_t *t)
{
    if (t->hpsbuf->len + 1 > PKTBUFSIZE)
    {
        _ERROR("rtun %d buffer overflow.\n", t->fd);
    } else {
        mlvpn_put_pkt(t->hpsbuf, NULL, 0);
    }
    t->next_keepalive = now + t->timeout/2;
}

void mlvpn_rtun_check_timeout()
{
    mlvpn_tunnel_t *t = rtun_start;
    time_t now = time((time_t *)NULL);

    while (t)
    {
        if (t->fd > 0 && t->status >= MLVPN_CHAP_AUTHSENT && t->timeout > 0)
        {
            if ((t->last_packet_time != 0) &&
                (t->last_packet_time + t->timeout) < now)
            {
                /* Timeout */
                _INFO("Link %d timeout.\n", t->fd);
                mlvpn_rtun_status_down(t);
            } else if (t->status == MLVPN_CHAP_AUTHOK) {
                if ((t->next_keepalive == 0) ||
                    (t->next_keepalive < now))
                {
                    /* Send a keepalive packet */
                    _DEBUG("Sending keepalive packet %d (next_keepalive = %d)\n", t->fd, t->next_keepalive);
                    mlvpn_rtun_keepalive(now, t);
                }
            }
        }
        t = t->next;
    }
}

int mlvpn_tuntap_read()
{
    int len;
    char buffer[DEFAULT_MTU];
    pktbuffer_t *sbuf;
    mlvpn_tunnel_t *lpt;

    /* least packets tunnel */
    lpt = mlvpn_rtun_choose();
    if (lpt)
        sbuf = lpt->sbuf;

    len = read(tuntap.fd, buffer, DEFAULT_MTU);
    if (len > 0)
    {
        /* Not connected to anyone. read and discard packet. */
        if (! lpt)
            return len;

#ifdef MLVPN_DECAP_FRAMES
        if (tuntap.type == MLVPN_TUNTAPMODE_TUN)
        {
            struct mlvpn_ipv4 ip4;
            decap_ip4_frame(&ip4, buffer);
            /* icmp ? */
            if (ip4.proto & 0x01 || ip4.tos & 0x10)
                sbuf = lpt->hpsbuf;
        }
#endif
            _WARNING("TUN %d buffer overflow.\n", lpt->fd);
            sbuf->len = 0;
        }
        mlvpn_put_pkt(sbuf, buffer, len);
    } else if (len < 0) {
        _ERROR("Error during read on %d: %s",
            tuntap.fd, strerror(errno));
        exit(1);
    } else {
        /* End of file */
        _ERROR("Big error dude, should never reach end of file on tuntap device!\n");
        exit(1);
    }
    return len;
}

int mlvpn_tuntap_write()
{
    int len;
    mlvpn_pkt_t *pkt;
    pktbuffer_t *buf = tap_send;

    if (buf->len <= 0)
    {
        _ERROR(
            "Nothing to write on tap! (%d) PROGRAMMING ERROR.\n",
                (int)buf->len);
        return -1;
    }
    pkt = &buf->pkts[0]; /* First pkt in queue */
    len = write(tuntap.fd, pkt->pktdata.data, pkt->pktdata.len);
    if (len < 0)
    {
        _ERROR("Write error on tuntap: %s\n", strerror(errno));
    } else {
        if (len != pkt->pktdata.len)
        {
            _ERROR("Error writing to tap device: written %d bytes out of %d.\n",
                len, pkt->pktdata.len);
        } else {
            _DEBUG("> Written %d bytes on TAP (%d pkts left).\n",
                len, (int)buf->len);
        }
    }
    mlvpn_pop_pkt(buf);
    return len;
}

/* Pass thru the mlvpn_rbuf to find packets received
 * from the TCP/UDP channel and prepare packets for TUN/TAP device. */
int mlvpn_rtun_tick_rbuf(mlvpn_tunnel_t *tun)
{
    struct mlvpn_pktdata pktdata;
    int i;
    int pkts = 0;
    int last_shift = -1;

    for (i = 0; i <= tun->rbuf.len - (PKTHDRSIZ(pktdata)) ; i++)
    {
        void *rbuf = tun->rbuf.data + i;
        /* Finding the magic and re-assemble valid pkt */
        memcpy(&pktdata, rbuf, PKTHDRSIZ(pktdata));
        if (pktdata.magic == MLVPN_MAGIC)
        {
            mlvpn_rtun_tick(tun);
            if (tun->rbuf.len - i >= pktdata.len+PKTHDRSIZ(pktdata))
            {
                /* Valid packet, copy the rest */
                memcpy(&pktdata, rbuf, PKTHDRSIZ(pktdata)+pktdata.len);

                /* This is a keepalive packet. Just send it back */
                if (pktdata.len == 0 && tun->status == MLVPN_CHAP_AUTHOK)
                {
                    /* We don't want to send back the packet if we
                     * are client side, as we would create a send/recv loop */
                    if (tun->server_mode)
                    {
                        if (tun->hpsbuf->len+1 > PKTBUFSIZE)
                        {
                            _WARNING("rtun %d buffer overflow.\n", tun->fd);
                            tun->hpsbuf->len = 0;
                        }
                        mlvpn_put_pkt(tun->hpsbuf, NULL, 0);
                    }
                } else {
                    if (tun->status == MLVPN_CHAP_AUTHOK)
                    {
                        if (tap_send->len+1 > PKTBUFSIZE)
                        {
                            _ERROR("TAP buffer overflow.\n");
                            tap_send->len = 0;
                        }
                        mlvpn_put_pkt(tap_send, pktdata.data, pktdata.len);
                    } else {
                        mlvpn_rtun_chap_dispatch(tun, pktdata.data, pktdata.len);
                    }
                }

                /* shift read buffer to the right */
                /* -1 because of i++ in the loop */
                i += (PKTHDRSIZ(pktdata) + pktdata.len - 1);
                last_shift = i+1;
                /* Overkill */
                memset(&pktdata, 0, sizeof(pktdata));
                pkts++;
            } else {
                _DEBUG("Found pkt but not enough data. Len=%d available=%d\n",
                    (int)pktdata.len, (int)(tun->rbuf.len - i));
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
int mlvpn_rtun_read(mlvpn_tunnel_t *tun)
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
    if (len > 0)
    {
        tun->recvbytes += len;
        tun->recvpackets += 1;

        if (tun->encap_prot == ENCAP_PROTO_TCP)
        {
            _DEBUG("< TUN %d read %d bytes.\n", tun->fd, len);
        } else {
            char clienthost[NI_MAXHOST];
            char clientport[NI_MAXSERV];
            int ret;
            if ( (ret = getnameinfo((struct sockaddr *)&clientaddr, addrlen,
                 clienthost, sizeof(clienthost),
                clientport, sizeof(clientport),
                NI_NUMERICHOST|NI_NUMERICSERV)) < 0)
            {
                _ERROR("Error in getnameinfo: %d: %s\n",
                    ret, strerror(errno));
            } else {
                _DEBUG("< TUN %d read %d bytes from %s:%s.\n", tun->fd, len,
                    clienthost, clientport);
                if (! tun->addrinfo->ai_addrlen)
                    tun->addrinfo->ai_addrlen = addrlen;
                if (memcmp(tun->addrinfo->ai_addr, &clientaddr, addrlen) != 0)
                {
                    _DEBUG("New UDP connection -> %s\n", clienthost);
                    memcpy(tun->addrinfo->ai_addr, &clientaddr, addrlen);
                    tun->status = MLVPN_CHAP_DISCONNECTED;
                }
            }
        }
        tun->rbuf.len += len;
        mlvpn_rtun_tick_rbuf(tun);
    } else if (len < 0) {
        _ERROR("Read error on %d: %s\n", tun->fd, strerror(errno));
        mlvpn_rtun_status_down(tun);
    } else {
        _INFO("Peer closed the connection %d.\n", tun->fd);
        mlvpn_rtun_status_down(tun);
    }
    return len;
}

int mlvpn_rtun_write_pkt(mlvpn_tunnel_t *tun, pktbuffer_t *pktbuf)
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
        _ERROR("Write error on %d: %s\n", tun->fd, strerror(errno));
        mlvpn_rtun_status_down(tun);
    } else {
        tun->sentbytes += len;
        if (wlen != len)
        {
            _ERROR("Error writing on TUN %d: written %d bytes over %d.\n",
                tun->fd, len, wlen);
        } else {
            _DEBUG("> TUN %d written %d bytes (%d pkts left).\n",
                tun->fd, len, (int)pktbuf->len - 1);
        }
    }
    mlvpn_pop_pkt(pktbuf);
    return len;
}

int mlvpn_rtun_write(mlvpn_tunnel_t *tun)
{
    int bytes = 0;
    if (tun->hpsbuf->len > 0)
        bytes += mlvpn_rtun_write_pkt(tun, tun->hpsbuf);

    if (tun->sbuf->len > 0)
        bytes += mlvpn_rtun_write_pkt(tun, tun->sbuf);

    return bytes;
}

int
mlvpn_rtun_timer_write(mlvpn_tunnel_t *t)
{
    int bytesent = -1;
    uint64_t now;
    mlvpn_pkt_t *pkt;

    /* Send high priority buffer as soon as possible */
    if (t->hpsbuf->len > 0)
        bytesent = mlvpn_rtun_write_pkt(t, t->hpsbuf);

    if (t->sbuf->len <= 0)
        return bytesent;

    pkt = &t->sbuf->pkts[0];
    now = mlvpn_millis();
    if (now >= pkt->next_packet_send || pkt->next_packet_send == 0)
    {
        bytesent += mlvpn_rtun_write_pkt(t, t->sbuf);
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

int mlvpn_config(int config_file_fd)
{
    config_t *config, *work;
    mlvpn_tunnel_t *tmptun;
    logfile_t *log;
    char *tmp;
    char *lastSection = NULL;
    int default_protocol = ENCAP_PROTO_UDP;
    int default_timeout = 60;
    int server_mode = 0;

    log = (logfile_t *)malloc(sizeof(logfile_t));
    log->fd = stderr;
    log->filename = NULL;
    log->name = "mlvpn";
    log->level = 4;

    work = config = _conf_parseConfig(config_file_fd);
    if (! config)
        goto error;

    while (work)
    {
        if ((work->section != NULL) &&
            (mystr_eq(work->section, lastSection) == 0))
        {
            lastSection = work->section;
            _DEBUG("Section %s\n", lastSection);
            if (mystr_eq(lastSection, "general"))
            {
                char *mode;

                _conf_set_str_from_conf(config, lastSection,
                    "statuscommand", &status_command, NULL, NULL, 0);
                _conf_set_str_from_conf(config, lastSection,
                    "logfile", &(log->filename), NULL, NULL, 0);
                _conf_set_int_from_conf(config, lastSection,
                    "loglevel", &(log->level), 4, NULL, 0);

                _conf_set_str_from_conf(config, lastSection,
                    "mode", &mode, NULL, "Operation mode is mandatory.", 1);

                _conf_set_str_from_conf(config, lastSection,
                    "protocol", &tmp, "udp", NULL, 0);
                if (mystr_eq(tmp, "udp")) {
                    default_protocol = ENCAP_PROTO_UDP;
                } else if (mystr_eq(tmp, "tcp")) {
                    default_protocol = ENCAP_PROTO_TCP;
                } else {
                    _ERROR("Unknown protocol %s.\n", tmp);
                }

                _conf_set_int_from_conf(config, lastSection,
                    "timeout", &default_timeout, 60, NULL, 0);
                _conf_set_str_from_conf(config, lastSection,
                    "interface_name", &tundevname, "mlvpn0", NULL, 0);

                _conf_set_str_from_conf(config, lastSection,
                    "tuntap", &tmp, "tun", NULL, 0);
                if (mystr_eq(tmp, "tun")) {
                    tuntap.type = MLVPN_TUNTAPMODE_TUN;
                } else {
                    tuntap.type = MLVPN_TUNTAPMODE_TAP;
                }

                if (mystr_eq(mode, "server"))
                    server_mode = 1;
            } else {
                char *bindaddr;
                char *bindport;
                char *dstaddr;
                char *dstport;
                int bwlimit = 0;
                int protocol = default_protocol;

                if (server_mode)
                {
                    _conf_set_str_from_conf(config, lastSection,
                        "bindhost",
                        &bindaddr, "0.0.0.0",
                        "binding to host 0.0.0.0\n", 0);

                    _conf_set_str_from_conf(config, lastSection,
                        "bindport",
                        &bindport, NULL,
                        "bind port is mandatory in server mode!\n", 1);

                    _conf_set_str_from_conf(config, lastSection,
                        "remotehost", &dstaddr, NULL, NULL, 0);

                    _conf_set_str_from_conf(config, lastSection,
                        "remoteport", &dstport, NULL, NULL, 0);

                    _conf_set_int_from_conf(config, lastSection,
                        "bandwidth_download", &bwlimit, 0, NULL, 0);
                } else {
                    _conf_set_str_from_conf(config, lastSection,
                        "bindhost",
                        &bindaddr, "0.0.0.0", "binding to host 0.0.0.0\n", 0);
                    _conf_set_str_from_conf(config, lastSection,
                        "bindport",
                        &bindport, NULL, NULL, 0);
                    _conf_set_str_from_conf(config, lastSection,
                        "remotehost",
                        &dstaddr, NULL, "No remote address specified.\n", 1);
                    _conf_set_str_from_conf(config, lastSection,
                        "remoteport",
                        &dstport, NULL, "No remote port specified.\n", 1);
                    _conf_set_int_from_conf(config, lastSection,
                        "bandwidth_upload", &bwlimit, 0, NULL, 0);
                }

                _conf_set_str_from_conf(config, lastSection,
                    "protocol", &tmp, NULL, NULL, 0);
                if (tmp)
                {
                    if (mystr_eq(tmp, "udp")) {
                        protocol = ENCAP_PROTO_UDP;
                    } else if (mystr_eq(tmp, "tcp")) {
                        protocol = ENCAP_PROTO_TCP;
                    } else {
                        _ERROR("Unknown protocol %s.\n", tmp);
                    }
                }

                tmptun = mlvpn_rtun_new(lastSection, bindaddr, bindport, dstaddr, dstport,
                    server_mode);
                tmptun->encap_prot = protocol;

                _conf_set_int_from_conf(config, lastSection,
                    "timeout",
                    (int *)&(tmptun->timeout), default_timeout, NULL, 0);

                if (bwlimit > 0)
                {
                    tmptun->sbuf->bandwidth = bwlimit;
                }
            }
        } else if (lastSection == NULL) {
            lastSection = work->section;
        }

        work = work->next;
    }

    logger_init(log);
    if (status_command)
        priv_init_script(status_command);
    return 0;
error:
    _ERROR("Error parsing config file.\n");
    return 1;
}

void init_buffers()
{
    tap_send = (pktbuffer_t *)calloc(1, sizeof(pktbuffer_t));
    tap_send->len = 0;
    tap_send->pkts = calloc(PKTBUFSIZE, sizeof(mlvpn_pkt_t));
    tap_send->bandwidth = 0;
}

void signal_handler(int sig)
{
    _DEBUG("Signal received: %d\n", sig);
    global_exit = 1;
}

void signal_hup(int sig)
{
    fprintf(stderr, "Must reload ? Received sig hup\n");
}


int main(int argc, char **argv)
{
    char **save_argv;
    int ret, i;
    struct timeval timeout;
    int maxfd = 0;
    struct sigaction sa;
#ifdef MLVPN_CONTROL
    struct mlvpn_control control;
#endif
    mlvpn_tunnel_t *tmptun;

    /* setup signals */
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = SIG_DFL;
    for(i = 1; i < _NSIG; i++)
        sigaction(i, &sa, NULL);

    sa.sa_handler = signal_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    sa.sa_handler = signal_hup;
    sigaction(SIGHUP, &sa, NULL);

    /* uptime statistics */
    last_reload = start_time = time((time_t *)NULL);

    mlvpn_options.change_process_title = 1;
    *mlvpn_options.process_name = '\0';
    strlcpy(mlvpn_options.config, "mlvpn.conf", 10+1);
    mlvpn_options.config_fd = -1;
    mlvpn_options.verbose = 0;
    mlvpn_options.background = 0;
    *mlvpn_options.pidfile = '\0';
    *mlvpn_options.unpriv_user = '\0';
    mlvpn_options.root_allowed = 0;

    /* ps_status misc */
    {
        char *p;
        progname = argv[0];
        if ((p = strrchr(progname, '/')) != NULL)
            progname = p+1;
        save_argv = save_ps_display_args(argc, argv);
    }

    /* TODO: Usefull anymore? */
    srand(time((time_t *)NULL));

    //printf("ML-VPN (c) 2012 Laurent Coustet\n");
    signal(SIGINT, signal_handler);

    /* Parse the command line quickly for config file name.
     * This is needed for priv_init to know where the config
     * file is.
     *
     * priv_init will not allow to change the config file path.
     */
    int c;
    int option_index = 0;
    while(1)
    {
        c = getopt_long(argc, save_argv, optstr,
            long_options, &option_index);
        if (c == -1)
            break;

        switch (c)
        {
        case 1:
            mlvpn_options.change_process_title = 0;
            break;
        case 'b':
            mlvpn_options.background = 1;
            break;
        case 'c':
            strlcpy(mlvpn_options.config, optarg, 1024);
            break;
        case 'n':
            strlcpy(mlvpn_options.process_name, optarg, 1024);
            break;
        case 'p':
            strlcpy(mlvpn_options.pidfile, optarg, 1024);
            break;
        case 'r':
            /* Yes run as root */
            mlvpn_options.root_allowed = 1;
            break;
        case 'u':
            strlcpy(mlvpn_options.unpriv_user, optarg, 128);
            break;
        case 'v':
            mlvpn_options.verbose++;
            break;
        case 'V':
            printf("mlvpn version %u.%u.\n", VER_MAJ, VER_MIN);
            _exit(0);
            break;
        case 'h':
        default:
            usage(argv);
        }
    }

    if (mlvpn_options.change_process_title)
    {
        if (mlvpn_options.process_name)
        {
            snprintf(mlvpn_priv_process_name, 2048, "mlvpn [priv] %s",
                mlvpn_options.process_name);
            snprintf(mlvpn_process_name, 2048, "mlvpn %s",
                mlvpn_options.process_name);
            init_ps_display(mlvpn_priv_process_name);
        } else {
            strlcpy(mlvpn_priv_process_name, "mlvpn [priv]", 2048);
            strlcpy(mlvpn_process_name, "mlvpn", 2048);
            init_ps_display("mlvpn");
        }
    }

    /* Some common checks */

    if (getuid() == 0)
    {
        void *pw = getpwnam(mlvpn_options.unpriv_user);
        if (!mlvpn_options.root_allowed && ! pw)
        {
            fprintf(stderr, "You are not allowed to run this program as root.\n"
                "Please specify a valid user with --user option.\n");
            _exit(1);
        }
        if (! pw)
        {
            fprintf(stderr, "Invalid `%s' username.\n", mlvpn_options.unpriv_user);
            _exit(1);
        }
    }
    if (access(mlvpn_options.config, R_OK) != 0)
    {
        fprintf(stderr, "Invalid config file: `%s'.\n", mlvpn_options.config);
        _exit(1);
    }
    /* TODO: Linux only */
    if (access("/dev/net/tun", R_OK|W_OK) != 0)
    {
        fprintf(stderr, "Unable to open tuntap node `%s'.\n", "/dev/net/tun");
        _exit(1);
    }

    priv_init(argv, mlvpn_options.unpriv_user);
    set_ps_display(mlvpn_process_name);

    /* TODO: Linux specific */
    /* Kill me if my root process dies ! */
    prctl(PR_SET_PDEATHSIG, SIGCHLD);

    /* Config file opening / parsing */
    mlvpn_options.config_fd = priv_open_config(mlvpn_options.config);
    if (mlvpn_options.config_fd < 0)
    {
        _ERROR("Unable to open config file %s.\n",
            mlvpn_options.config);
        _exit(1);
    }

    if (mlvpn_config(mlvpn_options.config_fd) != 0)
        _exit(1);

    /* tun/tap initialization */
    memset(&tuntap, 0, sizeof(tuntap));
    snprintf(tuntap.devname, IFNAMSIZ, "%s", tundevname);
    tuntap.mtu = 1500;
    ret = mlvpn_tuntap_alloc();
    if (ret <= 0)
    {
        _ERROR("Unable to create tunnel device.\n");
        return 1;
    } else {
        _INFO("Created tap interface %s\n", tuntap.devname);
    }
    init_buffers();

    priv_set_running_state();

#ifdef MLVPN_CONTROL
    /* Initialize mlvpn remote control system */
    strlcpy(control.fifo_path, "mlvpn.sock", 11);
    control.mode = MLVPN_CONTROL_READWRITE;
    control.fifo_mode = 0600;
    control.bindaddr = "0.0.0.0";
    control.bindport = "1040";
    mlvpn_control_init(&control);
#endif

    /* re-compute rtun weight based on bandwidth allocation */
    mlvpn_rtun_recalc_weight();

    /* Last check before running */
    if (getppid() == 1)
    {
        _ERROR("Privileged process died!\n");
        _exit(2);
    }

    while (1)
    {
#ifdef MLVPN_CONTROL
        /* TODO: Optimize */
        mlvpn_control_timeout(&control);
#endif
        /* Connect rtun if not connected. tick if connected */
        mlvpn_rtun_tick_connect();
        mlvpn_rtun_check_timeout();

        fd_set rfds, wfds;

        FD_ZERO(&rfds);
        FD_ZERO(&wfds);

#ifdef MLVPN_CONTROL
        if (control.fifofd >= 0)
        {
            FD_SET(control.fifofd, &rfds);
            if (control.fifofd > maxfd)
                maxfd = control.fifofd;
        }
        if (control.sockfd >= 0)
        {
            FD_SET(control.sockfd, &rfds);
            if (control.sockfd > maxfd)
                maxfd = control.sockfd;
        }
#endif

        FD_SET(tuntap.fd, &rfds);
        if (tuntap.fd > maxfd)
            maxfd = tuntap.fd;

        if (tap_send->len > 0)
            FD_SET(tuntap.fd, &wfds);

        /* set rfds/wfds for rtunnels */
        tmptun = rtun_start;
        while (tmptun)
        {
            if (tmptun->server_fd > 0 && tmptun->encap_prot == ENCAP_PROTO_TCP)
            {
                FD_SET(tmptun->server_fd, &rfds);
                if (tmptun->server_fd > maxfd)
                    maxfd = tmptun->server_fd;
            }

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

#ifdef MLVPN_CONTROL
        /* Control system */
        if (control.fifofd >= 0)
        {
            FD_SET(control.fifofd, &rfds);
            if (control.fifofd > maxfd)
                maxfd = control.fifofd;
        }
        if (control.sockfd >= 0)
        {
            FD_SET(control.sockfd, &rfds);
            if (control.sockfd > maxfd)
                maxfd = control.sockfd;
        }
        if (control.clientfd >= 0)
        {
            if (control.wbufpos > 0)
            {
                FD_SET(control.clientfd, &wfds);
                if (control.clientfd > maxfd)
                    maxfd = control.clientfd;
            }
            FD_SET(control.clientfd, &rfds);
            if (control.clientfd > maxfd)
                maxfd = control.clientfd;
        }
#endif

        timeout.tv_sec = 1;
        timeout.tv_usec = 1000;

        ret = select(maxfd+1, &rfds, &wfds, NULL, &timeout);
        if (ret > 0)
        {
            if (FD_ISSET(tuntap.fd, &rfds))
                mlvpn_tuntap_read();
            if (FD_ISSET(tuntap.fd, &wfds))
                mlvpn_tuntap_write();
            tmptun = rtun_start;
            while (tmptun)
            {
                if (tmptun->fd > 0)
                    if (FD_ISSET(tmptun->fd, &rfds))
                        mlvpn_rtun_read(tmptun);

                /* YES another check as mlvpn_rtun_read can close the socket */
                if (tmptun->fd > 0)
                    if (FD_ISSET(tmptun->fd, &wfds))
                        mlvpn_rtun_timer_write(tmptun);

                if (tmptun->server_fd > 0 && tmptun->encap_prot == ENCAP_PROTO_TCP)
                    if (FD_ISSET(tmptun->server_fd, &rfds))
                        mlvpn_server_accept();

                tmptun = tmptun->next;
            }
#ifdef MLVPN_CONTROL
            if (control.clientfd >= 0)
                if(FD_ISSET(control.clientfd, &rfds))
                    mlvpn_control_read(&control);

            /* YES another check as mlvpn_control_read can close the socket */
            if (control.clientfd >= 0)
                if(FD_ISSET(control.clientfd, &wfds))
                    mlvpn_control_send(&control);

            if (control.fifofd >= 0 && FD_ISSET(control.fifofd, &rfds))
                mlvpn_control_accept(&control, control.fifofd);
            if (control.sockfd >= 0 && FD_ISSET(control.sockfd, &rfds))
                mlvpn_control_accept(&control, control.sockfd);
#endif
        } else if (ret == 0) {
            /* timeout, check for "normalize sending" */

        } else if (ret < 0) {
            /* Error */
            _ERROR("Select error: %s\n", strerror(errno));
        }

        if (global_exit > 0)
        {
            _INFO("Exit by signal %d.\n", global_exit);
            tmptun = rtun_start;
            while (tmptun)
            {
                if (tmptun->fd > 0)
                    close(tmptun->fd);
                if (tmptun->server_mode && tmptun->server_fd > 0)
                    close(tmptun->server_fd);
                tmptun = tmptun->next;
            }
            break;
        }
    }
    {
        char *cmdargs[3] = {tuntap.devname, "tuntap_down", NULL};
        priv_run_script(2, cmdargs);
    }

    return 0;
}

