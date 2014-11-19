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
#include <ev.h>

#include "debug.h"
#include "mlvpn.h"
#include "tool.h"
#include "configlib.h"
#include "ps_status.h"
#include "config.h"
#include "crypto.h"
#ifdef HAVE_MLVPN_CONTROL
#include "control.h"
#endif
#include "strlcpy.h"
#include "tuntap_generic.h"

/* Linux specific things */
#ifdef HAVE_LINUX
 #include <sys/prctl.h>
#endif

#ifdef HAVE_FREEBSD
 #define _NSIG _SIG_MAXSIG
#endif

/* GLOBALS */
struct tuntap_s tuntap;
mlvpn_tunnel_t *rtun_start = NULL;
char *progname;
logfile_t *logger = NULL;

/* "private" */
static char *status_command = NULL;

/* Statistics */
time_t start_time;
time_t last_reload;

/* Triggered by signal if sigint is raised */
int global_exit = 0;
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

static void mlvpn_rtun_read_dispatch(mlvpn_tunnel_t *tun);
static void mlvpn_rtun_read(struct ev_loop *loop, ev_io *w, int revents);
static void mlvpn_rtun_write(struct ev_loop *loop, ev_io *w, int revents);
static int mlvpn_rtun_send(mlvpn_tunnel_t *tun, circular_buffer_t *pktbuf);
static void mlvpn_rtun_auth(mlvpn_tunnel_t *t);

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
        " -p, --pidfile [path]  path to pidfile (ex. /run/mlvpn.pid)\n"
        " -u, --user [username] drop privileges to user 'username'\n"
        " -v, --verbose         more debug messages on stdout\n"
        " --yes-run-as-root     ! please do not use !\n"
        " -V, --version         output version information and exit\n"
        "\n"
        "For more details see mlvpn(1) and mlvpn.conf(5).\n", argv[0]);
    exit(2);
}

int
mlvpn_sock_set_nonblocking(int fd)
{
    int ret = 0;
    int fl = fcntl(fd, F_GETFL);
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
    time_t now = time((time_t *)NULL);
    t->last_packet_time = now;
}

/* read from the rtunnel => write directly to the tap send buffer */
static void
mlvpn_rtun_read(struct ev_loop *loop, ev_io *w, int revents)
{
    mlvpn_tunnel_t *tun = w->data;
    ssize_t len;
    struct sockaddr_storage clientaddr;
    socklen_t addrlen = sizeof(clientaddr);
    mlvpn_pkt_t *pkt;

    if (mlvpn_cb_is_full(tun->rbuf)) {
        _WARNING("[rtun %s] receive buffer overflow.\n", tun->name);
        mlvpn_cb_reset(tun->rbuf);
    }
    pkt = mlvpn_pktbuffer_write(tun->rbuf);
    len = recvfrom(tun->fd, pkt->pktdata.data,
                   sizeof(pkt->pktdata.data),
                   MSG_DONTWAIT, (struct sockaddr *)&clientaddr, &addrlen);
    if (len > 0)
    {
        pkt->pktdata.len = len;
        tun->recvbytes += len;
        tun->recvpackets += 1;

        if (! tun->addrinfo)
        {
            _FATAL("tun->addrinfo is NULL!\n");
            _exit(32);
        }

        if ((tun->addrinfo->ai_addrlen != addrlen) ||
            (memcmp(tun->addrinfo->ai_addr, &clientaddr, addrlen) != 0))
        {
            char clienthost[NI_MAXHOST];
            char clientport[NI_MAXSERV];
            int ret;
            if ( (ret = getnameinfo((struct sockaddr *)&clientaddr, addrlen,
                             clienthost, sizeof(clienthost),
                             clientport, sizeof(clientport),
                             NI_NUMERICHOST|NI_NUMERICSERV)) < 0)
            {
                _ERROR("[rtun %s] Error in getnameinfo: %d: %s\n",
                        tun->name, ret, strerror(errno));
            } else {
                _DEBUG("[rtun %s] new UDP connection -> %s\n",
                        tun->name, clienthost);
                memcpy(tun->addrinfo->ai_addr, &clientaddr, addrlen);
                //tun->status = MLVPN_CHAP_DISCONNECTED;
            }
        }
    	_DEBUG("< rtun %s read %d bytes.\n", tun->name, len);
        mlvpn_rtun_read_dispatch(tun);
    } else if (len < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            _ERROR("[rtun %s] read error on %d: %s\n",
                    tun->name, tun->fd, strerror(errno));
            mlvpn_rtun_status_down(tun);
        }
    } else {
        _INFO("[rtun %s] peer closed the connection %d.\n", tun->name, tun->fd);
        mlvpn_rtun_status_down(tun);
    }
}

/* Pass thru the mlvpn_rbuf to find packets received
 * from the UDP channel and prepare packets for TUN/TAP device. */
static void
mlvpn_rtun_read_dispatch(mlvpn_tunnel_t *tun)
{
    mlvpn_pkt_t *rawpkt = mlvpn_pktbuffer_read(tun->rbuf);
    if (rawpkt->pktdata.len < PKTHDRSIZ(rawpkt->pktdata)) {
        _ERROR("[rtun %s] Invalid packet of len %d.\n",
            tun->name, rawpkt->pktdata.len);
        return;
    }
    /* Decapsulate the packet */
    struct mlvpn_pktdata decap_pkt;
    memset(&decap_pkt, 0, sizeof(decap_pkt));
    memcpy(&decap_pkt, &rawpkt->pktdata.data, rawpkt->pktdata.len);

    decap_pkt.len = ntohs(decap_pkt.len);
    _DEBUG("[rtun %s] Encapsulated len: %d real %d type: %d tun status: %d\n",
        tun->name, rawpkt->pktdata.len, decap_pkt.len, decap_pkt.type, tun->status);

    if (decap_pkt.type == MLVPN_PKT_DATA && tun->status == MLVPN_CHAP_AUTHOK) {
        mlvpn_rtun_tick(tun);
        mlvpn_pkt_t *tuntap_pkt = mlvpn_pktbuffer_write(tuntap.sbuf);
        tuntap_pkt->pktdata.len = decap_pkt.len;
        memcpy(tuntap_pkt->pktdata.data, decap_pkt.data, tuntap_pkt->pktdata.len);
        /* Send the packet back into the LAN */
        _DEBUG("should write packet to tuntap.\n");
        if (!ev_is_active(&tuntap.io_write)) {
            _DEBUG("io write start tuntap\n");
            ev_io_start(EV_DEFAULT_UC, &tuntap.io_write);
        }
    } else if (decap_pkt.type == MLVPN_PKT_KEEPALIVE) {
        mlvpn_rtun_tick(tun);

        // if (tun->server_mode) {
        //     mlvpn_pkt_t *pkt = mlvpn_pktbuffer_write(tun->hpsbuf);
        //     pkt->pktdata.len = 0;
        //     pkt->pktdata.type = MLVPN_PKT_KEEPALIVE;
        // }
    } else {
        mlvpn_rtun_auth(tun);
    }
}

static void
mlvpn_rtun_write(struct ev_loop *loop, ev_io *w, int revents)
{
    mlvpn_tunnel_t *tun = w->data;
    if (! mlvpn_cb_is_empty(tun->hpsbuf)) {
        mlvpn_rtun_send(tun, tun->hpsbuf);
    }

    if (! mlvpn_cb_is_empty(tun->sbuf)) {
        mlvpn_rtun_send(tun, tun->sbuf);
    }
}

static int
mlvpn_rtun_send(mlvpn_tunnel_t *tun, circular_buffer_t *pktbuf)
{
    ssize_t ret;
    size_t wlen;

    mlvpn_pkt_t *pkt = mlvpn_pktbuffer_read(pktbuf);

    wlen = PKTHDRSIZ(pkt->pktdata) + pkt->pktdata.len;
    pkt->pktdata.len = htons(pkt->pktdata.len);

    ret = sendto(tun->fd, &pkt->pktdata, wlen, MSG_DONTWAIT,
        tun->addrinfo->ai_addr, tun->addrinfo->ai_addrlen);
    if (ret < 0)
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            _ERROR("[rtun %s] write error: %s\n", tun->name, strerror(errno));
            mlvpn_rtun_status_down(tun);
        }
    } else {
        tun->sentbytes += ret;
        if (wlen != ret)
        {
            _ERROR("[rtun %s] write error: written %u over %u.n",
                tun->name, ret, wlen);
        } else {
            _DEBUG("> rtun %s written %u bytes.\n",
                tun->name, ret);
        }
    }

    if (ev_is_active(&tun->io_write) && ! mlvpn_cb_is_empty(pktbuf)) {
        _DEBUG("io write stop tun %s\n", tun->name);
        ev_io_stop(EV_DEFAULT_UC, &tun->io_write);
    }
    return ret;
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

    new->sbuf = mlvpn_pktbuffer_init(PKTBUFSIZE);
    new->hpsbuf = mlvpn_pktbuffer_init(PKTBUFSIZE);
    new->rbuf = mlvpn_pktbuffer_init(PKTBUFSIZE);

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

    new->io_read.data = new;
    new->io_write.data = new;
    new->io_timeout.data = new;
    ev_init(&new->io_read, mlvpn_rtun_read);
    ev_init(&new->io_write, mlvpn_rtun_write);
    ev_init(&new->io_timeout, mlvpn_rtun_check_timeout);
    new->io_timeout.repeat = 1.;
    return new;
}

/* Based on tunnel bandwidth, compute a "weight" value
 * to balance correctly the round robin rtun_choose.
 */
void
mlvpn_rtun_recalc_weight()
{
    mlvpn_tunnel_t *t = rtun_start;
    uint32_t bandwidth_total = 0;
    int warned = 0;

    /* If the bandwidth limit is not set on all interfaces, then
     * it's impossible to balance correctly! */
    while (t)
    {
        if (mlvpn_pktbuffer_bandwidth(t->sbuf) == 0)
        {
            _WARNING("MLVPN can't balance correctly the traffic on"
                " tunnels if bandwidth limit is disabled! (tun '%s')\n",
                t->name);
            warned++;
        }
        bandwidth_total += mlvpn_pktbuffer_bandwidth(t->sbuf);
        t = t->next;
    }

    if (warned == 0)
    {
        t = rtun_start;
        while (t)
        {
            /* useless, but we want to be sure not to divide by 0 ! */
            if (mlvpn_pktbuffer_bandwidth(t->sbuf) > 0 && bandwidth_total > 0)
            {
                t->weight = (((double)mlvpn_pktbuffer_bandwidth(t->sbuf) /
                                        (double)bandwidth_total) * 100.0);
                _DEBUG("tun %s weight = %f (%u %u)\n", t->name, t->weight,
                    mlvpn_pktbuffer_bandwidth(t->sbuf), bandwidth_total);
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

    memset(&hints, 0, sizeof(hints));
    /* AI_PASSIVE flag: the resulting address is used to bind
       to a socket for accepting incoming connections.
       So, when the hostname==NULL, getaddrinfo function will
       return one entry per allowed protocol family containing
       the unspecified address for that family. */
    hints.ai_flags    = AI_PASSIVE;
    hints.ai_family   = AF_INET; /* TODO IPV6 */
    fd = t->fd;
    hints.ai_socktype = SOCK_DGRAM;

    bindaddr = t->bindaddr;
    bindport = t->bindport;

    if (t->bindaddr == NULL)
        bindaddr = "0.0.0.0";
    if (t->bindport == NULL)
        bindport = "0";

    n = priv_getaddrinfo(bindaddr, bindport, &res, &hints);
    if (n < 0)
    {
        _ERROR("getaddrinfo error: %s\n", gai_strerror(n));
        return -1;
    }

    /* Try open socket with each address getaddrinfo returned,
       until getting a valid listening socket. */
    _INFO("Binding socket %d to %s\n", fd, t->bindaddr);
    n = bind(fd, res->ai_addr, res->ai_addrlen);
    if (n < 0)
    {
        _ERROR("bind error on %d: %s\n", fd, strerror(errno));
        return -1;
    }
    return 0;
}

int
mlvpn_rtun_start(mlvpn_tunnel_t *t)
{
    int ret, fd = -1;
    char *addr, *port;
    struct addrinfo hints, *res;

    fd = t->fd;
    if (t->server_mode)
    {
        addr = t->bindaddr;
        port = t->bindport;
    } else {
        addr = t->destaddr;
        port = t->destport;
    }

    /* Initialize hints */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; /* TODO IPv6 */
    hints.ai_socktype = SOCK_DGRAM;

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
            _ERROR("[rtun %s] Socket creation error: %s\n",
                    t->name, strerror(fd));
        } else {
            t->fd = fd;
            break;
        }
        res = res->ai_next;
    }

    if (fd < 0)
    {
        _ERROR("[rtun %s] connection failed. Check DNS?\n",
                t->name);
        return 1;
    }

    /* setup non blocking sockets */
    socklen_t val = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(socklen_t));
    if (t->bindaddr)
    {
        if (mlvpn_rtun_bind(t) < 0)
        {
            _ERROR("[rtun %s] unable to bind socket %d.\n", t->name, fd);
            if (t->server_mode)
                return -2;
        }
    }

    /* set non blocking after connect... May lockup the entiere process */
    mlvpn_sock_set_nonblocking(fd);
    mlvpn_rtun_tick(t);
    ev_io_set(&t->io_read, fd, EV_READ);
    ev_io_set(&t->io_write, fd, EV_WRITE);
    ev_io_start(EV_DEFAULT_UC, &t->io_read);
    ev_timer_start(EV_DEFAULT_UC, &t->io_timeout);
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

void
mlvpn_rtun_status_down(mlvpn_tunnel_t *t)
{
    enum chap_status old_status = t->status;
    t->status = MLVPN_CHAP_DISCONNECTED;
    mlvpn_pktbuffer_reset(t->rbuf);
    mlvpn_pktbuffer_reset(t->sbuf);
    mlvpn_pktbuffer_reset(t->hpsbuf);
    mlvpn_rtun_tick(t);
    t->next_keepalive = 0;
    if (old_status >= MLVPN_CHAP_AUTHOK)
    {
        char *cmdargs[4] = {tuntap.devname, "rtun_down", t->name, NULL};
        priv_run_script(3, cmdargs);
        /* Re-initialize weight round robin */
        mlvpn_rtun_wrr_init(rtun_start);
    }
}

void
mlvpn_rtun_drop(mlvpn_tunnel_t *t)
{
    mlvpn_tunnel_t *tmp = rtun_start;
    mlvpn_tunnel_t *prev = NULL;
    mlvpn_rtun_status_down(t);
    ev_io_stop(EV_DEFAULT_UC, &t->io_read);
    ev_io_stop(EV_DEFAULT_UC, &t->io_write);
    ev_timer_stop(EV_DEFAULT_UC, &t->io_timeout);

    while (tmp)
    {
        if (mystr_eq(tmp->name, t->name))
        {
            if (prev)
                prev->next = tmp->next;
            else
                rtun_start = NULL;

            if (tmp->name)
                free(tmp->name);
            if (tmp->bindaddr)
                free(tmp->bindaddr);
            if (tmp->bindport)
                free(tmp->bindport);
            if (tmp->destaddr)
                free(tmp->destaddr);
            if (tmp->destport)
                free(tmp->destport);
            if (tmp->addrinfo)
                freeaddrinfo(tmp->addrinfo);
            mlvpn_pktbuffer_free(tmp->sbuf);
            mlvpn_pktbuffer_free(tmp->hpsbuf);
            /* Safety */
            tmp->name = NULL;
            break;
        } else
            prev = tmp;

        tmp = tmp->next;
    }
}

void
mlvpn_rtun_challenge_send(mlvpn_tunnel_t *t)
{
    mlvpn_pkt_t *pkt;

    if (mlvpn_cb_is_full(t->hpsbuf))
        _WARNING("[rtun %s] buffer overflow.\n", t->name);

    pkt = mlvpn_pktbuffer_write(t->hpsbuf);
    pkt->pktdata.data[0] = 'A';
    pkt->pktdata.data[1] = 'U';
    pkt->pktdata.len = 2;
    pkt->pktdata.type = MLVPN_PKT_AUTH;

    t->status = MLVPN_CHAP_AUTHSENT;
    _DEBUG("[rtun %s] mlvpn_rtun_challenge_send\n", t->name);
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
static void
mlvpn_rtun_auth(mlvpn_tunnel_t *t)
{
    mlvpn_pkt_t *pkt;
    if (t->server_mode)
    {
        /* server side */
        _DEBUG("chap_dispatch(tunnel=%s status=%d\n", t->name, t->status);
        if (t->status == MLVPN_CHAP_DISCONNECTED)
        {
            if (mlvpn_cb_is_full(t->hpsbuf))
                _WARNING("[rtun %s] buffer overflow.\n", t->name);

            pkt = mlvpn_pktbuffer_write(t->hpsbuf);
            pkt->pktdata.data[0] = 'O';
            pkt->pktdata.data[1] = 'K';
            pkt->pktdata.len = 2;
            pkt->pktdata.type = MLVPN_PKT_AUTH_OK;

            t->status = MLVPN_CHAP_AUTHSENT;
            _DEBUG("Sending 'OK' packet to client.\n");
        } else if (t->status == MLVPN_CHAP_AUTHSENT) {
            _INFO("[rtun %s] authenticated.\n", t->name);
            mlvpn_rtun_status_up(t);
        }
    } else {
        /* client side */
        if (t->status == MLVPN_CHAP_AUTHSENT)
        {
            mlvpn_rtun_status_up(t);
        }
    }
}

void
mlvpn_rtun_tick_connect(mlvpn_tunnel_t *t)
{
    int ret, fd;
    time_t now;

    fd = t->fd;
    if (fd < 0)
    {
        now = time((time_t *)NULL);
        if (t->next_attempt <= 0 || now >= t->next_attempt)
        {
            t->conn_attempts += 1;
            ret = mlvpn_rtun_start(t);
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
}

mlvpn_tunnel_t *
mlvpn_rtun_choose()
{
    mlvpn_tunnel_t *tun;
    tun = mlvpn_rtun_wrr_choose();
    if (tun)
        tun->sentpackets++;
    return tun;
}

void
mlvpn_rtun_keepalive(time_t now, mlvpn_tunnel_t *t)
{
    mlvpn_pkt_t *pkt;
    if (mlvpn_cb_is_full(t->hpsbuf))
        _ERROR("[rtun %s] buffer overflow.\n", t->name);
    else {
        pkt = mlvpn_pktbuffer_write(t->hpsbuf);
        pkt->pktdata.len = 0;
        pkt->pktdata.type = MLVPN_PKT_KEEPALIVE;
    }
    t->next_keepalive = now + t->timeout/2;
}

void
mlvpn_rtun_check_timeout(struct ev_loop *loop, ev_timer *w, int revents)
{
    mlvpn_tunnel_t *t = w->data;
    time_t now = time((time_t *)NULL);

    if (t->fd > 0 && t->status != MLVPN_CHAP_DISCONNECTED && t->timeout > 0)
    {
        if ((t->last_packet_time != 0) &&
            (t->last_packet_time + t->timeout) < now)
        {
            /* Timeout */
            _INFO("[rtun %s] timeout.\n", t->name);
            mlvpn_rtun_status_down(t);
        } else if (t->status == MLVPN_CHAP_AUTHOK) {
            if ((t->next_keepalive == 0) ||
                (t->next_keepalive < now))
            {
                /* Send a keepalive packet */
                _DEBUG("[rtun %s] Sending keepalive packet (next_keepalive = %d)\n",
                    t->name, t->next_keepalive);
                mlvpn_rtun_keepalive(now, t);
            }
        }
    }
    if (t->status == MLVPN_CHAP_DISCONNECTED)  {
        mlvpn_rtun_tick_connect(t);
    }
    if (!ev_is_active(&t->io_write) && ! mlvpn_cb_is_empty(t->hpsbuf)) {
        _DEBUG("io write start tun %s\n", t->name);
        ev_io_start(EV_DEFAULT_UC, &t->io_write);
    }
    ev_timer_again(EV_DEFAULT_UC, w);
}


/* Config file reading / re-read.
 * config_file_fd: fd opened in priv_open_config
 * first_time: set to 0 for re-read, or 1 for initial configuration
 */
int
mlvpn_config(int config_file_fd, int first_time)
{
    config_t *config, *work;
    mlvpn_tunnel_t *tmptun;
    char *tmp;
    char *mode;
    char *lastSection = NULL;
    char *tundevname;

    int default_protocol = ENCAP_PROTO_UDP;
    int default_timeout = 60;
    int default_server_mode = 0; /* 0 => client */

    if (first_time)
    {
        logger = (logfile_t *)malloc(sizeof(logfile_t));
        logger->fd = stderr;
        logger->filename = NULL;
        logger->name = "mlvpn";
        logger->level = 4;
    }

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
                if (first_time)
                {
                    _conf_set_str_from_conf(config, lastSection,
                        "statuscommand", &status_command, NULL, NULL, 0);
                    _conf_set_str_from_conf(config, lastSection,
                        "interface_name", &tundevname, "mlvpn0", NULL, 0);
                    strlcpy(tuntap.devname, tundevname, MLVPN_IFNAMSIZ-1);
                    _conf_set_str_from_conf(config, lastSection,
                        "tuntap", &tmp, "tun", NULL, 0);
                    if (mystr_eq(tmp, "tun"))
                        tuntap.type = MLVPN_TUNTAPMODE_TUN;
                    else
                        tuntap.type = MLVPN_TUNTAPMODE_TAP;
                }

                _conf_set_str_from_conf(config, lastSection,
                    "mode", &mode, NULL, "Operation mode is mandatory.", 1);
                if (mystr_eq(mode, "server"))
                    default_server_mode = 1;

                _conf_set_str_from_conf(config, lastSection,
                    "logfile", &(logger->filename), NULL, NULL, 0);
                _conf_set_int_from_conf(config, lastSection,
                    "loglevel", &(logger->level), 4, NULL, 0);

                _conf_set_str_from_conf(config, lastSection,
                    "protocol", &tmp, "udp", NULL, 0);
                if (mystr_eq(tmp, "udp")) {
                    default_protocol = ENCAP_PROTO_UDP;
                } else if (mystr_eq(tmp, "tcp")) {
                    _ERROR("TCP is nto supported.\n");
                } else {
                    _ERROR("Unknown protocol %s.\n", tmp);
                }

                _conf_set_int_from_conf(config, lastSection,
                    "timeout", &default_timeout, 60, NULL, 0);
            } else {
                char *bindaddr;
                char *bindport;
                char *dstaddr;
                char *dstport;
                int bwlimit = 0;
                int timeout = 30;
                int protocol = default_protocol;
                int create_tunnel = 1;
                uint32_t latency_increase = 0;

                if (default_server_mode)
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
                        _ERROR("TCP is not supported.\n");
                    } else {
                        _ERROR("Unknown protocol %s.\n", tmp);
                    }
                }

                _conf_set_int_from_conf(config, lastSection,
                    "timeout",
                    (int *)&timeout, default_timeout, NULL, 0);

                _conf_set_int_from_conf(config, lastSection,
                    "latency_increase",
                    (int *)&latency_increase, 0, NULL, 0);

                if (rtun_start)
                {
                    tmptun = rtun_start;
                    while (tmptun)
                    {
                        if (mystr_eq(lastSection, tmptun->name))
                        {
                            _INFO("Updating tunnel %s during config reload.\n",
                                tmptun->name);
                            if ((! mystr_eq(tmptun->bindaddr, bindaddr)) ||
                                (! mystr_eq(tmptun->bindport, bindport)) ||
                                (! mystr_eq(tmptun->destaddr, dstaddr)) ||
                                (! mystr_eq(tmptun->destport, dstport)) ||
                                (tmptun->encap_prot != protocol))
                            {
                                mlvpn_rtun_status_down(tmptun);
                            }

                            if (bindaddr)
                            {
                                if (! tmptun->bindaddr)
                                    tmptun->bindaddr = calloc(1, MLVPN_MAXHNAMSTR+1);
                                strlcpy(tmptun->bindaddr, bindaddr, MLVPN_MAXHNAMSTR);
                            }
                            if (bindport)
                            {
                                if (! tmptun->bindport)
                                    tmptun->bindport = calloc(1, MLVPN_MAXPORTSTR+1);
                                strlcpy(tmptun->bindport, bindport, MLVPN_MAXPORTSTR);
                            }
                            if (dstaddr)
                            {
                                if (! tmptun->destaddr)
                                    tmptun->destaddr = calloc(1, MLVPN_MAXHNAMSTR+1);
                                strlcpy(tmptun->destaddr, dstaddr, MLVPN_MAXHNAMSTR);
                            }
                            if (dstport)
                            {
                                if (! tmptun->destport)
                                    tmptun->destport = calloc(1, MLVPN_MAXPORTSTR+1);
                                strlcpy(tmptun->destport, dstport, MLVPN_MAXPORTSTR);
                            }
                            create_tunnel = 0;
                            break; /* Very important ! */
                        }
                        tmptun = tmptun->next;
                    }
                }

                if (create_tunnel)
                {
                    _INFO("Adding tunnel %s.\n", lastSection);
                    tmptun = mlvpn_rtun_new(lastSection, bindaddr, bindport,
                        dstaddr, dstport, default_server_mode);
                }
                tmptun->encap_prot = protocol;
                tmptun->timeout = timeout;
                if (bwlimit > 0)
                    mlvpn_pktbuffer_bandwidth(tmptun->sbuf) = bwlimit;
                tmptun->latency_increase = latency_increase;
                mlvpn_rtun_tick_connect(tmptun);
            }
        } else if (lastSection == NULL)
            lastSection = work->section;

        work = work->next;
    }

    /* Ok, let's delete old tunnels */
    if (! first_time)
    {
        tmptun = rtun_start;
        while (tmptun)
        {
            int found_in_config = 0;

            work = config;
            while (work)
            {
                if (work->conf && work->section &&
                    mystr_eq(work->section, tmptun->name))
                {
                    found_in_config = 1;
                    break;
                }
                work = work->next;
            }

            if (! found_in_config)
            {
                _INFO("Deleting tunnel %s.\n", tmptun->name);
                mlvpn_rtun_drop(tmptun);
            }
            tmptun = tmptun->next;
        }
    }
    _conf_printConfig(config);
    _conf_freeConfig(config);

    /* TODO: Memleak here ! */
    logger_init(logger);
    if (first_time && status_command)
        priv_init_script(status_command);
    return 0;
error:
    _ERROR("Error parsing config file.\n");
    return 1;
}

void signal_handler(int sig)
{
    _DEBUG("Signal received: %d\n", sig);
    if (global_exit > 0)
        _exit(sig);
    global_exit = 1;
}

void signal_setup()
{
    int i;
    struct sigaction sa;
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
}

static void
tuntap_io_event(struct ev_loop *loop, ev_io *w, int revents)
{
    if (revents & EV_READ) {
        mlvpn_tuntap_read(&tuntap);
    } else if (revents & EV_WRITE) {
        mlvpn_tuntap_write(&tuntap);
        /* Nothing else to read */
        if (mlvpn_cb_is_empty(tuntap.sbuf)) {
            _DEBUG("io write stop tuntap\n");
            ev_io_stop(EV_DEFAULT_UC, &tuntap.io_write);
        }
    }
}

void
mlvpn_tuntap_init()
{
    memset(&tuntap, 0, sizeof(tuntap));
    snprintf(tuntap.devname, MLVPN_IFNAMSIZ-1, "%s", "mlvpn0");
    tuntap.mtu = 1500;
    tuntap.type = MLVPN_TUNTAPMODE_TUN;
    tuntap.sbuf = mlvpn_pktbuffer_init(PKTBUFSIZE);
    ev_init(&tuntap.io_read, tuntap_io_event);
    ev_init(&tuntap.io_write, tuntap_io_event);
}

int
main(int argc, char **argv)
{
    char **save_argv;
    int ret;
    struct ev_loop *loop = EV_DEFAULT;
#ifdef HAVE_MLVPN_CONTROL
    struct mlvpn_control control;
#endif
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
            strlcpy(mlvpn_options.config, optarg, 1023);
            break;
        case 'n':
            strlcpy(mlvpn_options.process_name, optarg, 1023);
            break;
        case 'p':
            strlcpy(mlvpn_options.pidfile, optarg, 1023);
            break;
        case 'r':
            /* Yes run as root */
            mlvpn_options.root_allowed = 1;
            break;
        case 'u':
            strlcpy(mlvpn_options.unpriv_user, optarg, 127);
            break;
        case 'v':
            mlvpn_options.verbose++;
            break;
        case 'V':
            printf("mlvpn version %s.\n", VERSION);
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
            strlcpy(mlvpn_priv_process_name, "mlvpn [priv]", 2047);
            strlcpy(mlvpn_process_name, "mlvpn", 2047);
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

#ifdef HAVE_LINUX
    if (access("/dev/net/tun", R_OK|W_OK) != 0)
    {
        fprintf(stderr, "Unable to open tuntap node `%s'.\n", "/dev/net/tun");
        _exit(1);
    }
#endif
    if (crypto_init() == -1) {
        fprintf(stderr, "libsodium initialization failed.\n");
        _exit(1);
    }
    priv_init(argv, mlvpn_options.unpriv_user);
    set_ps_display(mlvpn_process_name);

    /* Handle signals properly */
    signal_setup();

    /* Kill me if my root process dies ! */
#ifdef HAVE_LINUX
    prctl(PR_SET_PDEATHSIG, SIGCHLD);
#endif

    /* Config file opening / parsing */
    mlvpn_options.config_fd = priv_open_config(mlvpn_options.config);
    if (mlvpn_options.config_fd < 0)
    {
        _ERROR("Unable to open config file %s.\n",
            mlvpn_options.config);
        _exit(1);
    }

    crypto_set_password("mlvpn", 5);

    /* tun/tap initialization */
    mlvpn_tuntap_init();

    if (mlvpn_config(mlvpn_options.config_fd, 1) != 0)
        _exit(1);

    ret = mlvpn_tuntap_alloc(&tuntap);
    if (ret <= 0)
    {
        _ERROR("Unable to create tunnel device.\n");
        return 1;
    } else {
        _INFO("Created tap interface %s\n", tuntap.devname);
    }
    ev_io_set(&tuntap.io_read, tuntap.fd, EV_READ);
    ev_io_set(&tuntap.io_write, tuntap.fd, EV_WRITE);
    ev_io_start(loop, &tuntap.io_read);

    priv_set_running_state();

#ifdef HAVE_MLVPN_CONTROL
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

    ev_run(loop, 0);

    char *cmdargs[3] = {tuntap.devname, "tuntap_down", NULL};
    mlvpn_hook(MLVPN_HOOK_TUNTAP, 2, cmdargs);

    return 0;
}

int mlvpn_hook(enum mlvpn_hook hook, int argc, char **argv)
{
    return priv_run_script(argc, argv);
}


