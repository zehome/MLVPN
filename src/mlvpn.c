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

#include "includes.h"
#include "mlvpn.h"
#include "tool.h"
#include "setproctitle.h"
#include "crypto.h"
#ifdef HAVE_MLVPN_CONTROL
#include "control.h"
#endif
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
char *_progname;
static char **saved_argv;

char *status_command = NULL;
char *process_title = NULL;
int logdebug = 0;

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

static void mlvpn_rtun_read(struct ev_loop *loop, ev_io *w, int revents);
static void mlvpn_rtun_write(struct ev_loop *loop, ev_io *w, int revents);
static void mlvpn_rtun_check_timeout(struct ev_loop *loop, ev_timer *w, int revents);
static void mlvpn_rtun_read_dispatch(mlvpn_tunnel_t *tun);
static void mlvpn_rtun_send_keepalive(ev_tstamp now, mlvpn_tunnel_t *t);
static int mlvpn_rtun_send(mlvpn_tunnel_t *tun, circular_buffer_t *pktbuf);
static void mlvpn_rtun_send_auth(mlvpn_tunnel_t *t);
static void mlvpn_rtun_status_up(mlvpn_tunnel_t *t);
static void mlvpn_rtun_tick_connect(mlvpn_tunnel_t *t);
static void mlvpn_rtun_recalc_weight();
static int mlvpn_rtun_bind(mlvpn_tunnel_t *t);
static void update_process_title();


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
            " --debug               more debug messages on stdout\n"
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
        log_warn("fcntl");
        ret = -1;
    } else {
        fl |= O_NONBLOCK;
        if ( (ret = fcntl(fd, F_SETFL, fl)) < 0)
            log_warn("Unable to set socket %d non blocking",
               fd);
    }
    return ret;
}

static void inline mlvpn_rtun_tick(mlvpn_tunnel_t *t) {
    t->last_activity = ev_now(EV_DEFAULT_UC);
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
        log_warnx("[rtun %s] receive buffer overflow.", tun->name);
        mlvpn_cb_reset(tun->rbuf);
    }
    pkt = mlvpn_pktbuffer_write(tun->rbuf);
    len = recvfrom(tun->fd, pkt->data,
                   sizeof(pkt->data),
                   MSG_DONTWAIT, (struct sockaddr *)&clientaddr, &addrlen);
    if (len > 0) {
        pkt->len = len;
        tun->recvbytes += len;
        tun->recvpackets += 1;

        if (! tun->addrinfo)
            fatalx("tun->addrinfo is NULL!");

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
                log_warnx("[rtun %s] Error in getnameinfo: %d",
                       tun->name, ret);
            } else {
                log_debug("[rtun %s] new UDP connection -> %s",
                   tun->name, clienthost);
                memcpy(tun->addrinfo->ai_addr, &clientaddr, addrlen);
            }
        }
        log_debug("< rtun %s read %d bytes.", tun->name, (int)len);
        mlvpn_rtun_read_dispatch(tun);
    } else if (len < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log_warn("[rtun %s] read error on %d",
               tun->name, tun->fd);
            mlvpn_rtun_status_down(tun);
        }
    } else {
        log_info("[rtun %s] peer closed the connection %d.", tun->name, tun->fd);
        mlvpn_rtun_status_down(tun);
    }
}

// void print_proto(mlvpn_proto_t *p)
// {
//     int i;
//     printf("len: %d flags: %d nonce: ", ntohs(p->len), p->flags);
//     for(i=0;i<sizeof(p->nonce);i++) {
//         printf("%02x ", p->nonce[i]);
//     }
//     printf("DATA: ");
//     for(i=0;i<ntohs(p->len);i++) {
//         printf("%02x ", (unsigned char)p->data[i]);
//     }
//     printf("\n");
// }

/* Pass thru the mlvpn_rbuf to find packets received
 * from the UDP channel and prepare packets for TUN/TAP device. */
static void
mlvpn_rtun_read_dispatch(mlvpn_tunnel_t *tun)
{
    uint16_t rlen;
    mlvpn_pkt_t *rawpkt = mlvpn_pktbuffer_read(tun->rbuf);
    // if (rawpkt->len < PKTHDRSIZ(*rawpkt)) {
    //     log_warn("[rtun %s] Invalid packet of len %d.\n",
    //         tun->name, rawpkt->len);
    //     return;
    // }
    /* Decapsulate the packet */
    mlvpn_pkt_t decap_pkt;
    mlvpn_proto_t proto;
    memset(&proto, 0, sizeof(proto));
    memset(&decap_pkt, 0, sizeof(decap_pkt));

    if (rawpkt->len > sizeof(proto)) {
        log_warnx("Invalid packet size received: %d.", rawpkt->len);
        return;
    }
    memcpy(&proto, rawpkt->data, rawpkt->len);
    rlen = ntohs(proto.len);
#ifdef ENABLE_CRYPTO
    int ret;
    if ((ret = crypto_decrypt((unsigned char *)&decap_pkt.data,
                              (const unsigned char *)&proto.data, rlen,
                              (const unsigned char *)&proto.nonce)) != 0) {
        log_warnx("crypto_decrypt failed: %d len=%d.", ret, rlen);
        return;
    }
#else
    memcpy(&decap_pkt.data, &proto.data, rlen);
#endif
    decap_pkt.len = rlen;
    decap_pkt.type = proto.flags;

    if (decap_pkt.type == MLVPN_PKT_DATA && tun->status == MLVPN_CHAP_AUTHOK) {
        mlvpn_rtun_tick(tun);
        mlvpn_pkt_t *tuntap_pkt = mlvpn_pktbuffer_write(tuntap.sbuf);
        tuntap_pkt->len = decap_pkt.len;
        memcpy(tuntap_pkt->data, decap_pkt.data, tuntap_pkt->len);
        /* Send the packet back into the LAN */
        if (!ev_is_active(&tuntap.io_write)) {
            ev_io_start(EV_DEFAULT_UC, &tuntap.io_write);
        }
    } else if (decap_pkt.type == MLVPN_PKT_KEEPALIVE) {
        mlvpn_rtun_tick(tun);
    } else {
        mlvpn_rtun_send_auth(tun);
    }
}

static int
mlvpn_rtun_send(mlvpn_tunnel_t *tun, circular_buffer_t *pktbuf)
{
    ssize_t ret;
    size_t wlen;
    mlvpn_proto_t proto;
    memset(&proto, 0, sizeof(proto));

    mlvpn_pkt_t *pkt = mlvpn_pktbuffer_read(pktbuf);
    wlen = PKTHDRSIZ(proto) + pkt->len;

    proto.len = pkt->len;
    proto.flags = pkt->type;
#ifdef ENABLE_CRYPTO
    crypto_nonce_random((unsigned char *)&proto.nonce, sizeof(proto.nonce));
    if (wlen + crypto_PADSIZE > sizeof(proto.data)) {
        log_warnx("Can't encrypt packet too long. Received: %u Max: %d",
            (unsigned int)wlen, (unsigned int)sizeof(proto.data) + crypto_PADSIZE);
        return -1;
    }
    if ((ret = crypto_encrypt((unsigned char *)&proto.data,
                              (const unsigned char *)&pkt->data, pkt->len,
                              (const unsigned char *)&proto.nonce)) != 0) {
        log_warnx("crypto_encrypt failed: %d", (int)ret);
        return -1;
    }
    proto.len += crypto_PADSIZE;
    wlen += crypto_PADSIZE;
#else
    memcpy(&proto.data, &pkt->data, wlen);
#endif
    proto.len = htons(proto.len);
    ret = sendto(tun->fd, &proto, wlen, MSG_DONTWAIT,
                 tun->addrinfo->ai_addr, tun->addrinfo->ai_addrlen);
    if (ret < 0)
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log_warn("[rtun %s] write error", tun->name);
            mlvpn_rtun_status_down(tun);
        }
    } else {
        tun->sentbytes += ret;
        if (wlen != ret)
        {
            log_warnx("[rtun %s] write error: written %d over %u.",
               tun->name, (int)ret, (unsigned int)wlen);
        } else {
            log_debug("> rtun %s written %d bytes.",
               tun->name, (int)ret);
        }
    }

    if (ev_is_active(&tun->io_write) && mlvpn_cb_is_empty(pktbuf)) {
        ev_io_stop(EV_DEFAULT_UC, &tun->io_write);
    }
    return ret;
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

mlvpn_tunnel_t *
mlvpn_rtun_new(const char *name,
               const char *bindaddr, const char *bindport,
               const char *destaddr, const char *destport,
               int server_mode, uint32_t timeout)
{
    mlvpn_tunnel_t *new;

    /* Some basic checks */
    if (server_mode)
    {
        if (bindaddr == NULL || bindport == NULL)
        {
            log_warnx("Can initialize socket with null bindaddr:bindport.");
            return NULL;
        }
    } else {
        if (destaddr == NULL || destport == NULL)
        {
            log_warnx("Can initialize socket with null destaddr:destport.");
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
    new->bandwidth = 0;

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

    new->timeout = timeout;
    new->next_keepalive = 0;

    LIST_INSERT_HEAD(&rtuns, new, entries);

    new->io_read.data = new;
    new->io_write.data = new;
    new->io_timeout.data = new;
    ev_init(&new->io_read, mlvpn_rtun_read);
    ev_init(&new->io_write, mlvpn_rtun_write);
    ev_init(&new->io_timeout, mlvpn_rtun_check_timeout);
    new->io_timeout.repeat = 1.;
    mlvpn_rtun_tick_connect(new);
    update_process_title();
    return new;
}

void
mlvpn_rtun_drop(mlvpn_tunnel_t *t)
{
    mlvpn_tunnel_t *tmp;
    mlvpn_rtun_status_down(t);
    ev_timer_stop(EV_DEFAULT_UC, &t->io_timeout);
    ev_io_stop(EV_DEFAULT_UC, &t->io_read);

    LIST_FOREACH(tmp, &rtuns, entries)
    {
        if (mystr_eq(tmp->name, t->name))
        {
            LIST_REMOVE(tmp, entries);
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
        }
    }
    update_process_title();
}

/* Based on tunnel bandwidth, compute a "weight" value
 * to balance correctly the round robin rtun_choose.
 */
void
mlvpn_rtun_recalc_weight()
{
    mlvpn_tunnel_t *t;
    uint32_t bandwidth_total = 0;
    int warned = 0;

    /* If the bandwidth limit is not set on all interfaces, then
     * it's impossible to balance correctly! */
    LIST_FOREACH(t, &rtuns, entries)
    {
        if (t->bandwidth == 0)
            warned++;
        bandwidth_total += t->bandwidth;
    }

    if (warned && bandwidth_total > 0) {
        log_warn("configuration error: you must set the bandwidth on all tunnels. (or 0 on all tunnels");
    }

    if (warned == 0)
    {
        LIST_FOREACH(t, &rtuns, entries)
        {
            /* useless, but we want to be sure not to divide by 0 ! */
            if (t->bandwidth > 0 && bandwidth_total > 0)
            {
                t->weight = (((double)t->bandwidth /
                              (double)bandwidth_total) * 100.0);
                log_debug("tun %s weight = %f (%u %u)", t->name, t->weight,
                    t->bandwidth, bandwidth_total);
            }
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
        log_warnx("getaddrinfo error: %s", gai_strerror(n));
        return -1;
    }

    /* Try open socket with each address getaddrinfo returned,
       until getting a valid listening socket. */
    log_info("Binding socket %d to %s", fd, t->bindaddr);
    n = bind(fd, res->ai_addr, res->ai_addrlen);
    if (n < 0)
    {
        log_warn("bind error on %d", fd);
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
        log_warnx("getaddrinfo(%s,%s) failed: %s",
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
            log_warn("[rtun %s] Socket creation error",
                t->name);
        } else {
            t->fd = fd;
            break;
        }
        res = res->ai_next;
    }

    if (fd < 0)
    {
        log_warnx("[rtun %s] connection failed. Check DNS?",
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
            log_warnx("[rtun %s] unable to bind socket %d.", t->name, fd);
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
    ev_tstamp now = ev_now(EV_DEFAULT_UC);
    t->status = MLVPN_CHAP_AUTHOK;
    t->next_keepalive = NEXT_KEEPALIVE(now, t);
    t->last_activity = now;
    mlvpn_rtun_wrr_init(&rtuns);
    priv_run_script(3, cmdargs);
    update_process_title();
}

void
mlvpn_rtun_status_down(mlvpn_tunnel_t *t)
{
    enum chap_status old_status = t->status;
    t->status = MLVPN_CHAP_DISCONNECTED;
    t->disconnects++;
    mlvpn_pktbuffer_reset(t->rbuf);
    mlvpn_pktbuffer_reset(t->sbuf);
    mlvpn_pktbuffer_reset(t->hpsbuf);
    if (ev_is_active(&t->io_write)) {
        ev_io_stop(EV_DEFAULT_UC, &t->io_write);
    }

    if (old_status >= MLVPN_CHAP_AUTHOK)
    {
        char *cmdargs[4] = {tuntap.devname, "rtun_down", t->name, NULL};
        priv_run_script(3, cmdargs);
        /* Re-initialize weight round robin */
        mlvpn_rtun_wrr_init(&rtuns);
    }
    update_process_title();
}


void
mlvpn_rtun_challenge_send(mlvpn_tunnel_t *t)
{
    mlvpn_pkt_t *pkt;

    if (mlvpn_cb_is_full(t->hpsbuf))
        log_warnx("[rtun %s] buffer overflow.", t->name);

    pkt = mlvpn_pktbuffer_write(t->hpsbuf);
    pkt->data[0] = 'A';
    pkt->data[1] = 'U';
    pkt->len = 2;
    pkt->type = MLVPN_PKT_AUTH;

    t->status = MLVPN_CHAP_AUTHSENT;
    log_debug("[rtun %s] mlvpn_rtun_challenge_send", t->name);
}

static void mlvpn_rtun_send_auth(mlvpn_tunnel_t *t)
{
    mlvpn_pkt_t *pkt;
    if (t->server_mode)
    {
        /* server side */
        log_debug("chap_dispatch(tunnel=%s status=%d)", t->name, t->status);
        if (t->status == MLVPN_CHAP_DISCONNECTED || t->status == MLVPN_CHAP_AUTHOK)
        {
            if (mlvpn_cb_is_full(t->hpsbuf)) {
                log_warnx("[rtun %s] hpsbuf buffer overflow.", t->name);
                mlvpn_cb_reset(t->hpsbuf);
            }
            pkt = mlvpn_pktbuffer_write(t->hpsbuf);
            pkt->data[0] = 'O';
            pkt->data[1] = 'K';
            pkt->len = 2;
            pkt->type = MLVPN_PKT_AUTH_OK;
            t->status = MLVPN_CHAP_AUTHSENT;
            log_debug("Sending 'OK' packet to client.");
            if (!ev_is_active(&t->io_write)) {
                ev_io_start(EV_DEFAULT_UC, &t->io_write);
            }
        } else if (t->status == MLVPN_CHAP_AUTHSENT) {
            log_info("[rtun %s] authenticated.", t->name);
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
    int fd;
    ev_tstamp now = ev_now(EV_DEFAULT_UC);

    fd = t->fd;
    if (fd < 0 && t->status < MLVPN_CHAP_AUTHOK) {
        t->conn_attempts += 1;
        t->last_connection_attempt = now;
        if (mlvpn_rtun_start(t) == 0) {
            t->conn_attempts = 0;
        }
    }

    if (! t->server_mode &&
            (t->fd > 0 && t->status < MLVPN_CHAP_AUTHOK)) {
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

static void
mlvpn_rtun_send_keepalive(ev_tstamp now, mlvpn_tunnel_t *t)
{
    mlvpn_pkt_t *pkt;
    if (mlvpn_cb_is_full(t->hpsbuf))
        log_warnx("[rtun %s] buffer overflow.", t->name);
    else {
        log_debug("[rtun %s] Sending keepalive packet for tunnel.", t->name);
        pkt = mlvpn_pktbuffer_write(t->hpsbuf);
        pkt->type = MLVPN_PKT_KEEPALIVE;
    }
    t->next_keepalive = NEXT_KEEPALIVE(now, t);
}

static void
mlvpn_rtun_check_timeout(struct ev_loop *loop, ev_timer *w, int revents)
{
    mlvpn_tunnel_t *t = w->data;
    ev_tstamp now = ev_now(EV_DEFAULT_UC);

    if (t->status == MLVPN_CHAP_AUTHOK && t->timeout > 0) {
        if ((t->last_activity != 0) && (t->last_activity + t->timeout) < now) {
            log_info("[rtun %s] timeout.", t->name);
            mlvpn_rtun_status_down(t);
        } else {
            if (now > t->next_keepalive)
                mlvpn_rtun_send_keepalive(now, t);
        }
    }
    if (t->status < MLVPN_CHAP_AUTHOK) {
        mlvpn_rtun_tick_connect(t);
    }
    if (!ev_is_active(&t->io_write) && ! mlvpn_cb_is_empty(t->hpsbuf)) {
        ev_io_start(EV_DEFAULT_UC, &t->io_write);
    }
    ev_timer_again(EV_DEFAULT_UC, w);
}

void signal_handler(int sig)
{
    log_debug("Signal received: %d", sig);
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

void
update_process_title()
{
    if (! process_title)
        return;
    char title[1024];
    char *s;
    mlvpn_tunnel_t *t;
    char status[32];
    int len;
    memset(title, 0, sizeof(title));
    if (*process_title)
        strlcat(title, process_title, sizeof(title));
    LIST_FOREACH(t, &rtuns, entries)
    {
        switch(t->status) {
            case MLVPN_CHAP_AUTHOK:
                s = "@";
                break;
            default:
                s = "!";
                break;
        }
        len = snprintf(status, sizeof(status) - 1, " %s%s", s, t->name);
        if (len) {
            status[len] = 0;
            strlcat(title, status, sizeof(title));
        }
    }
    setproctitle(title);
}

int
main(int argc, char **argv)
{
    int ret, i;
    struct ev_loop *loop = EV_DEFAULT;
    extern char *__progname;
#ifdef HAVE_MLVPN_CONTROL
    struct mlvpn_control control;
#endif
    /* uptime statistics */
    last_reload = start_time = time((time_t *)NULL);

    _progname = strdup(__progname);
    saved_argv = calloc(argc + 1, sizeof(*saved_argv));
    for(i = 0; i < argc; i++) {
        saved_argv[i] = strdup(argv[i]);
    }
    saved_argv[i] = NULL;
    compat_init_setproctitle(argc, argv);
    argv = saved_argv;

    mlvpn_options.change_process_title = 1;
    *mlvpn_options.process_name = '\0';
    strlcpy(mlvpn_options.config, "mlvpn.conf", 10+1);
    mlvpn_options.config_fd = -1;
    mlvpn_options.verbose = 0;
    mlvpn_options.background = 0;
    *mlvpn_options.pidfile = '\0';
    *mlvpn_options.unpriv_user = '\0';
    mlvpn_options.root_allowed = 0;

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
        c = getopt_long(argc, saved_argv, optstr,
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
            setproctitle("%s [priv]", mlvpn_options.process_name);
        else
            setproctitle("[priv]");
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
    log_init(mlvpn_options.verbose);
    priv_init(argv, mlvpn_options.unpriv_user);
    if (mlvpn_options.change_process_title) {
        if (mlvpn_options.process_name)
            process_title = mlvpn_options.process_name;
        else
            process_title = "";
        update_process_title();
    }

    LIST_INIT(&rtuns);

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
        fatalx("Unable to open config file.");
    }

    /* tun/tap initialization */
    mlvpn_tuntap_init();

    if (mlvpn_config(mlvpn_options.config_fd, 1) != 0)
        _exit(1);

    ret = mlvpn_tuntap_alloc(&tuntap);
    if (ret <= 0)
    {
        log_warnx("Unable to create tunnel device.");
        return 1;
    } else {
        log_info("Created tap interface %s", tuntap.devname);
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
        fatalx("Privileged process died.");

    ev_run(loop, 0);

    char *cmdargs[3] = {tuntap.devname, "tuntap_down", NULL};
    mlvpn_hook(MLVPN_HOOK_TUNTAP, 2, cmdargs);

    free(_progname);
    return 0;
}

int mlvpn_hook(enum mlvpn_hook hook, int argc, char **argv)
{
    return priv_run_script(argc, argv);
}


