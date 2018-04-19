/*
 * Copyright (c) 2015, Laurent COUSTET <ed@zehome.com>
 *
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
#ifdef ENABLE_CONTROL
#include "control.h"
#endif
#include "tuntap_generic.h"

/* Linux specific things */
#ifdef HAVE_LINUX
#include <sys/prctl.h>
#include "systemd.h"
#endif

#ifdef HAVE_FREEBSD
#define _NSIG _SIG_MAXSIG
#include <sys/endian.h>
#endif

#ifdef HAVE_DARWIN
#include <libkern/OSByteOrder.h>
#define be16toh OSSwapBigToHostInt16
#define be32toh OSSwapBigToHostInt32
#define be64toh OSSwapBigToHostInt64
#define htobe16 OSSwapHostToBigInt16
#define htobe32 OSSwapHostToBigInt32
#define htobe64 OSSwapHostToBigInt64
#endif

/* GLOBALS */
struct tuntap_s tuntap;
char *_progname;
static char **saved_argv;
struct ev_loop *loop;
static ev_timer reorder_drain_timeout;
static ev_timer reorder_adjust_rtt_timeout;
char *status_command = NULL;
char *process_title = NULL;
int logdebug = 0;

static uint64_t data_seq = 0;

struct mlvpn_status_s mlvpn_status = {
    .start_time = 0,
    .last_reload = 0,
    .fallback_mode = 0,
    .connected = 0,
    .initialized = 0
};
struct mlvpn_options_s mlvpn_options = {
    .change_process_title = 1,
    .process_name = "mlvpn",
    .control_unix_path = "",
    .control_bind_host = "",
    .control_bind_port = "",
    .ip4 = "",
    .ip6 = "",
    .ip4_gateway = "",
    .ip6_gateway = "",
    .ip4_routes = "",
    .ip6_routes = "",
    .mtu = 0,
    .config_path = "mlvpn.conf",
    .config_fd = -1,
    .debug = 0,
    .verbose = 2,
    .unpriv_user = "mlvpn",
    .cleartext_data = 1,
    .root_allowed = 0,
    .reorder_buffer_size = 0
};
#ifdef HAVE_FILTERS
struct mlvpn_filters_s mlvpn_filters = {
    .count = 0
};
#endif

struct mlvpn_reorder_buffer *reorder_buffer;
freebuffer_t *freebuf;

static char *optstr = "c:n:u:hvVD:";
static struct option long_options[] = {
    {"config",        required_argument, 0, 'c' },
    {"debug",         no_argument,       0, 2   },
    {"name",          required_argument, 0, 'n' },
    {"natural-title", no_argument,       0, 1   },
    {"help",          no_argument,       0, 'h' },
    {"user",          required_argument, 0, 'u' },
    {"verbose",       no_argument,       0, 'v' },
    {"quiet",         no_argument,       0, 'q' },
    {"version",       no_argument,       0, 'V' },
    {"yes-run-as-root",no_argument,      0, 3   },
    {0,               0,                 0, 0 }
};

static int mlvpn_rtun_start(mlvpn_tunnel_t *t);
static void mlvpn_rtun_read(EV_P_ ev_io *w, int revents);
static void mlvpn_rtun_write(EV_P_ ev_io *w, int revents);
static uint32_t mlvpn_rtun_reorder_drain(uint32_t reorder);
static void mlvpn_rtun_reorder_drain_timeout(EV_P_ ev_timer *w, int revents);
static void mlvpn_rtun_check_timeout(EV_P_ ev_timer *w, int revents);
static void mlvpn_rtun_adjust_reorder_timeout(EV_P_ ev_timer *w, int revents);
static void mlvpn_rtun_send_keepalive(ev_tstamp now, mlvpn_tunnel_t *t);
static void mlvpn_rtun_send_disconnect(mlvpn_tunnel_t *t);
static int mlvpn_rtun_send(mlvpn_tunnel_t *tun, circular_buffer_t *pktbuf);
static void mlvpn_rtun_send_auth(mlvpn_tunnel_t *t);
static void mlvpn_rtun_status_up(mlvpn_tunnel_t *t);
static void mlvpn_rtun_tick_connect(mlvpn_tunnel_t *t);
static void mlvpn_rtun_recalc_weight();
static void mlvpn_update_status();
static int mlvpn_rtun_bind(mlvpn_tunnel_t *t);
static void update_process_title();
static void mlvpn_tuntap_init();
static int
mlvpn_protocol_read(mlvpn_tunnel_t *tun,
                    mlvpn_pkt_t *rawpkt,
                    mlvpn_pkt_t *decap_pkt);


static void
usage(char **argv)
{
    fprintf(stderr,
            "usage: %s [options]\n\n"
            "Options:\n"
            " -c, --config [path]   path to config file (ex. /etc/mlvpn.conf)\n"
            " --debug               don't use syslog, print to stdout\n"
            " --natural-title       do not change process title\n"
            " -n, --name            change process-title and include 'name'\n"
            " -h, --help            this help\n"
            " -u, --user [username] drop privileges to user 'username'\n"
            " --yes-run-as-root     ! please do not use !\n"
            " -v --verbose          increase verbosity\n"
            " -q --quiet            decrease verbosity\n"
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
        log_warn(NULL, "fcntl");
        ret = -1;
    } else {
        fl |= O_NONBLOCK;
        if ( (ret = fcntl(fd, F_SETFL, fl)) < 0)
            log_warn(NULL, "Unable to set socket %d non blocking",
               fd);
    }
    return ret;
}

inline static 
void mlvpn_rtun_tick(mlvpn_tunnel_t *t) {
    t->last_activity = ev_now(EV_DEFAULT_UC);
}

/* Inject the packet to the tuntap device (real network) */
inline static 
void mlvpn_rtun_inject_tuntap(mlvpn_pkt_t *pkt)
{
    mlvpn_pkt_t *tuntap_pkt = mlvpn_pktbuffer_write(tuntap.sbuf);
    tuntap_pkt->len = pkt->len;
    memcpy(tuntap_pkt->data, pkt->data, tuntap_pkt->len);
    /* Send the packet back into the LAN */
    if (!ev_is_active(&tuntap.io_write)) {
        ev_io_start(EV_A_ &tuntap.io_write);
    }
}

static void
mlvpn_rtun_reorder_drain_timeout(EV_P_ ev_timer *w, int revents)
{
    log_debug("reorder", "reorder timeout. Packet loss?");
    mlvpn_rtun_reorder_drain(0);
    if (freebuf->used == 0) {
        ev_timer_stop(EV_A_ w);
    }
}

static uint32_t
mlvpn_rtun_reorder_drain(uint32_t reorder)
{
    int i;
    uint32_t drained = 0;
    mlvpn_pkt_t *drained_pkts[1024];
    mlvpn_pkt_t *pkt;
    /* Try to drain packets */
    if (reorder) {
        drained = mlvpn_reorder_drain(reorder_buffer, drained_pkts, 1024);
        for(i = 0; i < drained; i++) {
            pkt = drained_pkts[i];
            mlvpn_rtun_inject_tuntap(pkt);
            mlvpn_freebuffer_free(freebuf, drained_pkts[i]);
        }
    } else {
        while ((pkt = mlvpn_freebuffer_drain_used(freebuf)) != NULL) {
            drained++;
            mlvpn_rtun_inject_tuntap(pkt);
        }
        mlvpn_freebuffer_reset(freebuf);
        mlvpn_reorder_reset(reorder_buffer);
    }
    if (freebuf->used == 0) {
        ev_timer_stop(EV_A_ &reorder_drain_timeout);
    }
    return drained;
}

/* Count the loss on the last 64 packets */
static void
mlvpn_loss_update(mlvpn_tunnel_t *tun, uint64_t seq)
{
    if (seq > tun->seq_last + 64) {
        /* consider a connection reset. */
        tun->seq_vect = (uint64_t) -1;
        tun->seq_last = seq;
    } else if (seq > tun->seq_last) {
        /* new sequence number -- recent message arrive */
        tun->seq_vect <<= seq - tun->seq_last;
        tun->seq_vect |= 1;
        tun->seq_last = seq;
    } else if (seq >= tun->seq_last - 63) {
        tun->seq_vect |= (1 << (tun->seq_last - seq));
    }
}

int
mlvpn_loss_ratio(mlvpn_tunnel_t *tun)
{
    int loss = 0;
    int i;
    /* Count zeroes */
    for (i = 0; i < 64; i++) {
        if (! (1 & (tun->seq_vect >> i))) {
            loss++;
        }
    }
    return loss * 100 / 64;
}

static int
mlvpn_rtun_recv_data(mlvpn_tunnel_t *tun, mlvpn_pkt_t *inpkt)
{
    int ret;
    uint32_t drained;
    if (reorder_buffer == NULL || !inpkt->reorder) {
        mlvpn_rtun_inject_tuntap(inpkt);
        return 1;
    } else {
        mlvpn_pkt_t *pkt = mlvpn_freebuffer_get(freebuf);
        if (!pkt) {
            log_warnx("reorder", "freebuffer full: reorder_buffer_size must be increased.");
            mlvpn_rtun_inject_tuntap(inpkt);
            return 1;
        }
        memcpy(pkt, inpkt, sizeof(mlvpn_pkt_t));
        ret = mlvpn_reorder_insert(reorder_buffer, pkt);
        if (ret == -1) {
            log_warnx("net", "reorder_buffer_insert failed: %d", ret);
            mlvpn_reorder_reset(reorder_buffer);
            drained = mlvpn_rtun_reorder_drain(0);
        } else if (ret == -2) {
            /* We have received a packet out of order just
             * after the forced drain (packet loss)
             * Just inject the packet as is
             */
            mlvpn_rtun_inject_tuntap(inpkt);
            return 1;
        } else {
            drained = mlvpn_rtun_reorder_drain(1);
        }
        if (freebuf->used > 0) {
            ev_timer_again(EV_A_ &reorder_drain_timeout);
        }
        //log_debug("reorder", "drained %d packets", drained);
    }
    return drained;
}


/* read from the rtunnel => write directly to the tap send buffer */
static void
mlvpn_rtun_read(EV_P_ ev_io *w, int revents)
{
    mlvpn_tunnel_t *tun = w->data;
    ssize_t len;
    struct sockaddr_storage clientaddr;
    socklen_t addrlen = sizeof(clientaddr);
    mlvpn_pkt_t pkt;
    len = recvfrom(tun->fd, pkt.data,
                   sizeof(pkt.data),
                   MSG_DONTWAIT, (struct sockaddr *)&clientaddr, &addrlen);
    if (len < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log_warn("net", "%s read error", tun->name);
            mlvpn_rtun_status_down(tun);
        }
    } else if (len == 0) {
        log_info("protocol", "%s peer closed the connection", tun->name);
    } else {
        pkt.len = len;
        mlvpn_pkt_t decap_pkt;

        /* validate the received packet */
        if (mlvpn_protocol_read(tun, &pkt, &decap_pkt) < 0) {
            return;
        }

        tun->recvbytes += len;
        tun->recvpackets += 1;

        if (! tun->addrinfo)
            fatalx("tun->addrinfo is NULL!");

        if ((tun->addrinfo->ai_addrlen != addrlen) ||
                (memcmp(tun->addrinfo->ai_addr, &clientaddr, addrlen) != 0)) {
            if (mlvpn_options.cleartext_data && tun->status >= MLVPN_AUTHOK) {
                log_warnx("protocol", "%s rejected non authenticated connection",
                    tun->name);
                return;
            }
            char clienthost[NI_MAXHOST];
            char clientport[NI_MAXSERV];
            int ret;
            if ( (ret = getnameinfo((struct sockaddr *)&clientaddr, addrlen,
                                    clienthost, sizeof(clienthost),
                                    clientport, sizeof(clientport),
                                    NI_NUMERICHOST|NI_NUMERICSERV)) < 0) {
                log_warn("protocol", "%s error in getnameinfo: %d",
                       tun->name, ret);
            } else {
                log_info("protocol", "%s new connection -> %s:%s",
                   tun->name, clienthost, clientport);
                memcpy(tun->addrinfo->ai_addr, &clientaddr, addrlen);
            }
        }
        log_debug("net", "< %s recv %d bytes (type=%d, seq=%"PRIu64", reorder=%d)",
            tun->name, (int)len, decap_pkt.type, decap_pkt.seq, decap_pkt.reorder);

        if (decap_pkt.type == MLVPN_PKT_DATA) {
            if (tun->status >= MLVPN_AUTHOK) {
                mlvpn_rtun_tick(tun);
                mlvpn_rtun_recv_data(tun, &decap_pkt);
            } else {
                log_debug("protocol", "%s ignoring non authenticated packet",
                    tun->name);
            }
        } else if (decap_pkt.type == MLVPN_PKT_KEEPALIVE &&
                tun->status >= MLVPN_AUTHOK) {
            log_debug("protocol", "%s keepalive received", tun->name);
            mlvpn_rtun_tick(tun);
            tun->last_keepalive_ack = ev_now(EV_DEFAULT_UC);
            /* Avoid flooding the network if multiple packets are queued */
            if (tun->last_keepalive_ack_sent + 1 < tun->last_keepalive_ack) {
                tun->last_keepalive_ack_sent = tun->last_keepalive_ack;
                mlvpn_rtun_send_keepalive(tun->last_keepalive_ack, tun);
            }
        } else if (decap_pkt.type == MLVPN_PKT_DISCONNECT &&
                tun->status >= MLVPN_AUTHOK) {
            log_info("protocol", "%s disconnect received", tun->name);
            mlvpn_rtun_status_down(tun);
        } else if (decap_pkt.type == MLVPN_PKT_AUTH ||
                decap_pkt.type == MLVPN_PKT_AUTH_OK) {
            mlvpn_rtun_send_auth(tun);
        }
    }
}

static int
mlvpn_protocol_read(
    mlvpn_tunnel_t *tun, mlvpn_pkt_t *pkt,
    mlvpn_pkt_t *decap_pkt)
{
    unsigned char nonce[crypto_NONCEBYTES];
    int ret;
    uint16_t rlen;
    mlvpn_proto_t proto;
    uint64_t now64 = mlvpn_timestamp64(ev_now(EV_DEFAULT_UC));
    /* Overkill */
    memset(&proto, 0, sizeof(proto));
    memset(decap_pkt, 0, sizeof(*decap_pkt));

    /* pkt->data contains mlvpn_proto_t struct */
    if (pkt->len > sizeof(pkt->data) || pkt->len > sizeof(proto) ||
            pkt->len < (PKTHDRSIZ(proto))) {
        log_warnx("protocol", "%s received invalid packet of %d bytes",
            tun->name, pkt->len);
        goto fail;
    }
    memcpy(&proto, pkt->data, pkt->len);
    rlen = be16toh(proto.len);
    if (rlen == 0 || rlen > sizeof(proto.data)) {
        log_warnx("protocol", "%s invalid packet size: %d", tun->name, rlen);
        goto fail;
    }
    proto.seq = be64toh(proto.seq);
    proto.timestamp = be16toh(proto.timestamp);
    proto.timestamp_reply = be16toh(proto.timestamp_reply);
    proto.flow_id = be32toh(proto.flow_id);
    /* now auth the packet using libsodium before further checks */
#ifdef ENABLE_CRYPTO
    if (mlvpn_options.cleartext_data && proto.flags == MLVPN_PKT_DATA) {
        memcpy(decap_pkt->data, &proto.data, rlen);
    } else {
        sodium_memzero(nonce, sizeof(nonce));
        memcpy(nonce, &proto.seq, sizeof(proto.seq));
        memcpy(nonce + sizeof(proto.seq), &proto.flow_id, sizeof(proto.flow_id));
        if ((ret = crypto_decrypt((unsigned char *)decap_pkt->data,
                                  (const unsigned char *)&proto.data, rlen,
                                  nonce)) != 0) {
            log_warnx("protocol", "%s crypto_decrypt failed: %d",
                tun->name, ret);
            goto fail;
        }
        rlen -= crypto_PADSIZE;
    }
#else
    memcpy(decap_pkt->data, &proto.data, rlen);
#endif
    decap_pkt->len = rlen;
    decap_pkt->type = proto.flags;
    if (proto.version >= 1) {
        decap_pkt->reorder = proto.reorder;
        decap_pkt->seq = be64toh(proto.data_seq);
        mlvpn_loss_update(tun, decap_pkt->seq);
    } else {
        decap_pkt->reorder = 0;
        decap_pkt->seq = 0;
    }
    if (proto.timestamp != (uint16_t)-1) {
        tun->saved_timestamp = proto.timestamp;
        tun->saved_timestamp_received_at = now64;
    }
    if (proto.timestamp_reply != (uint16_t)-1) {
        uint16_t now16 = mlvpn_timestamp16(now64);
        double R = mlvpn_timestamp16_diff(now16, proto.timestamp_reply);
        if (R < 5000) { /* ignore large values, e.g. server was Ctrl-Zed */
            if (!tun->rtt_hit) { /* first measurement */
                tun->srtt = R;
                tun->rttvar = R / 2;
                tun->rtt_hit = 1;
            } else {
                const double alpha = 1.0 / 8.0;
                const double beta = 1.0 / 4.0;
                tun->rttvar = (1 - beta) * tun->rttvar + (beta * fabs(tun->srtt - R));
                tun->srtt = (1 - alpha) * tun->srtt + (alpha * R);
            }
        }
        log_debug("rtt", "%ums srtt %ums loss ratio: %d",
            (unsigned int)R, (unsigned int)tun->srtt, mlvpn_loss_ratio(tun));
    }
    return 0;
fail:
    return -1;
}

static int
mlvpn_rtun_send(mlvpn_tunnel_t *tun, circular_buffer_t *pktbuf)
{
    unsigned char nonce[crypto_NONCEBYTES];
    ssize_t ret;
    size_t wlen;
    mlvpn_proto_t proto;
    uint64_t now64 = mlvpn_timestamp64(ev_now(EV_DEFAULT_UC));
    memset(&proto, 0, sizeof(proto));

    mlvpn_pkt_t *pkt = mlvpn_pktbuffer_read(pktbuf);
    pkt->reorder = 1;
    if (pkt->type == MLVPN_PKT_DATA && pkt->reorder) {
        proto.data_seq = data_seq++;
    }
    wlen = PKTHDRSIZ(proto) + pkt->len;
    proto.len = pkt->len;
    proto.flags = pkt->type;
    if (pkt->reorder) {
        proto.seq = tun->seq++;
    }
    proto.flow_id = tun->flow_id;
    proto.version = MLVPN_PROTOCOL_VERSION;
    proto.reorder = pkt->reorder;

    /* we have a recent received timestamp */
    if (now64 - tun->saved_timestamp_received_at < 1000 ) {
        /* send "corrected" timestamp advanced by how long we held it */
        /* Cast to uint16_t there intentional */
        proto.timestamp_reply = tun->saved_timestamp + (now64 - tun->saved_timestamp_received_at);
        tun->saved_timestamp = -1;
        tun->saved_timestamp_received_at = 0;
    } else {
        proto.timestamp_reply = -1;
    }
    proto.timestamp = mlvpn_timestamp16(now64);
#ifdef ENABLE_CRYPTO
    if (mlvpn_options.cleartext_data && pkt->type == MLVPN_PKT_DATA) {
        memcpy(&proto.data, &pkt->data, pkt->len);
    } else {
        if (wlen + crypto_PADSIZE > sizeof(proto.data)) {
            log_warnx("protocol", "%s packet too long: %u/%d (packet=%d)",
                tun->name,
                (unsigned int)wlen + crypto_PADSIZE,
                (unsigned int)sizeof(proto.data),
                pkt->len);
            return -1;
        }
        sodium_memzero(nonce, sizeof(nonce));
        memcpy(nonce, &proto.seq, sizeof(proto.seq));
        memcpy(nonce + sizeof(proto.seq), &proto.flow_id, sizeof(proto.flow_id));
        if ((ret = crypto_encrypt((unsigned char *)&proto.data,
                                  (const unsigned char *)&pkt->data, pkt->len,
                                  nonce)) != 0) {
            log_warnx("protocol", "%s crypto_encrypt failed: %d incorrect password?",
                tun->name, (int)ret);
            return -1;
        }
        proto.len += crypto_PADSIZE;
        wlen += crypto_PADSIZE;
    }
#else
    memcpy(&proto.data, &pkt->data, pkt->len);
#endif
    proto.len = htobe16(proto.len);
    proto.seq = htobe64(proto.seq);
    proto.data_seq = htobe64(proto.data_seq);
    proto.flow_id = htobe32(proto.flow_id);
    proto.timestamp = htobe16(proto.timestamp);
    proto.timestamp_reply = htobe16(proto.timestamp_reply);
    ret = sendto(tun->fd, &proto, wlen, MSG_DONTWAIT,
                 tun->addrinfo->ai_addr, tun->addrinfo->ai_addrlen);
    if (ret < 0)
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log_warn("net", "%s write error", tun->name);
            mlvpn_rtun_status_down(tun);
        }
    } else {
        tun->sentpackets++;
        tun->sentbytes += ret;
        if (wlen != ret)
        {
            log_warnx("net", "%s write error %d/%u",
                tun->name, (int)ret, (unsigned int)wlen);
        } else {
            log_debug("net", "> %s sent %d bytes (size=%d, type=%d, seq=%"PRIu64", reorder=%d)",
                tun->name, (int)ret, pkt->len, pkt->type, pkt->seq, pkt->reorder);
        }
    }

    if (ev_is_active(&tun->io_write) && mlvpn_cb_is_empty(pktbuf)) {
        ev_io_stop(EV_A_ &tun->io_write);
    }
    return ret;
}


static void
mlvpn_rtun_write(EV_P_ ev_io *w, int revents)
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
               const char *bindaddr, const char *bindport, uint32_t bindfib,
               const char *destaddr, const char *destport,
               int server_mode, uint32_t timeout,
               int fallback_only, uint32_t bandwidth,
               uint32_t loss_tolerence)
{
    mlvpn_tunnel_t *new;

    /* Some basic checks */
    if (server_mode)
    {
        if (bindport == NULL)
        {
            log_warnx(NULL,
                "cannot initialize socket without bindport");
            return NULL;
        }
    } else {
        if (destaddr == NULL || destport == NULL)
        {
            log_warnx(NULL,
                "cannot initialize socket without destaddr or destport");
            return NULL;
        }
    }

    new = (mlvpn_tunnel_t *)calloc(1, sizeof(mlvpn_tunnel_t));
    if (! new)
        fatal(NULL, "calloc failed");
    /* other values are enforced by calloc to 0/NULL */
    new->name = strdup(name);
    new->fd = -1;
    new->server_mode = server_mode;
    new->weight = 1;
    new->status = MLVPN_DISCONNECTED;
    new->addrinfo = NULL;
    new->sentpackets = 0;
    new->sentbytes = 0;
    new->recvbytes = 0;
    new->seq = 0;
    new->expected_receiver_seq = 0;
    new->saved_timestamp = -1;
    new->saved_timestamp_received_at = 0;
    new->srtt = 1000;
    new->rttvar = 500;
    new->rtt_hit = 0;
    new->seq_last = 0;
    new->seq_vect = (uint64_t) -1;
    new->flow_id = crypto_nonce_random();
    new->bandwidth = bandwidth;
    new->fallback_only = fallback_only;
    new->loss_tolerence = loss_tolerence;
    if (bindaddr)
        strlcpy(new->bindaddr, bindaddr, sizeof(new->bindaddr));
    if (bindport)
        strlcpy(new->bindport, bindport, sizeof(new->bindport));
    new->bindfib = bindfib;
    if (destaddr)
        strlcpy(new->destaddr, destaddr, sizeof(new->destaddr));
    if (destport)
        strlcpy(new->destport, destport, sizeof(new->destport));
    new->sbuf = mlvpn_pktbuffer_init(PKTBUFSIZE);
    new->hpsbuf = mlvpn_pktbuffer_init(PKTBUFSIZE);
    mlvpn_rtun_tick(new);
    new->timeout = timeout;
    new->next_keepalive = 0;
    LIST_INSERT_HEAD(&rtuns, new, entries);
    new->io_read.data = new;
    new->io_write.data = new;
    new->io_timeout.data = new;
    ev_init(&new->io_read, mlvpn_rtun_read);
    ev_init(&new->io_write, mlvpn_rtun_write);
    ev_timer_init(&new->io_timeout, mlvpn_rtun_check_timeout,
        0., MLVPN_IO_TIMEOUT_DEFAULT);
    ev_timer_start(EV_A_ &new->io_timeout);
    update_process_title();
    return new;
}

void
mlvpn_rtun_drop(mlvpn_tunnel_t *t)
{
    mlvpn_tunnel_t *tmp;
    mlvpn_rtun_send_disconnect(t);
    mlvpn_rtun_status_down(t);
    ev_timer_stop(EV_A_ &t->io_timeout);
    ev_io_stop(EV_A_ &t->io_read);

    LIST_FOREACH(tmp, &rtuns, entries)
    {
        if (mystr_eq(tmp->name, t->name))
        {
            LIST_REMOVE(tmp, entries);
            if (tmp->name)
                free(tmp->name);
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
static void
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
        log_warnx("config", "you must set the bandwidth on every tunnel");
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
                log_debug("wrr", "%s weight = %f (%u %u)", t->name, t->weight,
                    t->bandwidth, bandwidth_total);
            }
        }
    }
}

static int
mlvpn_rtun_bind(mlvpn_tunnel_t *t)
{
    struct addrinfo hints, *res;
    int n, fd;

    memset(&hints, 0, sizeof(hints));
    /* AI_PASSIVE flag: the resulting address is used to bind
       to a socket for accepting incoming connections.
       So, when the hostname==NULL, getaddrinfo function will
       return one entry per allowed protocol family containing
       the unspecified address for that family. */
    hints.ai_flags    = AI_PASSIVE;
    hints.ai_family   = AF_UNSPEC;
    fd = t->fd;
    hints.ai_socktype = SOCK_DGRAM;

    n = priv_getaddrinfo(t->bindaddr, t->bindport, &res, &hints);
    if (n < 0)
    {
        log_warnx(NULL, "%s getaddrinfo error: %s", t->name, gai_strerror(n));
        return -1;
    }

    /* Try open socket with each address getaddrinfo returned,
       until getting a valid listening socket. */
    log_info(NULL, "%s bind to %s", t->name, *t->bindaddr ? t->bindaddr : "any");
    n = bind(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    if (n < 0)
    {
        log_warn(NULL, "%s bind error", t->name);
        return -1;
    }
    return 0;
}

static int
mlvpn_rtun_start(mlvpn_tunnel_t *t)
{
    int ret, fd = -1;
    char *addr, *port;
    struct addrinfo hints, *res;
#if defined(HAVE_FREEBSD) || defined(HAVE_OPENBSD)
    int fib = t->bindfib;
#endif
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
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    ret = priv_getaddrinfo(addr, port, &t->addrinfo, &hints);
    if (ret < 0 || !t->addrinfo)
    {
        log_warnx("dns", "%s getaddrinfo(%s,%s) failed: %s",
           t->name, addr, port, gai_strerror(ret));
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
            log_warn(NULL, "%s socket creation error",
                t->name);
        } else {
            /* Setting fib/routing-table is supported on FreeBSD and OpenBSD only */
#if defined(HAVE_FREEBSD)
            if (fib > 0 && setsockopt(fd, SOL_SOCKET, SO_SETFIB, &fib, sizeof(fib)) < 0)
#elif defined(HAVE_OPENBSD)
            if (fib > 0 && setsockopt(fd, SOL_SOCKET, SO_RTABLE, &fib, sizeof(fib)) < 0)
            {
                log_warn(NULL, "Cannot set FIB %d for kernel socket", fib);
                goto error;
            }
#endif
            t->fd = fd;
            break;
        }
        res = res->ai_next;
    }

    if (fd < 0) {
        log_warnx("dns", "%s connection failed. Check DNS?",
            t->name);
        goto error;
    }

    /* setup non blocking sockets */
    socklen_t val = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(socklen_t)) < 0) {
        log_warn(NULL, "%s setsockopt SO_REUSEADDR failed", t->name);
        goto error;
    }
    if (*t->bindaddr) {
        if (mlvpn_rtun_bind(t) < 0) {
            goto error;
        }
    }

    /* set non blocking after connect... May lockup the entiere process */
    mlvpn_sock_set_nonblocking(fd);
    mlvpn_rtun_tick(t);
    ev_io_set(&t->io_read, fd, EV_READ);
    ev_io_set(&t->io_write, fd, EV_WRITE);
    ev_io_start(EV_A_ &t->io_read);
    t->io_timeout.repeat = MLVPN_IO_TIMEOUT_DEFAULT;
    return 0;
error:
    if (t->fd > 0) {
        close(t->fd);
        t->fd = -1;
    }
    if (t->io_timeout.repeat < MLVPN_IO_TIMEOUT_MAXIMUM)
        t->io_timeout.repeat *= MLVPN_IO_TIMEOUT_INCREMENT;
    return -1;
}

static void
mlvpn_script_get_env(int *env_len, char ***env) {
    char **envp;
    int arglen;
    *env_len = 8;
    *env = (char **)calloc(*env_len + 1, sizeof(char *));
    if (! *env)
        fatal(NULL, "out of memory");
    envp = *env;
    arglen = sizeof(mlvpn_options.ip4) + 4;
    envp[0] = calloc(1, arglen + 1);
    if (snprintf(envp[0], arglen, "IP4=%s", mlvpn_options.ip4) < 0)
        log_warn(NULL, "snprintf IP4= failed");

    arglen = sizeof(mlvpn_options.ip6) + 4;
    envp[1] = calloc(1, arglen + 1);
    if (snprintf(envp[1], arglen, "IP6=%s", mlvpn_options.ip6) < 0)
        log_warn(NULL, "snprintf IP6= failed");

    arglen = sizeof(mlvpn_options.ip4_gateway) + 12;
    envp[2] = calloc(1, arglen + 1);
    if (snprintf(envp[2], arglen, "IP4_GATEWAY=%s", mlvpn_options.ip4_gateway) < 0)
        log_warn(NULL, "snprintf IP4_GATEWAY= failed");

    arglen = sizeof(mlvpn_options.ip6_gateway) + 12;
    envp[3] = calloc(1, arglen + 1);
    if (snprintf(envp[3], arglen, "IP6_GATEWAY=%s", mlvpn_options.ip6_gateway) < 0)
        log_warn(NULL, "snprintf IP6_GATEWAY= failed");

    arglen = sizeof(mlvpn_options.ip4_routes) + 11;
    envp[4] = calloc(1, arglen + 1);
    if (snprintf(envp[4], arglen, "IP4_ROUTES=%s", mlvpn_options.ip4_routes) < 0)
        log_warn(NULL, "snprintf IP4_ROUTES= failed");

    arglen = sizeof(mlvpn_options.ip6_routes) + 11;
    envp[5] = calloc(1, arglen + 1);
    if (snprintf(envp[5], arglen, "IP6_ROUTES=%s", mlvpn_options.ip6_routes) < 0)
        log_warn(NULL, "snprintf IP6_ROUTES= failed");

    arglen = sizeof(tuntap.devname) + 7;
    envp[6] = calloc(1, arglen + 1);
    if (snprintf(envp[6], arglen, "DEVICE=%s", tuntap.devname) < 0)
        log_warn(NULL, "snprintf DEVICE= failed");

    envp[7] = calloc(1, 16);
    if (snprintf(envp[7], 15, "MTU=%d", mlvpn_options.mtu) < 0)
        log_warn(NULL, "snprintf MTU= failed");
    envp[8] = NULL;
}

static void
mlvpn_free_script_env(char **env)
{
    char **envp = env;
    while (*envp) {
        free(*envp);
        envp++;
    }
    free(env);
}

static void
mlvpn_rtun_status_up(mlvpn_tunnel_t *t)
{
    char *cmdargs[4] = {tuntap.devname, "rtun_up", t->name, NULL};
    char **env;
    int env_len;
    ev_tstamp now = ev_now(EV_DEFAULT_UC);
    t->status = MLVPN_AUTHOK;
    t->next_keepalive = NEXT_KEEPALIVE(now, t);
    t->last_activity = now;
    t->last_keepalive_ack = now;
    t->last_keepalive_ack_sent = now;
    mlvpn_update_status();
    mlvpn_rtun_wrr_reset(&rtuns, mlvpn_status.fallback_mode);
    mlvpn_script_get_env(&env_len, &env);
    priv_run_script(3, cmdargs, env_len, env);
    if (mlvpn_status.connected > 0 && mlvpn_status.initialized == 0) {
        cmdargs[0] = tuntap.devname;
        cmdargs[1] = "tuntap_up";
        cmdargs[2] = NULL;
        priv_run_script(2, cmdargs, env_len, env);
        mlvpn_status.initialized = 1;
        if (reorder_buffer != NULL) {
            mlvpn_rtun_reorder_drain(0);
            mlvpn_reorder_reset(reorder_buffer);
        }
    }
    mlvpn_free_script_env(env);
    update_process_title();
}

void
mlvpn_rtun_status_down(mlvpn_tunnel_t *t)
{
    char *cmdargs[4] = {tuntap.devname, "rtun_down", t->name, NULL};
    char **env;
    int env_len;
    enum chap_status old_status = t->status;
    t->status = MLVPN_DISCONNECTED;
    t->disconnects++;
    mlvpn_pktbuffer_reset(t->sbuf);
    mlvpn_pktbuffer_reset(t->hpsbuf);
    if (ev_is_active(&t->io_write)) {
        ev_io_stop(EV_A_ &t->io_write);
    }

    mlvpn_update_status();
    if (old_status >= MLVPN_AUTHOK)
    {
        mlvpn_script_get_env(&env_len, &env);
        priv_run_script(3, cmdargs, env_len, env);
        /* Re-initialize weight round robin */
        mlvpn_rtun_wrr_reset(&rtuns, mlvpn_status.fallback_mode);
        if (mlvpn_status.connected == 0 && mlvpn_status.initialized == 1) {
            cmdargs[0] = tuntap.devname;
            cmdargs[1] = "tuntap_down";
            cmdargs[2] = NULL;
            priv_run_script(2, cmdargs, env_len, env);
            mlvpn_status.initialized = 0;
        }
        mlvpn_free_script_env(env);
        if (reorder_buffer != NULL) {
            mlvpn_rtun_reorder_drain(0);
            mlvpn_reorder_reset(reorder_buffer);
        }
    }
    update_process_title();
}

static void
mlvpn_update_status()
{
    mlvpn_tunnel_t *t;
    mlvpn_status.fallback_mode = mlvpn_options.fallback_available;
    mlvpn_status.connected = 0;
    LIST_FOREACH(t, &rtuns, entries)
    {
        if (t->status >= MLVPN_AUTHOK) {
            if (!t->fallback_only)
                mlvpn_status.fallback_mode = 0;
            mlvpn_status.connected++;
        }
    }
}

static void
mlvpn_rtun_challenge_send(mlvpn_tunnel_t *t)
{
    mlvpn_pkt_t *pkt;

    if (mlvpn_cb_is_full(t->hpsbuf))
        log_warnx("net", "%s high priority buffer: overflow", t->name);

    pkt = mlvpn_pktbuffer_write(t->hpsbuf);
    pkt->data[0] = 'A';
    pkt->data[1] = 'U';
    pkt->len = 2;
    pkt->type = MLVPN_PKT_AUTH;

    t->status = MLVPN_AUTHSENT;
    log_debug("protocol", "%s mlvpn_rtun_challenge_send", t->name);
}

static void
mlvpn_rtun_send_auth(mlvpn_tunnel_t *t)
{
    mlvpn_pkt_t *pkt;
    if (t->server_mode)
    {
        /* server side */
        if (t->status == MLVPN_DISCONNECTED || t->status >= MLVPN_AUTHOK)
        {
            if (mlvpn_cb_is_full(t->hpsbuf)) {
                log_warnx("net", "%s high priority buffer: overflow", t->name);
                mlvpn_cb_reset(t->hpsbuf);
            }
            pkt = mlvpn_pktbuffer_write(t->hpsbuf);
            pkt->data[0] = 'O';
            pkt->data[1] = 'K';
            pkt->len = 2;
            pkt->type = MLVPN_PKT_AUTH_OK;
            if (t->status < MLVPN_AUTHOK)
                t->status = MLVPN_AUTHSENT;
            log_debug("protocol", "%s sending 'OK'", t->name);
            log_info("protocol", "%s authenticated", t->name);
            mlvpn_rtun_tick(t);
            mlvpn_rtun_status_up(t);
            if (!ev_is_active(&t->io_write)) {
                ev_io_start(EV_A_ &t->io_write);
            }
        }
    } else {
        /* client side */
        if (t->status == MLVPN_AUTHSENT) {
            log_info("protocol", "%s authenticated", t->name);
            mlvpn_rtun_tick(t);
            mlvpn_rtun_status_up(t);
        }
    }
}

static void
mlvpn_rtun_tick_connect(mlvpn_tunnel_t *t)
{
    ev_tstamp now = ev_now(EV_DEFAULT_UC);
    if (t->server_mode) {
        if (t->fd < 0) {
            if (mlvpn_rtun_start(t) == 0) {
                t->conn_attempts = 0;
            } else {
                return;
            }
        }
    } else {
        if (t->status < MLVPN_AUTHOK) {
            t->conn_attempts++;
            t->last_connection_attempt = now;
            if (t->fd < 0) {
                if (mlvpn_rtun_start(t) == 0) {
                    t->conn_attempts = 0;
                } else {
                    return;
                }
            }
        }
        mlvpn_rtun_challenge_send(t);
    }
}

mlvpn_tunnel_t *
mlvpn_rtun_choose()
{
    mlvpn_tunnel_t *tun;
    tun = mlvpn_rtun_wrr_choose();
    return tun;
}

static void
mlvpn_rtun_send_keepalive(ev_tstamp now, mlvpn_tunnel_t *t)
{
    mlvpn_pkt_t *pkt;
    if (mlvpn_cb_is_full(t->hpsbuf))
        log_warnx("net", "%s high priority buffer: overflow", t->name);
    else {
        log_debug("protocol", "%s sending keepalive", t->name);
        pkt = mlvpn_pktbuffer_write(t->hpsbuf);
        pkt->type = MLVPN_PKT_KEEPALIVE;
    }
    t->next_keepalive = NEXT_KEEPALIVE(now, t);
}

static void
mlvpn_rtun_send_disconnect(mlvpn_tunnel_t *t)
{
    mlvpn_pkt_t *pkt;
    if (mlvpn_cb_is_full(t->hpsbuf))
        log_warnx("net", "%s high priority buffer: overflow", t->name);
    else {
        log_debug("protocol", "%s sending disconnect", t->name);
        pkt = mlvpn_pktbuffer_write(t->hpsbuf);
        pkt->type = MLVPN_PKT_DISCONNECT;
    }
    mlvpn_rtun_send(t, t->hpsbuf);
}

static void
mlvpn_rtun_check_lossy(mlvpn_tunnel_t *tun)
{
    int loss = mlvpn_loss_ratio(tun);
    int status_changed = 0;
    if (loss >= tun->loss_tolerence && tun->status == MLVPN_AUTHOK) {
        log_info("rtt", "%s packet loss reached threashold: %d%%/%d%%",
            tun->name, loss, tun->loss_tolerence);
        tun->status = MLVPN_LOSSY;
        status_changed = 1;
    } else if (loss < tun->loss_tolerence && tun->status == MLVPN_LOSSY) {
        log_info("rtt", "%s packet loss acceptable again: %d%%/%d%%",
            tun->name, loss, tun->loss_tolerence);
        tun->status = MLVPN_AUTHOK;
        status_changed = 1;
    }
    /* are all links in lossy mode ? switch to fallback ? */
    if (status_changed) {
        mlvpn_tunnel_t *t;
        LIST_FOREACH(t, &rtuns, entries) {
            if (! t->fallback_only && t->status != MLVPN_LOSSY) {
                mlvpn_status.fallback_mode = 0;
                mlvpn_rtun_wrr_reset(&rtuns, mlvpn_status.fallback_mode);
                return;
            }
        }
        if (mlvpn_options.fallback_available) {
            log_info(NULL, "all tunnels are down or lossy, switch fallback mode");
            mlvpn_status.fallback_mode = 1;
            mlvpn_rtun_wrr_reset(&rtuns, mlvpn_status.fallback_mode);
        } else {
            log_info(NULL, "all tunnels are down or lossy but fallback is not available");
        }
    }
}

static void
mlvpn_rtun_check_timeout(EV_P_ ev_timer *w, int revents)
{
    mlvpn_tunnel_t *t = w->data;
    ev_tstamp now = ev_now(EV_DEFAULT_UC);
    if (t->status >= MLVPN_AUTHOK && t->timeout > 0) {
        if ((t->last_keepalive_ack != 0) && (t->last_keepalive_ack + t->timeout) < now) {
            log_info("protocol", "%s timeout", t->name);
            mlvpn_rtun_status_down(t);
        } else {
            if (now > t->next_keepalive)
                mlvpn_rtun_send_keepalive(now, t);
        }
    } else if (t->status < MLVPN_AUTHOK) {
        mlvpn_rtun_tick_connect(t);
    }
    if (!ev_is_active(&t->io_write) && ! mlvpn_cb_is_empty(t->hpsbuf)) {
        ev_io_start(EV_A_ &t->io_write);
    }
    mlvpn_rtun_check_lossy(t);
}

static void
mlvpn_rtun_adjust_reorder_timeout(EV_P_ ev_timer *w, int revents)
{
    mlvpn_tunnel_t *t;
    double max_srtt = 0.0;
    double tmp;

    LIST_FOREACH(t, &rtuns, entries)
    {
        if (t->status >= MLVPN_AUTHOK) {
           /* We don't want to monitor fallback only links inside the
            * reorder timeout algorithm
            */
            if (!t->fallback_only && t->rtt_hit) {
                tmp = t->srtt + (4 * t->rttvar);
                max_srtt = max_srtt > tmp ? max_srtt : tmp;
            }
        }
    }

    /* Update the reorder algorithm */
    if (max_srtt > 0) {
        /* Apply a factor to the srtt in order to get a window */
        max_srtt *= 2.2;
        log_debug("reorder", "adjusting reordering drain timeout to %.0fms",
            max_srtt);
        reorder_drain_timeout.repeat = max_srtt / 1000.0;
    } else {
        reorder_drain_timeout.repeat = 0.8; /* Conservative 800ms shot */
    }
}

static void
tuntap_io_event(EV_P_ ev_io *w, int revents)
{
    if (revents & EV_READ) {
        mlvpn_tuntap_read(&tuntap);
    } else if (revents & EV_WRITE) {
        mlvpn_tuntap_write(&tuntap);
        /* Nothing else to read */
        if (mlvpn_cb_is_empty(tuntap.sbuf)) {
            ev_io_stop(EV_A_ &tuntap.io_write);
        }
    }
}

static void
mlvpn_tuntap_init()
{
    mlvpn_proto_t proto;
    memset(&tuntap, 0, sizeof(tuntap));
    snprintf(tuntap.devname, MLVPN_IFNAMSIZ-1, "%s", "mlvpn0");
    tuntap.maxmtu = 1500 - PKTHDRSIZ(proto) - IP4_UDP_OVERHEAD;
    log_debug(NULL, "absolute maximum mtu: %d", tuntap.maxmtu);
    tuntap.type = MLVPN_TUNTAPMODE_TUN;
    tuntap.sbuf = mlvpn_pktbuffer_init(PKTBUFSIZE);
    ev_init(&tuntap.io_read, tuntap_io_event);
    ev_init(&tuntap.io_write, tuntap_io_event);
}

static void
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
            case MLVPN_AUTHOK:
                s = "@";
                break;
            case MLVPN_LOSSY:
                s = "~";
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
    setproctitle("%s", title);
}

static void
mlvpn_config_reload(EV_P_ ev_signal *w, int revents)
{
    log_info("config", "reload (SIGHUP)");
    priv_reload_resolver();
    /* configuration file path does not matter after
     * the first intialization.
     */
    int config_fd = priv_open_config("");
    if (config_fd > 0)
    {
        if (mlvpn_config(config_fd, 0) != 0) {
            log_warn("config", "reload failed");
        } else {
            if (time(&mlvpn_status.last_reload) == -1)
                log_warn("config", "last_reload time set failed");
            mlvpn_rtun_recalc_weight();
        }
    } else {
        log_warn("config", "open failed");
    }
}

static void
mlvpn_quit(EV_P_ ev_signal *w, int revents)
{
    mlvpn_tunnel_t *t;
    log_info(NULL, "killed by signal SIGTERM, SIGQUIT or SIGINT");
    LIST_FOREACH(t, &rtuns, entries)
    {
        ev_timer_stop(EV_A_ &t->io_timeout);
        ev_io_stop(EV_A_ &t->io_read);
        if (t->status >= MLVPN_AUTHOK) {
            mlvpn_rtun_send_disconnect(t);
        }
    }
    ev_break(EV_A_ EVBREAK_ALL);
}

int
main(int argc, char **argv)
{
    int i, c, option_index, config_fd;
    struct stat st;
    ev_signal signal_hup;
    ev_signal signal_sigquit, signal_sigint, signal_sigterm;
    extern char *__progname;
#ifdef ENABLE_CONTROL
    struct mlvpn_control control;
#endif
    /* uptime statistics */
    if (time(&mlvpn_status.start_time) == -1)
        log_warn(NULL, "start_time time() failed");
    if (time(&mlvpn_status.last_reload) == -1)
        log_warn(NULL, "last_reload time() failed");

    log_init(1, 2, "mlvpn");

    _progname = strdup(__progname);
    saved_argv = calloc(argc + 1, sizeof(*saved_argv));
    for(i = 0; i < argc; i++) {
        saved_argv[i] = strdup(argv[i]);
    }
    saved_argv[i] = NULL;
    compat_init_setproctitle(argc, argv);
    argv = saved_argv;

    /* Parse the command line quickly for config file name.
     * This is needed for priv_init to know where the config
     * file is.
     *
     * priv_init will not allow to change the config file path.
     */
    while(1)
    {
        c = getopt_long(argc, saved_argv, optstr,
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c)
        {
        case 1:  /* --natural-title */
            mlvpn_options.change_process_title = 0;
            break;
        case 2:  /* --debug */
            mlvpn_options.debug = 1;
            break;
        case 3:  /* --yes-run-as-root */
            mlvpn_options.root_allowed = 1;
            break;
        case 'c': /* --config */
            strlcpy(mlvpn_options.config_path, optarg,
                    sizeof(mlvpn_options.config_path));
            break;
        case 'D': /* debug= */
            mlvpn_options.debug = 1;
            log_accept(optarg);
            break;
        case 'n': /* --name */
            strlcpy(mlvpn_options.process_name, optarg,
                    sizeof(mlvpn_options.process_name));
            break;
        case 'u': /* --user */
            strlcpy(mlvpn_options.unpriv_user, optarg,
                    sizeof(mlvpn_options.unpriv_user));
            break;
        case 'v': /* --verbose */
            mlvpn_options.verbose++;
            break;
        case 'V': /* --version */
            printf("mlvpn version %s.\n", VERSION);
            _exit(0);
            break;
        case 'q': /* --quiet */
            mlvpn_options.verbose--;
            break;
        case 'h': /* --help */
        default:
            usage(argv);
        }
    }

    /* Config file check */
    if (access(mlvpn_options.config_path, R_OK) != 0) {
        log_warnx("config", "unable to read config file %s",
            mlvpn_options.config_path);
    }
    if (stat(mlvpn_options.config_path, &st) < 0) {
        fatal("config", "unable to open file");
    } else if (st.st_mode & (S_IRWXG|S_IRWXO)) {
        fatal("config", "file is group/other accessible");
    }

    /* Some common checks */
    if (getuid() == 0)
    {
        void *pw = getpwnam(mlvpn_options.unpriv_user);
        if (!mlvpn_options.root_allowed && ! pw)
            fatal(NULL, "you are not allowed to run this program as root. "
                        "please specify a valid user with --user option");
        if (! pw)
            fatal(NULL, "invalid unprivilged username");
    }

#ifdef HAVE_LINUX
    if (access("/dev/net/tun", R_OK|W_OK) != 0)
    {
        fatal(NULL, "unable to open /dev/net/tun");
    }
#endif

    if (mlvpn_options.change_process_title)
    {
        __progname = "mlvpn";
        if (*mlvpn_options.process_name)
        {
            process_title = mlvpn_options.process_name;
            setproctitle("%s [priv]", mlvpn_options.process_name);
        } else {
            process_title = "";
            setproctitle("[priv]");
        }
    }

    if (crypto_init() == -1)
        fatal(NULL, "libsodium initialization failed");

    log_init(mlvpn_options.debug, mlvpn_options.verbose, mlvpn_options.process_name);

#ifdef HAVE_LINUX
    mlvpn_systemd_notify();
#endif

    priv_init(argv, mlvpn_options.unpriv_user);
    if (mlvpn_options.change_process_title)
        update_process_title();

    LIST_INIT(&rtuns);
    freebuf = mlvpn_freebuffer_init(512);

    /* Kill me if my root process dies ! */
#ifdef HAVE_LINUX
    prctl(PR_SET_PDEATHSIG, SIGCHLD);
#endif

    /* Config file opening / parsing */
    config_fd = priv_open_config(mlvpn_options.config_path);
    if (config_fd < 0)
        fatalx("cannot open config file");
    if (! (loop = ev_default_loop(EVFLAG_AUTO)))
        fatal(NULL, "cannot initialize libev. check LIBEV_FLAGS?");
    /* tun/tap initialization */
    mlvpn_tuntap_init();
    if (mlvpn_config(config_fd, 1) != 0)
        fatalx("cannot open config file");

    if (mlvpn_tuntap_alloc(&tuntap) <= 0)
        fatalx("cannot create tunnel device");
    else
        log_info(NULL, "created interface `%s'", tuntap.devname);
    mlvpn_sock_set_nonblocking(tuntap.fd);

    /* This is a dummy value which will be overwritten when the first
     * SRTT values will be available
     */
    ev_init(&reorder_drain_timeout, &mlvpn_rtun_reorder_drain_timeout);
    ev_io_set(&tuntap.io_read, tuntap.fd, EV_READ);
    ev_io_set(&tuntap.io_write, tuntap.fd, EV_WRITE);
    ev_io_start(loop, &tuntap.io_read);

    ev_timer_init(&reorder_adjust_rtt_timeout,
        mlvpn_rtun_adjust_reorder_timeout, 0., 1.0);
    ev_timer_start(EV_A_ &reorder_adjust_rtt_timeout);

    priv_set_running_state();

#ifdef ENABLE_CONTROL
    /* Initialize mlvpn remote control system */
    strlcpy(control.fifo_path, mlvpn_options.control_unix_path,
        sizeof(control.fifo_path));
    control.mode = MLVPN_CONTROL_READWRITE;
    control.fifo_mode = 0600;
    control.bindaddr = strdup(mlvpn_options.control_bind_host);
    control.bindport = strdup(mlvpn_options.control_bind_port);
    mlvpn_control_init(&control);
#endif

    /* re-compute rtun weight based on bandwidth allocation */
    mlvpn_rtun_recalc_weight();

    /* Last check before running */
    if (getppid() == 1)
        fatalx("Privileged process died");

    ev_signal_init(&signal_hup, mlvpn_config_reload, SIGHUP);
    ev_signal_init(&signal_sigint, mlvpn_quit, SIGINT);
    ev_signal_init(&signal_sigquit, mlvpn_quit, SIGQUIT);
    ev_signal_init(&signal_sigterm, mlvpn_quit, SIGTERM);
    ev_signal_start(loop, &signal_hup);
    ev_signal_start(loop, &signal_sigint);
    ev_signal_start(loop, &signal_sigquit);
    ev_signal_start(loop, &signal_sigterm);

    ev_run(loop, 0);

    free(_progname);
    return 0;
}
