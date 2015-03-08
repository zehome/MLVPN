/*
 * Copyright (c) 2008 Vincent Bernat <bernat@luffy.cx>
 * Copyright (c) 2015 Laurent COUSTET <ed@zehome.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "mlvpn.h"
#include "systemd.h"

/**
 * Tell if we have been started by systemd.
 */
void
mlvpn_systemd_notify()
{
    int fd = -1;
    const char *notifysocket = getenv("NOTIFY_SOCKET");
    if (!notifysocket ||
        !strchr("@/", notifysocket[0]) ||
        strlen(notifysocket) < 2)
        return;

    log_debug("systemd",
        "running with systemd, don't fork but signal ready");
    if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
        log_warn("systemd",
            "unable to open systemd notification socket %s",
            notifysocket);
        return;
    }

    struct sockaddr_un su = { .sun_family = AF_UNIX };
    strlcpy(su.sun_path, notifysocket, sizeof(su.sun_path));
    if (notifysocket[0] == '@') su.sun_path[0] = 0;

    struct iovec iov = {
        .iov_base = "READY=1",
        .iov_len = strlen("READY=1")
    };
    struct msghdr hdr = {
        .msg_name = &su,
        .msg_namelen = offsetof(struct sockaddr_un, sun_path) + strlen(notifysocket),
        .msg_iov = &iov,
        .msg_iovlen = 1
    };
    unsetenv("NOTIFY_SOCKET");
    if (sendmsg(fd, &hdr, MSG_NOSIGNAL) < 0) {
        log_warn("systemd",
            "unable to send notification to systemd");
        close(fd);
        return;
    }
    close(fd);
}
