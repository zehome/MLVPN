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

#include "includes.h"
#include "mlvpn.h"
#include "configlib.h"
#include "tool.h"
#include "crypto.h"
#include "tuntap_generic.h"

extern char *status_command;
extern struct mlvpn_options_s mlvpn_options;
extern struct mlvpn_filters_s mlvpn_filters;
extern struct tuntap_s tuntap;
extern struct mlvpn_reorder_buffer *reorder_buffer;

/* Config file reading / re-read.
 * config_file_fd: fd opened in priv_open_config
 * first_time: set to 0 for re-read, or 1 for initial configuration
 */
int
mlvpn_config(int config_file_fd, int first_time)
{
    config_t *config, *work;
    mlvpn_tunnel_t *tmptun;
    char *tmp = NULL;
    char *mode = NULL;
    char *lastSection = NULL;
    char *tundevname = NULL;
    char *password = NULL;
    uint32_t tun_mtu = 0;

    uint32_t default_loss_tolerence = 100;
    uint32_t default_timeout = 60;
    uint32_t default_server_mode = 0; /* 0 => client */
    uint32_t cleartext_data = 0;
    uint32_t fallback_only = 0;
    uint32_t reorder_buffer_size = 0;

    mlvpn_options.fallback_available = 0;

    /* reset all bpf filters on every interface */
#ifdef HAVE_FILTERS
    struct bpf_program filter;
    pcap_t *pcap_dead_p = pcap_open_dead(DLT_RAW, DEFAULT_MTU);
    memset(&mlvpn_filters, 0, sizeof(mlvpn_filters));
#endif

    work = config = _conf_parseConfig(config_file_fd);
    if (! config)
        goto error;

    while (work)
    {
        if ((work->section != NULL) && !mystr_eq(work->section, lastSection))
        {
            lastSection = work->section;
            if (mystr_eq(lastSection, "general"))
            {
                /* Thoses settings can only by set at start time */
                if (first_time)
                {
                    _conf_set_str_from_conf(
                        config, lastSection, "statuscommand", &status_command, NULL,
                        NULL, 0);
                    _conf_set_str_from_conf(
                        config, lastSection, "interface_name", &tundevname, "mlvpn0",
                        NULL, 0);
                    if (tundevname) {
                        strlcpy(tuntap.devname, tundevname, sizeof(tuntap.devname));
                        free(tundevname);
                    }
                    _conf_set_str_from_conf(
                        config, lastSection, "tuntap", &tmp, "tun", NULL, 0);
                    if (tmp) {
                        if (mystr_eq(tmp, "tun"))
                            tuntap.type = MLVPN_TUNTAPMODE_TUN;
                        else
                            tuntap.type = MLVPN_TUNTAPMODE_TAP;
                        free(tmp);
                    }
                    /* Control configuration */
                    _conf_set_str_from_conf(
                        config, lastSection, "control_unix_path", &tmp, NULL,
                        NULL, 0);
                    if (tmp) {
                        strlcpy(mlvpn_options.control_unix_path, tmp,
                            sizeof(mlvpn_options.control_unix_path));
                        free(tmp);
                    }
                    _conf_set_str_from_conf(
                        config, lastSection, "control_bind_host", &tmp, NULL,
                        NULL, 0);
                    if (tmp) {
                        strlcpy(mlvpn_options.control_bind_host, tmp,
                            sizeof(mlvpn_options.control_bind_host));
                        free(tmp);
                    }
                    _conf_set_str_from_conf(
                        config, lastSection, "control_bind_port", &tmp, NULL,
                        NULL, 0);
                    if (tmp) {
                        strlcpy(mlvpn_options.control_bind_port, tmp,
                            sizeof(mlvpn_options.control_bind_port));
                        free(tmp);
                    }
                }
                /* This is important to be parsed every time because
                 * it's used later in the configuration parsing
                 */
                _conf_set_str_from_conf(
                    config, lastSection, "mode", &mode, NULL,
                    "Operation mode is mandatory.", 1);
                if (mystr_eq(mode, "server"))
                    default_server_mode = 1;
                if (mode)
                    free(mode);

                _conf_set_str_from_conf(
                    config, lastSection, "password", &password, NULL,
                    "Password is mandatory.", 2);
                if (password) {
                    log_info("config", "new password set");
                    crypto_set_password(password, strlen(password));
                    memset(password, 0, strlen(password));
                    free(password);
                }
                _conf_set_uint_from_conf(
                    config, lastSection, "cleartext_data", &cleartext_data, 0,
                    NULL, 0);
                mlvpn_options.cleartext_data = cleartext_data;


                _conf_set_uint_from_conf(
                    config, lastSection, "timeout", &default_timeout, 60,
                    NULL, 0);
                if (default_timeout < 5) {
                    log_warnx("config", "timeout capped to 5 seconds");
                    default_timeout = 5;
                }

                _conf_set_uint_from_conf(
                    config, lastSection, "reorder_buffer_size",
                    &reorder_buffer_size,
                    0, NULL, 0);
                if (reorder_buffer_size != mlvpn_options.reorder_buffer_size) {
                    log_info("config",
                        "reorder_buffer_size changed from %d to %d",
                        mlvpn_options.reorder_buffer_size,
                        reorder_buffer_size);
                    if (reorder_buffer_size != 0 &&
                            mlvpn_options.reorder_buffer_size != 0) {
                        mlvpn_reorder_free(reorder_buffer);
                        reorder_buffer = NULL;
                    }
                    mlvpn_options.reorder_buffer_size = reorder_buffer_size;
                    if (mlvpn_options.reorder_buffer_size > 0) {
                        if (reorder_buffer) {
                            mlvpn_reorder_free(reorder_buffer);
                        }
                        reorder_buffer = mlvpn_reorder_create(
                            mlvpn_options.reorder_buffer_size);
                        if (reorder_buffer == NULL) {
                            fatal("config", "reorder_buffer allocation failed");
                        }
                    }
                }

                _conf_set_uint_from_conf(
                    config, lastSection, "loss_tolerence",
                    &default_loss_tolerence, 100,  NULL, 0);
                if (default_loss_tolerence > 100) {
                    log_warnx("config", "loss_tolerence is capped to 100 %%");
                    default_loss_tolerence = 100;
                }

                /* Tunnel configuration */
                _conf_set_str_from_conf(
                    config, lastSection, "ip4", &tmp, NULL, NULL, 0);
                if (tmp) {
                    strlcpy(mlvpn_options.ip4, tmp, sizeof(mlvpn_options.ip4));
                    free(tmp);
                } else {
                    memset(mlvpn_options.ip4_gateway, 0,
                        sizeof(mlvpn_options.ip4_gateway));
                }

                _conf_set_str_from_conf(
                    config, lastSection, "ip6", &tmp, NULL, NULL, 0);
                if (tmp) {
                    strlcpy(mlvpn_options.ip6, tmp, sizeof(mlvpn_options.ip6));
                    free(tmp);
                } else {
                    memset(mlvpn_options.ip4_gateway, 0,
                        sizeof(mlvpn_options.ip4_gateway));
                }

                _conf_set_str_from_conf(
                    config, lastSection, "ip4_gateway", &tmp, NULL, NULL, 0);
                if (tmp) {
                    strlcpy(mlvpn_options.ip4_gateway, tmp,
                        sizeof(mlvpn_options.ip4_gateway));
                    free(tmp);
                } else {
                    memset(mlvpn_options.ip4_gateway, 0,
                        sizeof(mlvpn_options.ip4_gateway));
                }

                _conf_set_str_from_conf(
                    config, lastSection, "ip6_gateway", &tmp, NULL, NULL, 0);
                if (tmp) {
                    strlcpy(mlvpn_options.ip6_gateway, tmp,
                        sizeof(mlvpn_options.ip6_gateway));
                    free(tmp);
                } else {
                    memset(mlvpn_options.ip6_gateway, 0,
                        sizeof(mlvpn_options.ip6_gateway));
                }

                _conf_set_str_from_conf(
                    config, lastSection, "ip4_routes", &tmp, NULL, NULL, 0);
                if (tmp) {
                    strlcpy(mlvpn_options.ip4_routes, tmp,
                        sizeof(mlvpn_options.ip4_routes));
                    free(tmp);
                } else {
                    memset(mlvpn_options.ip4_routes, 0,
                        sizeof(mlvpn_options.ip4_routes));
                }

                _conf_set_str_from_conf(
                    config, lastSection, "ip6_routes", &tmp, NULL, NULL, 0);
                if (tmp) {
                    strlcpy(mlvpn_options.ip6_routes, tmp,
                        sizeof(mlvpn_options.ip6_routes));
                    free(tmp);
                } else {
                    memset(mlvpn_options.ip6_routes, 0,
                        sizeof(mlvpn_options.ip6_routes));
                }

                _conf_set_uint_from_conf(
                    config, lastSection, "mtu", &tun_mtu, 1432, NULL, 0);
                if (tun_mtu != 0) {
                    mlvpn_options.mtu = tun_mtu;
                }
            } else if (strncmp(lastSection, "filters", 7) != 0) {
                char *bindaddr;
                char *bindport;
                uint32_t bindfib = 0;
                char *dstaddr;
                char *dstport;
                uint32_t bwlimit = 0;
                uint32_t timeout = 30;
                uint32_t loss_tolerence;
                int create_tunnel = 1;

                if (default_server_mode)
                {
                    _conf_set_str_from_conf(
                        config, lastSection, "bindhost", &bindaddr, NULL,
                        NULL, 0);
                    _conf_set_str_from_conf(
                        config, lastSection, "bindport", &bindport, NULL,
                        "bind port is mandatory in server mode.\n", 1);
                    _conf_set_uint_from_conf(
                        config, lastSection, "bindfib", &bindfib, 0,
                        NULL, 0);
                    _conf_set_str_from_conf(
                        config, lastSection, "remotehost", &dstaddr, NULL,
                        NULL, 0);
                    _conf_set_str_from_conf(
                        config, lastSection, "remoteport", &dstport, NULL,
                        NULL, 0);
                } else {
                    _conf_set_str_from_conf(
                        config, lastSection, "bindhost", &bindaddr, NULL,
                        NULL, 0);
                    _conf_set_str_from_conf(
                        config, lastSection, "bindport", &bindport, NULL,
                        NULL, 0);
                     _conf_set_uint_from_conf(
                        config, lastSection, "bindfib", &bindfib, 0,
                        NULL, 0);
                    _conf_set_str_from_conf(
                        config, lastSection, "remotehost", &dstaddr, NULL,
                        "No remote address specified.\n", 1);
                    _conf_set_str_from_conf(
                        config, lastSection, "remoteport", &dstport, NULL,
                        "No remote port specified.\n", 1);
                }
                _conf_set_uint_from_conf(
                    config, lastSection, "bandwidth_upload", &bwlimit, 0,
                    NULL, 0);
                _conf_set_uint_from_conf(
                    config, lastSection, "timeout", &timeout, default_timeout,
                    NULL, 0);
                if (timeout < 5) {
                    log_warnx("config", "timeout capped to 5 seconds");
                    timeout = 5;
                }
                _conf_set_uint_from_conf(
                    config, lastSection, "loss_tolerence", &loss_tolerence,
                    default_loss_tolerence, NULL, 0);
                if (loss_tolerence > 100) {
                    log_warnx("config", "loss_tolerence is capped to 100 %%");
                    loss_tolerence = 100;
                }
                _conf_set_uint_from_conf(
                    config, lastSection, "fallback_only", &fallback_only, 0,
                    NULL, 0);
                if (fallback_only) {
                    mlvpn_options.fallback_available = 1;
                }
                LIST_FOREACH(tmptun, &rtuns, entries)
                {
                    if (mystr_eq(lastSection, tmptun->name))
                    {
                        log_info("config",
                            "%s restart for configuration reload",
                              tmptun->name);
                        if ((! mystr_eq(tmptun->bindaddr, bindaddr)) ||
                                (! mystr_eq(tmptun->bindport, bindport)) ||
                                (tmptun->bindfib != bindfib) ||
                                (! mystr_eq(tmptun->destaddr, dstaddr)) ||
                                (! mystr_eq(tmptun->destport, dstport))) {
                            mlvpn_rtun_status_down(tmptun);
                        }

                        if (bindaddr) {
                            strlcpy(tmptun->bindaddr, bindaddr, sizeof(tmptun->bindaddr));
                        }
                        if (bindport) {
                            strlcpy(tmptun->bindport, bindport, sizeof(tmptun->bindport));
                        }
                        if (tmptun->bindfib != bindfib) {
                            tmptun->bindfib = bindfib;
                        }
                        if (dstaddr) {
                            strlcpy(tmptun->destaddr, dstaddr, sizeof(tmptun->destaddr));
                        }
                        if (dstport) {
                            strlcpy(tmptun->destport, dstport, sizeof(tmptun->destport));
                        }
                        if (tmptun->fallback_only != fallback_only)
                        {
                            log_info("config", "%s fallback_only changed from %d to %d",
                                tmptun->name, tmptun->fallback_only, fallback_only);
                            tmptun->fallback_only = fallback_only;
                        }
                        if (tmptun->bandwidth != bwlimit)
                        {
                        log_info("config", "%s bandwidth changed from %d to %d",
                                tmptun->name, tmptun->bandwidth, bwlimit);
                            tmptun->bandwidth = bwlimit;
                        }
                        if (tmptun->loss_tolerence != loss_tolerence)
                        {
                            log_info("config", "%s loss tolerence changed from %d%% to %d%%",
                                tmptun->name, tmptun->loss_tolerence, loss_tolerence);
                            tmptun->loss_tolerence = loss_tolerence;
                        }
                        create_tunnel = 0;
                        break; /* Very important ! */
                    }
                }

                if (create_tunnel)
                {
                    log_info("config", "%s tunnel added", lastSection);
                    mlvpn_rtun_new(
                        lastSection, bindaddr, bindport, bindfib, dstaddr, dstport,
                        default_server_mode, timeout, fallback_only,
                        bwlimit, loss_tolerence);
                }
                if (bindaddr)
                    free(bindaddr);
                if (bindport)
                    free(bindport);
                if (dstaddr)
                    free(dstaddr);
                if (dstport)
                    free(dstport);
            }
        } else if (lastSection == NULL)
            lastSection = work->section;
        work = work->next;
    }

    /* Ok, let's delete old tunnels */
    if (! first_time)
    {
        LIST_FOREACH(tmptun, &rtuns, entries)
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
                log_info("config", "%s tunnel removed", tmptun->name);
                mlvpn_rtun_drop(tmptun);
            }
        }
    }

#ifdef HAVE_FILTERS
    work = config;
    int found_in_config = 0;
    while (work)
    {
        if (work->section != NULL &&
                strncmp(work->section, "filters", 7) == 0) {
            memset(&filter, 0, sizeof(filter));
            if (pcap_compile(pcap_dead_p, &filter, work->conf->val,
                    1, PCAP_NETMASK_UNKNOWN) != 0) {
                log_warnx("config", "invalid filter %s = %s: %s",
                    work->conf->var, work->conf->val, pcap_geterr(pcap_dead_p));
            } else {
                found_in_config = 0;
                LIST_FOREACH(tmptun, &rtuns, entries) {
                    if (strcmp(work->conf->var, tmptun->name) == 0) {
                        if (mlvpn_filters_add(&filter, tmptun) != 0) {
                            log_warnx("config", "%s filter %s error: too many filters",
                                tmptun->name, work->conf->val);
                        } else {
                            log_debug("config", "%s added filter: %s",
                                tmptun->name, work->conf->val);
                            found_in_config = 1;
                            break;
                        }
                    }
                }
                if (!found_in_config) {
                    log_warnx("config", "(filters) %s interface not found",
                        work->conf->var);
                }
            }
        }
        work = work->next;
    }
#endif

    //_conf_printConfig(config);
    _conf_freeConfig(config);
#ifdef HAVE_FILTERS
    pcap_close(pcap_dead_p);
#endif

    if (first_time && status_command)
        priv_init_script(status_command);
    return 0;
error:
    log_warnx("config", "parse error");
    return 1;
}
