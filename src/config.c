#include "includes.h"
#include "mlvpn.h"
#include "configlib.h"
#include "tool.h"
#include "crypto.h"
#include "tuntap_generic.h"

extern char *status_command;
extern char *process_title;
extern struct tuntap_s tuntap;

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
    int logverbose = 0;

    work = config = _conf_parseConfig(config_file_fd);
    if (! config)
        goto error;

    while (work)
    {
        if ((work->section != NULL) &&
                (mystr_eq(work->section, lastSection) == 0))
        {
            lastSection = work->section;
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
                    char *password;
                    _conf_set_str_from_conf(config, lastSection,
                        "password", &password, NULL, "Password is mandatory.", 2);
                    crypto_set_password(password, strlen(password));
                    memset(password, 0, strlen(password));
                    if (mystr_eq(tmp, "tun"))
                        tuntap.type = MLVPN_TUNTAPMODE_TUN;
                    else
                        tuntap.type = MLVPN_TUNTAPMODE_TAP;
                }

                _conf_set_str_from_conf(config, lastSection,
                                        "mode", &mode, NULL, "Operation mode is mandatory.", 1);
                if (mystr_eq(mode, "server"))
                    default_server_mode = 1;

                _conf_set_int_from_conf(config, lastSection,
                                        "loglevel", &logverbose, 0, NULL, 0);
                log_verbose(logverbose);
                _conf_set_str_from_conf(config, lastSection,
                                        "protocol", &tmp, "udp", NULL, 0);
                if (mystr_eq(tmp, "udp")) {
                    default_protocol = ENCAP_PROTO_UDP;
                } else if (mystr_eq(tmp, "tcp")) {
                    log_warnx("TCP is not supported.");
                } else {
                    log_warnx("Unknown protocol %s.", tmp);
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
                                            "bandwidth_upload", &bwlimit, 0, NULL, 0);
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
                        log_warnx("TCP is not supported.");
                    } else {
                        log_warnx("Unknown protocol %s.", tmp);
                    }
                }

                _conf_set_int_from_conf(config, lastSection,
                                        "timeout",
                                        (int *)&timeout, default_timeout, NULL, 0);

                if (! LIST_EMPTY(&rtuns))
                {
                    LIST_FOREACH(tmptun, &rtuns, entries)
                    {
                        if (mystr_eq(lastSection, tmptun->name))
                        {
                            log_info("Updating tunnel %s during config reload.",
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
                    }
                }

                if (create_tunnel)
                {
                    log_info("Adding tunnel %s.", lastSection);
                    mlvpn_rtun_new(
                        lastSection, bindaddr, bindport, dstaddr, dstport,
                        default_server_mode, timeout);
                }
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
                log_info("Deleting tunnel %s.", tmptun->name);
                mlvpn_rtun_drop(tmptun);
            }
        }
    }
    //_conf_printConfig(config);
    _conf_freeConfig(config);

    if (first_time && status_command)
        priv_init_script(status_command);
    return 0;
error:
    log_warnx("Error parsing config file.");
    return 1;
}
