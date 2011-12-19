#ifndef PS_STATUS_H
#define PS_STATUS_H

char ** save_ps_display_args(int argc, char **argv);
void init_ps_display(const char *username, const char *dbname, const char *host_info, const char *initial_str);

#endif
