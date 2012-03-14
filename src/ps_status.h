#ifndef PS_STATUS_H
#define PS_STATUS_H

char **save_ps_display_args(int argc, char **argv);
void init_ps_display(const char *initial_str);
void set_ps_display(const char *activity);

#endif
