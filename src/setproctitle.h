#ifndef _SETPROCTITLE_H
#define _SETPROCTITLE_H

#include "includes.h"

void setproctitle(const char *fmt, ...);
void compat_init_setproctitle(int argc, char *argv[]);

#endif
