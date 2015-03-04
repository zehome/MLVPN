#ifndef _INCLUDES_H
#define _INCLUDES_H

#include "config.h"
#include "defines.h"

#include <inttypes.h>
#include <sys/param.h>
#include <sys/types.h>

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_CLOSEFROM
void closefrom(int lowfd);
#endif

#endif
