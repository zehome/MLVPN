#ifndef _INCLUDES_H
#define _INCLUDES_H

#include "config.h"
#include "defines.h"

#include <sys/types.h>

#ifndef HAVE_STRLCPY
/* #include <sys/types.h> XXX Still needed? */
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif
#ifndef HAVE_STRLCAT
/* #include <sys/types.h> XXX Still needed? */
size_t strlcat(char *dst, const char *src, size_t siz);
#endif

#endif
