#ifndef _INCLUDES_H
#define _INCLUDES_H

#include "config.h"
#include "defines.h"

#include <inttypes.h>
#include <sys/param.h>
#include <sys/types.h>

/*
 * We want functions in openbsd-compat, if enabled, to override system ones.
 * We no-op out the weak symbol definition rather than remove it to reduce
 * future sync problems.
 */
#define DEF_WEAK(x)

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
