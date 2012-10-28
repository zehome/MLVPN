#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/time.h>

#include "config.h"
#include "tool.h"
#include "debug.h"

int mystr_eq(const char *s1, const char *s2)
{
  if ((s1 == NULL) || (s2 == NULL)) 
    return 0;

  if (strcmp(s1, s2) == 0)
    return 1;

  return 0;
}

void stripBadChar(const char *from, char *to)
{
  if (from == NULL)
    return;

  while (*from != '\0')
  {
    switch (*from)
    {
      case '|':
        *to++ = 'l';
        break;
      case '`':
        *to++ = '\'';
        break;
      case '/':
      case '\\':
        break;

      default:
        if (isascii(*from))
          *to++ = *from;
        break;
    }
    from++;
  }

  *to = '\0';
}

char *
tool_get_bytes(unsigned long long bytes)
{
    char *str;
    char *conv_unit = NULL;
    int conv_div = 1;
    
    if (bytes < 1024)
    {
        conv_unit = "B";
        conv_div = 1;
    } else if (bytes < 1024*1024) {
        conv_unit = "KiB";
        conv_div = 1024;
    } else if (bytes < 1024*1024*1024) {
        conv_unit = "MiB";
        conv_div = 1024*1024;
    } else {
        conv_unit = "GiB";
        conv_div = 1024*1024*1024;
    }

    str = (char *)calloc(32, 1); /* 32 chars should be enough !!! */
    snprintf(str, 32, "%0.3f %s", (double)(bytes / (double)conv_div), conv_unit);
    return str;
}

uint64_t
mlvpn_millis()
{
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0)
    {
        _ERROR("Error in gettimeofday: %s\n", strerror(errno));
        return 1;
    }
    return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}