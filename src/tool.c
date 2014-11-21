#include "includes.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/time.h>

#include "tool.h"

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