/********************************************************
 * cPige2, under GNU/GPL v2. See LICENCE for details
 *
 * http://ed.zehome.com/?page=cpige-en
 *
 * (c) 2007 Laurent Coustet
 ********************************************************/

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "debug.h"
#include "tool.h"
#include "mlvpn.h"

static int current_level;
static FILE *output_file = NULL;

/* Main debug routine */
void 
__DEBUG(int _debug_line, const char *_debug_filename, 
        int _debug_priority,  const char *_debug_message, ...)
{
    char z_format[1024] = {0};
    va_list ap;
    time_t now;
    struct tm curTime;
    FILE *output;

    if (output_file)
        output = output_file;
    else
        output = stdout;


    /* message de priorit�e inf�rieure a notre prio, on vire */
    if (_debug_priority >= current_level)
        return;

    now = time((time_t *)NULL);
    if (now == (time_t)-1)
    {
        fprintf(stderr, "Can't log line: time() failed.\n");
        perror("time");
        return;
    }
  
    if (localtime_r(&now, &curTime) == NULL)
    {
        fprintf(stderr, "Can't log line: localtime_r() failed.\n");
        return;
    }
    snprintf(z_format, 1023, "[%.2d:%.2d:%.2d][%s:%d] %s", 
            curTime.tm_hour, curTime.tm_min, curTime.tm_sec, 
            _debug_filename, _debug_line, _debug_message);
  
    va_start(ap, _debug_message);  
    vfprintf(output, z_format, ap);
    
    fflush(output);
  
    va_end(ap);
}

int logger_init(logfile_t *logfile)
{
    current_level = logfile->level;

    /* No filename: defaults stderr */
    if (! logfile->filename)
    {
        logfile->fd = stderr;
        return 0;
    }

    if (logfile->fd == NULL)
    {
        /* Not opened */
        output_file = logfile->fd = priv_open_log(logfile->filename);
        if (! logfile->fd)
        {
            fprintf(stderr, "Unable to open logfile %s for writing. Check permissions!\n", 
                        logfile->filename);
            return -1;
        }
    }
    return 0;
}
