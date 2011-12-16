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
#include <pthread.h>


#include "debug.h"
#include "tool.h"
#include "time.h"
#ifdef HAVE_CPIGE_THREAD
 #include "cpige2.h"
 #include "thread.h"
#endif

/* Main debug routine */
void 
__DEBUG(int _debug_line, const char *_debug_filename, 
            int _debug_priority,  const char *_debug_message, ...)
{
    char *z_format;
    va_list ap;
    time_t now;
    struct tm *curTime = NULL;
    FILE *output = NULL;
    int level;
#ifdef HAVE_CPIGE_THREAD
    char *threadName;
    cpige_thread_t *currentThread;

    /* Resolve the right threadName */
    currentThread = thread_get_current();
    if (! currentThread)
    {
        threadName = "main";
        output     = stderr;
        level      = DEBUGLEVEL; /* Main debug level */
    } else {
        threadName = currentThread->log->name;
        if (currentThread->log->fd != NULL)
            output = currentThread->log->fd;
        else
            output = stderr;
        level = currentThread->log->level;
 
        pthread_mutex_lock(&(currentThread->log->mutex));
    }
#else
    output = stdout;
    level  = DEBUGLEVEL;
#endif

    /* message de prioritée inférieure a notre prio, on vire */
    if (_debug_priority > level)
        goto exit;

    now = time(NULL);
    if (now == (time_t)-1)
    {
        fprintf(stderr, "Can't log line: time() failed.\n");
        perror("time");
        goto exit;
    }
  
#ifndef WIN32
    curTime = (struct tm *) malloc(sizeof(struct tm));
    localtime_r(&now, curTime); /* Get the current time */
#else
    curTime = localtime(&now);
#endif
    if (curTime == NULL)
    {
        fprintf(stderr, "Can't log line: localtime(_r)() failed.\n");
        goto exit;
    }
    z_format = calloc(1024, 1);
    snprintf(z_format, 1023, "[%.2d:%.2d:%.2d][%s:%d] %s", 
            curTime->tm_hour, curTime->tm_min, curTime->tm_sec, 
            _debug_filename, _debug_line, _debug_message);
  
    va_start(ap, _debug_message);  
    vfprintf(output, z_format, ap);
    
    fflush(output);
  
#ifndef WIN32
    (void)free(curTime);
#endif
    (void)free(z_format);
    va_end(ap);

exit:
#ifdef HAVE_CPIGE_THREAD
    if (currentThread != NULL)
        pthread_mutex_unlock(&(currentThread->log->mutex));
#endif
    return;
}

int logger_init(logfile_t *logfile)
{
    /* No filename: defaults stderr */
    if (! logfile->filename)
    {
        logfile->fd = stderr;
        return 0;
    }

    if (logfile->fd == NULL)
    {
        /* Not opened */
        logfile->fd = fopen(logfile->filename, "w+");
        if (! logfile->fd)
        {
            fprintf(stderr, "Unable to open logfile %s for writing. Check permissions!\n", 
                        logfile->filename);
            return -1;
        }
    }
    return 0;
}
