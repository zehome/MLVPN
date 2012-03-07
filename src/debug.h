/********************************************************
 * (c) 2012 Laurent Coustet
 * <ed chez zehome.com>
 ********************************************************/

#ifndef _H_DEBUG
#define _H_DEBUG

#include <stdio.h>
#include <stdarg.h>

enum {
    LOG_LEVEL_FATAL,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG
};

/* Logfile structure */
typedef struct logfile_s
{
    FILE *fd;
    char *filename;
    char *name;
    int level;
} logfile_t;

#define DEBUGLEVEL LOG_LEVEL_DEBUG

#define DEBUG(priority, ...) __DEBUG(__LINE__, __FILE__, priority, __VA_ARGS__)

#define _FATAL(...)   DEBUG(LOG_LEVEL_FATAL,  __VA_ARGS__)
#define _ERROR(...)   DEBUG(LOG_LEVEL_ERROR,  __VA_ARGS__)
#define _WARNING(...) DEBUG(LOG_LEVEL_WARN,   __VA_ARGS__)
#define _INFO(...)    DEBUG(LOG_LEVEL_INFO,   __VA_ARGS__)
#define _DEBUG(...)   DEBUG(LOG_LEVEL_DEBUG,  __VA_ARGS__)

void __DEBUG(int _debug_line, const char *_debug_filename, 
             int _debug_priority, const char *_debug_message, ...);

int logger_init(logfile_t *logfile);

#endif
