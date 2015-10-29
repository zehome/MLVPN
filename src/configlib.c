/*
 * Copyright (c) 2015, Laurent COUSTET <ed@zehome.com>
 *
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "tool.h"
#include "configlib.h"
#include "mlvpn.h"
#include "log.h"

#define MAXLINE 1024

config_t *
_conf_parseConfig(int config_fd)
{
    int size, i = 0;
    int bufsize = 256;
    unsigned int linenum = 0;
    char c;
    char *buf;
    char *newline;
    char *tmp;
    char *section = NULL;
    FILE *configFile;

    config_t *config;
    confObj_t *confObj;

    configFile = fdopen(config_fd, "r");
    if (! configFile)
    {
        log_warn("config", "cannot open file %d",
            config_fd);
        return NULL;
    }
    config = (config_t *)calloc(1, sizeof(config_t));
    if (! config)
        fatal("config", "calloc");
    config->next    = NULL;
    config->section = NULL;
    config->conf    = NULL;

    buf = (char *)calloc(1, bufsize);
    if (! buf)
        fatal("config", "calloc");

    while (! feof(configFile))
    {
        size = fread(&c, 1, 1, configFile);
        if (size <= 0)
        {
            if (feof(configFile))
                break;
            else
            {
                log_warn("config", "read error");
                if (section != NULL)
                    free(section);
                free(config);
                free(buf);
                fclose(configFile);
                return NULL;
            }
        }

        if (bufsize < i + 64)
        {
            bufsize += 64;
            buf = realloc(buf, bufsize);
        }

        switch (c)
        {
        case '\r':
            break; /* Do nothing */
        case '\n':
            linenum++;
            buf[i] = 0;
            newline = _conf_strip_comment(buf, i);

            if (newline)
            {
                if ( (tmp = _conf_get_section(newline, i, linenum)) != NULL)
                {
                    if (section != NULL)
                        free(section);

                    section = tmp;
                } else if ( (confObj = _conf_parseLine(newline,
                                                       strlen(newline), linenum)) != NULL)
                {
                    if (section == NULL)
                    {
                        log_warnx("config",
                            "error near line %d: variables should "
                            "always been defined in a section", linenum);
                    } else if (_conf_setValue(config, confObj, section) == NULL) {
                        /* Error there, cleanup memory */
                        if (confObj->var)
                            free(confObj->var);
                        if (confObj->val)
                            free(confObj->val);
                        free(confObj);
                    }
                }
                free(newline);
            }

            i = 0;
            break;
        default:
            buf[i++] = c;
        }
    }

    if (section)
        free(section);
    free(buf);
    /* Do not close for fseeking */
    fclose(configFile);
    return config;
}

/*
 * This function will strip comments
 */
char *
_conf_strip_comment(char *line, unsigned int size)
{
    unsigned int i, j = 0;
    short quote = 0;
    char c;
    char *new;

    new = calloc(1, size + 1);
    if (! new)
        fatal("config", "new");
    for (i = 0; i < size; i++)
    {
        c = line[i];

        switch (c)
        {
        case '\"':
            quote ^= 1; /* Nice :) */
            new[j++] = '\"';
            break;

        case '#':
            if (quote == 1)
            {
                new[j++] = c; /* Avoid counting "http://" */
                break;
            }
            else
            {
                /* There is a comment there, remove it :) */
                goto exit;
            }

            break;

        default:
            new[j++] = c;
            break;
        }
    }

exit:
    /* Make sure the char* is ended. */
    if (j == 0)
    {
        free(new);
        return NULL;
    } else {
        new[j] = '\0';
        return new;
    }
}

/*
 * Returns section name if line is a section.
 * Otherwise, returns NULL.
 */
char *
_conf_get_section(char *line, unsigned int linelen, unsigned int linenum)
{
    unsigned int i, j;
    char *section = NULL;
    char *errorMsg = NULL;
    int found_terminator = 0;

    for (i = 0, j = 0; i < linelen && !found_terminator; i++)
    {
        switch(line[i])
        {
        case '[':
            if (section)
            {
                errorMsg = "parse error near line %d: '[' followed by another '['";
                goto error;
            }
            section = (char *)calloc(1, linelen + 1 - i);
            if (! section)
                fatal("config", "calloc");
            break;
        case ']':
            if (! section)
            {
                errorMsg = "parse error near line %d: ']' found, without '['";
                goto error;
            }
            found_terminator = 1;
            section[j] = 0;
            break;
        default:
            if (section)
                section[j++] = line[i];
            break;
        }
    }

    if (section && ! found_terminator)
    {
        errorMsg = "parse error near line %d: ending ']' not found";
        goto error;
    }

    return section;
error:
    if (section)
        free(section);
    if (errorMsg)
        log_warnx("config", errorMsg, linenum);
    return NULL;
}

/*
 * Parse the line and returns a confObj_t object,
 * or NULL if parse error.
 */
confObj_t *
_conf_parseLine(char *line, unsigned int linelen, unsigned int linenum)
{
    unsigned int i, j, k;
    int len;
    int quote, space;
    char *buf;
    char c;
    void *ptr;
    confObj_t *confObj;

    if ((line == NULL) || (*line == '\0'))
        return NULL;

    confObj = (confObj_t *)calloc(1, sizeof(confObj_t));
    if (! confObj)
        fatal("config", "calloc");
    confObj->var = NULL;
    confObj->val = NULL;

    buf = calloc(1, linelen + 1);
    if (! buf)
        fatal("config", "calloc");

    /* First step: getting variable */
    for (i = 0, quote = 0, space = 0, j = 0; i < linelen; i++)
    {
        c = line[i];

        switch (c)
        {
        case '\"':
            quote ^= 1;
            break;

        case '=':
            if (quote) {
                buf[j++] = c;
                continue;
            }
            if (j == 0)
            {
                log_warnx("config",
                    "parse error near line %d: line should not start with '='",
                    linenum);
                free(confObj);
                free(buf);
                return NULL;
            }

            if (confObj->var != NULL)
            {
                log_warnx("config",
                    "parse error near line %d: two '=' are not permitted",
                    linenum);
                free(confObj->var);
                free(confObj);
                free(buf);
                return NULL;
            }

            buf[j] = 0;
            len = j;
            j = 0;

            /* Strip ending spaces */
            for (k = len-1; (k > 0) && (buf[k] == ' '); k--);
            buf[k+1] = 0;

            confObj->var = strdup(buf);
            break;

        default:
            if ((c == ' ') && (space == 0))
                space = 1;
            else if (c != ' ')
                space = 0;

            if ((space == 1) && (quote == 0))
                break; /* Discards */
            if ((space == 1) && (j == 0))
                break; /* Discards */

            if (! isascii(c))
            {
                log_warnx("config",
                    "parse error near line %d: "
                    "variable/value must be ASCII",
                    linenum);
                free(buf);
                if (confObj->var)
                    free(confObj->var);
                free(confObj);
                return NULL;
            }
            buf[j++] = c;
        }
    }

    if ((j == 0) || (confObj->var == NULL))
    {
        /* _ERROR("Parse error near line %d: Variable not found.\n", linenum); */
        free(confObj);
        free(buf);
        return NULL;
    }

    buf[j] = 0;
    len = j;

    /* Ugly strip */
    for (k = len-1; (k > 0) && (buf[k] == ' '); k--);
    buf[k+1] = 0;
    len = k;

    /* Backup */
    ptr = buf;

    for (k = 0; (k < len) && (buf[k] == ' '); k++) buf++;

    if (! *buf)
    {
        log_warnx("config",
            "parse error near line %d: no value",
            linenum);
        free(ptr);
        free(confObj->var);
        free(confObj);
        return NULL;
    }

    confObj->val = strdup(buf);

    /* Some cleanup */
    free(ptr);

    return confObj;
}

/* Private stuff */
config_t *
_conf_setValue(config_t *start,
               confObj_t *confObj,
               const char *section)
{
    config_t *work;
    config_t *last;

    if (start == NULL)
    {
        log_warnx("config",
            "unable to set value: no sections");
        return NULL;
    }

    if (section == NULL)
    {
        log_warnx("config",
            "unable to set value: no sections");
        return NULL;
    }

    if (start->conf == NULL)
    {
        start->conf     = confObj;
        start->section  = strdup(section);
        start->next     = NULL; /* Useless, but safe :) */
    } else {
        work = (config_t *)calloc(1, sizeof(config_t));
        if (! work)
            fatal("config", "calloc");
        work->next    = NULL;
        work->section = strdup(section);
        work->conf    = confObj;
        last = start;
        while (last->next != NULL)
            last = last->next;

        last->next    = work;
    }

    return start;
}

/* Public stuff :) */
void
conf_setValue( config_t **start,
               const char *var,
               const char *val,
               const char *section )
{
    confObj_t *obj;

    if ((var == NULL) || (val == NULL))
    {
        log_warnx("config", "cannot set value: no variable or no value");
        return;
    }

    if ((*start) == NULL)
    {
        (*start) = (config_t *)calloc(1, sizeof(config_t));
        if (! *start)
            fatal("config", "calloc");
        (*start)->next      = NULL;
        (*start)->section   = NULL;
        (*start)->conf      = NULL;
    }

    obj = (confObj_t *)calloc(1, sizeof(confObj_t));
    if (! obj)
        fatal("config", "calloc");
    obj->var = strdup(var);
    obj->val = strdup(val);

    (*start) = _conf_setValue( *start, obj, section );
    if (*start == NULL) {
        free(obj->var);
        free(obj->val);
        free(obj);
    }
}

/*
 * This function will walk thru config_t *start
 * and affect dest to the value of var in config file.
 */
config_t *
_conf_getValue(config_t *start,
               const char *section,
               const char *var,
               char **dest )
{
    while (start != NULL)
    {
        if ((start->conf == NULL) ||
                (start->conf->var == NULL) ||
                (! mystr_eq(start->section, section)))
            goto next;

        if (mystr_eq(start->conf->var, var) == 1)
        {
            *dest = strdup(start->conf->val);
            return start->next;
        }
next:
        start = start->next;
    }

    *dest = NULL;
    return NULL;
}

void
_conf_printConfig(config_t *start)
{
    config_t *tmp = start;
    while (tmp != NULL)
    {
        if (tmp->conf)
            printf("section: %s, var: `%s' val: `%s'\n",
                   tmp->section, tmp->conf->var, tmp->conf->val);
        tmp = tmp->next;
    }
}

void
_conf_freeConfig(config_t *start)
{
    config_t *old;

    while (start != NULL)
    {
        if (start->conf != NULL)
        {
            if (start->conf->var != NULL)
                free(start->conf->var);
            if (start->conf->val != NULL)
                free(start->conf->val);

            free(start->conf);
        }

        if (start->section != NULL)
            free(start->section);

        old = start;
        start = start->next;
        free(old);
    }
}

void
_conf_set_str_from_conf(config_t *config,
                        const char *section,
                        const char *type,
                        char **value,
                        const char *def,
                        const char *errMsg,
                        int exit_n)
{
    _conf_getValue(config, section, type, value);

    if (*value == NULL)
    {
        if (exit_n > 0)
            fatalx(errMsg);
        if (errMsg)
            log_warnx("config", "%s", errMsg);
        if (def != NULL)
            *value = strdup(def);
    }
}

void
_conf_set_uint_from_conf(config_t *config, const char *section,
    const char *type, uint32_t *value, uint32_t def, const char *errMsg,
    int exit_n)
{
    char *tmp;
    _conf_getValue(config, section, type, &tmp);

    if ( tmp == NULL )
    {
        if (exit_n > 0)
            fatalx(errMsg);
        if (errMsg)
            log_warnx("config", "%s", errMsg);
        *value = def;
    } else {
        *value = atoi(tmp);
        free(tmp);
    }
}

void
_conf_set_bool_from_conf(config_t *config,
                         const char *section,
                         const char *type,
                         int *value,
                         int def,
                         const char *errMsg,
                         int exit_n)
{
    char *tmp;
    _conf_getValue(config, section, type, &tmp);

    if ( tmp == NULL )
    {
        if (exit_n > 0)
            fatalx(errMsg);
        if (errMsg)
            log_warnx("config", "%s", errMsg);
        *value = def;
    } else {
        *value = atoi(tmp);
        if ( (*value) != 1)
            *value = 0;
        free(tmp);
    }
}
