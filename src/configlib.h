/********************************************************
 * cPige2, under GNU/GPL v2. See LICENCE for details
 *
 * http://ed.zehome.com/?page=cpige-en
 *
 * (c) 2007 Laurent Coustet
 ********************************************************/

#ifndef _CONFIGLIB_H_
#define _CONFIGLIB_H_

typedef struct
{
    char *var;
    char *val;
} confObj_t;

/* Base of the chained list */
typedef struct config_t
{
    confObj_t       *conf;
    char            *section;
    struct config_t *next;
} config_t;

config_t *
_conf_parseConfig(int config_file_fd);

char *
_conf_strip_comment(char *line, unsigned int size);

char *
_conf_get_section(char *line, unsigned int linelen, unsigned int linenum);

confObj_t *
_conf_parseLine(char *line, unsigned int linelen, unsigned int linenum);

config_t *
_conf_setValue(config_t *start, confObj_t *confObj, const char *section);

void
conf_setValue(config_t **start,
              const char *var,
              const char *val,
              const char *section);

config_t *
_conf_getValue(config_t *start,
               const char *section,
               const char *var,
               char **dest);

void
_conf_printConfig(config_t *start);

void
_conf_freeConfig(config_t *start);

void
_conf_set_str_from_conf(config_t *config,
                        const char *section, const char *type,
                        char **value, const char *def,
                        const char *errMsg, int exit_n);

void
_conf_set_uint_from_conf(config_t *config, const char *section,
                        const char *type, uint32_t *value,
                        uint32_t def, const char *errMsg, int exit_n);

void
_conf_set_bool_from_conf(config_t *config, const char *section,
                         const char *type, int *value,
                         int def, const char *errMsg, int exit_n);

#endif
