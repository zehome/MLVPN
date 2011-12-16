#ifndef __MLVPN_TOOL
#define __MLVPN_TOOL

int mystr_eq(const char *s1, const char *s2);
void stripBadChar(const char *from, char *to);
char *myprintf(const char *format, ...);
char *tool_get_bytes(unsigned long long bytes);

#endif
