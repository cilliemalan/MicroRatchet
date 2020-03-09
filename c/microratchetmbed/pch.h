#pragma once

#include <memory.h>

#ifdef __GNUC__
#define WEAK_SYMBOL __attribute__((weak))
#else
#define WEAK_SYMBOL
#endif

#ifdef DEBUG
#include <stdio.h>

#define STRINGIZE(x) STRINGIZE2(x)
#define STRINGIZE2(x) #x
#define LINE_STRING STRINGIZE(__LINE__)

int _write(int file, char *ptr, int len);
#define _MYWRITE(x) _write((int)stdout, x, sizeof(x))

#define FAILIF(condition, error, messageonfailure) if (condition) { _MYWRITE(__FILE__ ":" LINE_STRING " " messageonfailure); return (error); }
#define FAILMSG(error, messageonfailure) _MYWRITE(__FILE__ ":" LINE_STRING " " messageonfailure); return (error);

#else
#define FAILIF(condition, error, messageonfailure) if (condition) { return (error); }
#endif