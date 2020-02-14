#pragma once

#include <memory.h>

#ifdef __GNUC__
#define WEAK_SYMBOL __attribute__((weak))
#else
#define WEAK_SYMBOL
#endif

#ifdef DEBUG
#include <stdio.h>
#define FAILIF(condition, error, messageonfailure) if (condition) { printf("%s:%d error: %s\n", __FILE__, __LINE__, messageonfailure); return (error); }
#else
#define FAILIF(condition, error, messageonfailure) if (condition) { return (error); }
#endif