#pragma once

#include <stdlib.h>
#include <string.h>

#ifdef DEBUG
#include <stdio.h>
#define FAILIF(condition, error, messageonfailure) if (condition) { printf("%s:%d error: %s\n", __FILE__, __LINE__, messageonfailure); return (error); }
#else
#define FAILIF(condition, error, messageonfailure) if (condition) { return (error); }
#endif