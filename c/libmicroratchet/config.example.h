#pragma once

// Prints debug messages. message will be null terminated, but amt is specified
// for applications that can make use of that. amt does not include the null terminator.
// MR_WRITE will be called in conjuction with MR_TRACE, MR_TRACE_DATA, or MR_DEBUG
#include <stdlib.h>
#define MR_WRITE(msg, amt) printf("%s", msg);

// set 1 to enable printing of debug messages (maybe INSECURE). This will print out
// messages if a failure status code is returned. Enable this if you are building and
// debugging 
#if defined(DEBUG) || defined(_DEBUG)
#define MR_DEBUG 1
#else
#define MR_DEBUG 0
#endif

// set 1 to enable trace messages (INSECURE). Trace messages print out
// specific information regarding the flow of the algorithms. You should not
// enable this unless you are debugging mr internals.
#define MR_TRACE 0

// set 1 to enable data trace messages (INSECURE). Data trace messages print out
// cryptographic key information for debugging purposes. You should not
// enable this unless you are debugging mr internals.
#define MR_TRACE_DATA 0

// define to an assert function enable assertions.
#include <assert.h>
#define MR_ASSERT(condition) assert(condition)

// called when an unrecoverable error occurs.
#include <stdlib.h>
#define MR_ABORT() abort()


