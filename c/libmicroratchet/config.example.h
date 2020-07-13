#pragma once

// Prints debug messages. message will be null terminated, but amt is specified
// for applications that can make use of that. amt does not include the null terminator.
// MR_WRITE will be called in conjuction with MR_TRACE or MR_DEBUG
#include <stdlib.h>
#define MR_WRITE(msg, amt) printf("%s\n", msg);

// define to enable trace messages (INSECURE). Trace messages print out
// cryptographic key information for debugging purposes. You should not
// enable this unless you are debugging crypto internals.
// #define MR_TRACE

// define to enable printing of debug messages (maybe INSECURE). This will print out
// messages if a failure status code is returned.
// #define MR_DEBUG

// define to an assert function enable assertions. 
#include <assert.h>
#define MR_ASSERT(condition) assert(condition)

// called when an unrecoverable error occurs.
#define MR_ABORT() abort()