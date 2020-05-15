#pragma once

#include <internal.h>
#include <stdint.h>

#define USE_FIELD_10X26 1
#define USE_SCALAR_8X32 1
#define USE_NUM_NONE 1
#define USE_FIELD_INV_BUILTIN 1
#define USE_SCALAR_INV_BUILTIN 1
#define ECMULT_WINDOW_SIZE 15
#define ECMULT_GEN_PREC_BITS 4


#ifdef MR_X64
#define USE_ECMULT_STATIC_PRECOMPUTATION 1
#define USE_ENDOMORPHISM 1
#endif

#ifdef MR_ARM
#endif
