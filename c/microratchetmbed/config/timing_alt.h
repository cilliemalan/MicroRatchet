#pragma once


#include <stdint.h>

struct mbedtls_timing_hr_time
{
    uint32_t ticks;
};

typedef struct mbedtls_timing_delay_context
{
    struct mbedtls_timing_hr_time   timer;
    uint32_t                        int_ms;
    uint32_t                        fin_ms;
} mbedtls_timing_delay_context;