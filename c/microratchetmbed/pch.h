#pragma once

#include <internal.h>
#include <memory.h>
#include <stdlib.h>

int mr_mbedtls_entropy_f_source(void *data, unsigned char *output, size_t len, size_t *olen);

