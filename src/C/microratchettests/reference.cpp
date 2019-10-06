#include "pch.h"
#include <microratchet.h>
#include "support.h"

mr_rng_ctx mr_rng_create_custom(mr_ctx mr_ctx, uint8_t* random_data, uint32_t random_data_length, uint32_t random_data_index);