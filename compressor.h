/* (c) 2018 - idlab - UGent - imec
 *
 * Bart Moons
 *
 * This file is part of the SCHC stack implementation
 *
 */

#ifndef __SCHC_COMPRESSOR_H__
#define __SCHC_COMPRESSOR_H__

#include "schc.h"

#ifdef __cplusplus
extern "C" {
#endif

uint8_t schc_compressor_init();
struct schc_compression_rule_t* schc_compress(uint8_t *data, uint16_t total_length,
		schc_bitarray_t* buf, uint32_t device_id, direction dir);

uint16_t schc_decompress(schc_bitarray_t* bit_arr, uint8_t *buf,
		uint32_t device_id, uint16_t total_length, direction dir);

#ifdef __cplusplus
}
#endif

#endif
