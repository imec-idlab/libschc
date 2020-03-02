/* (c) 2018 - idlab - UGent - imec
 *
 * Bart Moons
 *
 * This file is part of the SCHC stack implementation
 *
 */

#ifndef __SCHCCOMPRESSOR_H__
#define __SCHCCOMPRESSOR_H__

#include "bit_operations.h"
#include "schc.h"

#ifdef __cplusplus
extern "C" {
#endif

int8_t set_rule_id(struct schc_rule_t* schc_rule, uint8_t* data);

uint8_t schc_compressor_init(uint8_t src[16]);
int16_t schc_compress(uint8_t *data, uint16_t total_length,
		schc_bitarray_t* buf, uint32_t device_id, direction dir,
		struct schc_rule_t **schc_rule);

struct schc_rule_t* get_schc_rule_by_reliability_mode(
		struct schc_rule_t* schc_rule, reliability_mode mode,
		uint32_t device_id);

struct schc_rule_t* get_schc_rule_by_rule_id(uint8_t* rule_id,
		uint32_t device_id);

uint16_t schc_decompress(schc_bitarray_t* bit_arr, uint8_t *buf,
		uint32_t device_id, uint16_t total_length, direction dir);

#ifdef __cplusplus
}
#endif

#endif
