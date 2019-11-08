/* (c) 2018 - idlab - UGent - imec
 *
 * Bart Moons
 *
 * This file is part of the SCHC stack implementation
 *
 */

#ifndef __SCHCCOMPRESSOR_H__
#define __SCHCCOMPRESSOR_H__

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

int8_t set_rule_id(struct schc_rule_t* schc_rule, uint8_t* data);

uint8_t schc_compressor_init(uint8_t src[16]);
int16_t schc_compress(const uint8_t *data, uint8_t* buf, uint16_t total_length,
		uint32_t device_id, direction dir, device_type device,
		struct schc_rule_t **schc_rule);

struct schc_rule_t* get_schc_rule_by_reliability_mode(
		struct schc_rule_t* schc_rule, reliability_mode mode,
		uint32_t device_id);

uint16_t schc_decompress(const unsigned char* data, unsigned char *buf,
		uint32_t device_id, uint16_t total_length, direction dir,
		device_type device);

#ifdef __cplusplus
}
#endif

#endif
