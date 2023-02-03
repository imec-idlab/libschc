/*
 * (c) 2018 - 2022  - idlab - UGent - imec
 *
 * Bart Moons
 *
 * This file is part of the SCHC stack implementation
 *
 */

#include "schc.h"
#include "bit_operations.h"
#include "rules/rule_config.h"

/**
 * Get a device by it's id
 *
 * @param device_id 	the id of the device
 *
 * @return schc_device 	the device which is found
 *         NULL			if no device was found
 *
 */
struct schc_device* get_device_by_id(uint32_t device_id) {
	int i = 0;

	for (i = 0; i < DEVICE_COUNT; i++) {
		if (devices[i]->device_id == device_id) {
			return (struct schc_device*) devices[i];
		}
	}

	return NULL;
}

/**
 * Revise the rules for all devices
 * Uncompressed rule ids should not be used for other rules
 *
 * @return 0 			the rules are not setup correctly
 *         1			the rules are setup correctly
 *
 */
uint8_t rm_revise_rule_context(void) {
	/* compare uncompressed rule ids and rule entries for possible duplicates */
	for (int i = 0; i < DEVICE_COUNT; i++) {
		for (int j = 0; j < devices[i]->compression_rule_count; j++) {
			const struct schc_compression_rule_t *curr_rule =
					(*devices[i]->compression_context)[j];
			if (devices[i]->uncomp_rule_id == curr_rule->rule_id) {
				DEBUG_PRINTF("rm_revise_rule_context(): rule=%p uses device with id=%02" PRIu32 " uncompressed rule id=%d\n", (void*) curr_rule, devices[i]->device_id, devices[i]->uncomp_rule_id);
				return 0;
			}
		}
	}

	return 1;
}

/**
 * Copy the uint32_t rule id to a uint8_t buffer
 *
 * @param rule_id 	the rule id
 * @param out		the buffer to copy the rule id to
 * @param len		the length in bits
 *
 */
void uint32_rule_id_to_uint8_buf(uint32_t rule_id, uint8_t* out, uint8_t len) {
	uint8_t rule_arr[4] = { 0 };
	uint8_t pos = get_position_in_first_byte(len);
	clear_bits(out, 0, len); // clear bits before setting
	little_end_uint8_from_uint32(rule_arr, rule_id); /* copy the uint32_t to a uint8_t array */

	copy_bits(out, 0, rule_arr, pos, len); /* set the rule id */
}
