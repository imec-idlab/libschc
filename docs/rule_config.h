/*
 * (c) 2018 - idlab - UGent - imec
 *
 * Bart Moons
 *
 * This file is part of the SCHC stack implementation
 *
 * Adjust this file to taste to include rules
 *
 */

// #include "rules.h"
#include "rules_pfw.h"
/*

#include "rules_interop.h"
#include "rules_lwm2m.h"

const struct schc_rule_t schc_rule_1 = { { 0x08 }, &compression_rule_1, NOT_FRAGMENTED, 0, 0, 0, 0 };
const struct schc_rule_t schc_rule_2 = { { 0x09 }, &compression_rule_1, NO_ACK, 1, 0, 0, 0 };
const struct schc_rule_t schc_rule_3 = { { 0x0A }, &compression_rule_1, ACK_ON_ERROR, 3, 6, 1, 0 };
const struct schc_rule_t schc_rule_4 = { { 0x0B }, &compression_rule_1, ACK_ALWAYS, 3, 6, 1, 0 };

const struct schc_rule_t schc_rule_5 = { 0x01, &registration_rule, NOT_FRAGMENTED, 0, 0, 0, 0 };
const struct schc_rule_t schc_rule_6 = { 0x02, &registration_rule, NO_ACK, 1, 0, 0, 0 };
const struct schc_rule_t schc_rule_7 = { 0x03, &registration_rule, ACK_ON_ERROR, 3, 6, 1, 0 };
const struct schc_rule_t schc_rule_8 = { 0x04, &registration_rule, ACK_ALWAYS, 3, 6, 1, 0 };

const struct schc_rule_t schc_rule_9 = { 0x05, &get_rule, NOT_FRAGMENTED, 0, 0, 0, 0 };
const struct schc_rule_t schc_rule_10 = { 0x06, &get_rule, NO_ACK, 1, 0, 0, 0 };
const struct schc_rule_t schc_rule_11 = { 0x07, &get_rule, ACK_ON_ERROR, 3, 6, 1, 0 };
const struct schc_rule_t schc_rule_12 = { 0x0C, &get_rule, ACK_ALWAYS, 3, 6, 1, 0 };

const struct schc_rule_t schc_rule_13 	= { 0x0D, &catch_all_rule, NOT_FRAGMENTED, 0, 0, 0, 0 };
const struct schc_rule_t schc_rule_14 	= { 0x0E, &catch_all_rule, NO_ACK, 1, 0, 0, 0 };
const struct schc_rule_t schc_rule_15 	= { 0x0F, &catch_all_rule, ACK_ON_ERROR, 3, 6, 1, 0 };
const struct schc_rule_t schc_rule_16 	= { 0x10, &catch_all_rule, ACK_ALWAYS, 3, 6, 1, 0 };

const struct schc_rule_t schc_rule_17 	= { 0x11, &not_found_404, NOT_FRAGMENTED, 0, 0, 0, 0 };
const struct schc_rule_t schc_rule_18 	= { 0x12, &not_found_404, NO_ACK, 1, 0, 0, 0 };
const struct schc_rule_t schc_rule_19 	= { 0x13, &not_found_404, ACK_ON_ERROR, 3, 6, 1, 0 };
const struct schc_rule_t schc_rule_20 	= { 0x14, &not_found_404, ACK_ALWAYS, 3, 6, 1, 0 };

const struct schc_rule_t schc_rule_21   = { 0x15, &update_registration_up, NOT_FRAGMENTED, 0, 0, 0, 0 };
const struct schc_rule_t schc_rule_22   = { 0x16, &update_registration_down, NOT_FRAGMENTED, 1, 0, 0, 0 };

const struct schc_rule_t* node1_schc_rules[] = {
				&schc_rule_1, &schc_rule_2, &schc_rule_3, &schc_rule_4,
				&schc_rule_5, &schc_rule_6, &schc_rule_7,
                &schc_rule_8, &schc_rule_9, &schc_rule_10, &schc_rule_11, &schc_rule_12,
                &schc_rule_13, &schc_rule_14, &schc_rule_15, &schc_rule_16,
                &schc_rule_17, &schc_rule_18, &schc_rule_19, &schc_rule_20,
				&schc_rule_21, &schc_rule_22 };

// todo #define
const uint8_t UNCOMPRESSED_ID[RULE_SIZE_BYTES] = { 0x00 }; // the rule id for an uncompressed packet
// todo
// const uint8_t UNCOMPRESSED_NO_ACK_ID[RULE_SIZE_BYTES] = { 0 };
// const uint8_t UNCOMPRESSED_ACK_ON_ERR[RULE_SIZE_BYTES] = { 0 };
// const uint8_t UNCOMPRESSED_ACK_ALWAYS[RULE_SIZE_BYTES] = { 0 };

const struct schc_device node1 = { 1, 22, &node1_schc_rules };

#define DEVICE_COUNT			1

const struct schc_device* devices[DEVICE_COUNT] = { &node1 }; */
