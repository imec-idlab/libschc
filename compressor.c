/*
 * (c) 2018 -2022  - idlab - UGent - imec
 *
 * Bart Moons
 *
 * This file is part of the SCHC stack implementation
 *
 */
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "jsmn.h"
#include "picocoap.h"

#include "compressor.h"
#include "bit_operations.h"

#if CLICK
#include <click/config.h>
#endif

jsmn_parser json_parser;
jsmntok_t json_token[JSON_TOKENS];

////////////////////////////////////////////////////////////////////////////////////
//                                LOCAL FUNCIONS                                  //
////////////////////////////////////////////////////////////////////////////////////

/*
 * Set the rule id of the compressed packet
 *
 * @param 	schc_rule 		the schc rule to use
 * @param	device_id		the ID of the device @p data will be sent over
 * @param 	data			the compressed packet buffer
 *
 * @return 	err				error codes
 * 			1				SUCCESS
 *
 */
int8_t set_rule_id(struct schc_compression_rule_t* schc_rule, uint32_t device_id, uint8_t* data) {
	// copy rule id in front of the buffer
	uint8_t pos = get_position_in_first_byte(RULE_SIZE_BITS);
	clear_bits(data, 0, RULE_SIZE_BITS); // clear bits before setting
	uint8_t rule_id[4] = { 0 };

	if(schc_rule != NULL) {
		little_end_uint8_from_uint32(rule_id, schc_rule->rule_id); /* copy the uint32_t to a uint8_t array */
	} else {
		struct schc_device *device = get_device_by_id(device_id);
		if (!device) {
			return 0;
		}
		/* copy the uint32_t to a uint8_t array */
		little_end_uint8_from_uint32(rule_id, device->uncomp_rule_id);
	}

	copy_bits(data, 0, rule_id, pos, RULE_SIZE_BITS); /* set the rule id */

	return 1;
}

/*
 * Combine the different layers to find the SCHC rule entry
 *
 * @param 	ip_rule_id 		the rule id for the IP layer
 * @param 	udp_rule_id		the rule id for the UDP layer
 * @param 	coap_rule_id	the rule id for the CoAP layer
 * @param 	device_id		the device to find a rule for
 * @param 	mode			the mode for which a rule should be found
 *
 * @return 	schc_rule		the rule that was found
 * 			NULL			if no rule was found
 *
 */
static struct schc_compression_rule_t* get_schc_rule_by_layer_ids(struct schc_layer_rule_t *ipv6_rule,
		struct schc_layer_rule_t *udp_rule, struct schc_layer_rule_t *coap_rule, uint32_t device_id) {
	int i;
	struct schc_device *device = get_device_by_id(device_id);

	if (device == NULL) {
		DEBUG_PRINTF(
				"get_schc_rule(): no device was found for id=%02" PRIu32 "\n", device_id);
		return NULL;
	}

	uint8_t rule_mask = 0x00;

	/* the rule selection is independent from the compiler flags.
	 * The decompressor's rules MUST match the one selected at the compressor side. */
	uint8_t layer_mask = (ipv6_rule == NULL) ? 0x00 : 0x04;
	layer_mask |= (udp_rule == NULL) ? 0x00 : 0x02;
	layer_mask |= (coap_rule == NULL) ? 0x00 : 0x01;

	if(layer_mask == 0x00) {
		return NULL; /* all layers are set to NULL, return */
	}

	for (i = 0; i < device->compression_rule_count; i++) {
		const struct schc_compression_rule_t* curr_rule = (*device->compression_context)[i];
#if USE_IP6 == 1
		if (curr_rule->ipv6_rule != NULL &&
				curr_rule->ipv6_rule == (struct schc_ipv6_rule_t*) ipv6_rule) {
			rule_mask |= 0x04;
		}
#endif
#if USE_UDP == 1
		if (curr_rule->udp_rule != NULL &&
				curr_rule->udp_rule == (struct schc_udp_rule_t*) udp_rule) {
			rule_mask |= 0x02;
		}
#endif
#if USE_COAP == 1
		if (curr_rule->coap_rule != NULL &&
				curr_rule->coap_rule == (struct schc_coap_rule_t*) coap_rule) {
			rule_mask |= 0x01;
		}
#endif
		if (rule_mask == layer_mask) {
			return (struct schc_compression_rule_t*) (curr_rule);
		}
	}

	return NULL;
}

/*
 * Find a SCHC rule entry for a device
 *
 * @param 	rule_arr 		the rule id in uint8_t array
 * @param 	device_id		the device to find a rule for
 *
 * @return 	schc_rule		the rule that was found
 * 			NULL			if no rule was found
 *
 */
static struct schc_compression_rule_t* get_compression_rule_by_rule_id(uint8_t* rule_arr, struct schc_device *device) {
	int i;

	if (device == NULL) {
		DEBUG_PRINTF("get_schc_rule(): no device was found for this id \n");
		return NULL;
	}

	for (i = 0; i < device->compression_rule_count; i++) {
		struct schc_compression_rule_t* curr_rule = (struct schc_compression_rule_t*) (*device->compression_context)[i];
		uint8_t curr_rule_pos = get_position_in_first_byte(RULE_SIZE_BITS);
		uint8_t rule_id[4] = { 0 };
		little_end_uint8_from_uint32(rule_id, curr_rule->rule_id); /* copy the uint32_t to a uint8_t array */
		if( compare_bits_aligned(rule_id, curr_rule_pos, rule_arr, 0, RULE_SIZE_BITS)) {
			DEBUG_PRINTF("get_compression_rule(): curr rule %p \n", (void*) curr_rule);
			return curr_rule;
		}
	}

	return NULL;
}


/**
 * The compression mechanism
 *
 * @param dst_arr	 			the bit array in which to copy the contents to
 * @param src_arr 				the original header
 * @param rule 					the rule to match the compression with
 *
 * @return the length 			length of the compressed header
 *
 */
static uint8_t compress(schc_bitarray_t* dst, schc_bitarray_t* src,
		const struct schc_layer_rule_t *rule, direction DI) {
	uint8_t i = 0;
	uint8_t j = 0;
	uint8_t field_length;
	uint8_t json_result;

	if(rule == NULL) {
		return 0;
	}

	for (i = 0; i < rule->length; i++) {
		// exclude fields in other direction
		if (((rule->content[i].dir) == BI) || ((rule->content[i].dir) == DI)) {
			field_length = rule->content[i].field_length;

			switch (rule->content[i].action) {
			case NOTSENT: { // do nothing
			}
				break;
			case VALUESENT: {
				copy_bits(dst->ptr, dst->offset, src->ptr, src->offset, field_length);
				dst->offset += field_length;
			}
				break;
			case MAPPINGSENT: {
				json_result = 0;

				/*
				jsmn_init(&json_parser); // reset the parser
				json_result = jsmn_parse(&json_parser, rule->content[i].target_value,
						strlen(rule->content[i].target_value), json_token,
						sizeof(json_token) / sizeof(json_token[0]));
				uint8_t match_counter = 0; */

				/* if the output of the jsmn parser is 0, the array is formatted as a normal unsigned char array */
				if (json_result == 0) { // formatted as a normal unsigned char array
					uint8_t list_len = get_required_number_of_bits(
							(rule->content[i].MO_param_length - 1)); // start from index 0
					for (j = 0; j < rule->content[i].MO_param_length; j++) {
						uint8_t ptr = j;
						if (!(field_length % 8)) // only support byte aligned matchmap
							ptr = j * get_number_of_bytes_from_bits(field_length); // for multiple byte entry

						if(compare_bit_sequence(
								src->ptr, src->offset, (uint8_t*) (rule->content[i].target_value + ptr), 0, field_length)) {
							uint8_t ind[1] = { j }; // room for 255 indices
							uint8_t src_pos = get_position_in_first_byte(list_len);
							copy_bits(dst->ptr, dst->offset, ind, src_pos, list_len);
							dst->offset += list_len;
							break; /* found the mapping index */
						}
					}

				} else {
					// formatted as a JSON object
//					j = 1; // the first token is the string received
//					while (j < json_result) {
//						uint8_t k = 0;
//						match_counter = 0;
//						uint8_t length = (json_token[j].start
//								+ (json_token[j].end - json_token[j].start));
//
//						uint8_t l = 0;
//						for (k = json_token[j].start; k < length; k++) {
//							if (rule->content[i].target_value[k]
//									== *((header + field_counter * cols) + l)) {
//								match_counter++;
//							}
//							l++;
//						}
//
//						if (match_counter
//								== (json_token[j].end - json_token[j].start)) {
//							// the field value is found in the mapping array
//							// send the index
//							schc_header[index] = (j - 1);
//							break;
//						}
//						j++;
//					}
				}
			}
				break;
			case LSB: {
				uint16_t lsb_len = rule->content[i].field_length - rule->content[i].MO_param_length;
				copy_bits(dst->ptr, dst->offset, (uint8_t*) (src->ptr),
						rule->content[i].MO_param_length + src->offset, lsb_len);
				dst->offset += lsb_len;
			}
				break;
			case COMPLENGTH:
			case COMPCHK: {
				// do nothing
			}
				break;
			case DEVIID: {
				// ToDo
			}
				break;
			case APPIID: {
				// ToDo
			}
				break;
			}
			src->offset += field_length;
		}
	}

	return 1;
}


/**
 * The decompression mechanism
 *
 * @param rule 			pointer to the rule to use during the decompression
 * @param src			the received SCHC bit buffer
 * @param dst			the buffer to store the decompressed, original packet
 *
 * @return the length of the decompressed header
 *
 */
static uint8_t decompress(struct schc_layer_rule_t* rule, schc_bitarray_t* src,
		schc_bitarray_t* dst, direction DI) {
	uint8_t i = 0;
	uint8_t field_length; int8_t json_result = -1;

	/* rule for layer can be set to NULL */
	if(rule == NULL)
		return 0;

	for (i = 0; i < rule->length; i++) {
		// exclude fields in other direction
		if (((rule->content[i].dir) == BI) || ((rule->content[i].dir) == DI)) {
			field_length = rule->content[i].field_length;
			switch (rule->content[i].action) {
			case NOTSENT: {
				// use value stored in context
				uint8_t src_pos = get_position_in_first_byte(field_length);
				copy_bits(dst->ptr, dst->offset, rule->content[i].target_value, src_pos, field_length);

			} break;
			case VALUESENT: {
				// build from received value
				copy_bits(dst->ptr, dst->offset, src->ptr, src->offset, field_length);
				src->offset += field_length;
			} break;
			case MAPPINGSENT: {
				// reset the parser
				jsmn_init(&json_parser);

				// parse the json string
				json_result = 0; // todo
						// jsmn_parse(&json_parser, rule->content[i].target_value,
						// strlen(rule->content[i].target_value), json_token, sizeof(json_token) / sizeof(json_token[0]));

				// if result is 0,
				if (json_result == 0) { // formatted as a normal unsigned uint8_t array
					uint32_t list_len = get_required_number_of_bits( (rule->content[i].MO_param_length - 1) ); // start from index 0
					uint8_t src_pos = get_position_in_first_byte(list_len);

					uint8_t map_index[1] = { 0 }; /* variable to store the index */
					copy_bits((uint8_t*) (map_index), src_pos, src->ptr, src->offset, list_len); /* copy the index from the received header */
					if( ! (field_length % 8) ) // multiply with byte alligned field length
						map_index[0] = map_index[0] * get_number_of_bytes_from_bits(field_length);

					uint8_t target_value_offset = (field_length % 8);
					if(target_value_offset)
						target_value_offset = 8 - target_value_offset;

					copy_bits(dst->ptr, dst->offset,
							(uint8_t*) (rule->content[i].target_value + map_index[0]),
							target_value_offset, field_length);
					src->offset += list_len;
				}

//				} else if(json_result > 0) {
//					// JSON object, grab the value(s), starting from the received index
//					mapping_index = mapping_index + 1; // first element in json token is total array, next are individual tokens
//					uint8_t length = (json_token[mapping_index].end - json_token[mapping_index].start);
//
//					uint8_t k = 0;
//					// store rule value in decompressed header
//					for (j = json_token[mapping_index].start; j < json_token[mapping_index].end; j++) {
//						schc_header[index + k] = rule->content[i].target_value[j];
//						k++;
//					}
//
//					field_length = length;
//				}
//
//				*header_offset = *header_offset + 1;

			} break;
			case LSB: {
				uint8_t msb_len = rule->content[i].MO_param_length;
				uint8_t lsb_len = rule->content[i].field_length - msb_len;
				// build partially from rule
				copy_bits(dst->ptr, dst->offset, rule->content[i].target_value, 0, msb_len);

				// .. and from received value
				copy_bits(dst->ptr, dst->offset + msb_len, src->ptr, src->offset, lsb_len);
				src->offset += lsb_len;
			} break;
			case COMPLENGTH:
			case COMPCHK: {
				clear_bits(dst->ptr, dst->offset, field_length); // set to 0, to indicate that it will be calculated after decompression
			} break;
			case DEVIID: {
//				if (!strcmp(rule->content[i].field, "src iid")) {
//
//					schc_ipaddr_t node_ip;
//					get_node_ip(node_ip);
//
//					unsigned char ip_addr[8] = {
//							(node_ip[4] & 0xFF),
//							(node_ip[4] & 0xFF00) >> 8,
//							(node_ip[5] & 0xFF),
//							(node_ip[5] & 0xFF00) >> 8,
//							(node_ip[6] & 0xFF),
//							(node_ip[6] & 0xFF00) >> 8,
//							(node_ip[7] & 0xFF),
//							(node_ip[7] & 0xFF00) >> 8,
//					};
//
//					for (j = 0; j < field_length; j++) {
//						schc_header[index + j] = ip_addr[j];
//					}
//				}
			} break;
			case APPIID: {
				// build iid from L2 server address
			} break;
			}

			dst->offset += field_length;
		}
	}

	return 1;
}

/**
 * Find a matching rule for a layer
 *
 * @param schc_bitarray the bit array as received from the network
 * 						note: a conversion is required for CoAP to decode the options
 *
 * @param device_id		the device to find an IP rule for
 * @param schc_layer	the layer for which to find a rule for
 *
 * @return the rule
 *         NULL if no rule is found
 */
static struct schc_layer_rule_t* schc_find_rule_from_header(
		schc_bitarray_t* src, uint32_t device_id, schc_layer_t layer, direction DI) {
	uint8_t i = 0;
	// set to 0 when a rule doesn't match
	uint8_t rule_is_found = 1; uint8_t max_layer_fields = 0; uint32_t prev_offset = src->offset;

	struct schc_device *device = get_device_by_id(device_id);
	if (device == NULL) {
		DEBUG_PRINTF(
				"schc_find_rule_from_header(): no device was found for this id=%02" PRIu32 "\n", device_id);
		return 0;
	}

	for (i = 0; i < device->compression_rule_count; i++) {
		struct schc_layer_rule_t* curr_rule = NULL;
#if USE_IP6 == 1
		if(layer == SCHC_IPV6) {
			max_layer_fields = IP6_FIELDS;
			curr_rule = (struct schc_layer_rule_t*) (*device->compression_context)[i]->ipv6_rule;
		}
#endif
#if USE_UDP == 1 
		else if(layer == SCHC_UDP) {
			max_layer_fields = UDP_FIELDS;
			curr_rule = (struct schc_layer_rule_t*) (*device->compression_context)[i]->udp_rule;
		}
#endif
#if USE_COAP == 1
		else if (layer == SCHC_COAP) {
			max_layer_fields = COAP_FIELDS;
			curr_rule = (struct schc_layer_rule_t*) (*device->compression_context)[i]->coap_rule;
		}
#endif

		/* rule for layer can be set to NULL */
		if(curr_rule == NULL) {
			DEBUG_PRINTF("schc_find_rule_from_header(): skipped rule %02" PRIu32 ", layer set to NULL \n", (*device->compression_context)[i]->rule_id);
			continue;
		}

		uint8_t j = 0; uint8_t k = 0;
		uint8_t dir_length = (DI == UP) ? curr_rule->up : curr_rule->down;

		while (j < dir_length) {
			// exclude fields in other direction
			if ((curr_rule->content[k].dir == BI) || (curr_rule->content[k].dir == DI)) {
				uint8_t src_pos = 0;
				if(src->offset >= 8)
					src_pos = get_number_of_bytes_from_bits(src->offset);
				if (!curr_rule->content[k].MO(&curr_rule->content[k],
						(uint8_t*) (src->ptr + src_pos), (src->offset % 8))) { // compare header field and rule field using the matching operator
					rule_is_found = 0;
					DEBUG_PRINTF(
							"schc_find_rule_from_header(): skipped rule %02" PRIu32 ", %s does not match\n", (*device->compression_context)[i]->rule_id, schc_header_field_names[curr_rule->content[k].field]);
					src->offset = prev_offset; // reset offset
					break;
				} else {
					rule_is_found = 1;
					src->offset += curr_rule->content[k].field_length;
				}
				j++;
			}
			k++; // increment to skip other directions
			if(k > max_layer_fields) { // todo coap <-> ipv6
				DEBUG_PRINTF("schc_find_rule_from_header(): more fields present than LAYER_FIELDS \n");
				return NULL;
			}
		}

		if (rule_is_found) {
			return (struct schc_layer_rule_t*) (curr_rule);
		}
	}

	return NULL;
}

#if USE_COAP == 1
/**
 * Generates an unsigned char array, based on the CoAP header provided
 *
 * @param header_fields the array to transfer the header to
 * @param dst			the destination array
 *
 * @return the length of the array, which represents the number of CoAP fields
 *
 */
static uint8_t generate_coap_header_fields(pcoap_pdu *pdu, schc_bitarray_t* dst) {
	uint8_t offset = 0;

	if (pcoap_validate_pkt(pdu) != CE_NONE) {
		DEBUG_PRINTF("schc_find_coap_rule_from_header(): invalid CoAP packet\n");
		return 0;
	}

	uint8_t field_length = 5; // the 5 first fields are always present (!= bytes)

	memcpy((uint8_t*) (dst->ptr + offset), pdu->buf, 4);
	offset += 4;

	if (pcoap_get_tkl(pdu) > 0) {
		uint8_t token[8];
		pcoap_get_token(pdu, token);

		memcpy((uint8_t*) (dst->ptr + offset), &token, pcoap_get_tkl(pdu));

		field_length++; offset += pcoap_get_tkl(pdu);
	}

	pcoap_option option;
	option = pcoap_get_option(pdu, NULL); // get first option

	while (option.num > 0) {
		memcpy((uint8_t*) (dst->ptr + offset), option.val, option.len);

		offset += option.len;
		option = pcoap_get_option(pdu, &option); // get next option
		field_length++;
	}

	pcoap_payload pl = pcoap_get_payload(pdu);
	if (pl.len > 0) {
		dst->ptr[offset] = 0xFF; // add payload marker
		field_length++;
	}

	return field_length; // the number of CoAP header fields (not bytes)
}

/**
 * Decompress a CoAP rule, based on an input packet
 *
 * @param rule 			the CoAP rule to use for decompression
 * @param src			the received SCHC bit buffer
 * @param msg 			pointer to the reconstructed CoAP message
 *
 */
static uint8_t decompress_coap_rule(struct schc_coap_rule_t* rule,
		schc_bitarray_t* src, pcoap_pdu *msg, direction DI) {
	uint8_t buf[MAX_COAP_HEADER_LENGTH] = { 0 };

	schc_bitarray_t dst;
	dst.ptr = buf; dst.offset = 0; uint8_t field_length = 0;

	if (rule != NULL) {
		decompress((struct schc_layer_rule_t*) rule, src, &dst, DI);
		pcoap_init_pdu(msg);
		uint8_t version = get_bits(dst.ptr, 0, 2);
		pcoap_set_version(msg, version);
		uint8_t type = get_bits(dst.ptr, 2, 2);
		pcoap_set_type(msg, type);
		pcoap_set_code(msg, dst.ptr[1]);

		uint16_t msg_id = ((dst.ptr[2] << 8) | dst.ptr[3]);
		pcoap_set_mid(msg, msg_id);

		uint8_t tkl = get_bits(dst.ptr, 4, 4);
		if(tkl != 0){
			pcoap_set_token(msg, (uint8_t*) (dst.ptr + 4), tkl);
		}

		uint8_t i;
		// keep track of the coap_header index
		field_length = (4 + tkl);

		for(i = 0; i < rule->length; i++) { // now the options
			if( ( (rule->content[i].dir) == BI) || ( (rule->content[i].dir) == DI)) {
				COAPO_fields option;
				// check which options are included in the rule
				for(option = COAP_IFMATCH; option < COAP_OPTIONS_MAX; option++) { // todo should not take COAP_OPTIONS_MAX iterations
					if( rule->content[i].field == option ) {
						// for each matching value, create a new option in the message
						pcoap_add_option(msg, option,
								(uint8_t*) (dst.ptr + field_length),
 								(rule->content[i].field_length / 8));
						field_length += (rule->content[i].field_length / 8); // increased length matches option length
					}
				}
			}
		}

		if(dst.ptr[field_length] == 0xFF) { // check if a payload marker is present in the decompressed rule
			msg->buf[msg->len] = 0xFF;
			msg->len = msg->len + 1;
		}

	} else {
		DEBUG_PRINTF("decompress_coap_rule(): no CoAP rule was found");
		return 0;
	}

	return msg->len;
}
#endif

/**
 * The equal matching operator
 *
 * @param target_field 	the field from the rule
 * @param field_value 	the value from the header to compare with the rule value
 * @param field_offset	the offset (in bits), starting from the field value pointer
 *
 * @return 1 if the target field matches the field value
 *         0 if the target field doesn't match the field value
 *
 */
uint8_t mo_equal(struct schc_field* target_field, unsigned char* field_value, uint16_t field_offset) {
	uint8_t bit_pos = get_position_in_first_byte(target_field->field_length);

	// todo no copy w/ compare_bit_sequence()
	return compare_bits_aligned((uint8_t*) (target_field->target_value), bit_pos,
			(uint8_t*) (field_value), field_offset, target_field->field_length);
}

/**
 * The ignore matching operator
 *
 * @param target_field the field from the rule
 * @param field_value the value from the header to compare with the rule value
 *
 * @return 1
 *
 */
uint8_t mo_ignore(__attribute__((unused))  struct schc_field *target_field,
		__attribute__((unused)) unsigned char *field_value,
		__attribute__((unused)) uint16_t field_offset) {
	// ignore, always true
	return 1;
}

/**
 * The MSB matching operator
 * MSB(x): 	a match is obtained if the most significant (leftmost) x
 *    		bits of the packet header field value are equal to the TV in the
 *			Rule.  The x parameter of the MSB MO indicates how many bits are
 * 	 	 	involved in the comparison.  If the FL is described as variable,
 *     	  	the x parameter must be a multiple of the FL unit.  For example, x
 *			must be multiple of 8 if the unit of the variable length is bytes.
 *
 * @param target_field the field from the rule
 * @param field_value the value from the header to compare with the rule value
 *
 * @return 1 if the MSB of the target field matches the MSB of the field value
 *         0 if the MSB of the target field doesn't match the MSB of the field value
 *
 */
uint8_t mo_MSB(struct schc_field *target_field, unsigned char *field_value,
		__attribute__((unused)) uint16_t field_offset) {
	if(compare_bits(target_field->target_value, field_value, target_field->MO_param_length)) {
		return 1; // left x bits match the target value
	}

	return 0;
}


/**
 * The match-map matching operator
 * match-mapping: 	With match-mapping, the Target Value is a list of
 * 					values.  Each value of the list is identified by an index.
 *					Compression is achieved by sending the index instead of the
 *					original header field value.
 *
 * @param target_field the field from the rule
 * @param field_value the value from the header to compare with the rule value
 *
 * @return 1 if the the field value is equal to one of the values found in the mapping array
 *         0 if no matching value is found in the mapping array
 *
 */
uint8_t mo_matchmap(struct schc_field *target_field, unsigned char *field_value,
		__attribute__((unused)) uint16_t field_offset) {
	uint8_t i;

	// reset the parser
	jsmn_init(&json_parser);

	uint8_t result;
	result = 0;// jsmn_parse(&json_parser, target_field->target_value,
			// strlen(target_field->target_value), json_token, sizeof(json_token) / sizeof(json_token[0]));

	// if result is 0,
	if (result == 0) {
		for (i = 0; i < target_field->MO_param_length; i++) {
			uint8_t ptr = i;
			if (! (target_field->field_length % 8) ) // only supports byte aligned matchmap
				ptr = i * get_number_of_bytes_from_bits(target_field->field_length);

			if (compare_bits_little_endian(field_value,
					(uint8_t*) (target_field->target_value + ptr),
					target_field->field_length)) {
				return 1;
			}
		}
	} else {
		// formatted as a JSON object

		// todo

//		i = 1; // the first token is the string received
//		while(i < result){
//			uint8_t j; uint8_t k = 0; match_counter = 0;
//			uint8_t length = (json_token[i].start + (json_token[i].end - json_token[i].start));
//
//			for (j = json_token[i].start; j < length; j++) {
//				if(target_field->target_value[j] == field_value[k]) {
//					match_counter++;
//				}
//				k++;
//			}
//
//			if(match_counter == (json_token[i].end - json_token[i].start)) {
//				// the field value is found in the mapping array
//				return 1;
//			}
//			i++;
//		}
	}

	// target value doesn't match with any field value
	return 0;
}

////////////////////////////////////////////////////////////////////////////////////
//                               GLOBAL FUNCIONS                                  //
////////////////////////////////////////////////////////////////////////////////////


/**
 * Initializes the SCHC compressor
 *
 * @return error 		error codes on error
 *
 */
uint8_t schc_compressor_init() {
	jsmn_init(&json_parser);

	return 1;
}

/**
 * Compresses a CoAP/UDP/IP packet
 *
 * @param 	data 			pointer to the original packet
 * @param 	total_length 	the length of the packet
 * @param 	dst				pointer to the bit array object, where the compressed packet will
 * 							be stored. Can later be passed to fragmenter
 * @param 	device_id		the device id to find a rule for
 * @param 	direction		the direction of the flow
 * 							UP: LPWAN to IPv6 or DOWN: IPv6 to LPWAN
 * @param	device_type		the device type: NETWORK_GATEWAY or DEVICE
 * @param	schc_rule		a pointer to a schc rule struct to return the rule that was found
 *
 * @return 	length			the length of the compressed packet
 *         	-1 				on a memory overflow
 *
 * @note 	the compressor will only look for rules configured with the
 * 			NOT_FRAGMENTED reliability mode
 */

struct schc_compression_rule_t* schc_compress(uint8_t *data, uint16_t total_length,
		schc_bitarray_t* dst, uint32_t device_id, direction dir) {
	struct schc_compression_rule_t* schc_rule;
	uint16_t coap_length = 0;

	/* buf must at least packet length + RULE_SIZE_BYTES */
	memset(dst->ptr, 0, total_length + RULE_SIZE_BYTES);
	/* use bit array for comparison */
	schc_bitarray_t src; src.ptr = data; src.offset = 0; uint8_t icmp6_packet = 0; uint8_t use_udp = 1;

	DEBUG_PRINTF("schc_compress(): \n");

	/* look for a matching rule */
	struct schc_layer_rule_t *ipv6_rule; struct schc_layer_rule_t *udp_rule; struct schc_layer_rule_t *coap_rule;
#if USE_IP6 == 1
	ipv6_rule = schc_find_rule_from_header(&src, device_id, SCHC_IPV6, dir);
	if(ipv6_rule != NULL) {
		DEBUG_PRINTF("schc_compress(): IPv6 rule id=%d \n", ipv6_rule->rule_id);
		if(data[6] == 0x3A) { // icmpv6 packet
			icmp6_packet 	= 1;
			use_udp 		= 0;
		}
	}
#endif
#if USE_UDP == 1
		if(use_udp) {
			udp_rule = schc_find_rule_from_header(&src, device_id, SCHC_UDP, dir);
			if(udp_rule != NULL) {
				DEBUG_PRINTF("schc_compress(): UDP rule id=%d \n", udp_rule->rule_id);
			}
		}
#endif
#if USE_COAP == 1
		/* CoAP pdu for CoAP specific actions */
		uint8_t* coap_ptr = (uint8_t*) (data + (IP6_HLEN * USE_IP6) + (UDP_HLEN * USE_UDP));
		pcoap_pdu coap_msg = { coap_ptr, (total_length - (IP6_HLEN * USE_IP6) - (UDP_HLEN * USE_UDP)),
				(total_length - (IP6_HLEN * USE_IP6) - (UDP_HLEN * USE_UDP)) };

		/* check the buffer for determining the CoAP header length */
		coap_length = pcoap_get_coap_offset(&coap_msg);

		/* generate a bit array, matchable to the rule */
		schc_bitarray_t coap_src; uint8_t coap_buffer[MAX_COAP_MSG_SIZE];
		coap_src.ptr = coap_buffer; coap_src.offset = 0;
		generate_coap_header_fields(&coap_msg, &coap_src);

		coap_rule = schc_find_rule_from_header(&coap_src, device_id, SCHC_COAP, dir);
		if(coap_rule != NULL) {
			DEBUG_PRINTF("schc_compress(): CoAP rule id=%d \n", coap_rule->rule_id);
		}
		/* reset the bit arrays offset and start compressing */
		coap_src.offset = 0;
#endif
	/* reset the offset and start compressing */
	src.offset = 0;

	schc_rule = get_schc_rule_by_layer_ids(ipv6_rule, udp_rule, coap_rule,
			device_id);

	if (set_rule_id(schc_rule, device_id, dst->ptr) != 1) {
		return NULL;
	}
	dst->offset = RULE_SIZE_BITS;

	if(schc_rule == NULL) {
		DEBUG_PRINTF("schc_compress(): no rule was found \n");
		/* if no rule was found and the use of a specific layer is set to 0,
		 * we expect that headers from these layers are not present in the original packet
		 */
#if USE_IP6 == 1
		copy_bits(dst->ptr, dst->offset, data, 0, BYTES_TO_BITS(IP6_HLEN));
		dst->offset += BYTES_TO_BITS(IP6_HLEN);
#endif
		if(!icmp6_packet) {
#if USE_UDP == 1
			copy_bits(dst->ptr, dst->offset, data, BYTES_TO_BITS(IP6_HLEN), BYTES_TO_BITS(UDP_HLEN));
			dst->offset += BYTES_TO_BITS(UDP_HLEN);
#endif
#if USE_COAP == 1
			copy_bits(dst->ptr, dst->offset, coap_ptr, 0, BYTES_TO_BITS(coap_length));
			dst->offset += BYTES_TO_BITS(coap_length);
#endif
		}
	}
	else { /* a rule was found - compress */
#if USE_IP6 == 1
		compress(dst, &src, (const struct schc_layer_rule_t*) ipv6_rule, dir);
#endif
		if(!icmp6_packet) {
#if USE_UDP == 1
		compress(dst, &src, (const struct schc_layer_rule_t*) udp_rule, dir);
#endif
#if USE_COAP == 1
		compress(dst, &coap_src, (const struct schc_layer_rule_t*) coap_rule, dir);
#endif
		}
	}

	/* copy the payload */
	uint16_t payload_len = (total_length - (IP6_HLEN * USE_IP6)
			- (UDP_HLEN * use_udp) - coap_length);
	const uint8_t *payload_ptr = (data + (IP6_HLEN * USE_IP6)
			+ (UDP_HLEN * use_udp) + coap_length);

	copy_bits(dst->ptr, dst->offset, payload_ptr, 0, BYTES_TO_BITS(payload_len));
    uint16_t new_pkt_length = (BITS_TO_BYTES(dst->offset) + payload_len);
    /* set the padding of the compressed packet */
    dst->padding = padded(dst);

    /* set the total packet length (w/o padding) */
    dst->bit_len = BYTES_TO_BITS(payload_len) + dst->offset;
    uint16_t total_packet_len_bits = dst->bit_len + dst->padding;

	DEBUG_PRINTF("\n");
	DEBUG_PRINTF(
			"schc_compress(): %d compressed header bits + %d payload bits + %d padding bits = %d bits (%dB)\n",
			(int) dst->offset, BYTES_TO_BITS(payload_len), dst->padding, total_packet_len_bits, BITS_TO_BYTES(total_packet_len_bits));
	DEBUG_PRINTF("+---------------------------------+\n");
	DEBUG_PRINTF("|          SCHC Packet            |\n");
	DEBUG_PRINTF("+---------------------------------+\n");

	int i;
	for(i = 0; i <  new_pkt_length; i++) {
		DEBUG_PRINTF("%02X ", dst->ptr[i]);
		if(!((i + 1) % 12)) {
			DEBUG_PRINTF("\n");
		}
	}

	DEBUG_PRINTF("\n");
	/* set the compressed packet length */
	dst->len = new_pkt_length;

	/* and return the schc rule */
	return schc_rule;
}

/**
 * Set the packet length for the UDP and IP headers
 *
 * @param data 			pointer to the data packet
 * @param data_len 		the length of the total packet
 *
 * @return 0
 *
 */
static uint16_t compute_length(unsigned char *data, uint16_t data_len) {
	// if the length fields are set to 0
	// the length must be calculated
	uint8_t* packet_ptr = (uint8_t*) data;
#if USE_IP6 == 1
	if(packet_ptr[4] == 0 && packet_ptr[5] == 0) {
		// ip length
		packet_ptr[4] = (((data_len - IP6_HLEN) & 0xFF00) >> 8);
		packet_ptr[5] = ((data_len - IP6_HLEN) & 0xFF);
	}
#endif
#if USE_UDP == 1
	if(packet_ptr[44] == 0 && packet_ptr[45] == 0) {
		// udp length
		packet_ptr[44] = (((data_len - IP6_HLEN) & 0xFF00) >> 8);
		packet_ptr[45] = ((data_len - IP6_HLEN) & 0xFF);
	}
#endif

	return 0;
}

static uint16_t chksum(uint16_t sum, const uint8_t *data, uint16_t len) {
	uint16_t t;
	const uint8_t *dataptr;
	const uint8_t *last_byte;

	dataptr = data;
	last_byte = data + len - 1;

	while (dataptr < last_byte) { /* At least two more bytes */
		t = (dataptr[0] << 8) + dataptr[1];
		sum += t;
		if (sum < t) {
			sum++; /* carry */
		}
		dataptr += 2;
	}

	if (dataptr == last_byte) {
		t = (dataptr[0] << 8) + 0;
		sum += t;
		if (sum < t) {
			sum++; // carry
		}
	}

	// return sum in host byte order
	return sum;
}

/**
 * Calculates the UDP checksum and sets the appropriate header fields
 *
 * @param data pointer to the data packet
 *
 * @return checksum the computed checksum
 *
 */
uint16_t compute_checksum(unsigned char *data) {
	// if the checksum fields are set to 0
	// the checksum must be calculated
#if USE_UDP == 1
	if(data[46] == 0 && data[47] == 0) {
		uint16_t upper_layer_len; uint16_t sum; uint16_t result;

		uint8_t proto = data[6];
		if(proto == 0x11) { // protocol (17 for UDP) and length fields. This addition cannot carry.
			upper_layer_len = (((uint16_t)(data[44]) << 8) + data[45]);

			sum = upper_layer_len + proto;

			// sum IP source and destination
			sum = chksum(sum, (uint8_t *)&data[8], 2 * sizeof(schc_ipaddr_t));

			// sum upper layer headers and data
			sum = chksum(sum, &data[IP6_HLEN], upper_layer_len);

			result = (~sum);

			data[46] = (uint8_t) ((result & 0xFF00) >> 8);
			data[47] = (uint8_t) (result & 0xFF);

			return 1;
		}
	}
#endif

	return 0;
}

/**
 * Construct the header from the layered set of rules
 *
 * @param 	bit_arr				pointer to the received data
 * @param 	buf	 				pointer where to save the decompressed packet
 * @param 	device_id 			the device its id
 * @param 	total_length 		the total length of the received data
 * @param 	direction			the direction of the flow (UP: LPWAN to IPv6, DOWN: IPv6 to LPWAN)
 *
 * @return 	length 				length of the newly constructed packet
 * 			0 					the rule or device was not found
 */
uint16_t schc_decompress(schc_bitarray_t* bit_arr, uint8_t *buf,
		uint32_t device_id, uint16_t total_length, direction dir) {
	struct schc_device *device = get_device_by_id(device_id);
	if(device == NULL) {
		DEBUG_PRINTF("schc_decompress(): No device found with id=%d\n", device_id);
		return 0;
	}

	DEBUG_PRINTF("\n");
	DEBUG_PRINTF("schc_decompress(): \n");

	struct schc_compression_rule_t *rule = get_compression_rule_by_rule_id(bit_arr->ptr, device);

	if(rule != NULL) {
#if USE_COAP == 1
		if(rule->coap_rule != NULL) {
			DEBUG_PRINTF("schc_decompress(): CoAP rule id=%d \n", rule->coap_rule->rule_id);
		}
#endif
#if USE_UDP == 1
		if(rule->udp_rule != NULL) {
			DEBUG_PRINTF("schc_decompress(): UDP rule id=%d \n", rule->udp_rule->rule_id);
		}
#endif
#if USE_IP6 == 1
		if(rule->ipv6_rule != NULL) {
			DEBUG_PRINTF("schc_decompress(): IPv6 rule id=%d \n", rule->ipv6_rule->rule_id);
		}
#endif
	} else {
		DEBUG_PRINTF("no rule was found \n");
	}

	uint8_t ret = 0;
	uint8_t coap_offset = 0;

#if USE_COAP == 1
	// CoAP buffer for parsing
	pcoap_pdu pcoap_msg = { (uint8_t*) (buf + (IP6_HLEN * USE_IP6) + (UDP_HLEN * USE_UDP)), 0,
			MAX_COAP_MSG_SIZE };
#endif

	/* indicate initial offset in the source array */
	bit_arr->offset = RULE_SIZE_BITS;

	/* copy rule id */
	uint8_t compressed_id[4] = { 0 };
	little_end_uint8_from_uint32(compressed_id, device->uncomp_rule_id); /* copy the uint32_t to a uint8_t array */

	uint8_t new_header_length = 0;

	if (compare_bits(bit_arr->ptr, compressed_id, RULE_SIZE_BITS)) { /* uncompressed packet, copy uncompressed headers */
#if USE_IP6 == 1
		if(rule->ipv6_rule != NULL) {
			copy_bits(buf, 0, bit_arr->ptr, RULE_SIZE_BITS, BYTES_TO_BITS(IP6_HLEN));
			bit_arr->offset += BYTES_TO_BITS(IP6_HLEN);
			new_header_length += IP6_HLEN;
		}
#endif
#if USE_UDP == 1
		if(rule->udp_rule != NULL) {
			copy_bits(buf, BYTES_TO_BITS((IP6_HLEN * USE_IP6)), bit_arr->ptr, bit_arr->offset, BYTES_TO_BITS(UDP_HLEN));
			bit_arr->offset += BYTES_TO_BITS(UDP_HLEN);
			new_header_length += UDP_HLEN;
		}
#endif
#if USE_COAP == 1
		if(rule->coap_rule != NULL) {
			/* only include IPv6 and UDP when enabled */
			uint16_t len = (RULE_SIZE_BITS + (( (IP6_HLEN * USE_IP6) + (UDP_HLEN * USE_UDP)) * 8));
			uint16_t coap_len = (total_length * 8) - len;
			copy_bits(buf, len, bit_arr->ptr, bit_arr->offset, coap_len);

			pcoap_msg.len = 4;
			memcpy(pcoap_msg.buf, (uint8_t*) (buf + (IP6_HLEN * USE_IP6) + (UDP_HLEN * USE_UDP)), coap_len);
			// coap_offset = pcoap_get_coap_offset(&pcoap_msg); // use CoAP lib to calculate CoAP offset

			coap_offset = BITS_TO_BYTES(coap_len);

			bit_arr->offset += coap_len;
			new_header_length += coap_len;
		}
#endif
	} else { // compressed packet, decompress with residue and rule
		schc_bitarray_t dst_arr;
		dst_arr.ptr = buf;
		dst_arr.offset = 0; /* there is no offset (yet) in the destination array */

#if USE_IP6 == 1
		if (rule->ipv6_rule != NULL != 0) {
			ret = decompress((struct schc_layer_rule_t *) rule->ipv6_rule, bit_arr, &dst_arr, dir);
			if (ret == 0) {
				return 0; // no rule was found
			}
			new_header_length += IP6_HLEN;
		}

#endif
#if USE_UDP == 1
		if (rule->udp_rule != NULL != 0) {
			ret = decompress((struct schc_layer_rule_t *) (rule->udp_rule), bit_arr, &dst_arr, dir);
			if (ret == 0) {
				return 0; // no rule was found
			}
			new_header_length += UDP_HLEN;
		}
#endif
#if USE_COAP == 1
		if (rule->coap_rule != NULL != 0) {
			coap_offset = decompress_coap_rule((struct schc_coap_rule_t *) rule->coap_rule, bit_arr, &pcoap_msg, dir);
			if (coap_offset == 0) {
				return 0; // no rule was found
			}
			new_header_length += coap_offset;
		}
#endif
	}

	/* calculate padding */
	bit_arr->padding = padded(bit_arr);
	uint16_t payload_bit_length = BYTES_TO_BITS(total_length) - bit_arr->offset - bit_arr->padding; // the schc header minus the total length is the payload length

	copy_bits(buf, BYTES_TO_BITS(new_header_length), bit_arr->ptr, bit_arr->offset, payload_bit_length);
	uint16_t payload_length = get_number_of_bytes_from_bits(payload_bit_length);

	/* set UDP and IPv6 length and checksum if the field is set to 0 */
	compute_length(buf, (payload_length + new_header_length));
	compute_checksum(buf);

	DEBUG_PRINTF("schc_decompress(): header length: %d, payload length %d \n", new_header_length, payload_length);

	DEBUG_PRINTF("\n");
	DEBUG_PRINTF("+---------------------------------+\n");
	DEBUG_PRINTF("|        Original Packet          |\n");
	DEBUG_PRINTF("+---------------------------------+\n");

	int i;
	for (i = 0; i < new_header_length + payload_length; i++) {
		DEBUG_PRINTF("%02X ", buf[i]);
		if (!((i + 1) % 12)) {
			DEBUG_PRINTF("\n");
		}
	}

	DEBUG_PRINTF("\n\n");

	return new_header_length + payload_length;
}

#if CLICK
ELEMENT_PROVIDES(schcCOMPRESSOR)
ELEMENT_REQUIRES(schcJSON schcCOAP schcBIT)
#endif
