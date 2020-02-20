/*
 * (c) 2018 - idlab - UGent - imec
 *
 * Bart Moons
 *
 * This file is part of the SCHC stack implementation
 *
 */

#include <string.h>
#include <stdio.h>

#include "jsmn.h"
#include "picocoap.h"
#include "rules.h"

#include "compressor.h"
#include "schc_config.h"

#if CLICK
#include <click/config.h>
#endif

// changes on server/client
static direction DI;
static device_type DEVICE_TYPE;
static schc_ipaddr_t node_ip_6;

jsmn_parser json_parser;
jsmntok_t json_token[JSON_TOKENS];

// buffers to store headers so we can compare rules and headers

// todo remove

unsigned char coap_header_fields[COAP_FIELDS][MAX_FIELD_LENGTH];

////////////////////////////////////////////////////////////////////////////////////
//                                LOCAL FUNCIONS                                  //
////////////////////////////////////////////////////////////////////////////////////

/**
 * Get the node its IP address as set during initialization
 *
 * @return node_ip_6 the node its IP address
 *
 */
static void get_node_ip(schc_ipaddr_t *node_ip) {
	memcpy(node_ip, node_ip_6, sizeof(schc_ipaddr_t));
}

/**
 * Get a device by it's id
 *
 * @param device_id 	the id of the device
 *
 * @return schc_device 	the device which is found
 *         NULL			if no device was found
 *
 */
static struct schc_device* get_device_by_id(uint32_t device_id) {
	int i = 0;

	for (i = 0; i < DEVICE_COUNT; i++) {
		if (devices[i]->device_id == device_id) {
			return (struct schc_device*) devices[i];
		}
	}

	return NULL;
}

/*
 * Set the rule id of the compressed packet
 *
 * @param 	schc_rule 		the schc rule to use
 * @param 	data			the compressed packet buffer
 *
 * @return 	err				error codes
 * 			1				SUCCESS
 *
 */
int8_t set_rule_id(struct schc_rule_t* schc_rule, uint8_t* data) {
	// copy uncompressed rule id in front of the buffer
	memcpy((uint8_t*) data, &schc_rule->id, RULE_SIZE_BYTES);

	return 1;
}

/*
 * Find a replacement rule with the correct reliability mode
 *
 * @param 	schc_rule 		the schc rule to find a replacement rule for
 * @param 	mode			the mode for which a rule should be found
 * @param 	device_id		the device to find a rule for
 *
 * @return 	schc_rule		the rule that was found
 * 			NULL			if no rule was found
 *
 */
struct schc_rule_t* get_schc_rule_by_reliability_mode(
		struct schc_rule_t* schc_rule, reliability_mode mode,
		uint32_t device_id) {
	struct schc_device *device = get_device_by_id(device_id);

	if (device == NULL) {
		DEBUG_PRINTF(
				"get_schc_rule(): no device was found for the id: %d\n", device_id);
		return NULL;
	}

	int i;
	for (i = 0; i < device->rule_count; i++) {
		const struct schc_rule_t* curr_rule = (*device->context)[i];
		if ((schc_rule->compression_rule == curr_rule->compression_rule)
				&& (curr_rule->mode == mode)) {
			return (struct schc_rule_t*) (curr_rule);
		}
	}

	return NULL;
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
static struct schc_rule_t* get_schc_rule_by_layer_ids(uint8_t ip_rule_id,
		uint8_t udp_rule_id, uint8_t coap_rule_id, uint32_t device_id,
		reliability_mode mode) {
	int i;
	struct schc_device *device = get_device_by_id(device_id);

	if (device == NULL) {
		DEBUG_PRINTF(
				"get_schc_rule(): no device was found for this id");
		return NULL;
	}

	for (i = 0; i < device->rule_count; i++) {
		const struct schc_rule_t* curr_rule = (*device->context)[i];

#if USE_IPv6
		if (curr_rule->compression_rule->ipv6_rule->rule_id == ip_rule_id) {
#if USE_UDP
			if (curr_rule->compression_rule->udp_rule->rule_id == udp_rule_id) {
#if USE_COAP
				if (curr_rule->compression_rule->coap_rule->rule_id == coap_rule_id) {
					if (curr_rule->mode == mode) {
						return curr_rule;
					}
				}
#else
				if (curr_rule->mode == mode) {
					return (struct schc_rule_t*) (curr_rule);
				}
#endif
			}
#endif
		}
#endif
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
struct schc_rule_t* get_schc_rule_by_rule_id(uint8_t* rule_arr, uint32_t device_id) {
	int i;
	struct schc_device *device = get_device_by_id(device_id);

	if (device == NULL) {
		DEBUG_PRINTF("get_schc_rule(): no device was found for this id");
		return NULL;
	}

	for (i = 0; i < device->rule_count; i++) {
		struct schc_rule_t* curr_rule = (struct schc_rule_t*) (*device->context)[i];
		if( compare_bits_BIG_END(curr_rule->id, rule_arr, RULE_SIZE_BITS)) {
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
		const struct schc_layer_rule_t *rule) {
	uint8_t i = 0;
	uint8_t j = 0;
	uint8_t field_length;
	uint8_t json_result;

	for (i = 0; i < rule->length; i++) {
		// exclude fields in other direction
		if (((rule->content[i].dir) == BI) || ((rule->content[i].dir) == DI)) {
			field_length = rule->content[i].field_length;

			switch (rule->content[i].action) {
			case NOTSENT: { // do nothing
			}
				break;
			case VALUESENT: {
				uint8_t src_pos = get_position_in_first_byte((field_length + src->offset));
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

				// if result is 0,
				if (json_result == 0) { // formatted as a normal unsigned char array
					uint32_t list_len = get_required_number_of_bits(rule->content[i].MO_param_length);
					for (j = 0; j < rule->content[i].MO_param_length; j++) {
						uint8_t src_pos = get_number_of_bytes_from_bits(src->offset);

						uint8_t ptr = j;
						if (! (field_length % 8) ) // only support byte aligned matchmap
							ptr = j * get_number_of_bytes_from_bits(field_length);

						if (compare_bits_BIG_END( (uint8_t*) (src->ptr + src_pos),
								(uint8_t*) (rule->content[i].target_value + ptr), field_length)) {
							uint8_t ind[1] = { j }; // room for 255 indices
							uint8_t src_pos = get_position_in_first_byte(list_len);
							copy_bits(dst->ptr, dst->offset, ind, src_pos, list_len);
							dst->offset += list_len;
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
static uint8_t decompress(struct schc_layer_rule_t* rule, schc_bitarray_t* src, schc_bitarray_t* dst) {
	uint8_t i = 0; uint8_t j;
	uint8_t field_length; int8_t json_result = -1;

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
					uint32_t list_len = get_required_number_of_bits(rule->content[i].MO_param_length);
					uint8_t src_pos = get_position_in_first_byte(list_len);

					uint8_t index[1] = { 0 };
					copy_bits((uint8_t*) (index), src_pos, src->ptr, src->offset, list_len); // copy the index from the received header
					if( ! (field_length % 8) ) // multiply with byte alligned field length
						index[0] = index[0] * get_number_of_bytes_from_bits(field_length);


					copy_bits(dst->ptr, dst->offset, (uint8_t*) (rule->content[i].target_value + index[0]), 0, field_length);
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
				// set to 0, to indicate that it will be calculated after decompression
				uint8_t len[2] = { 0 };
				copy_bits(dst->ptr, dst->offset, len, 0, field_length);
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

#if USE_IPv6
/**
 * Find a matching rule for the IP header
 *
 * @param ip_udp_header the IP/UDP header struct
 * @param device_id		the device to find an IP rule for
 *
 * @return the rule
 *         NULL if no rule is found
 */
static struct schc_ipv6_rule_t* schc_find_ipv6_rule_from_header(
		schc_bitarray_t* src, uint32_t device_id) {
	uint8_t i = 0;
	// set to 0 when a rule doesn't match
	uint8_t rule_is_found = 1;

	struct schc_device *device = get_device_by_id(device_id);
	if (device == NULL) {
		DEBUG_PRINTF(
				"schc_find_ipv6_rule_from_header(): no device was found for this id");
		return 0;
	}

	for (i = 0; i < device->rule_count; i++) { // process device context
		const struct schc_ipv6_rule_t* curr_rule = (*device->context)[i]->compression_rule->ipv6_rule;

		uint8_t j = 0; uint8_t k = 0;

		do { // process one rule
			if( (curr_rule->content[k].dir == BI) || (curr_rule->content[k].dir == DI)) { // exclude fields in other direction
				uint8_t src_pos = get_number_of_bytes_from_bits(src->offset);
				if (!curr_rule->content[k].MO(&curr_rule->content[k],
						(uint8_t*) (src->ptr + src_pos))) { // compare header field and rule field using the matching operator
					rule_is_found = 0;
					break; // break from while loop
				} else {
					rule_is_found = 1;
				}
				j++; src->offset += curr_rule->content[k].field_length;
			}
			k++;
		} while (j < curr_rule->length);

		if (rule_is_found) {
			return (struct schc_ipv6_rule_t*) (curr_rule);
		}
	}

	return NULL;
}

#endif

#if USE_UDP
/**
 * Find a matching rule for the UDP header
 *
 * @param data 				pointer to the application generated data
 * @param device_id			the device to find a UDP rule for
 *
 * @return rule id 			the rule id
 *         0 				if no rule is found
 */
static struct schc_udp_rule_t* schc_find_udp_rule_from_header(schc_bitarray_t* src, uint32_t device_id) {
	uint8_t i = 0;
	// set to 0 when a rule doesn't match
	uint8_t rule_is_found = 1;

	struct schc_device *device = get_device_by_id(device_id);
	if (device == NULL) {
		DEBUG_PRINTF(
				"schc_find_udp_rule_from_header(): no device was found for this id");
		return 0;
	}

	for (i = 0; i < device->rule_count; i++) {
		const struct schc_udp_rule_t* curr_rule = (*device->context)[i]->compression_rule->udp_rule;

		uint8_t j = 0; uint8_t k = 0;

		while (j < curr_rule->length) {
			// exclude fields in other direction
			if ((curr_rule->content[k].dir == BI) || (curr_rule->content[k].dir == DI)) {
				uint8_t src_pos = get_number_of_bytes_from_bits(src->offset);
				if (!curr_rule->content[k].MO(&curr_rule->content[k],
						(uint8_t*) (src->ptr + src_pos))) { // compare header field and rule field using the matching operator
					rule_is_found = 0;
					break;
				} else {
					rule_is_found = 1;
				}
				j++; src->offset += curr_rule->content[k].field_length;
			}
			k++;
		}

		if (rule_is_found) {
			return (struct schc_udp_rule_t*) (curr_rule);
		}
	}

	return NULL;
}

#endif

#if USE_COAP
/**
 * Generates an unsigned char array, based on the CoAP header provided
 *
 * @param header_fields the array to transfer the header to
 * @param cols the number of columns the header contains
 * @param pdu the CoAP message to construct the header from
 *
 * @return the length of the array, which represents the number of CoAP fields
 *
 */
static uint8_t generate_coap_header_fields(pcoap_pdu *pdu) {
	uint8_t i = 0;
	// the 5 first fields are always present (!= bytes)
	uint8_t field_length = 5;

	coap_header_fields[0][0] = pcoap_get_version(pdu);
	coap_header_fields[1][0] = pcoap_get_type(pdu);
	coap_header_fields[2][0] = pcoap_get_tkl(pdu);
	coap_header_fields[3][0] = pcoap_get_code(pdu);

	unsigned char msg_id[2] = { (pcoap_get_mid(pdu) & 0xFF00) >> 8, pcoap_get_mid(
			pdu) & 0x00FF };
	memcpy(&coap_header_fields[4], msg_id, 2);

	if (pcoap_get_tkl(pdu) > 0) {
		uint8_t token[8];
		pcoap_get_token(pdu, token);

		memcpy(&coap_header_fields[5], &token, pcoap_get_tkl(pdu));

		field_length++;
	}

	uint8_t coap_length = pdu->len;

	pcoap_option option;
	// get first option
	option = pcoap_get_option(pdu, NULL);

	while (option.num > 0) {
		for (i = 0; i < option.len; ++i) {
			coap_header_fields[field_length][i] = *(option.val + i);
		}

		// get next option
		option = pcoap_get_option(pdu, &option);
		field_length++;
	}

	pcoap_payload pl = pcoap_get_payload(pdu);
	if (pl.len > 0) {
		// add payload marker
		coap_header_fields[field_length][0] = 0xFF;
		field_length++;
	}

	return field_length; // the number of CoAP header fields (not bytes)
}

/**
 * Find a matching rule for the CoAP header for a device id
 *
 * @param pdu 					the CoAP buffer
 * @param device_id				the device to find a rule for
 *
 * @return id 					the CoAP rule id
 *         0 					if no rule was found
 */
static struct schc_coap_rule_t* schc_find_coap_rule_from_header(schc_bitarray_t* src, uint32_t device_id) {
	uint16_t i = 0;
	// set to 0 when a rule doesn't match
	uint8_t rule_is_found = 1;
	uint8_t direction_field_length = 0;

	/*if(pcoap_validate_pkt(pdu) != CE_NONE) {
		DEBUG_PRINTF("schc_find_coap_rule_from_header(): invalid CoAP packet");
		return 0;
	}*/

	// generate a char array, matchable to the rule
	// uint8_t coap_field_length = generate_coap_header_fields(pdu);

	// get device rules
	struct schc_device *device = get_device_by_id(device_id);
	if(device == NULL) {
		DEBUG_PRINTF("schc_find_coap_rule_from_header(): no device was found for this id");
		return 0;
	}

	int j; int k;

	for (i = 0; i < device->rule_count; i++) {
		const struct schc_udp_rule_t* curr_rule =
				(*device->context)[i]->compression_rule->udp_rule;

		uint8_t j = 0;
		uint8_t k = 0;

		while (j < curr_rule->length) {
			// exclude fields in other direction
			if ((curr_rule->content[k].dir == BI) || (curr_rule->content[k].dir == DI)) {

				uint8_t value[MAX_HEADER_FIELD_LENGTH] = { 0 };
				copy_bits(value, 0, src->ptr, src->offset, curr_rule->content[k].field_length);

				// encode CoAP options before comparing
				// but how do we compress them?

				uint8_t src_pos = get_number_of_bytes_from_bits(src->offset);

				if (!curr_rule->content[k].MO(&curr_rule->content[k],
						(uint8_t*) (src->ptr + src_pos))) { // compare header field and rule field using the matching operator
					rule_is_found = 0;
					break;
				} else {
					rule_is_found = 1;
				}
				j++;
				src->offset += curr_rule->content[k].field_length;
			}
			k++;
		}

		if (rule_is_found) {
			return (struct schc_udp_rule_t*) (curr_rule);
		}
	}

	return NULL;
		/*
		(DI == DOWN) ? (direction_field_length = curr_rule->down) : (direction_field_length = curr_rule->up);

		// save compare cycles by checking the number of the specified direction fields
		if (coap_field_length == direction_field_length) {
			j = 0; k = 0;
			while (k < curr_rule->length) {
				// exclude fields in other direction
				if( (curr_rule->content[k].dir == BI) || (curr_rule->content[k].dir == DI)) {
					uint8_t value[MAX_HEADER_FIELD_LENGTH] = { 0 };
					copy_bits(value, );
					// compare header field and rule field using the matching operator
					if (!curr_rule->content[k].MO(&curr_rule->content[k], (uint8_t*) value)) {
						rule_is_found = 0;
						break;
					} else {
						rule_is_found = 1;
					}
					j++;
				}
				k++;
			}

			if (rule_is_found) {
				return (struct schc_coap_rule_t*) (curr_rule);
			}
		} */
}

/**
 * Decompress a CoAP rule, based on an input packet
 *
 * @param rule 			the CoAP rule to use for decompression
 * @param src			the received SCHC bit buffer
 * @param dst			the buffer to store the decompressed, original packet
 * @param msg 			pointer to the CoAP message to use during the reconstruction
 *
 */
static uint8_t decompress_coap_rule(struct schc_coap_rule_t* rule,
		schc_bitarray_t* src, schc_bitarray_t* dst, pcoap_pdu *msg) {
	 // ToDo
	// directly alter the packet buffer
	// or the coap_header buffer to save RAM


	// buffer to store decompressed values
	unsigned char coap_header[MAX_COAP_HEADER_LENGTH];

	// first number of bytes is always 4
	uint8_t byte_length = 4;

	if (rule != NULL) {

		// the problem with the CoAP header is that we have to encode the options
		// the options are encoded using type-length-value

		// two options

		// 1
		// first encode the option found in a rule
		// compress the encoded option, uncompress on the other side
		// transfer the uncompressed data to the header

		// 2
		// grab the raw value from the rule
		// compress the raw value, uncompress the raw value on the other side
		// encode the uncompressed raw value in the header
		// .. this is what we used to do in the past

		// what happens when we send a coap packet
		// first encode the options
		// send the packet to the compressor
		// decode the options in order to read what is inside them
		//

		// the tlv value can not be used in the rule;
		// for match-map: different values, based on the previous type
		// for rule management: too difficult


		uint8_t coap_length = decompress((struct schc_layer_rule_t*) coap_header, src, dst);

		pcoap_init_pdu(msg);
		pcoap_set_version(msg, coap_header[0]);
		pcoap_set_type(msg, coap_header[1]);
		pcoap_set_code(msg, coap_header[3]);

		uint16_t msg_id = ((coap_header[4] << 8) | coap_header[5]);
		pcoap_set_mid(msg, msg_id);

		uint8_t tkl = coap_header[2];
		if(tkl != 0){
			pcoap_set_token(msg, (uint8_t*) (coap_header + 6), tkl);
			byte_length += tkl;
		}

		// now the options
		uint8_t i;
		// keep track of the coap_header index
		uint8_t field_length = (6 + tkl);


		for(i = 0; i < rule->length; i++) {
			if( ( (rule->content[i].dir) == BI) || ( (rule->content[i].dir) == DI)) {
				uint8_t j;
				// check which options are included in the rule
				for(j = 0; j < COAP_OPTIONS_LENGTH; j++) {
					if( !strcmp(rule->content[i].field, coap_options[j].name) ) {
						// for each matching value, create a new option in the message
						pcoap_add_option(msg, coap_options[j].id, (uint8_t*) (coap_header + field_length), rule->content[i].field_length);
						field_length += rule->content[i].field_length;
					}
				}
			}
		}

		// last index is the payload marker
		if(coap_header[coap_length - 1] == 0xFF) {
			msg->buf[msg->len]= 0xFF;
			msg->len = msg->len + 1;
		}
	} else {
		DEBUG_PRINTF("decompress_coap_rule(): no CoAP rule was found");
		return 0;
	}

	return 1;
}
#endif

/**
 * The equal matching operator
 *
 * @param target_field the field from the rule
 * @param field_value the value from the header to compare with the rule value
 *
 * @return 1 if the target field matches the field value
 *         0 if the target field doesn't match the field value
 *
 */
static uint8_t equal(struct schc_field* target_field,
		unsigned char* field_value) {
	uint8_t bit_pos = get_position_in_first_byte(target_field->field_length);
	return compare_bits_aligned((uint8_t*) (target_field->target_value), bit_pos,
			(uint8_t*) (field_value), 0, target_field->field_length);
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
static uint8_t ignore(struct schc_field* target_field, unsigned char* field_value){
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
static uint8_t MSB(struct schc_field* target_field, unsigned char* field_value){
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
static uint8_t matchmap(struct schc_field* target_field, unsigned char* field_value){
	uint8_t i;

	// reset the parser
	jsmn_init(&json_parser);

	uint8_t result; uint8_t match_counter = 0;
	result = 0;// jsmn_parse(&json_parser, target_field->target_value,
			// strlen(target_field->target_value), json_token, sizeof(json_token) / sizeof(json_token[0]));

	// if result is 0,
	if (result == 0) {
		uint16_t list_len = get_required_number_of_bits(
				target_field->MO_param_length);
		for (i = 0; i < target_field->MO_param_length; i++) {
			uint8_t ptr = i;
			if (! (target_field->field_length % 8) ) // only support byte aligned matchmap
				ptr = i * get_number_of_bytes_from_bits(target_field->field_length);

			if (compare_bits_BIG_END(field_value,
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

/**
 * Notifies the compressor about the node its IP address
 *
 * @param node_ip pointer to the ip address array
 *
 * @return 0
 *
 */
static void set_node_ip(schc_ipaddr_t *node_ip) {
	memcpy(node_ip_6, node_ip, sizeof(schc_ipaddr_t));
}

////////////////////////////////////////////////////////////////////////////////////
//                               GLOBAL FUNCIONS                                  //
////////////////////////////////////////////////////////////////////////////////////


/**
 * Initializes the SCHC compressor
 *
 * @param node_ip 		a pointer to the source it's ip address
 *
 * @return error 		error codes on error
 *
 */
uint8_t schc_compressor_init(uint8_t src[16]) {
	jsmn_init(&json_parser);
	set_node_ip(src);

	return 1;
}

/**
 * Compresses a CoAP/UDP/IP packet
 *
 * @param 	data 			pointer to the original packet
 * @param 	total_length 	the length of the packet
 * @param 	dst				pointer to the bit array object, where the compressed packet will reside
 * @param 	device_id		the device id to find a rule for
 * @param 	direction		the direction of the flow (UP: LPWAN to IPv6, DOWN: IPv6 to LPWAN)
 * @param	device_type		the device type: NETWORK_GATEWAY or DEVICE
 * @param	schc_rule		a pointer to a schc rule struct to return the rule that was found
 *
 * @return 	length			the length of the compressed packet
 *         	-1 				on a memory overflow
 *
 * @note 	the compressor will only look for rules configured with the
 * 			NOT_FRAGMENTED reliability mode
 */

int16_t schc_compress(uint8_t *data, uint16_t total_length,
		schc_bitarray_t* dst, uint32_t device_id, direction dir,
		device_type device_type, struct schc_rule_t **schc_rule) {
	DI = dir;
	DEVICE_TYPE = device_type;

	uint16_t coap_length = 0; uint8_t coap_rule_id = 0; uint8_t udp_rule_id = 0; uint8_t ipv6_rule_id = 0;
#if USE_COAP
	struct schc_coap_rule_t *coap_rule;
#endif
#if USE_UDP
	struct schc_udp_rule_t *udp_rule;
#endif
#if USE_IPv6
	struct schc_ipv6_rule_t *ipv6_rule;
#endif

	/*
	 * **** look for a matching rule ****
	 * */
	dst->offset = RULE_SIZE_BITS;
	memset(dst->ptr, 0, total_length);
	schc_bitarray_t src; src.ptr = data; src.offset = 0; // use bit array for comparison

#if USE_IPv6
	ipv6_rule = schc_find_ipv6_rule_from_header(&src, device_id); // todo merge
	if(ipv6_rule != NULL) {
		ipv6_rule_id = ipv6_rule->rule_id;
		DEBUG_PRINTF("schc_compress(): IPv6 rule id %d \n", ipv6_rule->rule_id);
	} else {
		DEBUG_PRINTF("schc_compress(): no IPv6 rule was found \n");
	}
	src.offset = 320; // todo should update in find method
#endif
#if USE_UDP
	udp_rule = schc_find_udp_rule_from_header(&src, device_id);
	if(udp_rule != NULL) {
		udp_rule_id = udp_rule->rule_id;
		DEBUG_PRINTF("schc_compress(): UDP rule id %d \n", udp_rule->rule_id);
	} else {
		DEBUG_PRINTF("schc_compress(): no UDP rule was found \n");
	}
#endif
#if USE_COAP
	// construct CoAP message from buffer
	uint8_t coap_buf[MAX_COAP_MSG_SIZE] = { 0 };
	memcpy(coap_buf, (uint8_t*) (data + IP6_HLEN + UDP_HLEN), (total_length - IP6_HLEN - UDP_HLEN)); // copy CoAP header
	pcoap_pdu coap_msg = { coap_buf, (total_length - IP6_HLEN - UDP_HLEN), MAX_COAP_MSG_SIZE };

	// check the buffer for determining the CoAP header length
	coap_length = pcoap_get_coap_offset(&coap_msg);

	// retrieve the first matching CoAP rule
	coap_rule = schc_find_coap_rule_from_header(&coap_msg, device_id);
	if(coap_rule != NULL) {
		coap_rule_id = coap_rule->rule_id;
		DEBUG_PRINTF("schc_compress(): CoAP rule id %d \n", coap_rule->rule_id);
	} else {
		DEBUG_PRINTF("schc_compress(): no CoAP rule was found \n");
	}
#endif

	src.offset = 0; // reset the bit array offset and start compressing

	// find the rule for this device by combining the available id's // todo pointers?
	uint8_t data_offset = 0;
	(*schc_rule) = get_schc_rule_by_layer_ids(ipv6_rule_id,
			udp_rule_id, coap_rule_id, device_id, NOT_FRAGMENTED);

	if((*schc_rule) == NULL) {
		/*
		 * **** no rule was found ****
		 * set the uncompressed rule id
		 * and copy the original header
		 * */
		copy_bits(dst->ptr, 0, UNCOMPRESSED_ID, 0, RULE_SIZE_BITS); // uncompressed rule id in front of buffer
		DEBUG_PRINTF("schc_compress(): no rule was found \n");
#if USE_IPv6
		copy_bits(dst->ptr, dst->offset, data, 0, BYTES_TO_BITS(IP6_HLEN));
		dst->offset += BYTES_TO_BITS(IP6_HLEN); data_offset += IP6_HLEN;
#endif
#if USE_UDP
		copy_bits(dst->ptr, dst->offset, data, BYTES_TO_BITS(data_offset), BYTES_TO_BITS(UDP_HLEN));
		dst->offset += BYTES_TO_BITS(UDP_HLEN);
		data_offset += UDP_HLEN;
#endif
#if USE_COAP
		copy_bits(dst->ptr, dst->offset, coap_buf, 0, BYTES_TO_BITS(coap_length));
		dst->offset += BYTES_TO_BITS(coap_length);
		data_offset += coap_length;
#endif
	} else {
		/*
		 * **** a rule was found - compress ****
		 * compress the headers according to the rule
		 * copy the contents to the bit array
		 * to keep track of the offset
		 * */
		copy_bits(dst->ptr, 0, (*schc_rule)->id, 0, RULE_SIZE_BITS); // matching rule id in front of buffer
#if USE_IPv6
		compress(dst, &src, (const struct schc_layer_rule_t*) ipv6_rule);
#endif
#if USE_UDP
		compress(dst, &src, (const struct schc_layer_rule_t*) udp_rule);
#endif
#if USE_COAP
		generate_coap_header_fields(&coap_msg); // generate a char array, which can easily be compared to the rule
		// compress(bit_array, coap_header_fields, MAX_COAP_FIELD_LENGTH, (const struct schc_layer_rule_t*) coap_rule);
#endif
	}

	uint16_t payload_len = (total_length - IP6_HLEN - UDP_HLEN - coap_length); // copy the payload
	const uint8_t* payload_ptr = (data + IP6_HLEN + UDP_HLEN + coap_length);

	copy_bits(dst->ptr, dst->offset, payload_ptr, 0, BYTES_TO_BITS(payload_len));
    uint16_t new_pkt_length = (BITS_TO_BYTES(dst->offset) + payload_len);

	DEBUG_PRINTF("\n");
	DEBUG_PRINTF(
			"schc_compress(): compressed header length: %d, payload length: %d (total length: %d) \n",
			BITS_TO_BYTES(dst->offset), payload_len, new_pkt_length);
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

	DEBUG_PRINTF("\n\n");

	// return the new length of the packet
	return new_pkt_length;
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
#if USE_IPv6
	if(packet_ptr[4] == 0 && packet_ptr[5] == 0) {
		// ip length
		packet_ptr[4] = (((data_len - IP6_HLEN) & 0xFF00) >> 8);
		packet_ptr[5] = ((data_len - IP6_HLEN) & 0xFF);
	}
#endif
#if USE_UDP
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
#if USE_UDP
	if(data[46] == 0 && data[47] == 0) {
		uint16_t upper_layer_len; uint16_t sum; uint16_t result;

		upper_layer_len = (((uint16_t)(data[44]) << 8) + data[45]);

		// protocol (17 for UDP) and length fields. This addition cannot carry.
		uint8_t proto = data[6];
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
#endif

	return 0;
}

/**
 * Construct the header from the layered set of rules
 *
 * @param 	data 				pointer to the received data
 * @param 	buf	 				pointer where to save the decompressed packet
 * @param 	device_id 			the device its id
 * @param 	total_length 		the total length of the received data
 * @param 	direction			the direction of the flow (UP: LPWAN to IPv6, DOWN: IPv6 to LPWAN)
 * @param	device_type			the type of device: NETWORK_GATEWAY or DEVICE
 *
 * @return 	length 				length of the newly constructed packet
 * 			0 					the rule was not found
 */
uint16_t schc_decompress(const uint8_t* data, uint8_t *buf,
		uint32_t device_id, uint16_t total_length, direction dir,
		device_type device_type) {
	DI = dir;
	DEVICE_TYPE = device_type;

	uint8_t coap_rule_id = 0; uint8_t udp_rule_id = 0; uint8_t ipv6_rule_id = 0;
	uint32_t bit_offset = RULE_SIZE_BITS;

	uint8_t rule_id[RULE_SIZE_BYTES] = { 0 };
	copy_bits(rule_id, 0, data, 0, RULE_SIZE_BITS);
	struct schc_rule_t *rule = get_schc_rule_by_rule_id(rule_id, device_id);
	if(rule != NULL) {
#if USE_COAP
		coap_rule_id = rule->compression_rule->coap_rule->rule_id;
#endif
#if USE_UDP
		udp_rule_id = rule->compression_rule->udp_rule->rule_id;
#endif
#if USE_IPv6
		ipv6_rule_id = rule->compression_rule->ipv6_rule->rule_id;
#endif
	}

	DEBUG_PRINTF("\n");
	DEBUG_PRINTF(
			"schc_decompress(): rule id: %d (0x%02X) = | %d | %d | %d | \n",
			rule_id[0], rule_id[0], ipv6_rule_id, udp_rule_id, coap_rule_id);

	uint8_t ret = 0;
	uint8_t coap_offset = 0;

	// CoAP buffers for parsing
	uint8_t msg_recv_buf[MAX_COAP_MSG_SIZE];
	pcoap_pdu pcoap_msg = { msg_recv_buf, 0, MAX_COAP_MSG_SIZE };

	if (compare_bits(rule_id, UNCOMPRESSED_ID, RULE_SIZE_BITS)) { // uncompressed packet
#if USE_IPv6
		// copy the uncompressed IPv6 header from the SCHC packet
		copy_bits(buf, 0, data, RULE_SIZE_BITS, BYTES_TO_BITS(IP6_HLEN));
		bit_offset += BYTES_TO_BITS(IP6_HLEN);
#endif
#if USE_UDP
		// copy the uncompressed UDP headers
		copy_bits(buf, BYTES_TO_BITS(IP6_HLEN), data, bit_offset, BYTES_TO_BITS(UDP_HLEN));
		bit_offset += BYTES_TO_BITS(UDP_HLEN);
#endif
#if USE_COAP
		// copy the uncompressed CoAP headers
		uint16_t coap_len = total_length - IP6_HLEN - UDP_HLEN - get_number_of_bytes_from_bits(RULE_SIZE_BITS);
		copy_bits(buf, BYTES_TO_BITS((IP6_HLEN + UDP_HLEN)), data, bit_offset, BYTES_TO_BITS(coap_len));

		// use CoAP lib to calculate CoAP offset
		pcoap_msg.len = 4;
		memcpy(pcoap_msg.buf, (uint8_t*) (buf + IP6_HLEN + UDP_HLEN), coap_len);
		coap_offset = pcoap_get_coap_offset(&pcoap_msg);

		bit_offset += BYTES_TO_BITS(coap_offset);
#endif
	} else { // compressed packet
		schc_bitarray_t src_arr;
		src_arr.ptr = data;
		src_arr.offset = RULE_SIZE_BITS;

		schc_bitarray_t dst_arr;
		dst_arr.ptr = buf;
		dst_arr.offset = 0;

#if USE_IPv6
		if (ipv6_rule_id != 0) {
			ret = decompress((struct schc_layer_rule_t *) rule->compression_rule->ipv6_rule, &src_arr, &dst_arr);
			if (ret == 0) {
				return 0; // no rule was found
			}
		}
#endif
#if USE_UDP
		if (udp_rule_id != 0) {
			ret = decompress((struct schc_layer_rule_t *) (rule->compression_rule->udp_rule), &src_arr, &dst_arr);
			if (ret == 0) {
				return 0; // no rule was found
			}
		}
#endif
#if USE_COAP
		// grab CoAP rule and decompress
		if (coap_rule_id != 0) {
			ret = decompress_coap_rule(rule->compression_rule->coap_rule, &src_arr, &dst_arr, &pcoap_msg);
			if (ret == 0) {
				return 0; // no rule was found
			}
			coap_offset = pcoap_msg.len;
		}
		memcpy((unsigned char*) (buf + (IP6_HLEN + UDP_HLEN)), pcoap_msg.buf, coap_offset); // grab the CoAP header from the CoAP buffer
#endif
		bit_offset = src_arr.offset; // the source array holds the offset of the SCHC header, and thus its length
	}

	uint8_t new_header_length = IP6_HLEN + UDP_HLEN + coap_offset;
	uint16_t payload_bit_length = BYTES_TO_BITS(total_length) - bit_offset; // the schc header minus the total length is the payload length

	copy_bits(buf, BYTES_TO_BITS(new_header_length), data, bit_offset, payload_bit_length);
	uint16_t payload_length = get_number_of_bytes_from_bits(payload_bit_length);

	compute_length(buf, (payload_length + new_header_length));
	compute_checksum(buf);

	DEBUG_PRINTF("schc_decompress(): header length: %d, payload length (with padding) %d \n", new_header_length, payload_length);

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
ELEMENT_REQUIRES(schcJSON schcCOAP)
#endif
