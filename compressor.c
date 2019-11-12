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
static uip_ipaddr_t node_ip_6;

jsmn_parser json_parser;
jsmntok_t json_token[JSON_TOKENS];

// buffers to store headers so we can compare rules and headers
unsigned char ipv6_header_fields[IPV6_FIELDS][MAX_IPV6_FIELD_LENGTH];
unsigned char udp_header_fields[UDP_FIELDS][MAX_UDP_FIELD_LENGTH];
unsigned char coap_header_fields[COAP_FIELDS][MAX_COAP_FIELD_LENGTH];

////////////////////////////////////////////////////////////////////////////////////
//                                LOCAL FUNCIONS                                  //
////////////////////////////////////////////////////////////////////////////////////

/**
 * Get the node its IP address as set during initialization
 *
 * @return node_ip_6 the node its IP address
 *
 */
static void get_node_ip(uip_ipaddr_t *node_ip) {
	memcpy(node_ip, node_ip_6, sizeof(uip_ipaddr_t));
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
			return devices[i];
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

	DEBUG_PRINTF("set_rule_id(): rule id set to %d \n", schc_rule->id);

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
				"get_schc_rule(): no device was found for this id");
		return NULL;
	}

	int i;
	for (i = 0; i < device->rule_count; i++) {
		const struct schc_rule_t* curr_rule = (*device->context)[i];
		if ((schc_rule->compression_rule == curr_rule->compression_rule)
				&& (curr_rule->mode == mode)) {
			return curr_rule;
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
		if(curr_rule->compression_rule->ipv6_rule->rule_id != ip_rule_id) {
			break;
		}
#endif
#if USE_UDP
		if(curr_rule->compression_rule->udp_rule->rule_id != udp_rule_id ) {
			break;
		}
#endif
#if USE_COAP
		if(curr_rule->compression_rule->coap_rule->rule_id != coap_rule_id) {
			break;
		}
#endif
		if(curr_rule->mode == mode) {
				return curr_rule;
		}
	}

	return NULL;
}

/*
 * Find a SCHC rule entry for a device
 *
 * @param 	rule_id 		the rule id
 * @param 	device_id		the device to find a rule for
 *
 * @return 	schc_rule		the rule that was found
 * 			NULL			if no rule was found
 *
 */
struct schc_rule_t* get_schc_rule_by_rule_id(uint8_t rule_id, uint32_t device_id) {
	int i;
	struct schc_device *device = get_device_by_id(device_id);

	if (device == NULL) {
		DEBUG_PRINTF("get_schc_rule(): no device was found for this id");
		return NULL;
	}

	for (i = 0; i < device->rule_count; i++) {
		const struct schc_rule_t* curr_rule = (*device->context)[i];
		if(curr_rule->id == rule_id) {
			return curr_rule;
		}
	}

	return NULL;
}


/**
 * The compression mechanism
 *
 * @param schc_header 			the header in which to operate
 * @param header 				the original header
 * @param cols 					the number of fields the header contains
 * @param rule 					the rule to match the compression with
 *
 * @return the length 			length of the compressed header
 *
 */
static uint8_t compress(unsigned char *schc_header, unsigned char *header,
		uint16_t cols, const struct schc_layer_rule_t *rule) {
	uint8_t i = 0; uint8_t field_counter = 0;
	uint8_t index = 0; // index in compressed header
	uint8_t field_length; uint8_t j; uint8_t lsb = 0;
	uint8_t json_result;

	for (i = 0; i < rule->length; i++) {
		// exclude fields in other direction
		if( ( (rule->content[i].dir) == BI) || ( (rule->content[i].dir) == DI)) {
			field_length = rule->content[i].field_length;

			switch (rule->content[i].action) {
			case NOTSENT: {
				// do nothing
			} break;
			case VALUESENT: {
				for (j = 0; j < field_length; j++) {
					schc_header[index + j] = *((header + field_counter * cols) + j);
				}
				index += field_length;
			} break;
			case MAPPINGSENT: {
				// reset the parser
				jsmn_init(&json_parser);

				// parse the json string
				json_result = jsmn_parse(&json_parser, rule->content[i].target_value,
						strlen(rule->content[i].target_value), json_token,
						sizeof(json_token) / sizeof(json_token[0]));
				uint8_t match_counter = 0;

				// if result is 0,
				if (json_result == 0) {
					for (j = 0; j < field_length; j++) {
						// formatted as a normal unsigned char array
						//  only the first field contains the value to map to
						if (rule->content[i].target_value[j] == *((header + field_counter * cols) + 0)) {
							// just send the index of the mapping array
							schc_header[index] = j;
						}
					}
				} else {
					// formatted as a JSON object
					j = 1; // the first token is the string received
					while (j < json_result) {
						uint8_t k = 0;
						match_counter = 0;
						uint8_t length = (json_token[j].start
								+ (json_token[j].end - json_token[j].start));

						uint8_t l = 0;
						for (k = json_token[j].start; k < length; k++) {
							if (rule->content[i].target_value[k]
									== *((header + field_counter * cols) + l)) {
								match_counter++;
							}
							l++;
						}

						if (match_counter
								== (json_token[j].end - json_token[j].start)) {
							// the field value is found in the mapping array
							// send the index
							schc_header[index] = (j - 1);
							break;
						}
						j++;
					}
				}
				index++;
			} break;
			case LSB: {
				lsb = ( ( (rule->content[i].field_length) * 8) - rule->content[i].msb_length);

				for (j = 0; j < field_length; j++) {
					// if the last bit of the current byte is larger than the msb length
					if( ((j + 1) * 8) > rule->content[i].msb_length) {
						uint8_t byte_marker = (rule->content[i].msb_length / 8);
						// start adding the lsb's to the compressed header field
						if(j >= byte_marker) {
							if( j == byte_marker ) {
								uint8_t number_of_bits_to_mask; uint8_t mask = 0;
								if(! (lsb % 8) ) {
									// on byte boundary
									number_of_bits_to_mask = 8;
								} else {
									number_of_bits_to_mask = (lsb - ( (lsb / 8) * 8));
								}

								// create mask
								uint8_t k;
								for (k = 0; k < number_of_bits_to_mask; k++) {
									mask |= 1 << k;
								}

								schc_header[index] = ( *((header + field_counter * cols) + j) & mask);
							} else {
								// add the remaining bytes
								schc_header[index] = *((header + field_counter * cols) + j);
							}
							index++;
						}
					}

				}
			} break;
			case COMPLENGTH:
			case COMPCHK: {
				// do nothing
			} break;
			case DEVIID: {
				// ToDo
			} break;
			case APPIID: {
				// ToDo
			} break;
			}

			field_counter++;

		}
	}
/*
	printf("\n");
	for (i = 0; i < index; i++) {
		printf("%x ", schc_header[i]);
	}
	printf("\n"); */

	return index;
}


/**
 * The decompression mechanism
 *
 * @param schc_header 	pointer to the header in which to operate
 * @param rule 			pointer to the rule to use during the decompression
 * @param nr_of_fields 	the number of fields
 * @param rule 			the rule to match the compression with
 * @param nr_of_fields 	the number of fields as found in the rule
 *
 * @return the length of the decompressed header
 *
 */
static uint8_t decompress(unsigned char *schc_header,
		const struct schc_layer_rule_t* rule, unsigned char *data, uint8_t* header_offset) {
	uint8_t i = 0;
	uint8_t index = 0;
	uint8_t field_length;
	uint8_t j; int8_t json_result = -1;
	uint8_t lsb = 0;

	// remove rules from header
	uint8_t *payload;
	payload = (uint8_t *) (data + RULE_SIZE_BYTES);

	for (i = 0; i < rule->length; i++) {
		// exclude fields in other direction
		if (((rule->content[i].dir) == BI) || ((rule->content[i].dir) == DI)) {
			field_length = rule->content[i].field_length;

			switch (rule->content[i].action) {
			case NOTSENT: {
				// use value stored in context
				for (j = 0; j < field_length; j++) {
					schc_header[index + j] = rule->content[i].target_value[j];
				}
			} break;
			case VALUESENT: {
				// build from received value
				for (j = 0; j < field_length; j++) {
					schc_header[index + j] = payload[*header_offset + j];
				}
				*header_offset += field_length;
			} break;
			case MAPPINGSENT: {
				// reset the parser
				jsmn_init(&json_parser);

				// parse the json string
				json_result = jsmn_parse(&json_parser, rule->content[i].target_value,
						strlen(rule->content[i].target_value), json_token, sizeof(json_token) / sizeof(json_token[0]));

				uint8_t mapping_index = payload[*header_offset]; // mapping index is the index in the rule field, representing the decompressed value

				// if result is 0,
				if (json_result == 0) {
					// formatted as a normal unsigned uint8_t array
					// grab the value at the index
					memcpy((uint8_t*)(schc_header + index), (uint8_t*) (rule->content[i].target_value + mapping_index), 1);

					field_length = 1;
				} else if(json_result > 0) {
					// JSON object, grab the value(s), starting from the received index
					mapping_index = mapping_index + 1; // first element in json token is total array, next are individual tokens
					uint8_t length = (json_token[mapping_index].end - json_token[mapping_index].start);

					uint8_t k = 0;
					// store rule value in decompressed header
					for (j = json_token[mapping_index].start; j < json_token[mapping_index].end; j++) {
						schc_header[index + k] = rule->content[i].target_value[j];
						k++;
					}

					field_length = length;
				}

				*header_offset = *header_offset + 1;

			} break;
			case LSB: {
				// compute value from received lsb
				for (j = 0; j < field_length; j++) {
					// the byte to do the bitwise operation on
					if (((j + 1) * 8) > rule->content[i].msb_length) {
						// cast to unsigned char for bitwise operation
						unsigned char tv_rule = rule->content[i].target_value[j];
						unsigned char tv_header = payload[*header_offset];

						schc_header[index + j] = (tv_rule | tv_header);

						// only move index pointer when LSB value is found
						*header_offset = *header_offset + 1;
					} else {
						// set field from rule
						schc_header[index + j] = rule->content[i].target_value[j];
					}
				}
			} break;
			case COMPLENGTH:
			case COMPCHK: {
				// set to 0, to indicate that it will be calculated after decompression
				schc_header[index] = 0;
				schc_header[index + 1] = 0;
			} break;
			case DEVIID: {
				if (!strcmp(rule->content[i].field, "src iid")) {

					uip_ipaddr_t node_ip;
					get_node_ip(node_ip);

					unsigned char ip_addr[8] = {
							(node_ip[4] & 0xFF),
							(node_ip[4] & 0xFF00) >> 8,
							(node_ip[5] & 0xFF),
							(node_ip[5] & 0xFF00) >> 8,
							(node_ip[6] & 0xFF),
							(node_ip[6] & 0xFF00) >> 8,
							(node_ip[7] & 0xFF),
							(node_ip[7] & 0xFF00) >> 8,
					};

					for (j = 0; j < field_length; j++) {
						schc_header[index + j] = ip_addr[j];
					}
				}
			} break;
			case APPIID: {
				// build iid from L2 server address
			} break;
			}

			index += field_length;
		}
	}

	/* printf("\n");

	 for(j = 0; j < index; j++) {
	 printf("%02x ", schc_header[j]);
	 }

	 printf("\n"); */

	return index;
}

/**
 * Fills the passed IP/UDP header struct from a 8-bit buffer
 *
 * @param data 				the buffer to copy the data from
 * @param ip_udp_header 	the IP/UDP header to construct the unified array from
 *
 */
static void generate_ip_udp_header_struct(const uint8_t* data, struct uip_udpip_hdr *ip_udp_header) {
#if USE_IPv6
	// construct the IP header
	ip_udp_header->vtc = data[0];
	ip_udp_header->tcf = data[1];
	ip_udp_header->flow = (uint16_t) ((data[2] << 8) | data[3]);
	ip_udp_header->len[0] = data[4];
	ip_udp_header->len[1] = data[5];
	ip_udp_header->proto = data[6];
	ip_udp_header->ttl = data[7];

	uip_ipaddr_t src = { ((data[9] << 8) | data[8]),
			((data[11] << 8) | data[10]), ((data[13] << 8) | data[12]),
			((data[15] << 8) | data[14]), ((data[17] << 8) | data[16]),
			((data[19] << 8) | data[18]), ((data[21] << 8) | data[20]),
			((data[23] << 8) | data[22]) };

	uip_ipaddr_t dest = { ((data[25] << 8) | data[24]), ((data[27] << 8)
			| data[26]), ((data[29] << 8) | data[28]), ((data[31] << 8)
			| data[30]), ((data[33] << 8) | data[32]), ((data[35] << 8)
			| data[34]), ((data[37] << 8) | data[36]), ((data[39] << 8)
			| data[38]) };

	memcpy(ip_udp_header->srcipaddr, src, sizeof(uip_ipaddr_t));
	memcpy(ip_udp_header->destipaddr, dest, sizeof(uip_ipaddr_t));
#endif

#if USE_UDP
	// construct the UDP header
	ip_udp_header->srcport = (uint16_t)((data[40] << 8) | data[41]);
	ip_udp_header->destport = (uint16_t)((data[42] << 8) | data[43]);
	ip_udp_header->udplen = (uint16_t)((data[44] << 8) | data[45]);
	ip_udp_header->udpchksum	= (uint16_t)((data[46] << 8) | data[47]);
#endif
}

#if USE_IPv6
/**
 * Generates a unified unsigned char array, based on the IP header provided
 *
 * @param header_fields the array to transfer the header to
 * @param ip_udp_header the IP/UDP header to construct the unified array from
 *
 * @return the length of the array, which represents the number of UDP fields
 *
 */
static uint8_t generate_ip_header_fields(struct uip_udpip_hdr *ip_udp_header) {

	unsigned char version[1] = { (ip_udp_header->vtc & 0xF0) >> 4};
	unsigned char traffic_class[1] = { (((ip_udp_header->vtc & 0xF) << 4) | (ip_udp_header->tcf & 0xF0) >> 4)  };
	unsigned char flow_label[3] = { ( (ip_udp_header->tcf & 0xF) >> 4),
			((ip_udp_header->flow & 0xFF00) >> 8), (ip_udp_header->flow & 0xFF) };
	unsigned char p_length[2] = { ip_udp_header->len[0], ip_udp_header->len[1]};
	unsigned char next_header[1] = { ip_udp_header->proto };
	unsigned char hop_limit[1] = { ip_udp_header->ttl };

	unsigned char src_prefix[8] = {
			(ip_udp_header->srcipaddr[0] & 0xFF),
			((ip_udp_header->srcipaddr[0] & 0xFF00) >> 8 ),
			(ip_udp_header->srcipaddr[1] & 0xFF),
			((ip_udp_header->srcipaddr[1] & 0xFF00) >> 8 ),
			(ip_udp_header->srcipaddr[2] & 0xFF),
			((ip_udp_header->srcipaddr[2] & 0xFF00) >> 8 ),
			(ip_udp_header->srcipaddr[3] & 0xFF),
			((ip_udp_header->srcipaddr[3] & 0xFF00) >> 8 ),
	};

	unsigned char src_iid[8] = {
			(ip_udp_header->srcipaddr[4] & 0xFF),
			((ip_udp_header->srcipaddr[4] & 0xFF00) >> 8 ),
			(ip_udp_header->srcipaddr[5] & 0xFF),
			((ip_udp_header->srcipaddr[5] & 0xFF00) >> 8 ),
			(ip_udp_header->srcipaddr[6] & 0xFF),
			((ip_udp_header->srcipaddr[6] & 0xFF00) >> 8 ),
			(ip_udp_header->srcipaddr[7] & 0xFF),
			((ip_udp_header->srcipaddr[7] & 0xFF00) >> 8 ),
	};


	unsigned char dest_prefix[8] = {
			(ip_udp_header->destipaddr[0] & 0xFF),
			((ip_udp_header->destipaddr[0] & 0xFF00) >> 8 ),
			(ip_udp_header->destipaddr[1] & 0xFF),
			((ip_udp_header->destipaddr[1] & 0xFF00) >> 8 ),
			(ip_udp_header->destipaddr[2] & 0xFF),
			((ip_udp_header->destipaddr[2] & 0xFF00) >> 8 ),
			(ip_udp_header->destipaddr[3] & 0xFF),
			((ip_udp_header->destipaddr[3] & 0xFF00) >> 8 ),
		};

	unsigned char dest_iid[8] = {
			(ip_udp_header->destipaddr[4] & 0xFF),
			((ip_udp_header->destipaddr[4] & 0xFF00) >> 8 ),
			(ip_udp_header->destipaddr[5] & 0xFF),
			((ip_udp_header->destipaddr[5] & 0xFF00) >> 8 ),
			(ip_udp_header->destipaddr[6] & 0xFF),
			((ip_udp_header->destipaddr[6] & 0xFF00) >> 8 ),
			(ip_udp_header->destipaddr[7] & 0xFF),
			((ip_udp_header->destipaddr[7] & 0xFF00) >> 8 ),
	};

	// extract header fields at same position as rule fields
	memcpy(ipv6_header_fields[0], version, 1);
	memcpy(ipv6_header_fields[1], traffic_class, 1);
	memcpy(ipv6_header_fields[2], flow_label, 3);
	memcpy(ipv6_header_fields[3], p_length, 2);
	memcpy(ipv6_header_fields[4], next_header, 1);
	memcpy(ipv6_header_fields[5], hop_limit, 1);

	// to allow a single rule for destination and source,
	// the values are identified by their role and not by their position in the frame
	// therefore, we switch positions depending on the direction indicator

	if( (DEVICE_TYPE != NETWORK_GATEWAY) && DI == UP) {
		// swap fields
		memcpy(ipv6_header_fields[6], dest_prefix, 8);
		memcpy(ipv6_header_fields[7], dest_iid, 8);
		memcpy(ipv6_header_fields[8], src_prefix, 8);
		memcpy(ipv6_header_fields[9], src_iid, 8);
	} else {
		memcpy(ipv6_header_fields[6], src_prefix, 8);
		memcpy(ipv6_header_fields[7], src_iid, 8);
		memcpy(ipv6_header_fields[8], dest_prefix, 8);
		memcpy(ipv6_header_fields[9], dest_iid, 8);
	}

	return IPV6_FIELDS;
}

/**
 * Find a matching rule for the IP header
 *
 * @param ip_udp_header the IP/UDP header struct
 * @param device_id		the device to find an IP rule for
 *
 * @return the rule
 *         NULL if no rule is found
 */
static struct schc_ipv6_rule_t* schc_find_ipv6_rule_from_header(struct uip_udpip_hdr *ip_udp_header, uint32_t device_id) {
	uint8_t i = 0;
	// set to 0 when a rule doesn't match
	uint8_t rule_is_found = 1;

	generate_ip_header_fields(ip_udp_header);

	struct schc_device *device = get_device_by_id(device_id);
	if (device == NULL) {
		DEBUG_PRINTF(
				"schc_find_ipv6_rule_from_header(): no device was found for this id");
		return 0;
	}

	for (i = 0; i < device->rule_count; i++) {
		const struct schc_ipv6_rule_t* curr_rule = (*device->context)[i]->compression_rule->ipv6_rule;

		uint8_t j = 0; uint8_t k = 0;

		while (j < curr_rule->length) {
			// exclude fields in other direction
			if( (curr_rule->content[k].dir == BI) || (curr_rule->content[k].dir == DI)) {
				// compare header field and rule field using the matching operator
				if (!curr_rule->content[k].MO(&curr_rule->content[k],
						ipv6_header_fields[j])) {
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
			return curr_rule;
		}
	}

	return NULL;
}

/**
 * Decompress an IPv6 rule, based on an input packet
 *
 * @param rule 			the IPv6 rule to use during the decompression
 * @param data 			pointer to the input data
 * @param pckt_out 		buffer to the packet to store the decompressed data in
 * @param header_offset pointer to the current offset in the decompressed header
 *
 */
static uint8_t decompress_ipv6_rule(struct schc_ipv6_rule_t* rule, unsigned char *data, unsigned char* pckt_out,
	uint8_t* header_offset) {
	// +1, flow label takes up 20 bits (formatted as 3 bytes)
	unsigned char ip_header[IP6_HLEN + 1];

	if (rule != NULL) {
		// fill the ipv6 header according to the decompression action
		// as described in the rule field
		decompress(ip_header, (const struct schc_layer_rule_t*) rule, data, header_offset);

		// version, flow label, traffic class
		pckt_out[0] = (ip_header[0] << 4) | (ip_header[1] >> 4);
		pckt_out[1] = (ip_header[1] << 4) | (ip_header[4] >> 4);
		pckt_out[2] = ip_header[3];
		pckt_out[3] = ip_header[2];
		// payload length
		pckt_out[4] = ip_header[5];
		pckt_out[5] = ip_header[6];

		if( (DI == UP) && (DEVICE_TYPE == NETWORK_GATEWAY)) {
			// next header, hop limit
			memcpy(&pckt_out[6], &ip_header[7], 2);
			// swap source and destination
			memcpy(&pckt_out[8], &ip_header[25], 16);
			memcpy(&pckt_out[24], &ip_header[9], 16);
		} else {
			memcpy(&pckt_out[6], &ip_header[7], (IP6_HLEN - 6));
		}
	} else {
		DEBUG_PRINTF("decompress_ipv6_rule(): no rule was found");
		return 0;
	}

	return 1;
}
#endif

#if USE_UDP
/**
 * Generates a unified unsigned char array, based on the UDP header provided
 *
 * @param header_fields the array to transfer the header to
 * @param ip_udp_header the IP/UDP header to construct the unified array from
 *
 * @return the length of the array, which represents the number of UDP fields
 *
 */
static uint8_t generate_udp_header_fields(struct uip_udpip_hdr *ip_udp_header) {

	uint8_t cols = MAX_UDP_FIELD_LENGTH;

	unsigned char src[2] = { ((ip_udp_header->srcport & 0xFF00) >> 8), (ip_udp_header->srcport & 0x00FF) };
	unsigned char dest[2] = { ((ip_udp_header->destport & 0xFF00) >> 8), (ip_udp_header->destport & 0x00FF) };
	unsigned char len[2] = { ((ip_udp_header->udplen & 0xFF00) >> 8), (ip_udp_header->udplen & 0x00FF) };
	unsigned char chksum[2] = { ((ip_udp_header->udpchksum & 0xFF00) >> 8), (ip_udp_header->udpchksum & 0x00FF) };

	// extract header fields at same position as rule fields
	memcpy(udp_header_fields[0], src, 2);
	memcpy(udp_header_fields[1], dest, 2);
	memcpy(udp_header_fields[2], len, 2);
	memcpy(udp_header_fields[3], chksum, 2);

	return UDP_FIELDS;
}

/**
 * Find a matching rule for the UDP header
 *
 * @param data 				pointer to the application generated data
 * @param device_id			the device to find a UDP rule for
 *
 * @return rule id 			the rule id
 *         0 				if no rule is found
 */
static struct schc_udp_rule_t* schc_find_udp_rule_from_header(const struct uip_udpip_hdr *ip_udp_header, uint32_t device_id) {
	uint8_t i = 0;
	// set to 0 when a rule doesn't match
	uint8_t rule_is_found = 1;

	generate_udp_header_fields(ip_udp_header);

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
			if( (curr_rule->content[k].dir == BI) || (curr_rule->content[k].dir == DI)) {
				// compare header field and rule field using the matching operator
				if (!curr_rule->content[k].MO(&curr_rule->content[k],
						udp_header_fields[j])) {
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
			return curr_rule;
		}
	}

	return NULL;
}

/**
 * Decompress a UDP rule, based on an input packet
 *
 * @param 	rule_id 		the id of the UDP rule to use during the decompression
 * @param 	data 			pointer to the input data
 * @param 	pckt_out 		buffer to the packet to store the decompressed data in
 * @param 	header_offset 	pointer to the current offset in the decompressed header
 *
 * @return  1				decompression succeeded
 * 			0				decompression failed
 *
 */
static uint8_t decompress_udp_rule(struct schc_udp_rule_t* rule, unsigned char *data,
		unsigned char* pckt_out, uint8_t* header_offset) {
	uint8_t udp_header[UDP_HLEN];

	if (rule != NULL) {
		// fill the udp header according to the decompression action
		// as described in the rule field
		decompress(udp_header, (const struct schc_layer_rule_t*) rule, data,
				header_offset);

		// copy UDP header after IP6 header
		memcpy(&pckt_out[IP6_HLEN], udp_header, UDP_HLEN);
	} else {
		DEBUG_PRINTF(
				"decompress_udp_rule(): no UDP rule could be found \n");
		return 0;
	}

	return 1;
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
static uint8_t generate_coap_header_fields(coap_pdu *pdu) {
	uint8_t i = 0;
	// the 5 first fields are always present (!= bytes)
	uint8_t field_length = 5;

	coap_header_fields[0][0] = coap_get_version(pdu);
	coap_header_fields[1][0] = coap_get_type(pdu);
	coap_header_fields[2][0] = coap_get_tkl(pdu);
	coap_header_fields[3][0] = coap_get_code(pdu);

	unsigned char msg_id[2] = { (coap_get_mid(pdu) & 0xFF00) >> 8, coap_get_mid(
			pdu) & 0x00FF };
	memcpy(&coap_header_fields[4], msg_id, 2);

	if (coap_get_tkl(pdu) > 0) {
		uint8_t token[8];
		coap_get_token(pdu, token);

		memcpy(&coap_header_fields[5], &token, coap_get_tkl(pdu));

		field_length++;
	}

	uint8_t coap_length = pdu->len;

	coap_option option;
	// get first option
	option = coap_get_option(pdu, NULL);

	while (option.num > 0) {
		for (i = 0; i < option.len; ++i) {
			coap_header_fields[field_length][i] = *(option.val + i);
		}

		// get next option
		option = coap_get_option(pdu, &option);
		field_length++;
	}

	coap_payload pl = coap_get_payload(pdu);
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
static struct schc_coap_rule_t* schc_find_coap_rule_from_header(coap_pdu *pdu, uint32_t device_id) {
	uint16_t i = 0;
	// set to 0 when a rule doesn't match
	uint8_t rule_is_found = 1;
	uint8_t direction_field_length = 0;

	if(coap_validate_pkt(pdu) != CE_NONE) {
		DEBUG_PRINTF("schc_find_coap_rule_from_header(): invalid CoAP packet");
		return 0;
	}

	// generate a char array, matchable to the rule
	uint8_t coap_field_length = generate_coap_header_fields(pdu);

	// get device rules
	struct schc_device *device = get_device_by_id(device_id);
	if(device == NULL) {
		DEBUG_PRINTF("schc_find_coap_rule_from_header(): no device was found for this id");
		return 0;
	}

	int j; int k;

	for (i = 0; i < device->rule_count; i++) {
		const struct schc_coap_rule_t* curr_rule = (*device->context)[i]->compression_rule->coap_rule;

		(DI == DOWN) ? (direction_field_length = curr_rule->down) : (direction_field_length = curr_rule->up);

		// save compare cycles by checking the number of the specified direction fields
		if (coap_field_length == direction_field_length) {
			j = 0; k = 0;
			while (k < curr_rule->length) {
				// exclude fields in other direction
				if( (curr_rule->content[k].dir == BI) || (curr_rule->content[k].dir == DI)) {

					// compare header field and rule field using the matching operator
					if (!curr_rule->content[k].MO(&curr_rule->content[k],
							coap_header_fields[j])) {
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
				return curr_rule;
			}
		}
	}

	return NULL;
}

/**
 * Decompress a CoAP rule, based on an input packet
 *
 * @param rule 			the id of the CoAP rule to use during the decompression
 * @param data 			pointer to the input data
 * @param header_offset pointer to the current offset in the decompressed header
 * @param msg 			pointer to the CoAP message to use during the reconstruction
 *
 */
static uint8_t decompress_coap_rule(struct schc_coap_rule_t* rule,
		unsigned char *data, uint8_t* header_offset, coap_pdu *msg) {
	 // ToDo
	// directly alter the packet buffer
	// or the coap_header buffer to save RAM


	// buffer to store decompressed values
	unsigned char coap_header[MAX_COAP_HEADER_LENGTH];

	// first number of bytes is always 4
	uint8_t byte_length = 4;

	if (rule != NULL) {
		uint8_t coap_length = decompress(&coap_header, (const struct schc_layer_rule_t*) rule, data, header_offset);

		coap_init_pdu(msg);
		coap_set_version(msg, coap_header[0]);
		coap_set_type(msg, coap_header[1]);
		coap_set_code(msg, coap_header[3]);

		uint16_t msg_id = ((coap_header[4] << 8) | coap_header[5]);
		coap_set_mid(msg, msg_id);

		uint8_t tkl = coap_header[2];
		if(tkl != 0){
			coap_set_token(msg, (uint8_t*) (coap_header + 6), tkl);
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
						coap_add_option(msg, coap_options[j].id, (uint8_t*) (coap_header + field_length), rule->content[i].field_length);
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
static uint8_t equal(struct schc_field* target_field, unsigned char* field_value){
	uint8_t i;

	// printf("compare %s \n", target_field->field);

	for(i = 0; i < target_field->field_length; i++) {
		// printf("%d - %d ", target_field->target_value[i], field_value[i]);
		if(target_field->target_value[i] != field_value[i]){
			return 0;
		}
		// printf("\n");
	}

	// target value matches field value
	return 1;
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
 *
 * @param target_field the field from the rule
 * @param field_value the value from the header to compare with the rule value
 *
 * @return 1 if the MSB of the target field matches the MSB of the field value
 *         0 if the MSB of the target field doesn't match the MSB of the field value
 *
 */
static uint8_t MSB(struct schc_field* target_field, unsigned char* field_value){
	uint8_t i; uint8_t j;

	// printf("MSB %s \n", target_field->field);

	for (i = 0; i < target_field->field_length; i++) {
		// printf("%d - %d ", target_field->target_value[i], field_value[i]);

		// the byte to do the bitwise operation on
		if( ( (i + 1) * 8) >=  target_field->msb_length) {
			uint8_t msb = 0; uint8_t mask = 0;

			if(target_field->msb_length > 8) {
				msb = ( (target_field->field_length * 8) - target_field->msb_length);
			} else {
				msb = target_field->msb_length;
			}

			// create mask
			for (j = (8 - msb); j <= 8; j++) {
			       mask |= 1 << j;
			}

			// cast to unsigned char for bitwise operation
			unsigned char tv_rule = target_field->target_value[i] ;
			unsigned char tv_header = field_value[i];

			// printf("msb is %d tv rule %d, tv header %d i is %d \n", msb, tv_rule, tv_header, i);


			if ( ( tv_rule & mask ) != ( tv_header & mask) ) {
				return 0;
			} else {
				// target value matches field value
				return 1;
			}
		} else {
			// normal check if fields are equal
			if(target_field->target_value[i] != field_value[i]){
				return 0;
			}
		}
		// printf("\n");
	}
}


/**
 * The match-map matching operator
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
	result = jsmn_parse(&json_parser, target_field->target_value,
			strlen(target_field->target_value), json_token, sizeof(json_token) / sizeof(json_token[0]));

	// if result is 0,
	if(result == 0) {
		for(i = 0; i < target_field->field_length; i++) {
			// formatted as a normal unsigned char array
			// but only the first index of the header contains the value to find a match for
			if (target_field->target_value[i] == field_value[0]) {
				// the field value is found in the mapping array
				return 1;
			}
		}
	} else {
		// formatted as a JSON object
		i = 1; // the first token is the string received
		while(i < result){
			uint8_t j; uint8_t k = 0; match_counter = 0;
			uint8_t length = (json_token[i].start + (json_token[i].end - json_token[i].start));

			for (j = json_token[i].start; j < length; j++) {
				if(target_field->target_value[j] == field_value[k]) {
					match_counter++;
				}
				k++;
			}

			if(match_counter == (json_token[i].end - json_token[i].start)) {
				// the field value is found in the mapping array
				return 1;
			}
			i++;
		}
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
static void set_node_ip(uip_ipaddr_t *node_ip) {
	memcpy(node_ip_6, node_ip, sizeof(uip_ipaddr_t));
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
 * @param 	data 			pointer to the packet
 * @param 	buf				pointer to the compressed packet buffer
 * @param 	total_length 	the length of the packet
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

int16_t schc_compress(const uint8_t *data, uint8_t* buf, uint16_t total_length,
		uint32_t device_id, direction dir, device_type device_type,
		struct schc_rule_t **schc_rule) {
	DI = dir;
	DEVICE_TYPE = device_type;

	uint16_t schc_offset = RULE_SIZE_BYTES;
	uint16_t coap_length = 0;
#if USE_COAP
	uint8_t coap_rule_id = 0;
	struct schc_coap_rule_t *coap_rule;
#endif
#if USE_UDP
	uint8_t udp_rule_id = 0;
	struct schc_udp_rule_t *udp_rule;
#endif
#if USE_IPv6
	uint8_t ipv6_rule_id = 0;
	struct schc_ipv6_rule_t *ipv6_rule;
#endif

	// clear buffer
	memset(buf, 0, total_length);

#if USE_COAP
	// construct CoAP message from buffer
	uint8_t coap_buf[MAX_COAP_MSG_SIZE] = { 0 };
	memcpy(coap_buf, (uint8_t*) (data + IP6_HLEN + UDP_HLEN), (total_length - IP6_HLEN - UDP_HLEN)); // copy CoAP header
	coap_pdu coap_msg = { coap_buf, (total_length - IP6_HLEN - UDP_HLEN), MAX_COAP_MSG_SIZE };

	// check the buffer for determining the CoAP header length
	coap_length = coap_get_coap_offset(&coap_msg);

	// retrieve the first matching CoAP rule
	coap_rule = schc_find_coap_rule_from_header(&coap_msg, device_id);
	if(coap_rule != NULL) {
		coap_rule_id = coap_rule->rule_id;
		DEBUG_PRINTF("schc_compress(): CoAP rule id %d \n", coap_rule->rule_id);
	} else {
		DEBUG_PRINTF("schc_compress(): no CoAP rule was found \n");
	}
#endif

	struct uip_udpip_hdr ip_udp_header;
	generate_ip_udp_header_struct(data, &ip_udp_header);

#if USE_UDP
	udp_rule = schc_find_udp_rule_from_header(&ip_udp_header, device_id);
	if(udp_rule != NULL) {
		udp_rule_id = udp_rule->rule_id;
		DEBUG_PRINTF("schc_compress(): UDP rule id %d \n", udp_rule->rule_id);
	} else {
		DEBUG_PRINTF("schc_compress(): no UDP rule was found \n");
	}
#endif
#if USE_IPv6
	ipv6_rule = schc_find_ipv6_rule_from_header(&ip_udp_header, device_id);
	if(ipv6_rule != NULL) {
		ipv6_rule_id = ipv6_rule->rule_id;
		DEBUG_PRINTF("schc_compress(): IPv6 rule id %d \n", ipv6_rule->rule_id);
	} else {
		DEBUG_PRINTF("schc_compress(): no IPv6 rule was found \n");
	}
#endif

	// find the rule for this device by combining the available id's
	uint16_t rule_id = 0;
	uint8_t buf_offset = RULE_SIZE_BYTES;
	uint8_t data_offset = 0;
	(*schc_rule) = get_schc_rule_by_layer_ids(ipv6_rule_id,
			udp_rule_id, coap_rule_id, device_id, NOT_FRAGMENTED);

	if((*schc_rule) == NULL) { // NO RULE WAS FOUND: COPY UNCOMPRESSED
		rule_id = UNCOMPRESSED_RULE_ID;
		DEBUG_PRINTF("schc_compress(): no rule was found \n");

		// copy uncompressed rule id in front of the buffer
		memcpy((uint8_t*) buf, &rule_id, RULE_SIZE_BYTES);

		// ... now copy the uncompressed headers
#if USE_IPv6
		memcpy((buf + buf_offset), data, IP6_HLEN);
		buf_offset += IP6_HLEN; data_offset += IP6_HLEN;
#endif
#if USE_UDP
		memcpy((buf + buf_offset), (data + data_offset), UDP_HLEN);
		buf_offset += UDP_HLEN; data_offset += UDP_HLEN;
#endif
#if USE_COAP
		memcpy((buf + buf_offset), coap_buf, coap_length);
		buf_offset += coap_length; data_offset += coap_length;
#endif
		schc_offset = buf_offset;
	} else { // A RULE WAS FOUND: COMPRESS
		rule_id = (*schc_rule)->id;
		DEBUG_PRINTF("schc_compress(): SCHC rule id %d \n", rule_id);
		// copy rule id in front of the buffer
		memcpy((uint8_t*) buf, &rule_id, RULE_SIZE_BYTES);

		// ... now compress the headers according to the rule
		// and copy the contents to the buffer
#if USE_IPv6
		generate_ip_header_fields(&ip_udp_header);
		schc_offset += compress((uint8_t*) (buf + schc_offset), ipv6_header_fields, MAX_IPV6_FIELD_LENGTH, (const struct schc_layer_rule_t*) ipv6_rule);
#endif
#if USE_UDP
		generate_udp_header_fields(&ip_udp_header);
		schc_offset += compress((uint8_t*) (buf + schc_offset), udp_header_fields, MAX_UDP_FIELD_LENGTH, (const struct schc_layer_rule_t*) udp_rule);
#endif
#if USE_COAP
		generate_coap_header_fields(&coap_msg); // generate a char array, which can easily be compared to the rule
		schc_offset += compress((uint8_t*) (buf + schc_offset), coap_header_fields, MAX_COAP_FIELD_LENGTH, (const struct schc_layer_rule_t*) coap_rule);
#endif
	}

	DEBUG_PRINTF("\n");
	DEBUG_PRINTF("schc_compress(): compressed header length: %d \n", schc_offset);
	DEBUG_PRINTF("+---------------------------------+\n");
	DEBUG_PRINTF("|          SCHC Header            |\n");
	DEBUG_PRINTF("+---------------------------------+\n");

	int i;
	for(i = 0; i < schc_offset; i++) {
		DEBUG_PRINTF("%02X ", buf[i]);
		if(!((i + 1) % 12)) {
			DEBUG_PRINTF("\n");
		}
	}
	DEBUG_PRINTF("\n\n");

	// copy the payload
	uint16_t payload_len = (total_length - IP6_HLEN - UDP_HLEN - coap_length);

	uint8_t* payload_ptr = (data + IP6_HLEN + UDP_HLEN + coap_length);
    memcpy((uint8_t*) (buf + schc_offset), payload_ptr, payload_len);

    uint16_t new_pkt_length = (schc_offset + payload_len);

	DEBUG_PRINTF("schc_compress(): payload length: %d (total length: %d) \n", payload_len, new_pkt_length);
	for(i = schc_offset; i < new_pkt_length; i++) {
		DEBUG_PRINTF("%02X ", buf[i]);
		if(!(((i - schc_offset) + 1) % 12)) {
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

	if(packet_ptr[4] == 0 && packet_ptr[5] == 0) {
		// ip length
		packet_ptr[4] = (((data_len - IP6_HLEN) & 0xFF00) >> 8);
		packet_ptr[5] = ((data_len - IP6_HLEN) & 0xFF);
	}
	if(packet_ptr[44] == 0 && packet_ptr[45] == 0) {
		// udp length
		packet_ptr[44] = (((data_len - IP6_HLEN) & 0xFF00) >> 8);
		packet_ptr[45] = ((data_len - IP6_HLEN) & 0xFF);
	}

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
	if(data[46] == 0 && data[47] == 0) {
		uint16_t upper_layer_len; uint16_t sum; uint16_t result;

		upper_layer_len = (((uint16_t)(data[44]) << 8) + data[45]);

		// protocol (17 for UDP) and length fields. This addition cannot carry.
		uint8_t proto = data[6];
		sum = upper_layer_len + proto;

		// sum IP source and destination
		sum = chksum(sum, (uint8_t *)&data[8], 2 * sizeof(uip_ipaddr_t));

		// sum upper layer headers and data
		sum = chksum(sum, &data[IP6_HLEN], upper_layer_len);

		result = (~sum);

		data[46] = (uint8_t) ((result & 0xFF00) >> 8);
		data[47] = (uint8_t) (result & 0xFF);

		return 1;
	}

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

	uint8_t rule_id; uint8_t coap_rule_id = 0; uint8_t udp_rule_id = 0; uint8_t ipv6_rule_id = 0;
	uint8_t header_offset = 0;

	rule_id = *(data + 0);
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
			rule_id, rule_id, ipv6_rule_id, udp_rule_id, coap_rule_id);

	uint8_t ret = 0;
	uint8_t coap_offset = 0;

	// CoAP buffers for parsing
	uint8_t msg_recv_buf[MAX_COAP_MSG_SIZE];
	coap_pdu coap_msg = { msg_recv_buf, 0, MAX_COAP_MSG_SIZE };

	if (rule_id == UNCOMPRESSED_RULE_ID) { // uncompressed packet
		header_offset += RULE_SIZE_BYTES;
#if USE_IPv6
		// copy the uncompressed IPv6 header from the SCHC packet
		memcpy((unsigned char*) (buf), (uint8_t *) (data + header_offset), IP6_HLEN);
		header_offset += IP6_HLEN;
#endif
#if USE_UDP
		// copy the uncompressed UDP headers
		memcpy((unsigned char*) (buf + IP6_HLEN), (uint8_t *) (data + header_offset), UDP_HLEN);
		header_offset += UDP_HLEN;
#endif
#if USE_COAP
		// copy the uncompressed CoAP headers
		uint16_t coap_len = (total_length - RULE_SIZE_BYTES - IP6_HLEN - UDP_HLEN);
		memcpy((unsigned char*) (buf + IP6_HLEN + UDP_HLEN), (uint8_t *) (data + header_offset), coap_len);

		// use CoAP lib to calculate CoAP offset
		coap_msg.len = 4; // we validate the CoAP packet, which also uses the length of the header
		memcpy(coap_msg.buf, (uint8_t*) (buf + IP6_HLEN + UDP_HLEN), coap_len);
		coap_offset = coap_get_coap_offset(&coap_msg);

		header_offset += coap_offset;
#endif
	} else { // compressed packet
#if USE_IPv6
		if (ipv6_rule_id != 0) {
			ret = decompress_ipv6_rule(rule->compression_rule->ipv6_rule, data, buf, &header_offset);
			if (ret == 0) {
				return 0; // no rule was found
			}
		}
#endif
#if USE_UDP
		// search udp rule
		if (udp_rule_id != 0) {
			ret = decompress_udp_rule(rule->compression_rule->udp_rule, data, buf, &header_offset);
			if (ret == 0) {
				return 0; // no rule was found
			}
		}
#endif
#if USE_COAP
		// grab CoAP rule and decompress
		if (coap_rule_id != 0) {
			ret = decompress_coap_rule(rule->compression_rule->coap_rule, data, &header_offset, &coap_msg);
			if (ret == 0) {
				return 0; // no rule was found
			}
			coap_offset = coap_msg.len;
		}
		memcpy((unsigned char*) (buf + (IP6_HLEN + UDP_HLEN)), coap_msg.buf, coap_offset); // grab the CoAP header from the CoAP buffer
#endif
		header_offset += RULE_SIZE_BYTES;
	}

	uint8_t new_headerlen = IP6_HLEN + UDP_HLEN + coap_offset;

	uint16_t payload_len = (total_length - header_offset); // the schc header minus the total length is the payload length
	DEBUG_PRINTF("schc_decompress(): header length: %d, payload length %d \n", new_headerlen, payload_len);

	memcpy((uint8_t*) (buf + new_headerlen), (uint8_t*) (data + header_offset), payload_len);

	compute_length(buf, (payload_len + new_headerlen));
	compute_checksum(buf);

	DEBUG_PRINTF("\n");
	DEBUG_PRINTF("+---------------------------------+\n");
	DEBUG_PRINTF("|        Original Packet          |\n");
	DEBUG_PRINTF("+---------------------------------+\n");

	int i;
	for (i = 0; i < new_headerlen + payload_len; i++) {
		DEBUG_PRINTF("%02X ", buf[i]);
		if (!((i + 1) % 12)) {
			DEBUG_PRINTF("\n");
		}
	}

	DEBUG_PRINTF("\n\n");

	return new_headerlen + payload_len;
}

#if CLICK
ELEMENT_PROVIDES(schcCOMPRESSOR)
ELEMENT_REQUIRES(schcJSON schcCOAP)
#endif
