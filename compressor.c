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

#include "pt/pt.h"
#include "jsmn.h"
#include "picocoap.h"
#include "rules.h"
#include "compressor.h"
#include "config.h"
#include "schc_config.h"

#if CLICK
#include <click/config.h>
#endif

// changes on server/client
static direction DI;
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
 * Finds the length of the CoAP header
 *
 * @param pdu the CoAP pdu, containing the header and payload
 *
 * @return the length of the CoAP header
 *
 */
static uint8_t get_coap_offset(coap_pdu *pdu) {
	if(coap_validate_pkt(pdu) == CE_INVALID_PACKET) {
		// coap length is 0
		return 0;
	}

	size_t offset = 4 + coap_get_tkl(pdu);

	uint8_t last_offset = 0;
	coap_option option;
	coap_payload payload;
	coap_error err;

	// Defaults
	payload.len = 0;
	payload.val = NULL;

	// Find Last Option
	do {
		err = coap_decode_option(pdu->buf + offset, pdu->len - offset, NULL,
				&option.len, &option.val);
		if (err == CE_FOUND_PAYLOAD_MARKER) {
			offset += 1;
			break;
		}
		if (err == CE_END_OF_PACKET) {
			break;
		}

		if (err != CE_NONE) {
			return offset;
		}

		// Add this option header and value length to offset.
		offset += (option.val - (pdu->buf + offset)) + option.len;

		if (offset > pdu->max) {
			return last_offset;
		}

		last_offset = offset;
	} while (1);

	return offset;
}

/**
 * Get a rule by it's id
 *
 * @param rule_id the id
 * @param length the length of the array containing the rules
 * @param rules the array containing the rules
 *
 * @return rule the rule which is found
 *         0 if no rule is found
 *
 */
static const struct schc_rule* get_rule_by_id(uint16_t rule_id, uint16_t length, const struct schc_rule* rules[]) {
	int i = 0;

	for(i = 0; i < length; i++) {
		if(rules[i]->rule_id == rule_id) {
			return rules[i];
		}
	}

	return 0;
}

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
 * The compression mechanism
 *
 * @param schc_header the header in which to operate
 * @param header the header
 * @param cols the number of columns the header contains
 * @param rule the rule to match the compression with
 * @param nr_of_fields the number of fields as found in the rule
 *
 * @return the length of the compressed header
 *
 */
static uint8_t compress(unsigned char *schc_header, unsigned char *header,
		uint16_t cols, const struct schc_rule *rule) {
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
		const struct schc_rule *rule, unsigned char *data, uint8_t* header_offset) {
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
 * Extracts the IP rule from the layered rule
 *
 * @param rule_id the layered rule
 *
 * @return the IP rule id
 *
 */
static uint8_t get_ip_rule_id(uint8_t rule_id) {
	return (rule_id & NWL_MASK) >> NWL_SHIFT;
}

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

	if( (!SERVER) && DI == UP) {
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
 *
 * @return the rule id
 *         0 if no rule is found
 */
static uint16_t schc_find_ipv6_rule_from_header(struct uip_udpip_hdr *ip_udp_header) {
	uint8_t i = 0;
	// set to 0 when a rule doesn't match
	uint8_t rule_is_found = 1;

	generate_ip_header_fields(ip_udp_header);

	for (i = 0; i < IPV6_RULES; i++) {
		uint8_t j = 0; uint8_t k = 0;
		while (j < schc_ipv6_rules[i]->length) {
			// exclude fields in other direction
			if( (schc_ipv6_rules[i]->content[k].dir == BI) || (schc_ipv6_rules[i]->content[k].dir == DI)) {
				// compare header field and rule field using the matching operator
				if (!schc_ipv6_rules[i]->content[k].MO(&schc_ipv6_rules[i]->content[k],
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
			return schc_ipv6_rules[i]->rule_id;
		}
	}

	return 0;
}

/**
 * Builds the compressed IP header
 *
 * @param schc_header the buffer to keep the compressed data in
 * @param ip_udp_header the IP/UDP header to compress
 * @param rule_id the rule to use while compressing
 *
 * @return the length of the compressed header
 *
 */
static uint8_t schc_build_ipv6_header(unsigned char* schc_header,
		struct uip_udpip_hdr *ip_udp_header, uint16_t rule_id) {
	uint8_t offset = 0;

	if (rule_id != 0) {
		const struct schc_rule *rule = get_rule_by_id(rule_id, IPV6_RULES, schc_ipv6_rules);

		generate_ip_header_fields(ip_udp_header);

		offset = compress(schc_header, ipv6_header_fields, MAX_IPV6_FIELD_LENGTH, rule);
	}

	return offset;
}

/**
 * Decompress an IPv6 rule, based on an input packet
 *
 * @param rule_id 		the id of the IPv6 rule to use during the decompression
 * @param data 			pointer to the input data
 * @param pckt_out 		buffer to the packet to store the decompressed data in
 * @param header_offset pointer to the current offset in the decompressed header
 *
 */
static uint8_t decompress_ipv6_rule(struct schc_device* device_rules, uint8_t rule_id,
	unsigned char *data, unsigned char* pckt_out,
	uint8_t* header_offset) {
	// +1, flow label takes up 20 bits (formatted as 3 bytes)
	unsigned char ip_header[IP6_HLEN + 1];

	if (rule_id != 0) {
		const struct schc_rule *rule = get_rule_by_id(rule_id, device_rules->ipv6_count,
				device_rules->ipv6_rules);
		if(rule == 0) {
			DEBUG_PRINTF("decompress_coap_rule(): no rule could be found with CoAP rule id %d", rule_id);
			return 0;
		}

		// fill the ipv6 header according to the decompression action
		// as described in the rule field
		decompress(ip_header, rule, data, header_offset);

		// version, flow label, traffic class
		pckt_out[0] = (ip_header[0] << 4) | (ip_header[1] >> 4);
		pckt_out[1] = (ip_header[1] << 4) | (ip_header[4] >> 4);
		pckt_out[2] = ip_header[3];
		pckt_out[3] = ip_header[2];
		// payload length
		pckt_out[4] = ip_header[5];
		pckt_out[5] = ip_header[6];

		if( (DI == UP) && SERVER) {
			// next header, hop limit
			memcpy(&pckt_out[6], &ip_header[7], 2);
			// swap source and destination
			memcpy(&pckt_out[8], &ip_header[25], 16);
			memcpy(&pckt_out[24], &ip_header[9], 16);
		} else {
			memcpy(&pckt_out[6], &ip_header[7], (IP6_HLEN - 6));
		}
	}

	return 1;
}

/**
 * Extracts the UDP rule from the layered rule
 *
 * @param rule_id the layered rule
 *
 * @return the UDP rule id
 *
 */
static uint8_t get_udp_rule_id(uint8_t rule_id) {
	return (rule_id & TPL_MASK) >> TPL_SHIFT;
}

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
 * @param ip_udp_header the IP/UDP header struct
 *
 * @return the rule id
 *         0 if no rule is found
 */
static uint16_t schc_find_udp_rule_from_header(struct uip_udpip_hdr *ip_udp_header) {
	uint8_t i = 0;
	// set to 0 when a rule doesn't match
	uint8_t rule_is_found = 1;

	generate_udp_header_fields(ip_udp_header);

	for (i = 0; i < UDP_RULES; i++) {
		uint8_t j = 0; uint8_t k = 0;

		while (j < UDP_FIELDS) {
			// exclude fields in other direction
			if( (schc_udp_rules[i]->content[k].dir == BI) || (schc_udp_rules[i]->content[k].dir == DI)) {
				// compare header field and rule field using the matching operator
				if (!schc_udp_rules[i]->content[k].MO(&schc_udp_rules[i]->content[k],
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
			return schc_udp_rules[i]->rule_id;
		}
	}

	return 0;
}

/**
 * Builds the compressed UDP header
 *
 * @param schc_header the buffer to keep the compressed data in
 * @param ip_udp_header the IP/UDP header to compress
 * @param rule_id the rule to use while compressing
 *
 * @return the length of the compressed header
 *
 */
static uint8_t schc_build_udp_header(unsigned char* schc_header,
		struct uip_udpip_hdr *ip_udp_header, uint16_t rule_id) {
	uint8_t offset = 0;

	if (rule_id != 0) {
		const struct schc_rule *rule = get_rule_by_id(rule_id, UDP_RULES, schc_udp_rules);

		generate_udp_header_fields(ip_udp_header);

		offset = compress(schc_header, udp_header_fields, MAX_UDP_FIELD_LENGTH, rule);
	}

	return offset;
}

/**
 * Decompress a UDP rule, based on an input packet
 *
 * @param rule_id 		the id of the UDP rule to use during the decompression
 * @param data 			pointer to the input data
 * @param pckt_out 		buffer to the packet to store the decompressed data in
 * @param header_offset pointer to the current offset in the decompressed header
 *
 */
static uint8_t decompress_udp_rule(struct schc_device* device_rules, uint8_t rule_id,
	unsigned char *data, unsigned char* pckt_out,
	uint8_t* header_offset) {
	uint8_t udp_header[UDP_HLEN];

	if (rule_id != 0) {
		const struct schc_rule *rule = get_rule_by_id(rule_id, device_rules->udp_count,
				device_rules->udp_rules);
		if(rule == 0) {
			DEBUG_PRINTF("decompress_udp_rule(): no rule could be found with udp rule id %d", rule_id);
			return 0;
		}

		// fill the udp header according to the decompression action
		// as described in the rule field
		decompress(udp_header, rule, data, header_offset);

		// copy UDP header after IP6 header
		memcpy(&pckt_out[IP6_HLEN], udp_header, UDP_HLEN);
	}

	return 1;
}

/**
 * Compress a UDP/IP header
 *
 * @param schc_header pointer to the header in which to save the compressed header
 * @param schc_offset pointer to the current offset in the compressed header
 * @param data pointer to the application generated data
 *
 * @return the layered UDP/IP rule id
 *
 */
static int16_t compress_udp_ip_header(unsigned char *schc_header,
		uint8_t *schc_offset, const uint8_t* data) {
	struct uip_udpip_hdr ip_udp_header;

	ip_udp_header.vtc = data[0];
	ip_udp_header.tcf = data[1];
	ip_udp_header.flow = (uint16_t)  ((data[2] << 8) | data[3]);
	ip_udp_header.len[0] = data[4];
	ip_udp_header.len[1] = data[5];
	ip_udp_header.proto = data[6];
	ip_udp_header.ttl = data[7];

	uip_ipaddr_t src = {
			((data[9] << 8) | data[8]),
			((data[11] << 8) | data[10]), ((data[13] << 8) | data[12]),
			((data[15] << 8) | data[14]), ((data[17] << 8) | data[16]),
			((data[19] << 8) | data[18]), ((data[21] << 8) | data[20]),
			((data[23] << 8) | data[22])
	};

	uip_ipaddr_t dest = {
		((data[25] << 8) | data[24]),
		((data[27] << 8) | data[26]), ((data[29] << 8) | data[28]),
		((data[31] << 8) | data[30]), ((data[33] << 8) | data[32]),
		((data[35] << 8) | data[34]), ((data[37] << 8) | data[36]),
		((data[39] << 8) | data[38])
	};

	memcpy(ip_udp_header.srcipaddr, src, sizeof(uip_ipaddr_t));
	memcpy(ip_udp_header.destipaddr, dest, sizeof(uip_ipaddr_t));

	// construct the UDP header
	ip_udp_header.srcport = (uint16_t)((data[40] << 8) | data[41]);
	ip_udp_header.destport = (uint16_t)((data[42] << 8) | data[43]);
	ip_udp_header.udplen = (uint16_t)((data[44] << 8) | data[45]);
	ip_udp_header.udpchksum	= (uint16_t)((data[46] << 8) | data[47]);

	uint8_t udp_rule_id = schc_find_udp_rule_from_header(&ip_udp_header);

	if (udp_rule_id != 0) {
		*schc_offset += schc_build_udp_header(
				(unsigned char*) (schc_header + *schc_offset), &ip_udp_header,
				udp_rule_id);
	} else {
		memcpy((unsigned char*) (schc_header + *schc_offset),
					(uint8_t*) (data + IP6_HLEN), UDP_HLEN);
		*schc_offset += UDP_HLEN;
	}

	// find ipv6 rule
	uint8_t ipv6_rule_id = schc_find_ipv6_rule_from_header(&ip_udp_header);

	if (ipv6_rule_id != 0) {
		*schc_offset += schc_build_ipv6_header(
				(unsigned char*) (schc_header + *schc_offset), &ip_udp_header,
				ipv6_rule_id);
	} else {
		memcpy((unsigned char*) (schc_header + *schc_offset),
					(uint8_t*) data, IP6_HLEN);
		*schc_offset += IP6_HLEN;
	}

	return ((uint8_t) (ipv6_rule_id << NWL_SHIFT ^ udp_rule_id << TPL_SHIFT));

}

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
 * Find a matching rule for the CoAP header
 *
 * @param pdu the CoAP buffer
 * @param coap_field_length the number of fields the header exists of (!= number of bytes)
 *
 * @return the rule id
 *         0 if no rule is found
 */
static uint16_t schc_find_coap_rule_from_header(coap_pdu *pdu, uint8_t* coap_field_length) {
	uint16_t i = 0;
	// set to 0 when a rule doesn't match
	uint8_t rule_is_found = 1;
	uint8_t direction_field_length = 0;

	if(coap_validate_pkt(pdu) != CE_NONE) {
		return 0;
	}

	*coap_field_length = generate_coap_header_fields(pdu);

	int j; int k;
	for (i = 0; i < COAP_RULES; i++) {
		(DI == DOWN) ? (direction_field_length = schc_coap_rules[i]->down) : (direction_field_length = schc_coap_rules[i]->up);
		// save compare cycles by checking the number of the specified direction fields
		if (*coap_field_length == direction_field_length) {
			j = 0; k = 0;
			while (k < schc_coap_rules[i]->length) {
				// exclude fields in other direction
				if( (schc_coap_rules[i]->content[k].dir == BI) || (schc_coap_rules[i]->content[k].dir == DI)) {

					// compare header field and rule field using the matching operator
					if (!schc_coap_rules[i]->content[k].MO(&schc_coap_rules[i]->content[k],
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
				return schc_coap_rules[i]->rule_id;
			}
		}
	}

	return 0;
}

/**
 * Builds the compressed CoAP header
 *
 * @param schc_header the buffer to keep the compressed data in
 * @param pdu the CoAP message to compress
 * @param rule_id the rule to use while compressing
 *
 * @return the length of the compressed header
 *
 */
static uint8_t schc_build_coap_header(unsigned char* schc_header, coap_pdu *pdu,
		uint16_t rule_id) {
	uint8_t offset = 0; uint8_t field_length;

	if (rule_id != 0) {
		const struct schc_rule *rule = get_rule_by_id(rule_id, COAP_RULES, schc_coap_rules);

		field_length = generate_coap_header_fields(pdu);

		offset = compress(schc_header, coap_header_fields, MAX_COAP_FIELD_LENGTH, rule);
	}

	return offset;
}

/**
 * Decompress a CoAP rule, based on an input packet
 *
 * @param rule_id 		the id of the CoAP rule to use during the decompression
 * @param data 			pointer to the input data
 * @param header_offset pointer to the current offset in the decompressed header
 * @param msg 			pointer to the CoAP message to use during the reconstruction
 *
 */
static uint8_t decompress_coap_rule(struct schc_device* device_rules, uint8_t rule_id,
	unsigned char *data, uint8_t* header_offset, coap_pdu *msg) {
	 // ToDo
	// directly alter the packet buffer
	// or the coap_header buffer to save RAM


	// buffer to store decompressed values
	unsigned char coap_header[MAX_COAP_HEADER_LENGTH];

	// first number of bytes is always 4
	uint8_t byte_length = 4;

	if (rule_id != 0) {
		const struct schc_rule *rule = get_rule_by_id(rule_id, device_rules->coap_count,
				device_rules->coap_rules);
		if(rule == 0) {
			DEBUG_PRINTF("decompress_coap_rule(): no rule could be found with CoAP rule id %d", rule_id);
			return 0;
		}

		uint8_t coap_length = decompress(&coap_header, rule, data, header_offset);

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
	}

	return 1;
}

/**
 * Compress a CoAP header
 *
 * @param schc_header pointer to the header in which to save the compressed header
 * @param schc_offset pointer to the offset in the compressed header
 * @param coap_pdu the CoAP message
 *
 * @return the CoAP rule id
 * 		   error codes on error
 *
 */
static int16_t compress_coap_header(unsigned char *schc_header, uint8_t *schc_offset, const coap_pdu* coap_msg) {
	// check the buffer for determining the CoAP length
	uint16_t coap_length = get_coap_offset(coap_msg);

	if((coap_length + 1) > MAX_COAP_MSG_SIZE) {
		DEBUG_PRINTF("compress_coap_header: CoAP buffer too small, aborting..");
		return -1;
	}

	// the number of CoAP fields, as returned by the compressor
	uint8_t coap_fields = 0;
	uint8_t coap_rule_id = schc_find_coap_rule_from_header(coap_msg,
			&coap_fields);

	// compress the header if the rule is not 0
	if (coap_rule_id != 0) {
		*schc_offset += schc_build_coap_header(
				(unsigned char*) (schc_header + *schc_offset), coap_msg,
				coap_rule_id);
	} else {
		memcpy((unsigned char*) (schc_header + *schc_offset), coap_msg->buf,
				coap_length);
		*schc_offset += coap_length;
	}

	return coap_rule_id;
}

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

	printf("compare %s \n", target_field->field);

	for(i = 0; i < target_field->field_length; i++) {
		printf("%d - %d ", target_field->target_value[i], field_value[i]);
		if(target_field->target_value[i] != field_value[i]){
			return 0;
		}
		printf("\n");
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

/**
 * Get a set of rules based on a device id
 *
 * @param device id the device it's id
 *
 * @return device the set of rules found
 * 		   NULL if no device is found
 *
 */
static const struct schc_device* get_device_rules(uint32_t device_id) {
	int i = 0;

	for(i = 0; i < DEVICE_COUNT; i++) {
		if(devices[i]->id == device_id) {
			return devices[i];
		}
	}

	return NULL;
}

////////////////////////////////////////////////////////////////////////////////////
//                               GLOBAL FUNCIONS                                  //
////////////////////////////////////////////////////////////////////////////////////

/**
 * Initializes the SCHC compressor
 *
 * @param node_ip a pointer to the source it's ip address
 *
 * @return error codes on error
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
 * @param data 			pointer to the packet
 * @param buf			pointer to the compressed packet buffer
 * @param total_length 	the length of the packet
 *
 * @return the length of the compressed packet
 *         -1 on a memory overflow
 */

int16_t schc_compress(const uint8_t *data, uint8_t* buf, uint16_t total_length) {
	if (SERVER) {
		DI = DOWN;
	} else {
		DI = UP;
	}

	uint16_t schc_offset = RULE_SIZE_BYTES;
	uint16_t coap_length = 0;

	uint8_t coap_buf[MAX_COAP_MSG_SIZE] = { 0 };
	memcpy(coap_buf, (uint8_t*) (data + IP6_HLEN + UDP_HLEN), (total_length - IP6_HLEN - UDP_HLEN)); // copy CoAP header
	coap_pdu msg = { coap_buf, (total_length - IP6_HLEN - UDP_HLEN), MAX_COAP_MSG_SIZE };

	memset(buf, 0, total_length);

	// check the buffer for determining the CoAP length
	coap_length = get_coap_offset(&msg);
	uint16_t payload_len = (total_length - IP6_HLEN - UDP_HLEN - coap_length);

	int16_t coap_rule_id = compress_coap_header(buf, &schc_offset, &msg);
	if(coap_rule_id < 0) {
		DEBUG_PRINTF("schc_output: something went wrong compressing the CoAP header, aborting..");
		return -1;
	}

	int16_t udpip_rule_id = compress_udp_ip_header(buf, &schc_offset, data);

	// construct the new rule by merging the rules from the different layers
	uint8_t rule_field = 0;
	rule_field = udpip_rule_id ^ (coap_rule_id << APL_SHIFT);

	// add the rule id to the front of the buffer
	memcpy(&buf[0], &rule_field, RULE_SIZE_BYTES);

    int8_t is_fragmented = 0;

    // add fragmentation bit, will be changed when fragmented
    buf[0] = (buf[0] | ((is_fragmented << FRAG_SHIFT) & FRAG_MASK));

    printf("\n");
    printf("+---------------------------------+\n");
    printf("|          SCHC Header            |\n");
    printf("+---------------------------------+\n");

    int i;
    for(i = 0; i < schc_offset; i++) {
    	printf("%02X ", buf[i]);
    }

    printf("\n\n");
    printf("Rule id: %d (0x%02X) = | %d | %d | %d | %d | \n\n", buf[0], buf[0], is_fragmented, coap_rule_id,
            (rule_field & TPL_MASK) >> TPL_SHIFT, (rule_field & NWL_MASK) >> NWL_SHIFT);

	uint8_t* payload_ptr = (data + IP6_HLEN + UDP_HLEN + coap_length);
    memcpy((uint8_t*) (buf + schc_offset), payload_ptr, payload_len);

    uint16_t new_pkt_length = (schc_offset + payload_len);
	for(i = 0; i < new_pkt_length; i++) {
		printf("%02X ", buf[i]);
	}

    printf("\nCompressed packet length %d \n\n", new_pkt_length);
	// return the new length of the packet
	return new_pkt_length;
}

/**
 * Construct the header from the layered set of rules
 *
 * @param data 			pointer to the received data
 * @param header 		pointer where to save the decompressed header
 * @param device_id 	the device its id
 * @param total_length 	the total length of the received data
 * @param header_offset an integer pointing to the current offset in the compressed header
 *
 * @return 	the length of the newly constructed header
 * 			0 one of the rules was not found
 */
uint16_t schc_construct_header(unsigned char* data, unsigned char *header,
	uint32_t device_id, uint16_t total_length, uint8_t *header_offset) {
	uint8_t rule_id;

	rule_id = *(data + 0);

	uint8_t ipv6_rule_id = (rule_id & NWL_MASK) >> NWL_SHIFT;
	uint8_t udp_rule_id = (rule_id & TPL_MASK) >> TPL_SHIFT;
	uint8_t coap_rule_id = (rule_id & APL_MASK) >> APL_SHIFT;
	uint8_t is_fragmented = (rule_id & FRAG_MASK) >> FRAG_SHIFT;

	DEBUG_PRINTF("\n");
	DEBUG_PRINTF("Rule id: %d (0x%02X) = | %d | %d | %d | %d | \n", rule_id, rule_id, is_fragmented, coap_rule_id,
	            udp_rule_id, ipv6_rule_id);

	uint8_t* payload = (uint8_t *) (data + RULE_SIZE_BYTES);
	uint8_t payload_length = total_length - RULE_SIZE_BYTES;

	// first we look for the device it's rules
	struct schc_device* device_rules = get_device_rules(device_id);

	uint8_t coap_offset = 0;
	uint8_t ret = 0;

	// CoAP buffers for parsing
	uint8_t msg_recv_buf[MAX_COAP_MSG_SIZE];
	coap_pdu msg = { msg_recv_buf, 0, MAX_COAP_MSG_SIZE };

	// grab CoAP rule and decompress
	if (coap_rule_id != 0) {
		ret = decompress_coap_rule(device_rules, coap_rule_id, data, header_offset, &msg);
		if(ret == 0) {
			return 0; // no rule was found
		}
		coap_offset = msg.len;
	} else { // grab uncompressed CoAP header
		msg.len = 4; // we validate the CoAP packet, which also uses the length of the header
		memcpy(msg.buf, (uint8_t*) payload, payload_length);
		coap_offset = get_coap_offset(&msg);
		*header_offset += coap_offset; // the length of the CoAP header
	}

	memcpy((unsigned char*) (header + (IP6_HLEN + UDP_HLEN)), msg.buf, coap_offset); // grab the CoAP header from the CoAP buffer

	// search udp rule
	if (udp_rule_id != 0) {
		ret = decompress_udp_rule(device_rules, udp_rule_id, data, header, header_offset);
		if (ret == 0) {
			return 0; // no rule was found
		}
	} else { // copy the uncompressed udp header
		uint8_t *udp_ptr = (uint8_t *) (payload + *header_offset);

		memcpy((unsigned char*) (header + IP6_HLEN), udp_ptr, UDP_HLEN);
		*header_offset += UDP_HLEN;
	}

	// look for ipv6 rule
	if (ipv6_rule_id != 0) {
		ret = decompress_ipv6_rule(device_rules, ipv6_rule_id, data, header, header_offset);
		if (ret == 0) {
			return 0; // no rule was found
		}
	} else { // copy the uncompressed ipv6 rule from the schc header
		memcpy((unsigned char*) (header), (uint8_t *) (payload + *header_offset), IP6_HLEN);
		*header_offset += IP6_HLEN;
	}
/*
	printf("\n");
	printf("+-----------------------------------------+\n");
	printf("|          Decompressed Header            |\n");
	printf("+-----------------------------------------+\n");

	int i;
	for (i = 0; i < IP6_HLEN + UDP_HLEN + coap_offset; i++) {
		printf("%02X ", header[i]);
	}

	printf("\n\n");
*/

	return (IP6_HLEN + UDP_HLEN + coap_offset);
}

/**
 * Set the packet length for the UDP and IP headers
 *
 * @param data pointer to the data packet
 * @param data_len the length of the total packet
 *
 * @return 0
 *
 */
uint16_t compute_length(unsigned char *data, uint16_t data_len) {
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

// ToDo
// is this the only way how we can integrate
// on both server and client?
#if CLICK
ELEMENT_PROVIDES(schcCOMPRESSOR)
ELEMENT_REQUIRES(schcJSON schcCOAP)
#endif
