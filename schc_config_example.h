#ifndef SCHC_CONFIG_H_
#define SCHC_CONFIG_H_

#define SCHC_CONF_RX_CONNS		2
#define UIP_CONF_IPV6			1

#define MAX_COAP_HEADER_LENGTH	64
#define MAX_PAYLOAD_LENGTH		192
#define MAX_COAP_MSG_SIZE		(MAX_COAP_HEADER_LENGTH + MAX_PAYLOAD_LENGTH)

// the maximum transfer unit of the underlying technology
#define MAX_MTU_LENGTH			51

// maximum number of header fields present in a rule (vertical, top to bottom)
#define UDP_FIELDS				4
#define IPV6_FIELDS				10
#define COAP_FIELDS				10

// the number of bytes a field can contain
// (e.g. UDP is max 2 bytes) (horizontal, contents of a rule field)
#define MAX_COAP_FIELD_LENGTH	32

// the maximum number of tokens inside a JSON structure
#define JSON_TOKENS				16

/*
 * define the number of bits to shift in order
 * for the layered rule header (1 byte)
 * to look as follows
 *    0     1     2    3     4     5    6     7
 * +-----+-----+-----+-----+----+----+-----+-----+
 * |  F  | APL | APL | APL | TL | TL | NWL | NWL |
 * +-----+-----+-----+-----+----+----+-----+-----+
 */

// ToDo
// can be calculated
#define NWL_SHIFT				0
#define NWL_MASK				3

#define TPL_SHIFT				2
#define TPL_MASK				12

#define APL_SHIFT				4
#define APL_MASK				112

#define FRAG_SHIFT				7
#define FRAG_MASK				128

#define DEBUG_PRINTF(...) 		log_print_string(__VA_ARGS__)
#define SERVER 					0

#endif
