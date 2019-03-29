#ifndef SCHC_CONFIG_H_
#define SCHC_CONFIG_H_

#include <unistd.h>
#include <inttypes.h>

#define CLICK					0

#define DYNAMIC_MEMORY			0
#define SCHC_BUFSIZE 			256

#define SCHC_CONF_RX_CONNS		1
#define SCHC_CONF_MBUF_POOL_LEN	8

#define MAX_HEADER_LENGTH		256

#define MAX_COAP_HEADER_LENGTH	64
#define MAX_PAYLOAD_LENGTH		256
#define MAX_COAP_MSG_SIZE		(MAX_COAP_HEADER_LENGTH + MAX_PAYLOAD_LENGTH)

// the maximum transfer unit of the underlying technology
#define MAX_MTU_LENGTH			160

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
 * for the layered rule header to look as follows
 *
 *    0     1     2    3     4     5    6     7
 * +-----+-----+-----+-----+----+----+-----+-----+
 * |  F  | APL | APL | APL | TL | TL | NWL | NWL |
 * +-----+-----+-----+-----+----+----+-----+-----+
 */

#define RULE_SIZE_BITS			8

// ToDo
// can be calculated

// NETWORK LAYER
#define NWL_SHIFT				0
#define NWL_MASK				3

// TRANSPORT LAYER
#define TPL_SHIFT				2
#define TPL_MASK				12

// APPLICATION LAYER
#define APL_SHIFT				4
#define APL_MASK				112

// FRAGMENTATION BIT
#define FRAG_SHIFT				7 // ToDo: refactor
#define FRAG_MASK				128 // ToDo: refactor

#define FRAG_POS				0 // todo remove

#define DEBUG_PRINTF(...) 		//log_print_string(__VA_ARGS__)
#define SERVER 					0

// the number of ack attempts
#define MAX_ACK_REQUESTS		3

// the number of FCN bits
#define FCN_SIZE_BITS			3

// the maximum number of fragments per window
#define MAX_WIND_FCN			6

// the number of DTAG bits
#define DTAG_SIZE_BITS			0

// the number of bytes the MIC consists of
#define MIC_SIZE_BYTES			4

// the length of the bitmap
#define BITMAP_SIZE_BYTES		2 // pow(2, FCN_SIZE_BITS) / 8

#if !(RULE_SIZE_BITS % 8)
#define RULE_SIZE_BYTES			(RULE_SIZE_BITS / 8)
#else
#define RULE_SIZE_BYTES			(RULE_SIZE_BITS / 8) + 1
#endif

#if !(((RULE_SIZE_BITS + DTAG_SIZE_BITS) / 8) % 8)
#define DTAG_SIZE_BYTES			((RULE_SIZE_BITS + DTAG_SIZE_BITS) / 8)
#else
#define DTAG_SIZE_BYTES			((RULE_SIZE_BITS + DTAG_SIZE_BITS) / 8) + 1
#endif

#if !(((RULE_SIZE_BITS + DTAG_SIZE_BITS + WINDOW_SIZE_BITS) / 8) % 8)
#define WINDOW_SIZE_BYTES		1
#else
#define WINDOW_SIZE_BYTES		((RULE_SIZE_BITS + DTAG_SIZE_BITS + WINDOW_SIZE_BITS) / 8) + 1
#endif


#endif
