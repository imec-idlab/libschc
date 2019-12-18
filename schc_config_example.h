#ifndef SCHC_CONFIG_H_
#define SCHC_CONFIG_H_

#include <unistd.h>
#include <inttypes.h>

#define CLICK					0
#define SCHC_BUFSIZE			256

#define DYNAMIC_MEMORY			0

#define SCHC_CONF_RX_CONNS		1
#define SCHC_CONF_MBUF_POOL_LEN	8

#define USE_COAP				1
#define USE_UDP					1
#define USE_IPv6				1

#define NUMBER_OF_LAYERS		USE_COAP + USE_UDP + USE_IPv6

// maximum number of header fields present in a rule (vertical, top to bottom)
#define IPV6_FIELDS				10
#define UDP_FIELDS				4
#define COAP_FIELDS				12

// the number of bytes a field can contain
// (e.g. UDP is max 2 bytes) (horizontal, contents of a rule field)
#define MAX_IPV6_FIELD_LENGTH	8
#define MAX_UDP_FIELD_LENGTH	2
#define MAX_COAP_FIELD_LENGTH	32

#define MAX_HEADER_LENGTH		256

#define MAX_COAP_HEADER_LENGTH	64
#define MAX_PAYLOAD_LENGTH		256
#define MAX_COAP_MSG_SIZE		(MAX_COAP_HEADER_LENGTH + MAX_PAYLOAD_LENGTH)

// the maximum transfer unit of the underlying technology
#define MAX_MTU_LENGTH			160

// the maximum number of tokens inside a JSON structure
#define JSON_TOKENS				16

#define RULE_SIZE_BITS			8

#define UNCOMPRESSED_RULE_ID	0

#define DEBUG_PRINTF(...) 		printf(__VA_ARGS__) //log_print_string(__VA_ARGS__)

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

typedef enum {
	ACK_ALWAYS = 1, ACK_ON_ERROR = 2, NO_ACK = 3, NOT_FRAGMENTED = 4
} reliability_mode;

#endif
