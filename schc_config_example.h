#ifndef __SCHC_CONFIG_H__
#define __SCHC_CONFIG_H__

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>

#define CLICK							0

#define DYNAMIC_MEMORY					0
#define STATIC_MEMORY_BUFFER_LENGTH		1024

#define SCHC_CONF_RX_CONNS				1
#define SCHC_CONF_MBUF_POOL_LEN			128

#define USE_COAP						1
#define USE_IP6_UDP						1

/* the maximum length of a single header field
 * e.g. you can use 4 ipv6 source iid addresses with match-mapping */
#define MAX_FIELD_LENGTH				32

/* maximum number of header fields present in a rule (vertical, top to bottom) */
#define IP6_FIELDS						14
#define UDP_FIELDS						4
#define COAP_FIELDS						16

#define MAX_HEADER_LENGTH				256

#define MAX_COAP_HEADER_LENGTH			64
#define MAX_PAYLOAD_LENGTH				256
#define MAX_COAP_MSG_SIZE				(MAX_COAP_HEADER_LENGTH + MAX_PAYLOAD_LENGTH)

/* the maximum transfer unit of the underlying technology */
#define MAX_MTU_LENGTH					242

/* the maximum number of tokens inside a JSON structure */
#define JSON_TOKENS						16

#define DEBUG_PRINTF(...) 				printf(__VA_ARGS__)

/* the number of ack attempts */
#define MAX_ACK_REQUESTS				3

/* the number of FCN bits */
#define FCN_SIZE_BITS					3

/* the number of DTAG bits */
#define DTAG_SIZE_BITS					0

/* the number of bytes the MIC consists of */
#define MIC_SIZE_BYTES					4

// the length of the bitmap
#define BITMAP_SIZE_BYTES				2 // pow(2, FCN_SIZE_BITS) / 8

#endif
