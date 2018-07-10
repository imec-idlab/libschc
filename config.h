#ifndef COMPRESSOR_CONFIG_H_
#define COMPRESSOR_CONFIG_H_

#include "schc_config.h"

/**
 * Return code: No error. Indicates successful completion of an SCHC
 * operation.
 */
#define SCHC_SUCCESS 			0

/**
 * Return code: Error. Generic indication that an SCHC operation went wrong
 */
#define SCHC_FAILURE			-1

/**
 * Return code: Error. Generic indication that no fragmentation was needed
 */
#define SCHC_NO_FRAGMENTATION	-2

// protocol definitions
#define UDP_HLEN				8
#define IP6_HLEN				40

// total number of CoAP options available
#define COAP_OPTIONS_LENGTH		15

// the number of bytes a field can contain
// (e.g. UDP is max 2 bytes) (horizontal, contents of a rule field)
#define MAX_IPV6_FIELD_LENGTH	8
#define MAX_UDP_FIELD_LENGTH	2

// fixed fragmentation definitions
#define WINDOW_SIZE_BITS		1

typedef enum {
	UP = 0, DOWN = 1, BI = 2
} direction;

typedef enum {
	NOTSENT = 0,
	VALUESENT = 1,
	MAPPINGSENT = 2,
	LSB = 3,
	COMPLENGTH = 4,
	COMPCHK = 5,
	DEVIID = 6,
	APPIID = 7
} CDA;

typedef enum {
	NOACK = 0, ACKALWAYS = 1, ACKONERROR = 2
} reliability_mode;

struct schc_field {
	char field[32];
	uint8_t msb_length; // custom added field
	uint8_t field_length;
	uint8_t field_pos;
	direction dir;
	unsigned char target_value[MAX_COAP_FIELD_LENGTH];
	uint8_t (*MO)(struct schc_field* target_field, unsigned char* field_value);
	CDA action;
};

// ToDo
// make struct for each layer to save space
// only CoAP is of variable length
// now we need maximum CoAP fields for UDP rule (factor 8)
struct schc_rule {
	uint16_t rule_id;
	uint8_t up;
	uint8_t down;
	uint8_t length;
	struct schc_field content[COAP_FIELDS];
};

struct schc_device {
	uint32_t id;
	uint8_t ipv6_count;
	const struct schc_rule* ipv6_rules;
	uint8_t udp_count;
	const struct schc_rule* udp_rules;
	uint8_t coap_count;
	const struct schc_rule* coap_rules;
};

typedef uint16_t uip_ip6addr_t[8];
typedef uip_ip6addr_t uip_ipaddr_t;

struct uip_udpip_hdr {
  /* IPv6 header. */
  uint8_t vtc,
    tcf;
  uint16_t flow;
  uint8_t len[2];
  uint8_t proto, ttl;
  uip_ip6addr_t srcipaddr, destipaddr;

  /* UDP header. */
  uint16_t srcport,
    destport;
  uint16_t udplen;
  uint16_t udpchksum;
};

static uint8_t equal(struct schc_field* target_field, unsigned char* field_value);
static uint8_t ignore(struct schc_field* target_field, unsigned char* field_value);
static uint8_t MSB(struct schc_field* target_field, unsigned char* field_value);
static uint8_t matchmap(struct schc_field* target_field, unsigned char* field_value);

#endif
