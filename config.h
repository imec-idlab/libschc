#ifndef COMPRESSOR_CONFIG_H_
#define COMPRESSOR_CONFIG_H_

#include "schc_config.h"

// protocol definitions
#define UDP_HLEN				8
#define IP6_HLEN				40

// total number of CoAP options available
#define COAP_OPTIONS_LENGTH		16 // .. actually a picocoap variable

// fixed fragmentation definitions
#define WINDOW_SIZE_BITS		1
#define MIC_C_SIZE_BITS			1

typedef enum {
	UP = 0, DOWN = 1, BI = 2
} direction;

typedef enum {
	NETWORK_GATEWAY = 0, DEVICE = 1
} device_type;

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

// specific protocol layer structure
#if USE_IPv6
struct schc_ipv6_rule_t {
	uint16_t rule_id;
	uint8_t up;
	uint8_t down;
	uint8_t length;
	struct schc_field content[IPV6_FIELDS];
};
#endif

#if USE_UDP
struct schc_udp_rule_t {
	uint16_t rule_id;
	uint8_t up;
	uint8_t down;
	uint8_t length;
	struct schc_field content[UDP_FIELDS];
};
#endif

#if USE_COAP
struct schc_coap_rule_t {
	uint16_t rule_id;
	uint8_t up;
	uint8_t down;
	uint8_t length;
	struct schc_field content[COAP_FIELDS];
};
#endif

// structure to allow generic compression of each layer
struct schc_layer_rule_t {
	uint16_t rule_id;
	uint8_t up;
	uint8_t down;
	uint8_t length;
	struct schc_field content[];
};

struct schc_compression_rule_t {
#if USE_IPv6
	/* a pointer to the IPv6 rule */
	const struct schc_ipv6_rule_t* ipv6_rule;
#endif
#if USE_UDP
	/* a pointer to the UDP rule */
	const struct schc_udp_rule_t* udp_rule;
#endif
#if USE_COAP
	/* a pointer to the CoAP rule */
	const struct schc_coap_rule_t* coap_rule;
#endif
};

struct schc_rule_t {
	/* the rule id */
	uint8_t id;
	/* a pointer to the SCHC rule */
	const struct schc_compression_rule_t *compression_rule;
	/* the reliability mode */
	reliability_mode mode;
	/* the fcn size in bits */
	uint8_t FCN_SIZE;
	/* the maximum number of fragments per window */
	uint8_t MAX_WND_FCN;
	/* the window size in bits */
	uint8_t WINDOW_SIZE;
	/* the dtag size in bits */
	uint8_t DTAG_SIZE;
};

struct schc_device {
	/* the device id (e.g. EUI) */
	uint32_t device_id;
	/* the total number of rules for a device */
	uint8_t rule_count;
	/* a pointer to the collection of rules for a device */
	const struct schc_rule_t *(*context)[];
};

typedef uint16_t schc_ip6addr_t[8];
typedef schc_ip6addr_t schc_ipaddr_t;

struct schc_udpip_hdr {
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
