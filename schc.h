#ifndef COMPRESSOR_CONFIG_H_
#define COMPRESSOR_CONFIG_H_

#include "schc_config.h"

// protocol definitions
#define UDP_HLEN				8
#define IP6_HLEN				40

// fixed fragmentation definitions
#define WINDOW_SIZE_BITS		1
#define MIC_C_SIZE_BITS			1

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

typedef struct schc_bitarray_t {
	uint8_t* ptr;
	uint32_t offset; // in bits
	uint8_t padding;
	uint16_t len; // in bytes
} schc_bitarray_t;

typedef enum {
	IPv6_V,
	IPv6_TC,
	IPv6_FL,
	IPv6_LEN,
	IPv6_NH,
	IPv6_HL,
	IPv6_SRCPRF,
	IPv6_SRCIID,
	IPv6_DSTPRF,
	IPv6_DSTIID
} IPv6_fields;

typedef enum {
	UDP_SRC,
	UDP_DST,
	UDP_LEN,
	UDP_CHK
} UDP_fields;

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
	SCHC_IPV6 = 0,
	SCHC_UDP = 1,
	SCHC_COAP = 2
} schc_layer_t;

typedef enum {
	ACK_ALWAYS = 1, ACK_ON_ERROR = 2, NO_ACK = 3, NOT_FRAGMENTED = 4
} reliability_mode;

struct schc_field {
	char field[32];
	uint8_t MO_param_length; // indicate number of bits for MSB and LSB or list length for MATCH-MAP
	uint8_t field_length; // in bits
	uint8_t field_pos;
	direction dir;
	unsigned char target_value[MAX_FIELD_LENGTH];
	uint8_t (*MO)(struct schc_field* target_field, unsigned char* field_value, uint16_t field_offset);
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
	uint8_t id[RULE_SIZE_BYTES];
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

typedef uint8_t schc_ip6addr_t[16];
typedef schc_ip6addr_t schc_ipaddr_t;

struct schc_udpip_hdr {
  /* IPv6 header. */
  uint8_t vtc,
    tcf;
  uint16_t flow;
  uint8_t len[2];
  uint8_t proto, ttl;
  schc_ip6addr_t srcipaddr, destipaddr;

  /* UDP header. */
  uint16_t srcport,
    destport;
  uint16_t udplen;
  uint16_t udpchksum;
};

static uint8_t equal(struct schc_field* target_field, unsigned char* field_value, uint16_t field_offset);
static uint8_t ignore(struct schc_field* target_field, unsigned char* field_value, uint16_t field_offset);
static uint8_t MSB(struct schc_field* target_field, unsigned char* field_value, uint16_t field_offset);
static uint8_t matchmap(struct schc_field* target_field, unsigned char* field_value, uint16_t field_offset);

#endif
