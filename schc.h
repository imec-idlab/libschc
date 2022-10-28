#ifndef __SCHC_H__
#define __SCHC_H__

#include "schc_config.h"

// protocol definitions
#define UDP_HLEN				8
#define IP6_HLEN				40

// UDP can only be used in conjunction with IPv6
#define USE_UDP					USE_IP6_UDP
#define USE_IP6					USE_IP6_UDP

#define NUMBER_OF_LAYERS		USE_COAP + USE_UDP + USE_IP6

// fixed fragmentation definitions
#define WINDOW_SIZE_BITS		1
#define MIC_C_SIZE_BITS			1
/* maximum number of bytes a rule id can take */
#define RULE_SIZE_BYTES			4
/* maximum number of bytes the ACK DTAG field can be */
#define DTAG_SIZE_BYTES			1
/* maximum number of bytes the ACK W field can be */
#define WINDOW_SIZE_BYTES		1

typedef struct schc_bitarray_t {
	uint8_t* ptr;
	uint32_t offset; // in bits
	uint8_t padding;
	uint16_t len; // in bytes
	uint32_t bit_len;
} schc_bitarray_t;

#define SCHC_DEFAULT_BIT_ARRAY(_len, _ptr) \
{ \
	.ptr = (_ptr), \
	.offset = 0, \
	.padding = 0, \
	.len = (_len), \
	.bit_len = (_len * 8), \
}

typedef enum {
	COAP_IFMATCH = 1,
	COAP_URIHOST = 3,
	COAP_ETAG = 4,
	COAP_IFNOMATCH = 5,
	COAP_URIPORT = 7,
	COAP_LOCPATH = 8,
	COAP_URIPATH = 11,
	COAP_CONTENTF = 12,
	COAP_MAXAGE = 14,
	COAP_URIQUERY = 15,
	COAP_ACCEPT = 17,
	COAP_LOCQUERY = 20,
	COAP_PROXYURI = 35,
	COAP_PROXYSCH = 39,
	COAP_SIZE1 = 60,
	COAP_NORESP = 258,
	COAP_OPTIONS_MAX = 259 /* set this to the largest CoAP option value + 1 */
} COAPO_fields;

typedef enum {
	IP6_V = 1024, /* this must be larger than the largest CoAP Option Value in order not to interfere with it */
	IP6_TC,
	IP6_FL,
	IP6_LEN,
	IP6_NH,
	IP6_HL,
	IP6_DEVPRE,
	IP6_DEVIID,
	IP6_APPPRE,
	IP6_APPIID,
	UDP_DEV,
	UDP_APP,
	UDP_LEN,
	UDP_CHK,
	COAP_V,
	COAP_T,
	COAP_TKL,
	COAP_C,
	COAP_MID,
	COAP_TKN,
	COAP_PAYLOAD
} schc_header_fields;

static const char * const schc_header_field_names[] = {
	[IP6_V] = "IPv6 Version",
	[IP6_TC] = "IPv6 Traffic Class",
	[IP6_FL] = "IPv6 Field Length",
	[IP6_LEN] = "IPv6 Length",
	[IP6_NH] = "IPv6 Next Header",
	[IP6_HL] = "IPv6 Hop Limit",
	[IP6_DEVPRE] = "IPv6 Device Prefix",
	[IP6_DEVIID] = "IPv6 Device IID",
	[IP6_APPPRE] = "IPv6 Application Prefix",
	[IP6_APPIID] = "IPv6 Application IID",
	[UDP_DEV] = "UDP Device Port",
	[UDP_APP] = "UDP Application Port",
	[UDP_LEN] = "UDP Length",
	[UDP_CHK] = "UDP Checksum",
	[COAP_V] = "CoAP Version",
	[COAP_T] = "CoAP Type",
	[COAP_TKL] = "CoAP Token Length",
	[COAP_C] = "CoAP Code",
	[COAP_MID] = "CoAP Message ID",
	[COAP_TKN] = "CoAP Token",
	[COAP_PAYLOAD] = "CoAP Payload Marker"
};

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
	ACK_ALWAYS = 1, ACK_ON_ERROR = 2, NO_ACK = 3, NOT_FRAGMENTED = 4, MAX_RELIABILITY_MODES
} reliability_mode;

struct schc_field {
	uint16_t field;
	uint8_t MO_param_length; // indicate number of bits for MSB and LSB or list length for MATCH-MAP
	uint8_t field_length; // in bits
	uint8_t field_pos;
	direction dir;
	unsigned char target_value[MAX_FIELD_LENGTH];
	uint8_t (*MO)(struct schc_field* target_field, unsigned char* field_value, uint16_t field_offset);
	CDA action;
};

// specific protocol layer structure
#if USE_IP6 == 1
struct schc_ipv6_rule_t {
	uint8_t up;
	uint8_t down;
	uint8_t length;
	struct schc_field content[IP6_FIELDS];
};
#endif

#if USE_UDP == 1
struct schc_udp_rule_t {
	uint8_t up;
	uint8_t down;
	uint8_t length;
	struct schc_field content[UDP_FIELDS];
};
#endif

#if USE_COAP == 1
struct schc_coap_rule_t {
	uint8_t up;
	uint8_t down;
	uint8_t length;
	struct schc_field content[COAP_FIELDS];
};
#endif

// structure to allow generic compression of each layer
struct schc_layer_rule_t {
	uint8_t up;
	uint8_t down;
	uint8_t length;
	struct schc_field content[];
};

struct schc_compression_rule_t {
	/* the rule id, can be maximum 4 bytes wide, defined by the profile */
	uint32_t rule_id;
	/* the rule id size in bits */
	uint8_t rule_id_size_bits;
#if USE_IP6 == 1
	/* a pointer to the IPv6 rule */
	const struct schc_ipv6_rule_t* ipv6_rule;
#endif
#if USE_UDP == 1
	/* a pointer to the UDP rule */
	const struct schc_udp_rule_t* udp_rule;
#endif
#if USE_COAP == 1
	/* a pointer to the CoAP rule */
	const struct schc_coap_rule_t* coap_rule;
#endif
};

struct schc_fragmentation_rule_t {
	/* the rule id, can be maximum 4 bytes wide, defined by the profile */
	uint32_t rule_id;
	/* the rule id size in bits */
	uint8_t rule_id_size_bits;
	/* the reliability mode */
	reliability_mode mode;
	/* the direction */
	direction dir;
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
	/* the rule id to use when a packet remains uncompressed */
	uint32_t uncomp_rule_id;
	/* the rule id size when a packet remains uncompressed in bits */
	uint8_t uncomp_rule_id_size_bits;
	/* the total number of compression rules for a device */
	uint8_t compression_rule_count;
	/* a pointer to the collection of compression rules for a device */
	const struct schc_compression_rule_t *(*compression_context)[];
	/* the total number of fragmentation rules for a device */
	uint8_t fragmentation_rule_count;
	/* a pointer to the collection of compression rules for a device */
	const struct schc_fragmentation_rule_t *(*fragmentation_context)[];
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

uint8_t mo_equal(struct schc_field* target_field, unsigned char* field_value, uint16_t field_offset);
uint8_t mo_ignore(struct schc_field* target_field, unsigned char* field_value, uint16_t field_offset);
uint8_t mo_MSB(struct schc_field* target_field, unsigned char* field_value, uint16_t field_offset);
uint8_t mo_matchmap(struct schc_field* target_field, unsigned char* field_value, uint16_t field_offset);

struct schc_device* get_device_by_id(uint32_t device_id);
void uint32_rule_id_to_uint8_buf(uint32_t rule_id, uint8_t* out, uint8_t len);
uint8_t rm_revise_rule_context(void);

#endif
