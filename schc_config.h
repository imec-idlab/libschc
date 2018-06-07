#ifndef SCHC_CONFIG_H_
#define SCHC_CONFIG_H_

#include "coap.h"

#include <unistd.h>
#include <inttypes.h>

#define SCHC_CONF_RX_CONNS		10
#define UIP_CONF_IPV6			1

#define MAX_COAP_MSG_SIZE		256
#define COAP_OPTIONS_LENGTH		15

#define UDP_HLEN				8
#define IP6_HLEN				40

// dependent on underlying technology
#define MAX_FRAG_HEADER_SIZE	8

// ToDo
// check decompression header buffers for overflow
#define MAX_MTU_LENGTH			51
#define MAX_COAP_HEADER_LENGTH	64

// maximum number of header fields (vertical, top to bottom)
#define UDP_FIELDS				4
#define IPV6_FIELDS				10
#define COAP_FIELDS				16

// the number of bytes a field can contain (e.g. UDP is max 2 bytes) (horizontal, contents of a rule field)
#define MAX_IPV6_FIELD_LENGTH	8
#define MAX_UDP_FIELD_LENGTH	2
#define MAX_COAP_FIELD_LENGTH	32

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

typedef struct fragmentation_t {
	uint32_t device_id;
	uint16_t mtu;
	uint8_t* headerptr;
	uint8_t headerlen;
	uint8_t* headertailptr;
	uint8_t* payloadptr;
	uint16_t payloadlen;
	uint8_t* payloadtailptr;
	uint8_t fragheadsize;
	uint8_t ruleid;
	uint8_t fcn;
	reliability_mode reliablitymode; // todo this is part of the rule id
	uint8_t MIC[4];
	struct pt* pt;
} fragmentation_t;

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
#if UIP_CONF_IPV6
  /* IPv6 header. */
  uint8_t vtc,
    tcf;
  uint16_t flow;
  uint8_t len[2];
  uint8_t proto, ttl;
  uip_ip6addr_t srcipaddr, destipaddr;
#else /* UIP_CONF_IPV6 */
  /* IP header. */
  uint8_t vhl,
    tos,
    len[2],
    ipid[2],
    ipoffset[2],
    ttl,
    proto;
  uint16_t ipchksum;
  uint16_t srcipaddr[2],
    destipaddr[2];
#endif /* UIP_CONF_IPV6 */

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
