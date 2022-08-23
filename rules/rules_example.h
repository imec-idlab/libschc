#include "../schc.h"

#if USE_IP6
const static struct schc_ipv6_rule_t ipv6_rule1 = {
	//	id, up, down, length
		1, 10, 10, 14,
		{
			//	field, 			   MO, len,	 pos,dir, 	val,			MO,			CDA
				{ "version", 		0, 4,	1, BI, 		{6},			&mo_equal, 		NOTSENT },
				{ "traffic class", 	0, 8,	1, BI, 		{0},			&mo_ignore, 	NOTSENT },
				{ "flow label", 	0, 20,	1, BI, 		{0, 0, 0},		&mo_ignore, 	NOTSENT },
				{ "length", 		0, 16,	1, BI, 		{0, 0},			&mo_ignore, 	COMPLENGTH },
				{ "next header", 	3, 8, 	1, BI, 		{6, 17, 58},	&mo_matchmap, 	MAPPINGSENT },
				{ "hop limit", 		0, 8, 	1, BI, 		{64}, 			&mo_ignore, 	NOTSENT },
				{ "src prefix",		4, 64,	1, UP,		{0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
														 0xBB, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
														 0xCC, 0xCC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
														 0xDD, 0xDD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&mo_matchmap, 	MAPPINGSENT }, // you can store as many IP's as (MAX_FIELD_LENGTH / 8)
				{ "src prefix",		4, 64,	1, DOWN,	{0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
														 0xBB, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
														 0xCC, 0xCC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
														 0xDD, 0xDD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&mo_matchmap, 	MAPPINGSENT }, // you can store as many IP's as (MAX_FIELD_LENGTH / 8)
				{ "src iid",		60, 64,	1, UP, 		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
						&mo_MSB, 		LSB },
				{ "src iid",		60, 64,	1, DOWN, 	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
										&mo_MSB, 		LSB },
				{ "dest prefix",	0, 64,	1, UP,		{0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&mo_equal, 		NOTSENT },
				{ "dest prefix",	0, 64,	1, DOWN,	{0xCC, 0xCC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&mo_equal, 		NOTSENT },
				{ "dest iid",		60, 64,	1, UP, 		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
						&mo_MSB, 		LSB }, // match the 60 first bits, send the last 4
				{ "dest iid",		60, 64,	1, DOWN, 	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
						&mo_MSB, 		LSB }, // match the 60 first bits, send the last 4
		}
};

const static struct schc_ipv6_rule_t ipv6_rule2 = {
		2, 10, 10, 10,
		{
				{ "version", 		0,  4,	 1, BI, 	{6},			&mo_equal, 	NOTSENT },
				{ "traffic class", 	0,  8,	 1, BI, 	{0},			&mo_equal, 	NOTSENT },
				{ "flow label", 	0,  20,	 1, BI, 	{0, 0, 0x20},	&mo_equal, 	NOTSENT },
				{ "length", 		0,  16,	 1, BI, 	{0, 0},			&mo_ignore, 	COMPLENGTH },
				{ "next header", 	0,  8, 	 1, BI, 	{17}, 			&mo_equal, 	NOTSENT },
				{ "hop limit", 		0,  8, 	 1, BI, 	{64}, 			&mo_ignore, 	NOTSENT },
				{ "src prefix",	 	0,  64,	 1, BI, 	{0x20, 0x01, 0x06, 0xA8, 0x1D, 0x80, 0x20, 0x21},
						&mo_equal, 	NOTSENT },
				{ "src iid",		16, 64,  1, BI, 	{0x02, 0x30, 0x48, 0xFF, 0xFE, 0x5A, 0x00, 0x00},
						&mo_MSB, 	LSB }, // match the 16 first bits, send the last 48
				{ "dest prefix",	0,  64,  1, BI, 	{0x20, 0x01, 0x06, 0xA8, 0x1D, 0x80, 0x20, 0x21},
						&mo_equal, 	NOTSENT },
				{ "dest iid",		16, 64,  1, BI, 	{0x50, 0x74, 0xF2, 0xFF, 0xFE, 0xB1, 0x00, 0x00},
						&mo_MSB, 	LSB },
		}
};

const static struct schc_ipv6_rule_t ipv6_rule3 = {
	//	id, up, down, length
		3, 10, 10, 10,
		{
			//	field, 			   MO, len,	 pos,dir, 	val,			MO,			CDA
				{ "version", 		0, 4,	 1, BI, 	{6},			&mo_equal, 	VALUESENT },
				{ "traffic class", 	0, 8,	 1, BI, 	{0},			&mo_ignore, 	NOTSENT },
				{ "flow label", 	0, 20,	 1, BI, 	{0, 0, 0},		&mo_ignore, 	NOTSENT },
				{ "length", 		0, 16,	 1, BI, 	{0, 0},			&mo_ignore, 	COMPLENGTH },
				{ "next header", 	0, 8, 	 1, BI, 	{17},			&mo_equal, 	NOTSENT },
				{ "hop limit", 		0, 8, 	 1, BI, 	{64}, 			&mo_ignore, 	NOTSENT },
				{ "src prefix",		0, 64,	 1, BI,		{0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&mo_equal, 	NOTSENT },
				{ "src iid",		0, 64, 	 1, BI, 	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
						&mo_equal, 	NOTSENT },
				{ "dest prefix",	0, 64, 	 1, BI,		{0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&mo_equal, 	NOTSENT },
				{ "dest iid",		60, 64,  1, BI, 	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&mo_MSB, 		LSB},
		}
};
#endif

#if USE_UDP
const static struct schc_udp_rule_t udp_rule1 = {
		1, 4, 4, 4,
		{
				{ "src port", 		2,	16, 	 1, BI, 	{0x33, 0x16, 0x33, 0x17},
						&mo_matchmap,	MAPPINGSENT }, // 5683 or 5684
				{ "dest port", 		2,	16, 	 1, BI, 	{0x33, 0x16, 0x33, 0x17},
						&mo_matchmap,	MAPPINGSENT },
						// set field length to 16 to indicate 16 bit values
						// MO param to 2 to indicate 2 indices
				{ "length", 		0,	16, 	 1, BI, 	{0, 0},		 		&mo_ignore,	COMPLENGTH },
				{ "checksum", 		0,	16, 	 1, BI, 	{0, 0},				&mo_ignore,	COMPCHK },
		}
};

const static struct schc_udp_rule_t udp_rule2 = {
		2, 4, 4, 4,
		{
				{ "src port", 		12,	16,	 1, BI, 	{0x33, 0x16},		&mo_MSB,		LSB },
				{ "dest port", 		12,	16,	 1, BI, 	{0x33, 0x16},		&mo_MSB,		LSB },
				{ "length", 		0,  16,	 1, BI, 	{0, 0},				&mo_ignore,	COMPLENGTH },
				{ "checksum", 		0,  16,	 1, BI, 	{0, 0},				&mo_ignore,	COMPCHK },
		}
};

const static struct schc_udp_rule_t udp_rule3 = {
		3, 4, 4, 4,
		{
				{ "src port", 		0,	16,	 1, BI, 	{0x13, 0x89}, 		&mo_equal,		NOTSENT },
				{ "dest port", 		0, 	16,	 1, BI, 	{0x13, 0x88}, 		&mo_equal,		NOTSENT },
				{ "length", 		0, 	16,	 1, BI, 	{0, 0},				&mo_ignore,	COMPLENGTH },
				{ "checksum", 		0, 	16,	 1, BI, 	{0, 0},				&mo_ignore,	COMPCHK },
		}
};
#endif

#if USE_COAP
// it is important to use strings, identical to the ones
// defined in coap.h for the options

// GET usage
const static struct schc_coap_rule_t coap_rule1 = {
		1, 9, 7, 9,
		{
				{ "version",		0,	2,	 1, BI,		{COAP_V1},		&mo_equal,			NOTSENT },
				{ "type",			4,	2,	 1, BI,		{CT_CON, CT_NON, CT_ACK, CT_RST},
						&mo_matchmap,	MAPPINGSENT	}, // todo: non word-aligned mo_matchmap
				{ "token length",	0,	4,	 1, BI,		{4},			&mo_equal,			NOTSENT },
				{ "code",			0,	8,	 1, BI,		{CC_PUT},		&mo_equal,			NOTSENT },
				{ "message ID",		0,	16,	 1, BI,		{0x23, 0xBB},	&mo_equal,			NOTSENT },
				{ "token",			24,	32,	 1, BI,		{0x21, 0xFA, 0x01, 0x00},
						&mo_MSB,		LSB },
				{ "uri-path", 		0,	40,	 1, BI,		"usage", 		&mo_equal,			NOTSENT },
				{ "no-response", 	0,	8,	 1, BI,		{0x1A}, 		&mo_equal,			NOTSENT },
				{ "payload marker",	0,	8,   1, BI, 	{0xFF},			&mo_equal,			NOTSENT }

		}
};

// POST temperature value
const static struct schc_coap_rule_t coap_rule2 = {
		2, 8, 8, 10,
		{
				{ "version",		0,	2,	 1, BI,		{COAP_V1},		&mo_equal,		NOTSENT },
				{ "type",			3,	2,	 1, BI,		{CT_CON, CT_ACK, CT_NON},
						// the MO_param_length is used to indicate the true length of the list
						&mo_matchmap, MAPPINGSENT	},
				{ "token length",	0,	4,	 1, BI,		{4},			&mo_equal,		NOTSENT },
				{ "code",			0,	4,	 1, UP,		{CC_CONTENT},	&mo_equal,		NOTSENT },
				{ "code",			0,	8,	 1, DOWN,	{CC_GET},		&mo_equal,		NOTSENT },
				{ "message ID",		12,	16,	 1, UP,		{0x23, 0xBB},	&mo_MSB,		LSB },
				{ "message ID",		12,	16,	 1, DOWN,	{0x7A, 0x10},	&mo_MSB,		LSB }, // match the first 12 bits
				{ "token",			0,	32,	 1, BI,		{0, 0, 0, 0},	&mo_ignore,	VALUESENT }, // GET sensor value
				{ "uri-path", 		4,	0,	 2, BI,		"[\"temp\",\"humi\",\"batt\",\"r\"]\0",
						// todo variable field length and json
						&mo_matchmap,		MAPPINGSENT },
				{ "payload marker",	0,	8,   1, BI, 	{255},			&mo_equal,		NOTSENT } // respond with CONTENT
		}
};

const static struct schc_coap_rule_t coap_rule4 = {
		4, 12, 12, 12,
		{
				{ "version",        0,	2,	1, BI,      {COAP_V1},		&mo_equal,         NOTSENT },
				{ "type",           0,  2,	1, BI,      {CT_CON},		&mo_equal,         NOTSENT },
				{ "token length",   0,  4,	1, BI,      {8}, 			&mo_equal,         NOTSENT },
				{ "code",           0,  8,	1, BI,      {CC_POST},      &mo_equal,         NOTSENT },
				{ "message ID",     0,  16,	1, BI,      {0x23, 0xBB},   &mo_ignore,	    VALUESENT },
				{ "token",			24,	32,	 1, BI,		{0x21, 0xFA, 0x01, 0x00},
						&mo_MSB,		LSB }, // match the 24 first bits, send the last 8
				{ "uri-path",       0,  16,	1, BI,      "rd",           &mo_equal,         NOTSENT },
                { "content-format", 0,  8,	1, BI,      {0x28},         &mo_equal,         NOTSENT },
                { "uri-query",      0,  72,	1, BI,      {0x6C, 0x77, 0x6D, 0x32, 0x6D, 0x3D, 0x31, 0x2E, 0x30},
                		&mo_equal,         NOTSENT },
                { "uri-query",      0,  88,	1, BI,      {0x65, 0x70, 0x3D, 0x6D, 0x61, 0x67, 0x69, 0x63, 0x69, 0x61, 0x6E},
                		&mo_equal,         NOTSENT },
                { "uri-query",      0,  48,	1, BI,      {0x6C, 0x74, 0x3D, 0x31, 0x32, 0x31},
                		&mo_equal,         NOTSENT },
				{ "payload marker", 0,  8,	1, BI,		{255},			&mo_equal,         NOTSENT } // respond with CONTENT
               }

};
#endif

const struct schc_compression_rule_t compression_rule_1 = {
#if USE_IP6
		&ipv6_rule1,
#endif
#if USE_UDP
		&udp_rule1,
#endif
#if USE_COAP
		&coap_rule1,
#endif
};

const struct schc_compression_rule_t compression_rule_2 = {
#if USE_IP6
		&ipv6_rule1,
#endif
#if USE_UDP
		NULL, // &udp_rule2,
#endif
#if USE_COAP
		&coap_rule2,
#endif
};

const struct schc_compression_rule_t compression_rule_3 = {
#if USE_IP6
		&ipv6_rule2,
#endif
#if USE_UDP
		&udp_rule2,
#endif
#if USE_COAP
		&coap_rule4,
#endif
};

const struct schc_compression_rule_t compression_rule_4 = {
#if USE_IP6
		&ipv6_rule3,
#endif
#if USE_UDP
		&udp_rule2,
#endif
#if USE_COAP
		&coap_rule1,
#endif
};

const uint8_t UNCOMPRESSED_ID[RULE_SIZE_BYTES] = { 0x00 }; // the rule id for an uncompressed packet
// todo
// const uint8_t UNCOMPRESSED_NO_ACK_ID[RULE_SIZE_BYTES] = { 0 };
// const uint8_t UNCOMPRESSED_ACK_ON_ERR[RULE_SIZE_BYTES] = { 0 };
// const uint8_t UNCOMPRESSED_ACK_ALWAYS[RULE_SIZE_BYTES] = { 0 };

const struct schc_rule_t schc_rule_1 = { 0x01, &compression_rule_1, NOT_FRAGMENTED, 0, 0, 0, 0 };
// const struct schc_rule_t schc_rule_1 = { { 0x00, 0x01} , &registration_rule, NOT_FRAGMENTED, 0, 0, 0, 0 }; // for rule id's > 8 bits

const struct schc_rule_t schc_rule_2 = { 0x02, &compression_rule_1, NO_ACK, 1, 0, 0, 0 };
const struct schc_rule_t schc_rule_3 = { 0x03, &compression_rule_1, ACK_ON_ERROR, 3, 6, 1, 0 };
const struct schc_rule_t schc_rule_4 = { 0x04, &compression_rule_1, ACK_ALWAYS, 3, 6, 1, 0 };

const struct schc_rule_t schc_rule_5 = { 0x05, &compression_rule_2, NOT_FRAGMENTED, 0, 0, 0, 0 };
const struct schc_rule_t schc_rule_6 = { 0x06, &compression_rule_2, NO_ACK, 1, 0, 0, 0 };
const struct schc_rule_t schc_rule_7 = { 0x07, &compression_rule_2, ACK_ON_ERROR, 3, 6, 1, 0 };
const struct schc_rule_t schc_rule_8 = { 0x08, &compression_rule_2, ACK_ALWAYS, 3, 6, 1, 0 };

const struct schc_rule_t schc_rule_9 	= { 0x09, &compression_rule_3, NOT_FRAGMENTED, 0, 0, 0, 0 };
const struct schc_rule_t schc_rule_10 	= { 0x0A, &compression_rule_3, NO_ACK, 1, 0, 0, 0 };
const struct schc_rule_t schc_rule_11 	= { 0x0B, &compression_rule_3, ACK_ON_ERROR, 3, 6, 1, 0 };
const struct schc_rule_t schc_rule_12 	= { 0x0C, &compression_rule_3, ACK_ALWAYS, 3, 6, 1, 0 };

const struct schc_rule_t schc_rule_13 	= { 0x0D, &compression_rule_4, NOT_FRAGMENTED, 0, 0, 0, 0 };
const struct schc_rule_t schc_rule_14 	= { 0x0E, &compression_rule_4, NO_ACK, 1, 0, 0, 0 };
const struct schc_rule_t schc_rule_15 	= { 0x0F, &compression_rule_4, ACK_ON_ERROR, 3, 6, 1, 0 };
const struct schc_rule_t schc_rule_16 	= { 0x10, &compression_rule_4, ACK_ALWAYS, 3, 6, 1, 0 };

/* save rules in flash */
const struct schc_rule_t* node1_schc_rules[] = { &schc_rule_1, &schc_rule_2,
                &schc_rule_3, &schc_rule_4, &schc_rule_5, &schc_rule_6, &schc_rule_7,
                &schc_rule_8, &schc_rule_9, &schc_rule_10, &schc_rule_11, &schc_rule_12,
                &schc_rule_13, &schc_rule_14, &schc_rule_15, &schc_rule_16 };

/* rules for a particular device */
const struct schc_device node1 = { 0x06, 16, &node1_schc_rules };
const struct schc_device node2 = { 0x01, 16, &node1_schc_rules };

#define DEVICE_COUNT			2

/* server keeps track of multiple devices: add devices to device list */
const struct schc_device* devices[DEVICE_COUNT] = { &node1, &node2 };
