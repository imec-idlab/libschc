#include "../schc.h"

#if USE_IP6
const static struct schc_ipv6_rule_t ipv6_rule1 = {
	//	id, up, down, length
		1, 10, 10, 10,
		{
			//	field, 			   MO, len,	 pos,dir, 	val,			MO,			CDA
				{ "version", 		0, 4,	1, BI, 		{6},			&mo_equal, 	NOTSENT },
				{ "traffic class", 	0, 8,	1, BI, 		{0},			&mo_equal, 	NOTSENT },
				{ "flow label", 	0, 20,	1, BI, 		{0x01, 0x23, 0x45},
						&mo_ignore, 	NOTSENT },
				{ "length", 		0, 16,	1, BI, 		{0, 0x39},		&mo_ignore, 	COMPLENGTH },
				{ "next header", 	0, 8, 	1, BI, 		{0x11},			&mo_ignore, 	VALUESENT },
				{ "hop limit", 		0, 8, 	1, BI, 		{0xFF}, 		&mo_ignore, 	NOTSENT },
				{ "src prefix",		2, 64,	1, BI,		{0x20, 0x01, 0x12, 0x22, 0x89, 0x05, 0x04, 0x70,
														 0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&mo_matchmap, 	MAPPINGSENT }, // you can store as many IP's as (MAX_FIELD_LENGTH / 8)
				{ "src iid",		0, 64,	1, BI, 		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x57},
						&mo_equal, 	NOTSENT },
				{ "dest prefix",	2, 64,	1, BI,		{0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
														 0x20, 0x01, 0x41, 0xd0, 0x57, 0xd7, 0x31, 0x00},
						&mo_matchmap, 	MAPPINGSENT },
				{ "dest iid",		0, 64,	1, BI, 		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01},
						&mo_equal, 	NOTSENT },
		}
};
#endif

#if USE_UDP
const static struct schc_udp_rule_t udp_rule1 = {
		1, 4, 4, 4,
		{
				{ "src port", 		12,	16, 	 1, BI, 	{0x16, 0x34},
						&mo_MSB,		LSB }, // 5683 or 5684
				{ "dest port", 		12,	16, 	 1, BI, 	{0x16, 0x33},
						&mo_MSB,		LSB }, // match the 12 first bits, send the last 4
				{ "length", 		0,	16, 	 1, BI, 	{0, 0x39},	&mo_ignore,	COMPLENGTH },
				{ "checksum", 		0,	16, 	 1, BI, 	{0x7a, 0x6e},
						&mo_ignore,	COMPCHK },
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
				{ "type",			0,	2,	 1, BI,		{CT_NON},		&mo_equal,			NOTSENT	},
				{ "token length",	0,	4,	 1, BI,		{1},			&mo_equal,			NOTSENT },
				{ "code",			0,	8,	 1, BI,		{CC_POST},		&mo_equal,			NOTSENT },
				{ "message ID",		0,	16,	 1, BI,		{0x00, 0xA0},	&mo_equal,			NOTSENT },
				{ "token",			0,	8,	 1, BI,		{0x20},			&mo_equal,			NOTSENT },
				{ "uri-path", 		0,	32,	 1, BI,		"temp", 		&mo_equal,			NOTSENT },
				{ "no-response", 	0,	8,	 1, BI,		{0x02},		 	&mo_equal,			NOTSENT },
				{ "payload marker",	0,	8,   1, BI, 	{0xFF},			&mo_equal,			NOTSENT }

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
