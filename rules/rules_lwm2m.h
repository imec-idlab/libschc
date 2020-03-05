#ifndef _RULES_H_
#define _RULES_H_

#include "../schc_config.h"

#if USE_IPv6
const static struct schc_ipv6_rule_t ipv6_rule1 = {
	//	id, up, down, length
		1, 10, 10, 10,
		{
				//	field, 			   MO, len,	 pos,dir, 	val,			MO,			CDA
				{ "version", 		0, 4,	1, BI, 		{6},			&equal, 	NOTSENT },
				{ "traffic class", 	0, 8,	1, BI, 		{0},			&ignore, 	NOTSENT },
				{ "flow label", 	0, 20,	1, BI, 		{0, 0, 0},		&ignore, 	NOTSENT },
				{ "length", 		0, 16,	1, BI, 		{0, 0},			&ignore, 	COMPLENGTH },
				{ "next header", 	3, 8, 	1, BI, 		{6, 17, 58},	&matchmap, 	MAPPINGSENT },
				{ "hop limit", 		0, 8, 	1, BI, 		{64}, 			&ignore, 	NOTSENT },
				{ "src prefix",		4, 64,	1, BI,		{0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
														 0xBB, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
														 0xCC, 0xCC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
														 0xDD, 0xDD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&matchmap, 	MAPPINGSENT }, // you can store as many IP's as (MAX_FIELD_LENGTH / 8)
				{ "src iid",		0, 64,	1, BI, 		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
						&equal, 	NOTSENT },
				{ "dest prefix",	0, 64,	1, BI,		{0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&equal, 	NOTSENT },
				{ "dest iid",		60, 64,	1, BI, 		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&MSB, 		LSB }, // match the 60 first bits, send the last 4
		}
};
#endif

#if USE_UDP
const static struct schc_udp_rule_t udp_rule1 = {
		1, 4, 4, 4,
		{
				{ "src port", 		2,	16, 	 1, BI, 	{0x33, 0x16, 0x33, 0x17},
						&matchmap,	MAPPINGSENT }, // 5683 or 5684
				{ "dest port", 		2,	16, 	 1, BI, 	{0x33, 0x16, 0x33, 0x17},
						&matchmap,	MAPPINGSENT },
						// set field length to 16 to indicate 16 bit values
						// MO param to 2 to indicate 2 indices
				{ "length", 			0,		16,		1, BI, 	{0, 0},		 		&ignore,		COMPLENGTH },
				{ "checksum", 			0,		16, 	1, BI, 	{0, 0},				&ignore,		COMPCHK },
		}
};
#endif

#if USE_COAP
const static struct schc_coap_rule_t lwm2m_registration_rule = {
		1, 13, 8, 16,
		{
				{ "version",            0,      2,      1, BI,      {COAP_V1},		&equal,         NOTSENT },
				{ "type",               0,  	2,      1, UP,      {CT_CON},		&equal,         NOTSENT },
				{ "type", 				0,		2,		1, DOWN,    {CT_ACK},		&equal,			NOTSENT },
				{ "token length",       0,      4,      1, BI,      {4}, 			&equal,         NOTSENT },
				{ "code",               0,     	8,		1, UP,      {CC_POST},      &equal,         NOTSENT },
				{ "code",               0,     	8,		1, DOWN,    {CC_CREATED},   &equal,         NOTSENT },
				{ "message ID",         0,      16,		1, BI,      {0x00, 0x00},   &ignore,	    VALUESENT },
				{ "token",              0,     	32,     1, BI,      {0x00, 0x00, 0x00, 0x00},
						&ignore,        VALUESENT },
				{ "uri-path",           0,      16,     1, BI,      "rd",           &equal,         NOTSENT },
				{ "uri-path",           0,      80,     1, DOWN,    "ZXV46xgT3I",   &ignore,        VALUESENT },
				{ "content-format", 	0,		8,		1, UP,		{40}, 			&equal,			NOTSENT }, // LWM2M_CONTENT_LINK
                { "uri-query",          0,      72,     1, UP,      "lwm2m=1.1",	&equal,         NOTSENT },
                { "uri-query",          0,      224,    1, UP,      "ep=port-forward-lwm2m-client",
                		&equal,         NOTSENT },
		        { "uri-query",          0,      24,     1, UP,      "b=U",			&equal,         NOTSENT },
		        { "uri-query",          0,      48,     1, UP,      "lt=300",		&equal,         NOTSENT },
				{ "payload marker",   	0,      1,   	1, UP,		{0xFF},			&equal,         NOTSENT }
		}
};

const static struct schc_coap_rule_t lwm2m_get_rule = {
		2, 8, 10, 14,
		{
				{ "version",            0,      2,      1, BI,      {COAP_V1},		&equal,         NOTSENT },
				{ "type",               0,  	2,      1, DOWN,    {CT_CON},		&equal,         NOTSENT },
				{ "type",               0,  	2,      1, UP,    	{CT_ACK},		&equal,         NOTSENT },
				{ "token length",       0,      4,      1, BI, 		{8}, 			&equal,         NOTSENT },
				{ "code",               0,     	8,		1, DOWN,    {CC_GET},      	&equal,         NOTSENT },
				{ "code",               0,     	8,		1, UP,    	{CC_CONTENT},   &ignore,        VALUESENT },
				{ "message ID",         0,      16,		1, BI,    	{0x00, 0x00},   &ignore,	    VALUESENT },
				{ "token",              0,     	64,      1, BI,	    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&ignore,        VALUESENT },
				{ "uri-path",           0,      8,      1, DOWN,    "1", 			&equal,         NOTSENT },
				{ "uri-path",           0,      8,      1, DOWN,    "0",          	&equal,         NOTSENT },
				{ "uri-path",           0,      8,      1, DOWN,    "1",          	&ignore,        VALUESENT },
				{ "accept",		        0,      16,     1, DOWN,	{0x2D, 0x16},	&equal,         NOTSENT },
				{ "content-format",		0,      16,     1, UP,		{0x2D, 0x16},	&equal,         NOTSENT },
				{ "payload marker",   	0,      8,  	1, UP,		{0xFF},			&equal,         NOTSENT }

		}
};

const static struct schc_coap_rule_t lwm2m_catch_all_rule = {
		3, 8, 10, 14,
		{
				{ "version",            0,      2,      1, BI,      {COAP_V1},		&equal,         NOTSENT },
				{ "type",               0,  	2,      1, DOWN,    {CT_CON},		&equal,         NOTSENT },
				{ "type",               0,  	2,      1, UP,    	{CT_ACK},		&equal,         NOTSENT },
				{ "token length",       0,      4,      1, BI, 		{8}, 			&equal,         NOTSENT },
				{ "code",               0,     	8,		1, DOWN,    {CC_GET},      	&equal,         NOTSENT },
				{ "code",               0,     	8,		1, UP,    	{CC_CONTENT},   &ignore,        VALUESENT },
				{ "message ID",         0,      16,		1, BI,    	{0x00, 0x00},   &ignore,	    VALUESENT },
				{ "token",              0,     	64,      1, BI,	    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&ignore,        VALUESENT },
				{ "uri-path",           0,      32,     1, DOWN,    "3303",			&ignore,        VALUESENT },
				{ "uri-path",           0,      8,      1, DOWN,    "0",          	&equal,         NOTSENT },
				{ "uri-path",           0,      32,     1, DOWN,    "5700",        	&ignore,        VALUESENT },
				{ "accept",		        0,      16,     1, DOWN,	{0x2D, 0x16},	&equal,         NOTSENT },
				{ "content-format",		0,      16,     1, UP,		{0x2D, 0x16},	&equal,         NOTSENT },
				{ "payload marker",   	0,      8,   	1, UP,		{0xFF},			&equal,         NOTSENT }

		}
};

const static struct schc_coap_rule_t lwm2m_404_not_found = {
		4, 6, 6, 6,
		{
				{ "version",            0,      2,      1, BI,    	{COAP_V1},		&equal,         NOTSENT },
				{ "type",               0,  	2,      1, BI,   	{CT_ACK},		&equal,         NOTSENT },
				{ "token length",       0,      4,      1, BI, 		{8}, 			&equal,         NOTSENT },
				{ "code",               0,     	8,		1, BI,   	{CC_NOT_FOUND}, &equal,         NOTSENT },
				{ "message ID",         0,      16,		1, BI,   	{0x00, 0x00},   &ignore,	    VALUESENT },
				{ "token",              0,     	64,      1, BI,    	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&ignore,        VALUESENT }
		}
};

const static struct schc_coap_rule_t lwm2m_update_registration_rule_up = {
		5, 8, 8, 8,
		{
				{ "version",            0,      2,      1, BI,      {COAP_V1},      &equal,         NOTSENT },
				{ "type",               0,      2,      1, BI,      {CT_CON},       &equal,         NOTSENT },
				{ "token length",       0,      4,      1, BI,      {4},			&equal,         NOTSENT },
				{ "code",               0,      8,      1, BI,      {CC_POST},      &equal,         NOTSENT },
				{ "message ID",         0,      16,     1, BI,      {0x00, 0x00},   &ignore,        VALUESENT },
				{ "token",              0,      32,     1, BI,      {0x00, 0x00, 0x00, 0x00},
						&ignore,        VALUESENT },
				{ "uri-path",           0,      8,      1, BI,      "rd",           &equal,         NOTSENT },
				{ "uri-path",           0,      80,     1, BI,      "ZXV46xgT3I",   &ignore,        VALUESENT }
		}
};


const static struct schc_coap_rule_t lwm2m_update_registration_rule_down = {
		6, 6, 6, 6,
		{
				{ "version",            0,      2,      1, BI,      {COAP_V1},      &equal,         NOTSENT },
				{ "type",               0,      2,      1, BI,      {CT_ACK},       &equal,         NOTSENT },
				{ "token length",       0,      4,      1, BI,      {4}, 			&equal,         NOTSENT },
				{ "code",               0,      8,		1, BI,      {CC_CHANGED},	&equal,         NOTSENT },
				{ "message ID",         0,      16,		1, BI,      {0x00, 0x00},	&ignore,        VALUESENT },
				{ "token",              0,      32,     1, BI,      {0x00, 0x00, 0x00, 0x00},
						&ignore,        VALUESENT }
         }
};


#endif

const struct schc_compression_rule_t registration_rule = {
#if USE_IPv6
		&ipv6_rule1,
#endif
#if USE_UDP
		&udp_rule1,
#endif
#if USE_COAP
		&lwm2m_registration_rule,
#endif
};

const struct schc_compression_rule_t get_rule = {
#if USE_IPv6
		&ipv6_rule1,
#endif
#if USE_UDP
		&udp_rule1,
#endif
#if USE_COAP
		&lwm2m_get_rule,
#endif
};

const struct schc_compression_rule_t catch_all_rule = {
#if USE_IPv6
		&ipv6_rule1,
#endif
#if USE_UDP
		&udp_rule1,
#endif
#if USE_COAP
		&lwm2m_catch_all_rule,
#endif
};

const struct schc_compression_rule_t not_found_404 = {
#if USE_IPv6
		&ipv6_rule1,
#endif
#if USE_UDP
		&udp_rule1,
#endif
#if USE_COAP
		&lwm2m_404_not_found,
#endif
};

const struct schc_compression_rule_t update_registration_up = {
#if USE_IPv6
                &ipv6_rule1,
#endif
#if USE_UDP
                &udp_rule1,
#endif
#if USE_COAP
                &lwm2m_update_registration_rule_up,
#endif
};



const struct schc_compression_rule_t update_registration_down = {
#if USE_IPv6
                &ipv6_rule1,
#endif
#if USE_UDP
                &udp_rule1,
#endif
#if USE_COAP
                &lwm2m_update_registration_rule_down,
#endif
};

const uint8_t UNCOMPRESSED_ID[RULE_SIZE_BYTES] = { 0x00 }; // the rule id for an uncompressed packet
// todo
// const uint8_t UNCOMPRESSED_NO_ACK_ID[RULE_SIZE_BYTES] = { 0 };
// const uint8_t UNCOMPRESSED_ACK_ON_ERR[RULE_SIZE_BYTES] = { 0 };
// const uint8_t UNCOMPRESSED_ACK_ALWAYS[RULE_SIZE_BYTES] = { 0 };

const struct schc_rule_t schc_rule_1 = { 0x01, &registration_rule, NOT_FRAGMENTED, 0, 0, 0, 0 };
const struct schc_rule_t schc_rule_2 = { 0x02, &registration_rule, NO_ACK, 1, 0, 0, 0 };
const struct schc_rule_t schc_rule_3 = { 0x03, &registration_rule, ACK_ON_ERROR, 3, 6, 1, 0 };
const struct schc_rule_t schc_rule_4 = { 0x04, &registration_rule, ACK_ALWAYS, 3, 6, 1, 0 };

const struct schc_rule_t schc_rule_5 = { 0x05, &get_rule, NOT_FRAGMENTED, 0, 0, 0, 0 };
const struct schc_rule_t schc_rule_6 = { 0x06, &get_rule, NO_ACK, 1, 0, 0, 0 };
const struct schc_rule_t schc_rule_7 = { 0x07, &get_rule, ACK_ON_ERROR, 3, 6, 1, 0 };
const struct schc_rule_t schc_rule_8 = { 0x08, &get_rule, ACK_ALWAYS, 3, 6, 1, 0 };

const struct schc_rule_t schc_rule_9 	= { 0x09, &catch_all_rule, NOT_FRAGMENTED, 0, 0, 0, 0 };
const struct schc_rule_t schc_rule_10 	= { 0x0A, &catch_all_rule, NO_ACK, 1, 0, 0, 0 };
const struct schc_rule_t schc_rule_11 	= { 0x0B, &catch_all_rule, ACK_ON_ERROR, 3, 6, 1, 0 };
const struct schc_rule_t schc_rule_12 	= { 0x0C, &catch_all_rule, ACK_ALWAYS, 3, 6, 1, 0 };

const struct schc_rule_t schc_rule_13 	= { 0x0D, &not_found_404, NOT_FRAGMENTED, 0, 0, 0, 0 };
const struct schc_rule_t schc_rule_14 	= { 0x0E, &not_found_404, NO_ACK, 1, 0, 0, 0 };
const struct schc_rule_t schc_rule_15 	= { 0x0F, &not_found_404, ACK_ON_ERROR, 3, 6, 1, 0 };
const struct schc_rule_t schc_rule_16 	= { 0x10, &not_found_404, ACK_ALWAYS, 3, 6, 1, 0 };

const struct schc_rule_t schc_rule_17   = { 0x11, &update_registration_up, NOT_FRAGMENTED, 0, 0, 0, 0 };
const struct schc_rule_t schc_rule_18   = { 0x12, &update_registration_down, NOT_FRAGMENTED, 1, 0, 0, 0 };

/* save rules in flash */
const struct schc_rule_t* node1_schc_rules[] = { &schc_rule_1, &schc_rule_2,
                &schc_rule_3, &schc_rule_4, &schc_rule_5, &schc_rule_6, &schc_rule_7,
                &schc_rule_8, &schc_rule_9, &schc_rule_10, &schc_rule_11, &schc_rule_12,
                &schc_rule_13, &schc_rule_14, &schc_rule_15, &schc_rule_16,
                &schc_rule_17, &schc_rule_18};

/* rules for a particular device */
const struct schc_device node1 = { 0x01, 18, &node1_schc_rules };

#define DEVICE_COUNT			1

/* server keeps track of multiple devices: add devices to device list */
const struct schc_device* devices[DEVICE_COUNT] = { &node1 };

#endif
