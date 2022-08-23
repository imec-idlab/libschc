#include "../schc.h"

#if USE_IP6
const static struct schc_ipv6_rule_t ipv6_lwm2m = {
	//	id, up, down, length
		1, 10, 10, 10,
		{
				//	field, 			   MO, len,	 pos,dir, 	val,			MO,			CDA
				{ "version", 		0, 4,	1, BI, 		{6},			&mo_equal, 	NOTSENT },
				{ "traffic class", 	0, 8,	1, BI, 		{0},			&mo_ignore, 	NOTSENT },
				{ "flow label", 	0, 20,	1, BI, 		{0, 0, 0},		&mo_ignore, 	NOTSENT },
				{ "length", 		0, 16,	1, BI, 		{0, 0},			&mo_ignore, 	COMPLENGTH },
				{ "next header", 	3, 8, 	1, BI, 		{6, 17, 58},	&mo_matchmap, 	MAPPINGSENT },
				{ "hop limit", 		0, 8, 	1, BI, 		{64}, 			&mo_ignore, 	NOTSENT },
				{ "src prefix",		4, 64,	1, BI,		{0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
														 0xBB, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
														 0xCC, 0xCC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
														 0xDD, 0xDD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&mo_matchmap, 	MAPPINGSENT }, // you can store as many IP's as (MAX_FIELD_LENGTH / 8)
				{ "src iid",		0, 64,	1, BI, 		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
						&mo_equal, 	NOTSENT },
				{ "dest prefix",	0, 64,	1, BI,		{0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&mo_equal, 	NOTSENT },
				{ "dest iid",		60, 64,	1, BI, 		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&mo_MSB, 		LSB }, // match the 60 first bits, send the last 4
		}
};
#endif

#if USE_UDP
const static struct schc_udp_rule_t udp_lwm2m = {
		1, 4, 4, 4,
		{
				{ "src port", 		2,	16, 	 1, BI, 	{0x33, 0x16, 0x33, 0x17},
						&mo_matchmap,	MAPPINGSENT }, // 5683 or 5684
				{ "dest port", 		2,	16, 	 1, BI, 	{0x33, 0x16, 0x33, 0x17},
						&mo_matchmap,	MAPPINGSENT },
						// set field length to 16 to indicate 16 bit values
						// MO param to 2 to indicate 2 indices
				{ "length", 			0,		16,		1, BI, 	{0, 0},		 		&mo_ignore,		COMPLENGTH },
				{ "checksum", 			0,		16, 	1, BI, 	{0, 0},				&mo_ignore,		COMPCHK },
		}
};
#endif

#if USE_COAP
const static struct schc_coap_rule_t lwm2m_registration_rule = {
		1, 13, 8, 16,
		{
				{ "version",            0,      2,      1, BI,      {COAP_V1},		&mo_equal,         NOTSENT },
				{ "type",               0,  	2,      1, UP,      {CT_CON},		&mo_equal,         NOTSENT },
				{ "type", 				0,		2,		1, DOWN,    {CT_ACK},		&mo_equal,			NOTSENT },
				{ "token length",       0,      4,      1, BI,      {4}, 			&mo_equal,         NOTSENT },
				{ "code",               0,     	8,		1, UP,      {CC_POST},      &mo_equal,         NOTSENT },
				{ "code",               0,     	8,		1, DOWN,    {CC_CREATED},   &mo_equal,         NOTSENT },
				{ "message ID",         0,      16,		1, BI,      {0x00, 0x00},   &mo_ignore,	    VALUESENT },
				{ "token",              0,     	32,     1, BI,      {0x00, 0x00, 0x00, 0x00},
						&mo_ignore,        VALUESENT },
				{ "uri-path",           0,      16,     1, BI,      "rd",           &mo_equal,         NOTSENT },
				{ "uri-path",           0,      80,     1, DOWN,    "ZXV46xgT3I",   &mo_ignore,        VALUESENT },
				{ "content-format", 	0,		8,		1, UP,		{40}, 			&mo_equal,			NOTSENT }, // LWM2M_CONTENT_LINK
                { "uri-query",          0,      72,     1, UP,      "lwm2m=1.1",	&mo_equal,         NOTSENT },
                { "uri-query",          0,      120,    1, UP,      "ep=lwm2m-client",
                		&mo_equal,         NOTSENT },
		        { "uri-query",          0,      24,     1, UP,      "b=U",			&mo_equal,         NOTSENT },
		        { "uri-query",          0,      48,     1, UP,      "lt=300",		&mo_equal,         NOTSENT },
				{ "payload marker",   	0,      8,   	1, UP,		{0xFF},			&mo_equal,         NOTSENT }
		}
};

const static struct schc_coap_rule_t lwm2m_get_rule = {
		2, 8, 10, 14,
		{
				{ "version",            0,      2,      1, BI,      {COAP_V1},		&mo_equal,         NOTSENT },
				{ "type",               0,  	2,      1, DOWN,    {CT_CON},		&mo_equal,         NOTSENT },
				{ "type",               0,  	2,      1, UP,    	{CT_ACK},		&mo_equal,         NOTSENT },
				{ "token length",       0,      4,      1, BI, 		{8}, 			&mo_equal,         NOTSENT },
				{ "code",               0,     	8,		1, DOWN,    {CC_GET},      	&mo_equal,         NOTSENT },
				{ "code",               0,     	8,		1, UP,    	{CC_CONTENT},   &mo_ignore,        VALUESENT },
				{ "message ID",         0,      16,		1, BI,    	{0x00, 0x00},   &mo_ignore,	    VALUESENT },
				{ "token",              0,     	64,      1, BI,	    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&mo_ignore,        VALUESENT },
				{ "uri-path",           0,      8,      1, DOWN,    "1", 			&mo_equal,         NOTSENT },
				{ "uri-path",           0,      8,      1, DOWN,    "0",          	&mo_equal,         NOTSENT },
				{ "uri-path",           0,      8,      1, DOWN,    "1",          	&mo_ignore,        VALUESENT },
				{ "accept",		        0,      16,     1, DOWN,	{0x2D, 0x16},	&mo_equal,         NOTSENT },
				{ "content-format",		0,      16,     1, UP,		{0x2D, 0x16},	&mo_equal,         NOTSENT },
				{ "payload marker",   	0,      8,  	1, UP,		{0xFF},			&mo_equal,         NOTSENT }

		}
};

const static struct schc_coap_rule_t lwm2m_catch_all_rule = {
		3, 8, 10, 14,
		{
				{ "version",            0,      2,      1, BI,      {COAP_V1},		&mo_equal,         NOTSENT },
				{ "type",               0,  	2,      1, DOWN,    {CT_CON},		&mo_equal,         NOTSENT },
				{ "type",               0,  	2,      1, UP,    	{CT_ACK},		&mo_equal,         NOTSENT },
				{ "token length",       0,      4,      1, BI, 		{8}, 			&mo_equal,         NOTSENT },
				{ "code",               0,     	8,		1, DOWN,    {CC_GET},      	&mo_equal,         NOTSENT },
				{ "code",               0,     	8,		1, UP,    	{CC_CONTENT},   &mo_ignore,        VALUESENT },
				{ "message ID",         0,      16,		1, BI,    	{0x00, 0x00},   &mo_ignore,	    VALUESENT },
				{ "token",              0,     	64,      1, BI,	    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&mo_ignore,        VALUESENT },
				{ "uri-path",           0,      32,     1, DOWN,    "3303",			&mo_ignore,        VALUESENT },
				{ "uri-path",           0,      8,      1, DOWN,    "0",          	&mo_equal,         NOTSENT },
				{ "uri-path",           0,      32,     1, DOWN,    "5700",        	&mo_ignore,        VALUESENT },
				{ "accept",		        0,      16,     1, DOWN,	{0x2D, 0x16},	&mo_equal,         NOTSENT },
				{ "content-format",		0,      16,     1, UP,		{0x2D, 0x16},	&mo_equal,         NOTSENT },
				{ "payload marker",   	0,      8,   	1, UP,		{0xFF},			&mo_equal,         NOTSENT }

		}
};

const static struct schc_coap_rule_t lwm2m_404_not_found = {
		4, 6, 6, 6,
		{
				{ "version",            0,      2,      1, BI,    	{COAP_V1},		&mo_equal,         NOTSENT },
				{ "type",               0,  	2,      1, BI,   	{CT_ACK},		&mo_equal,         NOTSENT },
				{ "token length",       0,      4,      1, BI, 		{8}, 			&mo_equal,         NOTSENT },
				{ "code",               0,     	8,		1, BI,   	{CC_NOT_FOUND}, &mo_equal,         NOTSENT },
				{ "message ID",         0,      16,		1, BI,   	{0x00, 0x00},   &mo_ignore,	    VALUESENT },
				{ "token",              0,     	64,      1, BI,    	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&mo_ignore,        VALUESENT }
		}
};

const static struct schc_coap_rule_t lwm2m_update_registration_rule_up = {
		5, 8, 8, 8,
		{
				{ "version",            0,      2,      1, BI,      {COAP_V1},      &mo_equal,         NOTSENT },
				{ "type",               0,      2,      1, BI,      {CT_CON},       &mo_equal,         NOTSENT },
				{ "token length",       0,      4,      1, BI,      {4},			&mo_equal,         NOTSENT },
				{ "code",               0,      8,      1, BI,      {CC_POST},      &mo_equal,         NOTSENT },
				{ "message ID",         0,      16,     1, BI,      {0x00, 0x00},   &mo_ignore,        VALUESENT },
				{ "token",              0,      32,     1, BI,      {0x00, 0x00, 0x00, 0x00},
						&mo_ignore,        VALUESENT },
				{ "uri-path",           0,      16,      1, BI,      "rd",           &mo_equal,         NOTSENT },
				{ "uri-path",           0,      80,     1, BI,      "ZXV46xgT3I",   &mo_ignore,        VALUESENT }
		}
};


const static struct schc_coap_rule_t lwm2m_update_registration_rule_down = {
		6, 6, 6, 6,
		{
				{ "version",            0,      2,      1, BI,      {COAP_V1},      &mo_equal,         NOTSENT },
				{ "type",               0,      2,      1, BI,      {CT_ACK},       &mo_equal,         NOTSENT },
				{ "token length",       0,      4,      1, BI,      {4}, 			&mo_equal,         NOTSENT },
				{ "code",               0,      8,		1, BI,      {CC_CHANGED},	&mo_equal,         NOTSENT },
				{ "message ID",         0,      16,		1, BI,      {0x00, 0x00},	&mo_ignore,        VALUESENT },
				{ "token",              0,      32,     1, BI,      {0x00, 0x00, 0x00, 0x00},
						&mo_ignore,        VALUESENT }
         }
};


#endif

const struct schc_compression_rule_t registration_rule = {
#if USE_IP6
		&ipv6_lwm2m,
#endif
#if USE_UDP
		&udp_lwm2m,
#endif
#if USE_COAP
		&lwm2m_registration_rule,
#endif
};

const struct schc_compression_rule_t get_rule = {
#if USE_IP6
		&ipv6_lwm2m,
#endif
#if USE_UDP
		&udp_lwm2m,
#endif
#if USE_COAP
		&lwm2m_get_rule,
#endif
};

const struct schc_compression_rule_t catch_all_rule = {
#if USE_IP6
		&ipv6_lwm2m,
#endif
#if USE_UDP
		&udp_lwm2m,
#endif
#if USE_COAP
		&lwm2m_catch_all_rule,
#endif
};

const struct schc_compression_rule_t not_found_404 = {
#if USE_IP6
		&ipv6_lwm2m,
#endif
#if USE_UDP
		&udp_lwm2m,
#endif
#if USE_COAP
		&lwm2m_404_not_found,
#endif
};

const struct schc_compression_rule_t update_registration_up = {
#if USE_IP6
                &ipv6_lwm2m,
#endif
#if USE_UDP
                &udp_lwm2m,
#endif
#if USE_COAP
                &lwm2m_update_registration_rule_up,
#endif
};



const struct schc_compression_rule_t update_registration_down = {
#if USE_IP6
                &ipv6_lwm2m,
#endif
#if USE_UDP
                &udp_lwm2m,
#endif
#if USE_COAP
                &lwm2m_update_registration_rule_down,
#endif
};
