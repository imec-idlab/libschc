#include "../schc.h"
#include "../picocoap.h"

/* first build the compression rules separately per layer */
#if USE_IP6
const static struct schc_ipv6_rule_t ipv6_rule1 = {
	//	id, up, down, length
		10, 10, 10,
		{
			//	field, 			MO, len, pos,dir, 	val,			MO,				CDA
				{ IP6_V,	 	0, 4,	1, BI, 		{6},			&mo_equal, 		NOTSENT },
				{ IP6_TC, 		0, 8,	1, BI, 		{0},			&mo_ignore, 	NOTSENT },
				{ IP6_FL, 		0, 20,	1, BI, 		{0, 0, 0},		&mo_ignore, 	NOTSENT },
				{ IP6_LEN, 		0, 16,	1, BI, 		{0, 0},			&mo_ignore, 	COMPLENGTH },
				{ IP6_NH, 		3, 8, 	1, BI, 		{6, 17, 58},	&mo_matchmap, 	MAPPINGSENT },
				{ IP6_HL, 		0, 8, 	1, BI, 		{64}, 			&mo_ignore, 	NOTSENT },
				{ IP6_DEVPRE,	4, 64,	1, BI,		{0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
														 0xBB, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
														 0xCC, 0xCC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
														 0xDD, 0xDD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&mo_matchmap, 	MAPPINGSENT }, // you can store as many IP's as (MAX_FIELD_LENGTH / 8)
				{ IP6_DEVIID,	60, 64,	1, BI, 		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
						&mo_MSB, 		LSB },
				{ IP6_APPPRE,	0, 64,	1, BI,		{0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&mo_equal, 		NOTSENT },
				{ IP6_APPIID,	60, 64,	1, BI, 	    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
						&mo_MSB, 		LSB }, // match the 60 first bits, send the last 4
		}
};

const static struct schc_ipv6_rule_t ipv6_rule2 = {
		10, 10, 10,
		{
				{ IP6_V,		0,  4,	 1, BI, 	{6},			&mo_equal, 	NOTSENT },
				{ IP6_TC, 		0,  8,	 1, BI, 	{0},			&mo_equal, 	NOTSENT },
				{ IP6_FL, 		0,  20,	 1, BI, 	{0, 0, 0x20},	&mo_equal, 	NOTSENT },
				{ IP6_LEN, 		0,  16,	 1, BI, 	{0, 0},			&mo_ignore, 	COMPLENGTH },
				{ IP6_NH, 		0,  8, 	 1, BI, 	{17}, 			&mo_equal, 	NOTSENT },
				{ IP6_HL, 		0,  8, 	 1, BI, 	{64}, 			&mo_ignore, 	NOTSENT },
				{ IP6_DEVPRE,	0,  64,	 1, BI, 	{0x20, 0x01, 0x06, 0xA8, 0x1D, 0x80, 0x20, 0x21},
						&mo_equal, 	NOTSENT },
				{ IP6_DEVIID,	16, 64,  1, BI, 	{0x02, 0x30, 0x48, 0xFF, 0xFE, 0x5A, 0x00, 0x00},
						&mo_MSB, 	LSB }, // match the 16 first bits, send the last 48
				{ IP6_APPPRE,	0,  64,  1, BI, 	{0x20, 0x01, 0x06, 0xA8, 0x1D, 0x80, 0x20, 0x21},
						&mo_equal, 	NOTSENT },
				{ IP6_APPIID,	16, 64,  1, BI, 	{0x50, 0x74, 0xF2, 0xFF, 0xFE, 0xB1, 0x00, 0x00},
						&mo_MSB, 	LSB },
		}
};

const static struct schc_ipv6_rule_t ipv6_rule3 = {
	//	id, up, down, length
		10, 10, 10,
		{
			//	field, 			   MO, len,	 pos,dir, 	val,			MO,			CDA
				{ IP6_V, 		0, 4,	 1, BI, 	{6},			&mo_equal, 	VALUESENT },
				{ IP6_TC, 		0, 8,	 1, BI, 	{0},			&mo_ignore, 	NOTSENT },
				{ IP6_FL, 		0, 20,	 1, BI, 	{0, 0, 0},		&mo_ignore, 	NOTSENT },
				{ IP6_LEN, 		0, 16,	 1, BI, 	{0, 0},			&mo_ignore, 	COMPLENGTH },
				{ IP6_NH, 		0, 8, 	 1, BI, 	{17},			&mo_equal, 	NOTSENT },
				{ IP6_HL, 		0, 8, 	 1, BI, 	{64}, 			&mo_ignore, 	NOTSENT },
				{ IP6_DEVPRE,	0, 64,	 1, BI,		{0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&mo_equal, 	NOTSENT },
				{ IP6_DEVIID,	0, 64, 	 1, BI, 	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
						&mo_equal, 	NOTSENT },
				{ IP6_APPPRE,	0, 64, 	 1, BI,		{0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&mo_equal, 	NOTSENT },
				{ IP6_APPIID,	60, 64,  1, BI, 	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&mo_MSB, 		LSB},
		}
};
#endif

#if USE_UDP
const static struct schc_udp_rule_t udp_rule1 = {
		4, 4, 4,
		{
				{ UDP_DEV, 		2,	16, 	 1, BI, 	{0x33, 0x16, 0x33, 0x17},
						&mo_matchmap,	MAPPINGSENT }, // 5683 or 5684
				{ UDP_APP, 		2,	16, 	 1, BI, 	{0x33, 0x16, 0x33, 0x17},
						&mo_matchmap,	MAPPINGSENT },
						// set field length to 16 to indicate 16 bit values
						// MO param to 2 to indicate 2 indices
				{ UDP_LEN, 		0,	16, 	 1, BI, 	{0, 0},		 		&mo_ignore,	COMPLENGTH },
				{ UDP_CHK, 		0,	16, 	 1, BI, 	{0, 0},				&mo_ignore,	COMPCHK },
		}
};

const static struct schc_udp_rule_t udp_rule2 = {
		4, 4, 4,
		{
				{ UDP_DEV, 		12,	16,	 1, BI, 	{0x33, 0x16},		&mo_MSB,		LSB },
				{ UDP_APP, 		12,	16,	 1, BI, 	{0x33, 0x16},		&mo_MSB,		LSB },
				{ UDP_LEN, 		0,  16,	 1, BI, 	{0, 0},				&mo_ignore,	COMPLENGTH },
				{ UDP_CHK, 		0,  16,	 1, BI, 	{0, 0},				&mo_ignore,	COMPCHK },
		}
};

const static struct schc_udp_rule_t udp_rule3 = {
		4, 4, 4,
		{
				{ UDP_DEV, 		0,	16,	 1, BI, 	{0x13, 0x89}, 		&mo_equal,		NOTSENT },
				{ UDP_APP, 		0, 	16,	 1, BI, 	{0x13, 0x88}, 		&mo_equal,		NOTSENT },
				{ UDP_LEN, 		0, 	16,	 1, BI, 	{0, 0},				&mo_ignore,	COMPLENGTH },
				{ UDP_CHK, 		0, 	16,	 1, BI, 	{0, 0},				&mo_ignore,	COMPCHK },
		}
};
#endif

#if USE_COAP
const static struct schc_coap_rule_t coap_rule1 = { /* GET /usage */
		9, 7, 9,
		{
				{ COAP_V,		0,	2,	 1, BI,		{COAP_V1},		&mo_equal,			NOTSENT },
				{ COAP_T,		4,	2,	 1, BI,		{CT_CON, CT_NON, CT_ACK, CT_RST},
						&mo_matchmap,	MAPPINGSENT	}, // todo: non word-aligned mo_matchmap
				{ COAP_TKL,		0,	4,	 1, BI,		{4},			&mo_equal,			NOTSENT },
				{ COAP_C,		0,	8,	 1, BI,		{CC_PUT},		&mo_equal,			NOTSENT },
				{ COAP_MID,		0,	16,	 1, BI,		{0x23, 0xBB},	&mo_equal,			NOTSENT },
				{ COAP_TKN,		24,	32,	 1, BI,		{0x21, 0xFA, 0x01, 0x00},
						&mo_MSB,		LSB },
				{ COAP_URIPATH, 0,	40,	 1, BI,		"usage", 		&mo_equal,			NOTSENT },
				{ COAP_NORESP, 	0,	8,	 1, BI,		{0x1A}, 		&mo_equal,			NOTSENT },
				{ COAP_PAYLOAD,	0,	8,   1, BI, 	{0xFF},			&mo_equal,			NOTSENT }

		}
};

const static struct schc_coap_rule_t coap_rule2 = { /* POST /temp= */
		8, 8, 10,
		{
				{ COAP_V,		0,	2,	 1, BI,		{COAP_V1},		&mo_equal,		NOTSENT },
				{ COAP_T,		3,	2,	 1, BI,		{CT_CON, CT_ACK, CT_NON},
						// the MO_param_length is used to indicate the true length of the list
						&mo_matchmap, MAPPINGSENT	},
				{ COAP_TKL,		0,	4,	 1, BI,		{4},			&mo_equal,		NOTSENT },
				{ COAP_C,		0,	4,	 1, UP,		{CC_CONTENT},	&mo_equal,		NOTSENT },
				{ COAP_C,		0,	8,	 1, DOWN,	{CC_GET},		&mo_equal,		NOTSENT },
				{ COAP_MID,		12,	16,	 1, UP,		{0x23, 0xBB},	&mo_MSB,		LSB },
				{ COAP_MID,		12,	16,	 1, DOWN,	{0x7A, 0x10},	&mo_MSB,		LSB }, // match the first 12 bits
				{ COAP_TKN,		0,	32,	 1, BI,		{0, 0, 0, 0},	&mo_ignore,	VALUESENT }, // GET sensor value
				{ COAP_URIPATH, 4,	0,	 2, BI,		"[\"temp\",\"humi\",\"batt\",\"r\"]\0",
						// todo variable field length and json
						&mo_matchmap,		MAPPINGSENT },
				{ COAP_PAYLOAD,	0,	8,   1, BI, 	{255},			&mo_equal,		NOTSENT } // respond with CONTENT
		}
};

const static struct schc_coap_rule_t coap_rule4 = {
		12, 12, 12,
		{
				{ COAP_V,       0,	2,	1, BI,      {COAP_V1},		&mo_equal,         NOTSENT },
				{ COAP_T,       0,  2,	1, BI,      {CT_CON},		&mo_equal,         NOTSENT },
				{ COAP_TKL,   	0,  4,	1, BI,      {8}, 			&mo_equal,         NOTSENT },
				{ COAP_C,       0,  8,	1, BI,      {CC_POST},      &mo_equal,         NOTSENT },
				{ COAP_MID,     0,  16,	1, BI,      {0x23, 0xBB},   &mo_ignore,	    VALUESENT },
				{ COAP_TKN,		24,	32,	 1, BI,		{0x21, 0xFA, 0x01, 0x00},
						&mo_MSB,		LSB }, // match the 24 first bits, send the last 8
				{ COAP_URIPATH, 0,  16,	1, BI,      "rd",           &mo_equal,         NOTSENT },
                { COAP_CONTENTF,0,  8,	1, BI,      {0x28},         &mo_equal,         NOTSENT },
                { COAP_URIQUERY,0,  72,	1, BI,      {0x6C, 0x77, 0x6D, 0x32, 0x6D, 0x3D, 0x31, 0x2E, 0x30},
                		&mo_equal,         NOTSENT },
                { COAP_URIQUERY,0,  88,	1, BI,      {0x65, 0x70, 0x3D, 0x6D, 0x61, 0x67, 0x69, 0x63, 0x69, 0x61, 0x6E},
                		&mo_equal,         NOTSENT },
                { COAP_URIQUERY,0,  48,	1, BI,      {0x6C, 0x74, 0x3D, 0x31, 0x32, 0x31},
                		&mo_equal,         NOTSENT },
				{ COAP_PAYLOAD, 0,  8,	1, BI,		{255},			&mo_equal,         NOTSENT } // respond with CONTENT
               }

};
#endif

/* next build the compression rules from the rules that make up a single layer */
const struct schc_compression_rule_t compression_rule_1 = {
		.rule_id = 0x01,
		.rule_id_size_bits = 8,
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
		.rule_id = 0x02,
		.rule_id_size_bits = 8,
#if USE_IP6
		&ipv6_rule1,
#endif
#if USE_UDP
		&udp_rule2,
#endif
#if USE_COAP
		&coap_rule2,
#endif
};

const struct schc_compression_rule_t compression_rule_3 = {
		0x03,
		8, /* rule id size bits */
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
		0x04,
		8, /* rule id size bits */
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

/* now build the fragmentation rules */
const struct schc_fragmentation_rule_t fragmentation_rule_1 = {
		.rule_id = 0x01,
		.rule_id_size_bits = 8,
		.mode = NOT_FRAGMENTED,
		.dir = BI,
		.FCN_SIZE = 0,
		.MAX_WND_FCN = 0, 	/* maximum fragments per window */
		.WINDOW_SIZE = 0,
		.DTAG_SIZE = 0
};

const struct schc_fragmentation_rule_t fragmentation_rule_2 = {
		.rule_id = 0x02,
		.rule_id_size_bits = 8,
		.mode = NO_ACK,
		.dir = BI,
		.FCN_SIZE = 1,
		.MAX_WND_FCN = 0,
		.WINDOW_SIZE = 0,
		.DTAG_SIZE = 0
};

const struct schc_fragmentation_rule_t fragmentation_rule_3 = {
		.rule_id = 0x03,
		.rule_id_size_bits = 8,
		.mode = ACK_ON_ERROR,
		.dir = BI,
		.FCN_SIZE = 3,
		.MAX_WND_FCN = 6,
		.WINDOW_SIZE = 1,
		.DTAG_SIZE = 0
};

const struct schc_fragmentation_rule_t fragmentation_rule_4 = {
		.rule_id = 0x04,
		.rule_id_size_bits = 8,
		.mode = ACK_ALWAYS,
		.dir = BI,
		.FCN_SIZE = 3,
		.MAX_WND_FCN = 6,
		.WINDOW_SIZE = 1,
		.DTAG_SIZE = 0
};

/* save compression rules in flash */
const struct schc_compression_rule_t* node1_compression_rules[] = {
		&compression_rule_1, &compression_rule_2, &compression_rule_3, &compression_rule_4
};

/* save fragmentation rules in flash */
const struct schc_fragmentation_rule_t* node1_fragmentation_rules[] = {
		&fragmentation_rule_1, &fragmentation_rule_2, &fragmentation_rule_3, &fragmentation_rule_4
};

/* now build the context for a particular device */
const struct schc_device node1 = {
		.device_id = 0x06,
		.uncomp_rule_id = 0,
		.uncomp_rule_id_size_bits = 8,
		.compression_rule_count = 4,
		.compression_context = &node1_compression_rules,
		.fragmentation_rule_count = 4,
		.fragmentation_context = &node1_fragmentation_rules
};
const struct schc_device node2 = {
		.device_id = 0x01,
		.uncomp_rule_id = 0,
		.uncomp_rule_id_size_bits = 8,
		.compression_rule_count = 4,
		.compression_context = &node1_compression_rules,
		.fragmentation_rule_count = 4,
		.fragmentation_context = &node1_fragmentation_rules
};

#define DEVICE_COUNT			2

/* server keeps track of multiple devices: add devices to device list */
const struct schc_device* devices[DEVICE_COUNT] = { &node1, &node2 };
