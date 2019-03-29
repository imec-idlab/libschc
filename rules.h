#ifndef _RULES_H_
#define _RULES_H_

// ToDo
// output functions should be adapted
// tie the output rules to the device which is sending
#define IPV6_RULES				2
#define UDP_RULES				3
#define COAP_RULES				3

#define DEVICE_COUNT			2

#include "pt/pt.h"
#include "schc_config.h"

const static struct schc_rule ipv6_rule1 = {
	//	id, up, down, length
		1, 10, 10, 10,
		{
			//	field, 			   MSB,len,	 pos,dir, 	val,			MO,			CDA
				{ "version", 		0, 1,	 1, BI, 	{6},			&equal, 	NOTSENT },
				{ "traffic class", 	0, 1,	 1, BI, 	{0},			&equal, 	NOTSENT },
				{ "flow label", 	0, 3,	 1, BI, 	{0, 0, 0},		&equal, 	NOTSENT },
				{ "length", 		0, 2,	 1, BI, 	{0, 0},			&ignore, 	COMPLENGTH },
				{ "next header", 	0, 1, 	 1, BI, 	{17}, 			&equal, 	NOTSENT },
				{ "hop limit", 		0, 1, 	 1, BI, 	{32}, 			&equal, 	NOTSENT },
				{ "src prefix",		0, 8,	 1, BI,		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&equal, 	NOTSENT },
				{ "src iid",		0, 8, 	 1, BI, 	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
						&equal, 	NOTSENT },
				{ "dest prefix",	0, 8, 	 1, BI,		{0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&equal, 	NOTSENT },
				{ "dest iid",		48, 8, 	 1, BI, 	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&MSB, 		LSB },
		}
};

const static struct schc_rule ipv6_rule2 = {
		2, 10, 10, 10,
		{
				{ "version", 		0,  1,	 1, BI, 	{6},			&equal, 	NOTSENT },
				{ "traffic class", 	0,  1,	 1, BI, 	{0},			&equal, 	NOTSENT },
				{ "flow label", 	0,  3,	 1, BI, 	{0, 0, 0x20},	&equal, 	NOTSENT },
				{ "length", 		0,  2,	 1, BI, 	{0, 0},			&ignore, 	COMPLENGTH },
				{ "next header", 	0,  1, 	 1, BI, 	{17}, 			&equal, 	NOTSENT },
				{ "hop limit", 		0,  1, 	 1, BI, 	{64}, 			&ignore, 	NOTSENT },
				{ "src prefix",	 	0,  8,	 1, BI, 	{0x20, 0x01, 0x06, 0xA8, 0x1D, 0x80, 0x20, 0x21},
						&equal, 	NOTSENT },
				{ "src iid",		48, 8, 	 1, BI, 	{0x02, 0x30, 0x48, 0xFF, 0xFE, 0x5A, 0x00, 0x00},
						&MSB, 	LSB }, // by setting the last bytes to 0xFF, we allow 8 bit variations
				{ "dest prefix",	0,  8, 	 1, BI, 	{0x20, 0x01, 0x06, 0xA8, 0x1D, 0x80, 0x20, 0x21},
						&equal, 	NOTSENT },
				{ "dest iid",		48, 8, 	 1, BI, 	{0x50, 0x74, 0xF2, 0xFF, 0xFE, 0xB1, 0x00, 0x00},
						&MSB, 	LSB },
		}
};

const static struct schc_rule ipv6_rule3 = {
		3, 10, 10, 10,
		{
			//	field, 			   MSB,len,	 pos,dir, 	val,			MO,			CDA
				{ "version", 		0, 1,	 1, BI, 	{6},			&equal, 	NOTSENT },
				{ "traffic class", 	0, 1,	 1, BI, 	{0},			&equal, 	NOTSENT },
				{ "flow label", 	0, 3,	 1, BI, 	{0, 0, 0},		&equal, 	NOTSENT },
				{ "length", 		0, 2,	 1, BI, 	{0, 0},			&ignore, 	COMPLENGTH },
				{ "next header", 	0, 1, 	 1, BI, 	{17}, 			&equal, 	NOTSENT },
				{ "hop limit", 		0, 1, 	 1, BI, 	{32}, 			&equal, 	NOTSENT },
				{ "src prefix",		0, 8,	 1, BI,		{0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&equal, 	NOTSENT },
				{ "src iid",		0, 8, 	 1, BI, 	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
						&equal, 	NOTSENT },
				{ "dest prefix",	0, 8, 	 1, BI,		{0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						&equal, 	NOTSENT },
				{ "dest iid",		48, 8, 	 1, BI, 	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
						&ignore, 	NOTSENT },
		}
};

const static struct schc_rule udp_rule1 = {
		1, 4, 4, 4,
		{
				{ "src port", 		0, 2, 	 1, BI, 	{0x16, 0x33}, 		&equal,		NOTSENT }, // 5683
				{ "dest port", 		0, 2, 	 1, BI, 	{0x16, 0x33}, 		&equal,		NOTSENT },
				{ "length", 		0, 2, 	 1, BI, 	{0, 0},		 		&ignore,	COMPLENGTH },
				{ "checksum", 		0, 2, 	 1, BI, 	{0, 0},				&ignore,	COMPCHK },
		}
};

const static struct schc_rule udp_rule2 = {
		2, 4, 4, 4,
		{
				{ "src port", 		12, 2, 	 1, BI, 	{4, 48},		&MSB,		LSB }, // 1072 - 1087 | {4, 48}
				{ "dest port", 		12, 2, 	 1, BI, 	{4, 48},		&MSB,		LSB }, // 1072 - 1087 | {4, 48}
				{ "length", 		0,  2, 	 1, BI, 	{0, 0},			&ignore,	COMPLENGTH },
				{ "checksum", 		0,  2, 	 1, BI, 	{0, 0},			&ignore,	COMPCHK },
		}
};

const static struct schc_rule udp_rule3 = {
		3, 4, 4, 4,
		{
				{ "src port", 		0, 2, 	 1, BI, 	{0x33, 0x16}, 		&equal,		NOTSENT },
				{ "dest port", 		0, 2, 	 1, BI, 	{0x33, 0x16}, 		&equal,		NOTSENT },
				{ "length", 		0, 	2,	 1, BI, 	{0, 0},				&ignore,	COMPLENGTH },
				{ "checksum", 		0, 	2,	 1, BI, 	{0, 0},				&ignore,	COMPCHK },
		}
};

// it is important to use strings, identical to the ones
// defined in coap.h for the options

// GET temperature value
const static struct schc_rule coap_rule1 = {
		1, 8, 7, 8,
		{
				{ "version",		0,	1,	 1, BI,		{COAP_V1},		&equal,		NOTSENT },
				{ "type",			0,	1,	 1, BI,		{CT_NON},		&equal, 	NOTSENT	},
				{ "token length",	0,	1,	 1, BI,		{2},			&equal,		NOTSENT },
				{ "code",			0,	1,	 1, UP,		{CC_POST},		&equal,		NOTSENT },
				{ "code",			0,	1,	 1, DOWN,	{CC_GET},		&equal,		NOTSENT },
				{ "message ID",		0,	2,	 1, BI,		{0x23, 0xBB},	&ignore,	VALUESENT }, // 23988
				{ "token",			0,	2,	 1, BI,		{0x21, 0xFA},	&equal,		NOTSENT }, // 0x21fa
				{ "uri-path", 		0,	4,	 2, BI,		"[\"temp\",\"humi\",\"batt\",\"r\"]\0",
						&matchmap,		MAPPINGSENT },
				{ "payload marker",	0,	1,   1, BI, 	{255},			&equal,		NOTSENT } // respond with CONTENT

		}
};

// POST temperature value
const static struct schc_rule coap_rule2 = {
		2, 8, 8, 10,
		{
				{ "version",		0,	1,	 1, BI,		{COAP_V1},		&equal,		NOTSENT },
				{ "type",			0,	3,	 1, BI,		{CT_CON, CT_ACK, CT_NON},
						&matchmap, MAPPINGSENT	},
				{ "token length",	0,	1,	 1, BI,		{4},			&equal,		NOTSENT },
				{ "code",			0,	1,	 1, UP,		{CC_CONTENT},	&equal,		NOTSENT },
				{ "code",			0,	1,	 1, DOWN,	{CC_GET},		&equal,		NOTSENT },
				{ "message ID",		12,	2,	 1, UP,		{0x23, 0xBB},	&MSB,		LSB },
				{ "message ID",		12,	2,	 1, DOWN,	{0x7A, 0x10},	&MSB,		LSB },
				{ "token",			0,	4,	 1, BI,		{0, 0, 0, 0},	&ignore,	VALUESENT }, // GET sensor value
				{ "uri-path", 		0,	4,	 2, BI,	"[\"temp\",\"humi\",\"batt\",\"r\"]\0",
						&matchmap,		MAPPINGSENT },
				{ "payload marker",	0,	1,   1, BI, 	{255},			&equal,		NOTSENT } // respond with CONTENT
		}
};


const static struct schc_rule coap_rule3 = {
		3, 5, 6, 8,
		{
				{ "version",		0,	1,	1, BI,		{COAP_V1},		&equal,		NOTSENT },
				{ "type",			0,	1,	1, DOWN,	{CT_CON},		&equal, 	NOTSENT	},
				{ "type",			0,	1,	1, UP,		{CT_ACK},		&equal, 	NOTSENT	},
				{ "token length",	0,	1,	1, BI,		{0},			&equal,		NOTSENT },
				{ "code",			0,	1,	1, DOWN,	{CC_POST},		&equal,		NOTSENT },
				{ "code",			0,	1,	1, UP,		{CC_POST},		&equal,		NOTSENT },
				{ "message ID",		0,	2,	1, BI,		{93, 180},		&equal,		VALUESENT }, // 23988
				{ "payload marker",	0,	1,  1, DOWN,	{255},			&equal,		NOTSENT }
		}
};

// save rules in flash
const struct schc_rule* schc_ipv6_rules[] = { &ipv6_rule1, &ipv6_rule2, &ipv6_rule3 };
const struct schc_rule* schc_udp_rules[] =
		{ &udp_rule1, &udp_rule2, &udp_rule3 };
const struct schc_rule* schc_coap_rules[] = { &coap_rule1, &coap_rule2,
		&coap_rule3 };

struct schc_device node1 = { 1, 3, &schc_ipv6_rules, 3, &schc_udp_rules,
		3, &schc_coap_rules };
struct schc_device node2 = { 2, 2, &schc_ipv6_rules, 3, &schc_udp_rules,
		3, &schc_coap_rules };

struct schc_device* devices[DEVICE_COUNT] = {
		&node1, &node2
};

#endif
