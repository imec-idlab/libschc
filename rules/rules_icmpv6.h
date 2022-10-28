/*
 * Copyright (C) 2018 imec IDLab
 * Copyright (C) 2022 Freie Universität Berlin
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @internal
 * @author  boortmans <bart.moons@gmail.com>
 * @author  Martine S. Lenders <m.lenders@fu-berlin.de>
 */
#ifndef RULES_RULES_H
#define RULES_RULES_H

#ifdef __cplusplus
extern "C" {
#endif

#if USE_IP6
/* ICMPv6 headers */
static const struct schc_ipv6_rule_t ipv6_rule1 = {
    .up = 10, .down = 10, .length = 10,
    {
        /* field,       ML, len, pos, dir,  val,                MO,             CDA         */
        { IP6_V,         0,   4,   1, BI,   {6},                &mo_equal,      NOTSENT     },
        { IP6_TC,        0,   8,   1, BI,   {0},                &mo_ignore,     NOTSENT     },
        { IP6_FL,        0,  20,   1, BI,   {0, 0, 0},          &mo_ignore,     NOTSENT     },
        { IP6_LEN,       0,  16,   1, BI,   {0, 0},             &mo_ignore,     COMPLENGTH  },
        { IP6_NH,        0,   8,   1, BI,   {58},               &mo_ignore,     NOTSENT     },
        { IP6_HL,        2,   8,   1, BI,   {64, 255},          &mo_matchmap,   MAPPINGSENT },
        { IP6_DEVPRE,    2,  64,   1, BI,   {
                0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            },                                                  &mo_matchmap,   MAPPINGSENT },
        /* TODO use DEVIID once it is implemented in libSCHC */
        { IP6_DEVIID,    0,  64,   1, BI,   {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            },                                                  &mo_ignore,     VALUESENT   },
        { IP6_APPPRE,    2,  64,   1, BI,   {
                0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            },                                                  &mo_matchmap,   MAPPINGSENT },
        { IP6_APPIID,    0,  64,   1, BI,   {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
            },                                                  &mo_ignore,     VALUESENT   },
    }
};
#endif

#if USE_UDP
/* TODO fit for udp command */
static const struct schc_udp_rule_t udp_rule1 = {
    .up = 4, .down = 4, .length = 4,
    {
        /* field,       ML, len, pos, dir,  val,                MO,             CDA         */
        /* set field length to 16 to indicate 16 bit values
         *  MO param length to 2 to indicate 2 indices */
        { UDP_DEV,       2,  16,   1,  BI,  {
                0x33, 0x16, /* 5683 or */
                0x33, 0x17  /* 5684 */
            },                                                  &mo_matchmap,   MAPPINGSENT },
        { UDP_APP,       2,  16,   1,  BI,  {
                0x33, 0x16, /* 5683 or */
                0x33, 0x17  /* 5684 */
            },                                                  &mo_matchmap,   MAPPINGSENT },
        { UDP_LEN,       0,  16,   1,  BI,  {0, 0},             &mo_ignore,     COMPLENGTH  },
        { UDP_CHK,       0,  16,   1,  BI,  {0, 0},             &mo_ignore,     COMPCHK     },
    }
};
#endif

static const struct schc_compression_rule_t comp_rule_1 = {
	.rule_id = 0x01,
	.rule_id_size_bits = 8,
#if USE_IP6
    &ipv6_rule1,
#endif
#if USE_UDP
    NULL,
#endif
#if USE_COAP
    NULL,
#endif
};

static const struct schc_compression_rule_t comp_rule_2 = {
    .rule_id = 0x02,
	.rule_id_size_bits = 8,
#if USE_IP6
    &ipv6_rule1,    /* TODO: needs dedicated rule */
#endif
#if USE_UDP
    &udp_rule1,
#endif
#if USE_COAP
    NULL,
#endif
};

static const struct schc_fragmentation_rule_t frag_rule_20 = {
    .rule_id = 20,
	.rule_id_size_bits = 8,
    .mode = ACK_ON_ERROR,
    .dir = UP,
    .FCN_SIZE = 6,      /* FCN size */
    .MAX_WND_FCN = 62,  /* Maximum fragments per window */
    .WINDOW_SIZE = 2,   /* Window size */
    .DTAG_SIZE = 0,     /* DTAG size */
};

static const struct schc_fragmentation_rule_t frag_rule_21 = {
    .rule_id = 21,
	.rule_id_size_bits = 8,
    .mode = ACK_ALWAYS,
    .dir = DOWN,
    .FCN_SIZE = 1,      /* FCN size */
    .MAX_WND_FCN = 1,   /* Maximum fragments per window */
    .WINDOW_SIZE = 1,   /* Window size */
    .DTAG_SIZE = 0,     /* DTAG size */
};

/* save compression rules in flash */
static const struct schc_compression_rule_t* node1_compression_rules[] = {
    &comp_rule_1, &comp_rule_2,
};

/* save fragmentation rules in flash */
static const struct schc_fragmentation_rule_t* node1_fragmentation_rules[] = {
    &frag_rule_20, &frag_rule_21,
};

/* rules for a particular device */
static const struct schc_device node1 = {
    .device_id = 1,
    .uncomp_rule_id = 0,
	.uncomp_rule_id_size_bits = 8,
    .compression_rule_count = 2,
    .compression_context = &node1_compression_rules,
    .fragmentation_rule_count = 2,
    .fragmentation_context = &node1_fragmentation_rules
};

/* server keeps track of multiple devices: add devices to device list */
static const struct schc_device* devices[] = { &node1 };

#define DEVICE_COUNT    ((int)(sizeof(devices) / sizeof(devices[0])))

#ifdef __cplusplus
}
#endif

#endif /* RULES_RULES_H */
