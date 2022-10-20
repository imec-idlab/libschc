/*
 * (c) 2018 - 2022  idlab - UGent - imec
 *
 * Bart Moons
 *
 * This file is part of the SCHC stack implementation
 *
 * This is a basic example on how to compress 
 * and decompress a packet
 *
 */

#include <stdio.h>
#include <stdint.h>

#include "../compressor.h"

#define MAX_PACKET_LENGTH		128

/* the direction is defined by the RFC as follows:
 * UP 	from device to network gateway
 * DOWN	from network gateway to device
 */
#define DIRECTION 				0 /* 0 = UP, 1 = DOWN */
#define PACKET_TYPE				1 /* 0 = Neighbor Discovery, 1 = Ping */

/* the IPv6/UDP/CoAP packet */
uint8_t msg[] = {
#if PACKET_TYPE == 0
				/* ND IPv6 header */
				0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3A, 0xFF, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
				0x85, 0x00, 0x7B, 0xB8, 0x00, 0x00, 0x00, 0x00
#else
				/* ICMPv6 Ping */
				0x60, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x3A, 0x40, 0xFE, 0x80,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x1A, 0x4C, 0xC6,
				0x01, 0x05, 0x36, 0xDB, 0xFE, 0x80, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x80, 0x00, 0xA4, 0x56, 0xE9, 0x80, 0x00, 0x00, 0x02, 0x13,
				0x0A, 0x0B
#endif
				};

int main() {
	/* COMPRESSION */
	/* initialize the client compressor */
	schc_compressor_init();

	uint8_t compressed_buf[MAX_PACKET_LENGTH] = { 0 };
	uint32_t device_id = 0x01;

	/* compress packet */
	struct schc_compression_rule_t *schc_rule;
	schc_bitarray_t bit_arr;
	bit_arr.ptr = (uint8_t*) (compressed_buf);

	schc_rule = schc_compress(msg, sizeof(msg), &bit_arr, device_id, DIRECTION);
#if PACKET_TYPE == 1
	uint8_t compressed_header[30] = {
			0x01, /* rule id */
#if DIRECTION == 0
			0x19, /* hop limit mapping index = 0 (1b), src prefix mapping index = 0 (1b), src iid = 0x64 >> 2 (6b) */
			0x06, 0x93, 0x31, 0x80, 0x41, 0x4D, 0xB6, /* src iid = 0x1A, 0x4C, 0xC6, 0x01, 0x05, 0x36, 0xDB >> 2 (56b) */
			0xC0, /* src iid = 0xDB (2b), dst prefix mapping index = 0 (1b), dst iid = 0 >> 3(5b) */
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* dst iid = ::1 >> 3 (56b) */
			0x30, /* dst iid = 0x01 (3b), payload = 0x80 >> 3 (5b) */
			0x00, 0x14, 0x8A, 0xDD, 0x30, 0x00, 0x00, 0x00, 0x42, 0x61, 0x41, 0x60 /* icmpv6 body >> 3, padding (5b)*/
#else
			/* direction DOWN */
			/* todo */
#endif
#else
	uint8_t compressed_header[27] = {
			0x01, /* rule id */
#if DIRECTION == 0
			/* direction UP */
			0xC0, /* hop limit mapping index = 1 (1b), src prefix mapping index = 1 (1b), src iid = 0x00 >> 2 (6b) */
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* src iid = ::0 >> 2 (56b) */
			0x20, /* src iid = 0x00 (2b), dst prefix mapping index = 1 (1b), dst iid = 0 >> 3(5b) */
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* dst iid = ::2 >> 3 (56b) */
			0x50, /* dst iid = 0x02 (3b), payload = 0x85 >> 3 (5b) */
			0xA0, 0x0F, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00 /* icmpv6 body >> 3, padding (5b)*/
#else
			/* direction DOWN */
			/* todo */
#endif
#endif
	};

	/* test the compressed bit array */
	int err = 0;
	printf("\n");
	for (int i = 0; i < bit_arr.len; i++) {
		if (compressed_header[i] != bit_arr.ptr[i]) {
			printf(
					"main(): an error occured while compressing, byte=%02d, original=0x%02x, compressed=0x%02x\n",
					i, compressed_header[i], bit_arr.ptr[i]);
			err = 1;
		}
	}

	if (!err) {
		printf("main(): compression succeeded\n");
	}

	/* DECOMPRESSION */
	uint8_t new_packet_len = 0;

	/* NOTE: DIRECTION is set to the flow the packet is following as this packet
	 * and thus equals the direction of the compressor
	 */
	unsigned char decomp_packet[MAX_PACKET_LENGTH] = { 0 };
	new_packet_len = schc_decompress(&bit_arr, decomp_packet, device_id,
			bit_arr.len, DIRECTION);
	if (new_packet_len == 0) { /* some error occurred */
		return 1;
	}

	/* test the result */
	for (int i = 0; i < sizeof(msg); i++) {
		if (msg[i] != decomp_packet[i]) {
			printf(
					"main(): an error occured while decompressing, byte=%02d, original=0x%02x, decompressed=0x%02x\n",
					i, msg[i], decomp_packet[i]);
			err = 1;
		}
	}

	if (sizeof(msg) != new_packet_len) {
		printf(
				"main(); an error occured while decompressing, original length=%ld, decompressed length=%d\n",
				sizeof(msg), new_packet_len);
		err = 1;
	}

	if (!err) {
		printf("main(): decompression succeeded\n");
	}

	return 0;
}
