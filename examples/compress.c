/*
 * (c) 2018 - idlab - UGent - imec
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

#include "../schc.h"
#include "../schc_config.h"
#include "../compressor.h"

#define MAX_PACKET_LENGTH		128

// the ipv6/udp/coap packet
uint8_t msg[] = {
#if USE_IPv6 == 1
		// IPv6 header
		0x60, 0x00, 0x00, 0x00, 0x00, 0x1E, 0x11, 0x40, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xCC, 0xCC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x02,
#endif
#if USE_UDP == 1
		// UDP header
		0x33, 0x16, 0x33, 0x16, 0x00, 0x1E, 0x27, 0x4E,
#endif
#if USE_COAP == 1
		// CoAP header
		0x54, 0x03, 0x23, 0xBB, 0x21, 0xFA, 0x01, 0xFB, 0xB5, 0x75, 0x73, 0x61, 0x67, 0x65, 0xD1, 0xEA, 0x1A, 0xFF,
#endif
		// Data
		0x01, 0x02, 0x03, 0x04
};

int main() {
	// COMPRESSION
	// initialize the client compressor
	uint8_t src[16] = { 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
	schc_compressor_init(src);
	
	uint8_t compressed_buf[MAX_PACKET_LENGTH] = { 0 };
	uint32_t device_id = 0x06;

	// compress packet
	struct schc_rule_t* schc_rule;
	schc_bitarray_t bit_arr;
	bit_arr.ptr = (uint8_t*) (compressed_buf);

	schc_rule = schc_compress(msg, sizeof(msg), &bit_arr, device_id, DOWN);
#if USE_IPv6 == 1
	uint8_t compressed_header[8] = {
			0x01, // rule id
			0x62, // next header mapping index = 1 (2b), src prefix mapping index = 2 (2b), src iid = 2 (4b)
			0x11, // dst iid = 1 (4b), src port = 0 (1b), dst port = 0 (1b), type = 1 (2b)
			0xFB, // token = fb (8b)
			0x01, 0x02, 0x03, 0x04 // payload
	};
#else
	uint8_t compressed_header[8] = {
			0x01, // rule id
			0x7E, // type = 1 (2b), token = fb (6 bits)
			0xC0, // token = fb (2 remaining bits) + 6 bits payload (0x01)
			0x40, // 2 bits payload (0x01) + 6 bits (0x02)
			0x80, // 2 bits payload (0x02) + 6 bits (0x03)
			0xC1, // 2 bits payload (0x03) + 6 bits (0x04)
			0x00  // 2 bits payload (0x04) + 6 bits padding
	};
#endif

	/* test the compressed bit array */
	for (int i = 0; i < bit_arr.len; i++) {
		if (compressed_header[i] != bit_arr.ptr[i]) {
			printf(
					"An error occured while compressing, byte=%02d, original=0x%02x, compressed=0x%02x\n",
					i, compressed_header[i], bit_arr.ptr[i]);
		}
	}

	// DECOMPRESSION
	uint8_t new_packet_len = 0;

	// NOTE: DIRECTION remains UP as this packet is forwarded to the IPv6 network
	unsigned char decomp_packet[MAX_PACKET_LENGTH] = { 0 };
	new_packet_len = schc_decompress(&bit_arr, decomp_packet, device_id,
			bit_arr.len, DOWN);
	if(new_packet_len == 0) { // some error occured
		return 1;
	}

	/* test the result */
	for (int i = 0; i < sizeof(msg); i++) {
		if (msg[i] != decomp_packet[i]) {
			printf(
					"An error occured while decompressing, byte=%02d, original=0x%02x, decompressed=0x%02x\n",
					i, msg[i], decomp_packet[i]);
		}
	}

	if(sizeof(msg) != new_packet_len) {
		printf(
				"An error occured while decompressing, original length=%ld, decompressed length=%d\n",
				sizeof(msg), new_packet_len);
	}

 	return 0;
 }
