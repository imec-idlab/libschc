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

#include "../compressor.h"
#include "../config.h"

#define MAX_PACKET_LENGTH		128

// the ipv6/udp/coap packet
uint8_t msg[] = {
		// IPv6 header
		0x60, 0x00, 0x00, 0x00, 0x00, 0x1E, 0x11, 0x40, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x02,
		// UDP header
		0x33, 0x16, 0x33, 0x16, 0x00, 0x1E, 0x27, 0x4E,
		// CoAP header
		0x54, 0x03, 0x23, 0xBB, 0x21, 0xFA, 0x01, 0xFB, 0xB5, 0x75, 0x73, 0x61, 0x67, 0x65, 0xD1, 0xEA, 0x1A, 0xFF,
		// Data
		0x01, 0x02, 0x03, 0x04
};

 int main() {
	// COMPRESSION
	// initialize the client compressor
	uint8_t src[16] = { 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
	schc_compressor_init(src);
	
	uint8_t compressed_buf[MAX_PACKET_LENGTH];
	uint32_t device_id = 0x02;

	// compress packet
	struct schc_rule_t* schc_rule;
	schc_bitarray_t bit_arr;
	bit_arr.ptr = &compressed_buf;
//
//	uint8_t ds[2] = { 0 }; uint8_t sr[2] = { 0x06 };
//
//	copy_bits_BIG_END(ds, 4, sr, 0, 4);
//	DEBUG_PRINTF("%2x %2x \n", ds[0], ds[1]);

	int compressed_len = schc_compress(msg, sizeof(msg), &bit_arr, device_id,
			UP, DEVICE, &schc_rule);

	// DECOMPRESSION
	uint8_t new_packet_len = 0;

	// NOTE: DIRECTION remains UP as this packet is forwarded to the IPv6 network
	unsigned char decomp_packet[MAX_PACKET_LENGTH] = { 0 };
	new_packet_len = schc_decompress((unsigned char*) compressed_buf,
			decomp_packet, device_id, compressed_len, UP, NETWORK_GATEWAY);
	if(new_packet_len == 0) { // some error occured
		return 1;
	}

	// todo
	// padding management

 	return 0;
 }
