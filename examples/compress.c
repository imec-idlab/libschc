/*
 * (c) 2018 - idlab - UGent - imec
 *
 * Bart Moons
 *
 * This file is part of the SCHC stack implementation
 * the basics on how to compress and decompress a packet
 * are presented
 *
 */

#include <stdio.h>
#include <stdint.h>

#include "../compressor.h"
#include "../schc_config.h"

#define MAX_PACKET_LENGTH		128

// the ipv6 packet
uint8_t msg[69] = { 0x60, 0x00, 0x00, 0x00, 0x00, 0x1E, 0x11, 0x40, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x01, 0x33, 0x16, 0x33, 0x16, 0x00, 0x1E, 0x2B, 0x54, 0x54, 0x03, 0x23, 0xBB, 0x21, 0xFA, 0x01, 0xFB, 0xB5, 0x75, 0x73, 0x61, 
 0x67, 0x65, 0xD1, 0xEA, 0x1A, 0xFF, 0x00, 0x00, 0x00, 0x00 };

 int main() {
	// initialize the de-compressor
	uint8_t src[16] = { 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
	schc_compressor_init(src);

	/*
	 * PACKET FROM IPV6 TO LPWAN
	*/

	// create a new packet to store the compressed packet
	// maximum length is uncompressed previous packet with an SCHC header
	uint8_t compressed_buf[MAX_PACKET_LENGTH];

	// compress packet
	int compressed_len = schc_compress(msg, compressed_buf, 69);
	
	/*
	 * PACKET FROM IPV6 TO LPWAN
	*/
	uint8_t schc_offset = 0; // schc offset is the compressed header size
	uint8_t new_headerlen = 0;

	unsigned char decomp_header[MAX_HEADER_LENGTH] = { 0 };
	new_headerlen = schc_construct_header((unsigned char*) compressed_buf, decomp_header, 1, compressed_len, &schc_offset);
	if(new_headerlen == 0) {
		// some error occured
		return 1;
	}

	uint16_t payload_len = (compressed_len - schc_offset); // the schc header minus the total length is the payload length
	uint8_t* packetptr = (uint8_t*) malloc(new_headerlen + payload_len);

	memcpy((uint8_t*) (packetptr), decomp_header, new_headerlen);
	memcpy((uint8_t*) (packetptr + new_headerlen),
			(uint8_t*) (compressed_buf + schc_offset), payload_len);

	// ToDo
	// should be integrated in library
	compute_length(packetptr, (payload_len + new_headerlen));
	compute_checksum(packetptr);

 	return 0;
 }