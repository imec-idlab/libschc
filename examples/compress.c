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
#define DIRECTION 				1 /* 0 = UP, 1 = DOWN */

/* the IPv6/UDP/CoAP packet */
uint8_t msg[] = {
#if USE_IP6_UDP == 1
#if DIRECTION == 0
				/* direction UP: from device (CCCC::2) to network gateway (AAAA::1) */
				/* IPv6 header */
				0x60, 0x00, 0x00, 0x00, 0x00, 0x1E, 0x11, 0x40, 0xCC, 0xCC,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x02,	0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				// UDP header
				0x33, 0x16, 0x33, 0x16, 0x00, 0x1E, 0x05, 0x2C,
#else 			/* direction DOWN: from network gateway (AAAA::1) to device (CCCC::2) */
				/* IPv6 header */
				0x60, 0x00, 0x00, 0x00, 0x00, 0x1E, 0x11, 0x40, 0xAA, 0xAA,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01, 0xCC, 0xCC, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
				/* UDP header */
				0x33, 0x16, 0x33, 0x16, 0x00, 0x1E, 0x05, 0x2C,
#endif
#endif
#if USE_COAP == 1
				/* CoAP header */
				0x54, 0x03, 0x23, 0xBB, 0x21, 0xFA, 0x01, 0xFB, 0xB5, 0x75,
				0x73, 0x61, 0x67, 0x65, 0xD1, 0xEA, 0x1A, 0xFF,
#endif
				/* Data */
				0x01, 0x02, 0x03, 0x04 };

int main() {
	/* COMPRESSION */
	/* initialize the client compressor */
	if(!schc_compressor_init()) {
		return 1;
	}

	uint8_t compressed_buf[MAX_PACKET_LENGTH] = { 0 };
	uint32_t device_id = 0x06;

	/* compress packet */
	struct schc_compression_rule_t *schc_rule;
	schc_bitarray_t c_bit_arr = SCHC_DEFAULT_BIT_ARRAY(MAX_PACKET_LENGTH, compressed_buf);

	schc_rule = schc_compress(msg, sizeof(msg), &c_bit_arr, device_id, DIRECTION);
#if USE_IP6_UDP == 1
	uint8_t compressed_header[8] = {
			0x01, /* rule id */
#if DIRECTION == 0
			/* direction UP */
			0x62, /* next header mapping index = 1 (2b), dev prefix mapping index = 2 (2b), dev iid LSB = 2 (4b) */
			0x11, /* app iid LSB = 1 (4b), dev port mapping index = 0 (1b), app port mapping index = 0 (1b), type mapping index = 1 (2b) */
			0xFB, /* token LSB = fb (8b) */
#else
			/* direction DOWN */
			0x62, /* next header mapping index = 1 (2b), dev prefix mapping index = 2 (2b), dev iid LSB = 2 (4b), */
			0x11, /* app iid LSB = 1 (4b), dev port mapping index = 0 (1b), app port mapping index = 0 (1b), type mapping index = 1 (2b) */
			0xFB, /* token LSB = fb (8b) */
#endif
			0x01, 0x02, 0x03, 0x04 /* payload */
	};
#elif USE_COAP == 1
	uint8_t compressed_header[7] = {
			0x01, /* rule id */
			0x7E, /* type = 1 (2b), token = fb (6 bits) */
			0xC0, /* token = fb (2 remaining bits) + 6 bits payload (0x01) */
			0x40, /* 2 bits payload (0x01) + 6 bits (0x02) */
			0x80, /* 2 bits payload (0x02) + 6 bits (0x03) */
			0xC1, /* 2 bits payload (0x03) + 6 bits (0x04) */
			0x00  /* 2 bits payload (0x04) + 6 bits padding */
	};
#else
	uint8_t compressed_header[5] = {
	0x01, /* rule id */
	0x01, 0x02, 0x03, 0x04 /* only payload */
};
#endif

	/* test the compressed bit array */
	int err = 0;
	printf("\n");
	if(schc_rule != NULL) {
		for (int i = 0; i < c_bit_arr.len; i++) {
			if (compressed_header[i] != c_bit_arr.ptr[i]) {
				printf(
						"main(): an error occured while compressing, byte=%02d, original=0x%02x, compressed=0x%02x\n",
						i, compressed_header[i], c_bit_arr.ptr[i]);
				err = 1;
			}
		}
	} else {
		err = 1;
	}

	if (!err) {
		printf("main(): compression succeeded\n");
	}

	/* DECOMPRESSION */
	uint8_t new_packet_len = 0;

	/* NOTE: DIRECTION is set to the flow the packet is following as this packet
	 * and thus equals the direction of the compressor
	 */
	unsigned char decomp_buf[MAX_PACKET_LENGTH] = { 0 };
	new_packet_len = schc_decompress(&c_bit_arr, decomp_buf, device_id,
			c_bit_arr.len, DIRECTION); /* use the compressed bit array to decompress */
	if (new_packet_len == 0) { /* some error occurred */
		return 1;
	}

	/* test the result */
	for (int i = 0; i < sizeof(msg); i++) {
		if (msg[i] != decomp_buf[i]) {
			printf(
					"main(): an error occured while decompressing, byte=%02d, original=0x%02x, decompressed=0x%02x\n",
					i, msg[i], decomp_buf[i]);
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

	return err;
}
