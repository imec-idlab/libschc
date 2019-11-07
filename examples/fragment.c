/*
 * (c) 2018 - idlab - UGent - imec
 *
 * Bart Moons
 *
 * This file is part of the SCHC stack implementation
 *
 * This is a basic example on how to fragment
 * and reassemble a packet
 * The client will send every 10 seconds a fragment
 * to the network gateway, which will reassemble the packet
 *
 */

#include <stdio.h>
#include <stdint.h>

#include "../compressor.h"
#include "../fragmenter.h"
#include "../config.h"

#include "timer.h"

#define PACKET_LENGTH			102
#define MAX_PACKET_LENGTH		128
#define MAX_TIMERS				256

int RUN = 1;

struct cb_t {
    schc_fragmentation_t* conn;
    void (*cb)(schc_fragmentation_t* conn);
};

// structure to keep track of the transmission
schc_fragmentation_t tx_conn;

// the ipv6/udp/coap packet
uint8_t msg[PACKET_LENGTH] = {
		// IPv6 header
		0x60, 0x00, 0x00, 0x00, 0x00, 0x1E, 0x11, 0x40, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		// UDP header
		0x33, 0x16, 0x33, 0x16, 0x00, 0x1E, 0x27, 0x4E,
		// CoAP header
		0x54, 0x03, 0x23, 0xBB, 0x21, 0xFA, 0x01, 0xFB, 0xB5, 0x75, 0x73, 0x61, 0x67, 0x65, 0xD1, 0xEA, 0x1A, 0xFF,
		// Data
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26
};

void timer_handler(size_t timer_id, void* user_data) {
	stop_timer(timer_id);

	struct cb_t* cb_t_ = (struct cb_t*) user_data;
	schc_fragmentation_t* conn = cb_t_->conn;

	DEBUG_PRINTF("timer_handler(): continue transmission to device %d \n", conn->device_id);

	cb_t_->cb(conn);
}

/*
 * The timer used by the SCHC library to schedule the transmission of fragments
 */
static void set_tx_timer(void (*callback)(void* conn), uint32_t device_id, uint32_t delay, void *arg) {
	uint16_t delay_sec = delay / 1000;

	struct cb_t* cb_t_= malloc(sizeof(struct cb_t)); // create on heap
	cb_t_->conn = arg;
	cb_t_->cb = callback;

	size_t timer_tx = start_timer(delay_sec, &timer_handler, TIMER_SINGLE_SHOT, cb_t_);
	if(timer_tx == 0) {
		DEBUG_PRINTF("set_tx_timer(): could not allocate memory for timer \n");
		exit(0);
	} else {
		DEBUG_PRINTF(
				"set_tx_timer(): schedule transmission for device %d in %d s \n", device_id, delay_sec);
	}
}

/*
 * Callback to remove a timer entry for a device
 * (required by some timer libraries)
 */
void remove_timer_entry(uint32_t device_id) {
	DEBUG_PRINTF("remove_timer_entry(): remove timer entry for device with id %d \n", device_id);
}

/*
 * Callback to handle transmission of fragments
 *
 * should return 1 or 0 to inform the fragmenter
 * whether the network driver is busy or not
 *
 */
uint8_t send_callback(uint8_t* data, uint16_t length, uint32_t device_id) {
	DEBUG_PRINTF("send_callback(): transmitting packet with length %d for device %d \n", length, device_id);
	return 1;
}

/*
 * Callback to handle the end of a fragmentation sequence
 */
void end_tx() {
	DEBUG_PRINTF("end_tx() callback \n");
	RUN = 0;
}

/*
 * Callback to handle the end of a fragmentation sequence
 * may be used to forward packet to IP network
 */
void end_rx(schc_fragmentation_t *conn) {
}

void init() {
	// initialize timer threads
	initialize_timer_thread();

	// initialize the client compressor
	uint8_t src[16] = { 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
	schc_compressor_init(src);

	schc_fragmenter_init(&tx_conn, &send_callback, &end_rx, &remove_timer_entry);
}

int main() {
	init();

	uint8_t compressed_packet[MAX_PACKET_LENGTH];
	uint32_t device_id = 0x01;

	// compress packet
	uint16_t compressed_len = schc_compress(msg, compressed_packet, PACKET_LENGTH, device_id, UP, DEVICE);

	tx_conn.mtu = 12; // network driver MTU
	tx_conn.dc = 5000; // 5 seconds duty cycle
	tx_conn.device_id = device_id; // the device id of the connection

	tx_conn.data_ptr = &compressed_packet;
	tx_conn.packet_len = compressed_len;
	tx_conn.send = &send_callback;
	tx_conn.end_tx = &end_tx;

	tx_conn.mode = ACK_ON_ERROR; // todo get from rule
	tx_conn.FCN_SIZE = 3; // todo get from rule
	tx_conn.MAX_WND_FCN = 6; // todo will be removed?
	tx_conn.WINDOW_SIZE = 1; // todo support multiple window sizes
	tx_conn.DTAG_SIZE = 0; // todo no support yet
	tx_conn.RULE_SIZE = 8; // todo get from rule

	tx_conn.post_timer_task = &set_tx_timer;

	int ret = schc_fragment(&tx_conn);

	while(RUN) {
	}

	finalize_timer_thread();

	return 0;
}
