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
#include "../compressor.h"
#include "../fragmenter.h"

#include "timer.h"


#define MAX_PACKET_LENGTH		256
#define MAX_TIMERS				256

int RUN = 1;
int counter = 1;

struct cb_t {
    schc_fragmentation_t* conn;
    void (*cb)(schc_fragmentation_t* conn);
    struct cb_t *next;
};

struct cb_t *head = NULL;

// structure to keep track of the transmission
schc_fragmentation_t tx_conn;
schc_fragmentation_t tx_conn_ngw;

// the ipv6/udp/coap packet
uint8_t msg[] = {
		// IPv6 header
		/*0x60, 0x01, 0x23, 0x45, 0x00, 0x39, 0x11, 0x33, 0x20, 0x01, 0x12, 0x22,
		0x89, 0x05, 0x04, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x57,
		0x20, 0x01, 0x41, 0xd0, 0x57, 0xd7, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x04, 0x01,

		// udp header
		0x16, 0x34, 0x16, 0x33, 0x00, 0x39, 0x7a, 0x6e,

		// coap header
		0x51, 0x02, 0x00, 0xa0, 0x20, 0xb4, 0x74, 0x65, 0x6d, 0x70, 0xd1, 0xea,
		0x02, 0xff,

		// data
		0x98, 0x1f, 0x19, 0x07, 0x4b, 0x21, 0x05, 0x03, 0x01, 0x05, 0x00, 0x22,
		 0x06, 0x22, 0x20, 0x06, 0x00, 0x25, 0x03, 0x01, 0x22, 0x04, 0x01, 0x03,
		 0x03, 0x00, 0x22, 0x03, 0x04, 0x01, 0x01, 0x22, 0x03, 0x0a, 0x05*/
/*
		0x60, 0x00, 0x00, 0x00, 0x00, 0x1E, 0x11, 0x40, 0x20, 0x01, 0x06, 0xA8,
		0x1D, 0x80, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
		0x20, 0x01, 0x06, 0xA8, 0x1D, 0x80, 0x00, 0x30, 0xBA, 0x27, 0xEB, 0xFF,
		0xFE, 0x08, 0x41, 0x5F, 0x16, 0x33, 0x16, 0x33, 0x00, 0x1E, 0x27, 0x68,
		0x44, 0x02, 0x89, 0xC5, 0xC5, 0x89, 0xA4, 0x03, 0xB2, 0x72, 0x64, 0x0A,
		0x6F, 0x4B, 0x45, 0x54, 0x74, 0x78, 0x71, 0x6D, 0x55, 0x47
		*/
		0x60, 0x5, 0x53, 0x64, 0x0, 0x11, 0x11, 0x40, 0x20, 0x1, 0x6, 0xa8,
		0x1d, 0x80, 0x0, 0x30, 0xba, 0x27, 0xeb, 0xff, 0xfe, 0x8, 0x41, 0x5f,
		0x20, 0x1, 0x6, 0xa8, 0x1d, 0x80, 0x0, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x3,
		0x16, 0x33, 0x16, 0x33, 0x0, 0x11, 0x4d, 0x49,
		0x64, 0x84, 0x89, 0xc5, 0xc5, 0x89, 0xa4, 0x3, 0xc
};

void cleanup() {
	struct cb_t* curr = head;
	struct cb_t* next = curr->next;
	struct cb_t* prev = NULL;

	while(curr->next != NULL) {
		prev = curr;
		curr = next;
		next = curr->next;
		free(prev);
	}
}

/*
 * Callback to handle the end of a fragmentation sequence
 */
void end_tx() {
	DEBUG_PRINTF("end_tx() callback \n");
}

/*
 * Callback to handle the end of a fragmentation sequence
 * may be used to forward packet to IP network
 */
void end_rx(schc_fragmentation_t *conn) {
	DEBUG_PRINTF("end_rx(): copy mbuf contents to message buffer \n");

	uint16_t packetlen = get_mbuf_len(conn); // calculate the length of the original packet
	uint8_t* compressed_packet = (uint8_t*) malloc(sizeof(uint8_t) * packetlen); // todo pass the mbuf chain to the decompressor
	uint8_t decomp_packet[MAX_PACKET_LENGTH] = { 0 };

	mbuf_copy(conn, compressed_packet); // copy the packet from the mbuf list

	DEBUG_PRINTF("end_rx(): decompress packet \n");
	schc_bitarray_t bit_arr;
	bit_arr.ptr = compressed_packet;
	uint16_t new_packet_len = schc_decompress(&bit_arr, decomp_packet,
			conn->device_id, packetlen, DOWN);
	if (new_packet_len == 0) { // some error occured
		exit(0);
	}

	DEBUG_PRINTF("end_rx(): forward packet to IP network \n");

	free(compressed_packet);

	schc_reset(conn);
}

void timer_handler(size_t timer_id, void* user_data) {
	stop_timer(timer_id);

	struct cb_t* cb_t_ = (struct cb_t*) user_data;
	schc_fragmentation_t* conn = cb_t_->conn;

	cb_t_->cb(conn);
}

/*
 * The timer used by the SCHC library to schedule the transmission of fragments
 */
static void set_tx_timer(void (*callback)(schc_fragmentation_t* conn),
		uint32_t device_id, uint32_t delay, void *arg) {
	counter++;

	uint16_t delay_sec = delay / 1000;

	struct cb_t* cb_t_= malloc(sizeof(struct cb_t)); // create on heap
	cb_t_->conn = arg;
	cb_t_->cb = callback;

	struct cb_t* curr = head;
	if(head == NULL) {
		head = cb_t_;
	} else {
		while(curr->next != NULL) {
			curr = curr->next;
		}
		curr->next = cb_t_;
	}

	DEBUG_PRINTF("\n+-------- TX  %02d --------+\n", counter);

	size_t timer_tx = start_timer(delay_sec, &timer_handler, TIMER_SINGLE_SHOT, cb_t_);
	if(timer_tx == 0) {
		DEBUG_PRINTF("set_tx_timer(): could not allocate memory for timer \n");
		exit(0);
	} else {
		DEBUG_PRINTF(
				"set_tx_timer(): schedule next tx state check in %d s \n\n", delay_sec);
	}
}

/*
 * The timer used by the SCHC library to time out the reception of fragments
 * should have multiple timers for a device
 */
static void set_rx_timer(void (*callback)(schc_fragmentation_t* conn),
		uint32_t device_id, uint32_t delay, void *arg) {
	uint16_t delay_sec = delay / 1000;

	struct cb_t* cb_t_= malloc(sizeof(struct cb_t)); // create on heap
	cb_t_->conn = arg;
	cb_t_->cb = callback;

	struct cb_t* curr = head;
	if (head == NULL) {
		head = cb_t_;
	} else {
		while (curr->next != NULL) {
			curr = curr->next;
		}
		curr->next = cb_t_;
	}

	size_t timer_tx = start_timer(delay_sec, &timer_handler, TIMER_SINGLE_SHOT, cb_t_);
	if(timer_tx == 0) {
		DEBUG_PRINTF("set_rx_timer(): could not allocate memory for timer \n");
		exit(0);
	} else {
		DEBUG_PRINTF(
				"set_rx_timer(): schedule rx callback in %d s \n", delay_sec);
	}
}

/*
 * Callback to remove a timer entry for a device
 * (required by some timer libraries)
 */
void remove_timer_entry(uint32_t device_id) {
	DEBUG_PRINTF("remove_timer_entry(): remove timer entry for device with id %d \n", device_id);
}

void received_packet(uint8_t* data, uint16_t length, uint32_t device_id, schc_fragmentation_t* receiving_conn) {

	DEBUG_PRINTF("\n+-------- RX  %02d --------+\n", counter);

	schc_fragmentation_t *conn = schc_input((uint8_t*) data, length,
			receiving_conn, device_id); // get active connection and set the correct rule for this connection

	if (conn != receiving_conn) { // if returned value is receiving_conn: acknowledgement is received, which is handled by the library
		conn->post_timer_task = &set_rx_timer;
		conn->dc = 20000; // retransmission timer: used for timeouts

		if ( conn->schc_rule->mode == NOT_FRAGMENTED) { // packet was not fragmented
			end_rx(conn);
		} else {
			int ret = schc_reassemble(conn);
			if(ret && conn->schc_rule->mode == NO_ACK){ // use the connection to reassemble
				end_rx(conn); // final packet arrived
			}
		}
	}
}

/*
 * Callback to handle transmission of fragments
 *
 * should return 1 or 0 to inform the fragmenter
 * whether the network driver is busy or not
 *
 */
uint8_t tx_send_callback(uint8_t* data, uint16_t length, uint32_t device_id) {
	DEBUG_PRINTF("tx_send_callback(): transmitting packet with length %d for device %d \n", length, device_id);
	received_packet(data, length, device_id, &tx_conn_ngw); // send packet to network gateway
	return 1;
}

uint8_t rx_send_callback(uint8_t* data, uint16_t length, uint32_t device_id) {
	DEBUG_PRINTF("rx_send_callback(): transmitting packet with length %d for device %d \n", length, device_id);
	// received_packet(data, length, device_id, &tx_conn); // send packet to constrained device
	return 1;
}

void init() {
	// initialize timer threads
	initialize_timer_thread();

	// initialize the client compressor
	uint8_t src[16] = { 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
	schc_compressor_init(src);

	// initialize fragmenter for constrained device
	schc_fragmenter_init(&tx_conn, &tx_send_callback, &end_rx, &remove_timer_entry);

	// initialize fragmenter for ngw
	tx_conn_ngw.send = &rx_send_callback;
	tx_conn_ngw.end_rx = &end_rx;
	tx_conn_ngw.remove_timer_entry = &remove_timer_entry;
}

int main() {
	init();

	uint8_t compressed_packet[MAX_PACKET_LENGTH] = { 0x00 };
	uint32_t device_id = 0x01;

	// compress packet
	struct schc_rule_t* schc_rule;
	schc_bitarray_t bit_arr;
	bit_arr.ptr = (uint8_t*) (compressed_packet);

	schc_rule = schc_compress(msg, sizeof(msg), &bit_arr, device_id, DOWN);

	tx_conn.mtu = 21; // network driver MTU
	tx_conn.dc = 5000; // 5 seconds duty cycle
	tx_conn.device_id = device_id; // the device id of the connection

	tx_conn.bit_arr = &bit_arr;
	tx_conn.send = &tx_send_callback;
	tx_conn.end_tx = &end_tx;

	tx_conn.schc_rule = schc_rule;
	tx_conn.RULE_SIZE = RULE_SIZE_BITS;
	tx_conn.MODE = ACK_ON_ERROR;

	tx_conn.post_timer_task = &set_tx_timer;

	if (schc_rule == NULL) {
		cleanup();
		finalize_timer_thread();
		return -1;
	}

	// start fragmentation loop
	DEBUG_PRINTF("\n+-------- TX  %02d --------+\n", counter);
	int ret = schc_fragment(&tx_conn);

	while(RUN) {
	}

	cleanup();
	finalize_timer_thread();

	return 0;
}
