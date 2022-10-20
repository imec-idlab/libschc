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
 * to the network gateway that will reassemble the packet
 *
 */

#include <stdio.h>
#include <stdint.h>

#include "../compressor.h"
#include "../fragmenter.h"

#include "timer.h"

#define COMPRESS				1 /* indicate to start fragmentation with or without compression first */

#define MAX_PACKET_LENGTH		256
#define MAX_TIMERS				256

int RUN = 1;
int counter = 1;

struct cb_t {
    void* arg;
    void (*cb)(void* arg);
    struct cb_t *next;
};

struct cb_t *head = NULL;

// structure to keep track of the transmission
schc_fragmentation_t tx_conn;
schc_fragmentation_t tx_conn_nwgw;

// the ipv6/udp/coap packet: length 251
uint8_t msg[] = {
		// IPv6 header
		0x60, 0x00, 0x00, 0x00, 0x00, 0xD3, 0x11, 0x40, 0xCC, 0xCC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		// UDP header
		0x33, 0x16, 0x33, 0x16, 0x00, 0xD3, 0x19, 0xED,
		// CoAP header
		0x54, 0x03, 0x23, 0xBB, 0x21, 0xFA, 0x01, 0xFB, 0xB5, 0x75, 0x73, 0x61, 0x67, 0x65, 0xD1, 0xEA, 0x1A, 0xFF,
		// Data
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 
		0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
		0x25,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 
		0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
		0x25,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 
		0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
		0x25,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 
		0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
		0x25,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 
		0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
		0x25
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

void compare_decompressed_buffer(uint8_t* decomp_packet, uint16_t new_packet_len) {
	int err = 0;
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
}

/*
 * Callback to handle the end of a fragmentation sequence
 */
void end_tx(schc_fragmentation_t *conn) {
	DEBUG_PRINTF("end_tx() callback \n");
}

/*
 * Callback to handle the end of a fragmentation sequence
 * may be used to forward packet to IP network
 */
void end_rx(schc_fragmentation_t *conn) {
	DEBUG_PRINTF("end_rx(): copy mbuf contents to message buffer \n");

	schc_bitarray_t bit_arr;
	conn->bit_arr 				= &bit_arr;

	uint16_t new_packet_len;
	uint16_t packetlen 			= get_mbuf_len(conn); /* calculate the length of the original packet */
	uint8_t* compressed_packet 	= (uint8_t*) malloc(sizeof(uint8_t) * packetlen); /* todo pass the mbuf chain to the decompressor */
	uint8_t  decomp_packet[MAX_PACKET_LENGTH]
						  	  	= { 0 };

	/* copy the packet from the mbuf list */
	mbuf_copy(conn, compressed_packet);

	DEBUG_PRINTF("\n\n");

#if COMPRESS
	DEBUG_PRINTF("end_rx(): decompress packet \n");
	bit_arr.ptr = compressed_packet;

	new_packet_len = schc_decompress(&bit_arr, decomp_packet, conn->device_id, packetlen, UP);
	if (new_packet_len <= 0) { /* some error occured */
		exit(1);
	}

	/* compare decompressed buffer with original packet */
	compare_decompressed_buffer(decomp_packet, new_packet_len);
#else
	/* compare mbuf reconstructed buffer with original packet */
	compare_decompressed_buffer(compressed_packet, packetlen);
#endif

	DEBUG_PRINTF("end_rx(): forward packet to IP network \n");

	free(compressed_packet);
	schc_reset(conn);

	/* end the program */
	RUN = 0;
}

void timer_handler(size_t timer_id, void* user_data) {
	stop_timer(timer_id);

	struct cb_t* cb_t_ = (struct cb_t*) user_data;
	schc_fragmentation_t* conn = cb_t_->arg;

	cb_t_->cb(conn);
}

/*
 * The timer used by the SCHC library to schedule the transmission of fragments
 */
static void set_tx_timer(schc_fragmentation_t *conn, void (*callback)(void* arg),
		uint32_t delay, void *arg) {
	counter++;

	uint16_t delay_sec = delay / 1000;

	struct cb_t* cb_t_= malloc(sizeof(struct cb_t)); // create on heap
	cb_t_->arg = arg;
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
static void set_rx_timer(schc_fragmentation_t *conn, void (*callback)(void* arg),
		uint32_t delay, void *arg) {
	uint16_t delay_sec = delay / 1000;

	struct cb_t* cb_t_= malloc(sizeof(struct cb_t)); // create on heap
	cb_t_->arg = arg;
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
void remove_timer_entry(schc_fragmentation_t *conn) {
	DEBUG_PRINTF("remove_timer_entry(): remove timer entry for device with id %d \n", conn->device_id);
}

void received_packet(uint8_t* data, uint16_t length, uint32_t device_id, schc_fragmentation_t* receiving_conn) {

	DEBUG_PRINTF("\n+-------- RX  %02d --------+\n", counter);

	schc_fragmentation_t *conn = schc_input((uint8_t*) data, length,
			receiving_conn, device_id); // get active connection and set the correct rule for this connection

	if (conn != receiving_conn) { // if returned value is receiving_conn: acknowledgement is received, which is handled by the library
		conn->post_timer_task = &set_rx_timer;
		conn->dc = 20000; // retransmission timer: used for timeouts

		if (conn->fragmentation_rule->mode == NOT_FRAGMENTED) { // packet was not fragmented
			end_rx(conn);
		} else {
			int ret = schc_reassemble(conn);
			if(ret && conn->fragmentation_rule->mode == NO_ACK){ // use the connection to reassemble
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
	received_packet(data, length, device_id, &tx_conn_nwgw); // send packet to network gateway
	return 1;
}

uint8_t rx_send_callback(uint8_t* data, uint16_t length, uint32_t device_id) {
	DEBUG_PRINTF("rx_send_callback(): transmitting packet with length %d for device %d \n", length, device_id);
	// received_packet(data, length, device_id, &tx_conn); // send packet to constrained device
	return 1;
}

void init() {
	/* initialize timer threads */
	initialize_timer_thread();

	/* initialize the client compressor */
	schc_compressor_init();

	/* initialize fragmenter for the constrained device */
	schc_fragmenter_init(&tx_conn, &tx_send_callback, &end_rx, &remove_timer_entry);
	
	/* initialize fragmenter for ngw */
	tx_conn_nwgw.send 					= &rx_send_callback;
	tx_conn_nwgw.end_rx 				= &end_rx;
	tx_conn_nwgw.remove_timer_entry 	= &remove_timer_entry;
}

int main() {
	init();

	uint32_t device_id = 0x01;
	struct schc_compression_rule_t* schc_rule;

#if COMPRESS
	schc_bitarray_t bit_arr;
	uint8_t compressed_packet[MAX_PACKET_LENGTH];
	bit_arr.ptr 				= (uint8_t*) (compressed_packet); /* provide a pointer to the buffer to store the compressed packet */
	schc_rule 					= schc_compress(msg, sizeof(msg), &bit_arr, device_id, UP); /* first compress the packet */
#else
	schc_bitarray_t bit_arr		= SCHC_DEFAULT_BIT_ARRAY(252, &msg);
#endif

	/* L2 connection information */
	tx_conn.mtu 				= 121; /* network driver MTU */
	tx_conn.dc 					= 1000; /* duty cycle in ms */
	tx_conn.device_id 			= device_id; /* the device id of the connection */

	/* SCHC callbacks */
	tx_conn.send 				= &tx_send_callback;
	tx_conn.end_tx				= &end_tx;
	tx_conn.post_timer_task 	= &set_tx_timer;

	/* SCHC connection information */
	tx_conn.fragmentation_rule 	= get_fragmentation_rule_by_reliability_mode(
			NO_ACK, device_id);
	tx_conn.RULE_SIZE 			= RULE_SIZE_BITS;
	tx_conn.bit_arr 			= &bit_arr;


	if (tx_conn.fragmentation_rule == NULL) {
		DEBUG_PRINTF("main(): no fragmentation rule was found. Exiting. \n");
		finalize_timer_thread();
		return -1;
	}

	/* start fragmentation loop */
	DEBUG_PRINTF("\n+-------- TX  %02d --------+\n", counter);
	int ret = schc_fragment(&tx_conn);

	while(RUN) {
	}

	cleanup();
	finalize_timer_thread();

	DEBUG_PRINTF("main(): end program \n");

	return 0;
}
