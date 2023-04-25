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
#include "socket/socket_server.h"

#include "timer.h"

#define CLIENT_DEVICE_ID  		1
#define COMPRESS				1 /* start fragmentation with or without compression first */
#define TEST_LOST_ACK  			0

#define MAX_PACKET_LENGTH		256
#define MAX_TIMERS				256

int RUN = 1;
int counter = 1;

struct cb_t {
    void* arg;
    void (*cb)(void* arg);
    struct cb_t *next;
};

struct cb_t* head = NULL;
udp_server* serv;
schc_fragmentation_t* tx_conn; /* structure to keep track of the transmission */

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
 * Callback to handle the next fragment
 * can be used for e.g. setting the tile size
 */
void duty_cycle_callback(schc_fragmentation_t *conn) {
	DEBUG_PRINTF("duty_cycle_callback() callback\n");
	// schc_set_tile_size(conn, 51); /* change the tile size mid-fragmentation to SF12 */
	schc_fragment(conn);
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
void end_rx_callback(schc_fragmentation_t *conn) {
	DEBUG_PRINTF("end_rx_callback(): copy mbuf contents to message buffer \n");

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
	DEBUG_PRINTF("end_rx_callback(): decompress packet \n");
	bit_arr.ptr = compressed_packet;

	new_packet_len = schc_decompress(&bit_arr, decomp_packet, conn->device->device_id, packetlen, UP);
	if (new_packet_len <= 0) { /* some error occured */
		exit(1);
	}

	/* compare decompressed buffer with original packet */
	compare_decompressed_buffer(decomp_packet, new_packet_len);
#else
	/* compare mbuf reconstructed buffer with original packet */
	compare_decompressed_buffer(compressed_packet, packetlen);
#endif

	DEBUG_PRINTF("end_rx_callback(): forward packet to IP network \n");

	free(compressed_packet);
	schc_reset(conn);
}

void timer_handler(struct timer_node * timer_id, void* user_data) {
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

	struct cb_t* cb_t_ = malloc(sizeof(struct cb_t)); // create on heap
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

	struct timer_node * timer_tx = start_timer(delay_sec, &timer_handler, TIMER_SINGLE_SHOT, cb_t_);
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
static void set_rx_timer_callback(schc_fragmentation_t *conn, void (*callback)(void* arg),
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

	struct timer_node * timer_tx = start_timer(delay_sec, &timer_handler, TIMER_SINGLE_SHOT, cb_t_);
	if(timer_tx == 0) {
		DEBUG_PRINTF("set_rx_timer_callback(): could not allocate memory for timer \n");
		exit(0);
	} else {
		conn->timer_ctx = timer_tx;
		DEBUG_PRINTF(
				"set_rx_timer_callback(): schedule rx callback in %d s\n", delay_sec);
	}
}

/*
 * Callback to remove a timer entry for a device
 * (required by some timer libraries)
 */
void remove_timer_entry_callback(schc_fragmentation_t *conn) {
	struct timer_node * timer_id = (struct timer_node *) conn->timer_ctx;
	stop_timer(timer_id);
	if(conn->device) {
		DEBUG_PRINTF("remove_timer_entry_callback(): remove timer entry for device with id %d \n", conn->device->device_id);
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
	DEBUG_PRINTF("tx_send_callback(): transmitting packet with length %d to device %d \n", length, device_id);
#if !TEST_LOST_ACK
	socket_server_send(serv, data, length);
#endif
	return 1;
}

uint8_t rx_send_callback(uint8_t* data, uint16_t length, uint32_t device_id) {
	DEBUG_PRINTF("rx_send_callback(): transmitting packet with length %d to device %d \n", length, device_id);
	// received_packet(data, length, device_id, &tx_conn); // send packet to constrained device
	return 1;
}

void free_connection_callback(schc_fragmentation_t *conn) {
	DEBUG_PRINTF("free_connection_callback(): freeing connections for device %d\n", conn->device->device_id);
}

void socket_receive_callback(char * data, int len) {
	struct schc_device *device = get_device_by_id(CLIENT_DEVICE_ID); /* get the device based on the id; usually based on MAC address */
	schc_fragmentation_t *conn = schc_input((uint8_t*) data, len, device); /* get active connection based on device */
}

int main() {
	/* initialize timer threads */
	initialize_timer_thread();

	/* initialize the client compressor */
	if(!schc_compressor_init()) {
		exit(1);
	}

    udp_server* serv = malloc(sizeof(udp_server));
    serv->socket_cb = &socket_receive_callback;

    /* start udp server */
    int rc = socket_server_start("127.0.0.1", 8000, serv);
	
// 	struct schc_device* device = get_device_by_id(CLIENT_DEVICE_ID);
// 	tx_conn = schc_set_tx_connection(device, SCHC_INIT);

	/* initialize default fragmenter callbacks */
	struct schc_fragmentation_t cb_conn;
	cb_conn.send 				= &tx_send_callback;
	cb_conn.end_rx 				= &end_rx_callback;
	cb_conn.remove_timer_entry 	= &remove_timer_entry_callback;
	cb_conn.post_timer_task 	= &set_rx_timer_callback;
	cb_conn.dc 					= 20000; /* duty cycle timer; schedules the next state machine check */
#if DYNAMIC_MEMORY
	cb_conn.free_conn_cb		= &free_connection_callback;
#endif

	schc_fragmenter_init(&cb_conn);

	while(RUN) {
		rc = socket_server_loop(serv);
	}

	cleanup();
	socket_server_stop(serv);
	finalize_timer_thread();
	free(serv);

	DEBUG_PRINTF("main(): end program \n");

	return 0;
}
