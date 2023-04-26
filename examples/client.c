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

#include "../rcs.h"
#include "../compressor.h"
#include "../fragmenter.h"
#include "socket/socket_client.h"

#include "timer.h"

#define CLIENT_DEVICE_ID  			1 /* this will usually be linked to a MAC address in the rule configuration */

#define COMPRESS					1 /* start fragmentation with or without compression first */
#define TRIGGER_PACKET_LOST			1
#define TRIGGER_MIC_CHECK			0
#define TRIGGER_CHANGE_TILE_SIZE	0
#define CONCURRENT_TRANSMISSIONS	0
#define TEST_SEND_ABORT 			0

#define MAX_PACKET_LENGTH			256
#define MAX_TIMERS					256

int RUN = 1;
int counter = 1;

struct cb_t {
    void* arg;
    void (*cb)(void* arg);
    struct cb_t *next;
};

struct cb_t *head = NULL;
udp_client *udp;
schc_fragmentation_t * tx_conn; /* structure to keep track of the transmission */

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
	int ret = SCHC_SUCCESS;
#if TRIGGER_CHANGE_TILE_SIZE
	ret = schc_set_tile_size(conn, 51); /* change the tile size mid-fragmentation to SF12 */
#endif
	schc_fragment(conn);
}

/*
 * Callback to handle the end of a fragmentation sequence
 */
void end_tx_callback(schc_fragmentation_t *conn) {
	DEBUG_PRINTF("end_tx_callback() callback \n");
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

	/* end the program */
	RUN = 0;
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
static void set_tx_timer_callback(schc_fragmentation_t *conn, void (*callback)(void* arg),
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
		DEBUG_PRINTF("set_tx_timer_callback(): could not allocate memory for timer \n");
		exit(0);
	} else {
		conn->timer_ctx = timer_tx;
		DEBUG_PRINTF(
				"set_tx_timer_callback(): schedule next tx state check in %d s \n\n", delay_sec);
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
				"set_rx_timer_callback(): schedule rx callback in %d s \n", delay_sec);
	}
}

/*
 * Callback to remove a timer entry for a device
 * (required by some timer libraries)
 */
void remove_timer_entry(schc_fragmentation_t *conn) {
	struct timer_node * timer_id = (struct timer_node *) conn->timer_ctx;
	stop_timer(timer_id);
	
	if(conn->device) {
		DEBUG_PRINTF("remove_timer_entry(): remove timer entry for device with id %d \n", conn->device->device_id);
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
	/* test cases for client */
	if( (tx_conn->frag_cnt == 7 && tx_conn->TX_STATE == SEND)) {
#if TRIGGER_PACKET_LOST
		/* do not send to udp server */
		DEBUG_PRINTF("tx_send_callback(): dropping packet\n");
    	return 1;
#elif TRIGGER_MIC_CHECK
	 /* change byte 2 to mimic bit fault during transmission and transmit */
		DEBUG_PRINTF("tx_send_callback(): invoking bit fault\n");
		data[2] = data[2] + 1; 
#endif
	}
#if TEST_SEND_ABORT
	if( (tx_conn->frag_cnt == 2 && tx_conn->TX_STATE == SEND) ) {
		DEBUG_PRINTF("tx_send_callback(): sending abort\n");
		schc_send_abort(tx_conn);
		RUN = 0;
		return 1;
	}
#endif

	DEBUG_PRINTF("tx_send_callback(): transmitting packet with length %d for device %d \n", length, device_id);

    int rc = socket_client_send(udp, data, length); /* send to udp server */
    return 1;
}

uint8_t rx_send_callback(uint8_t* data, uint16_t length, uint32_t device_id) {
	DEBUG_PRINTF("rx_send_callback(): transmitting packet with length %d for device %d \n", length, device_id);
	// received_packet(data, length, device_id);
	return 1;
}

void free_callback(schc_fragmentation_t *conn) {
	DEBUG_PRINTF("free_callback(): freeing connections for device %d\n", conn->device->device_id);
}
 
static void socket_receive_callback(char* data, int len) {   
	struct schc_device* device = get_device_by_id(CLIENT_DEVICE_ID); /* this is the SCHC device id; can be linked to various MAC addresses */
	schc_fragmentation_t *conn = schc_input((uint8_t*) data, len, device);
}

static void set_connection_info(schc_fragmentation_t* conn, schc_bitarray_t* bit_arr, uint32_t device_id) {
	/* L2 connection information */
	conn->tile_size					= 12; /* network driver MTU */
	conn->dc 						= 1000; /* duty cycle in ms */

	/* SCHC callbacks */
	conn->send 						= &tx_send_callback;
	conn->end_tx					= &end_tx_callback;
	conn->post_timer_task 			= &set_tx_timer_callback;
	conn->remove_timer_entry 		= &remove_timer_entry;
	conn->duty_cycle_cb 			= &duty_cycle_callback;

	/* SCHC connection information */
	conn->fragmentation_rule 		= get_fragmentation_rule_by_reliability_mode(ACK_ON_ERROR, device_id);
	conn->bit_arr 					= bit_arr;

	/* currently only the default CRC32 is supported */
	// conn.reassembly_check_sequence	= &schc_crc32; // todo

	if (conn->fragmentation_rule == NULL) {
		DEBUG_PRINTF("main(): no fragmentation rule was found. Exiting. \n");
		finalize_timer_thread();
		exit(1);
	}
}

int main() {
	/* initialize timer threads */
	initialize_timer_thread();

	/* setup connection with udp server */
    udp = malloc(sizeof(udp_client));
    udp->socket_cb = &socket_receive_callback;
    socket_client_start("127.0.0.1", 8000, udp);

	/* initialize the client compressor */
	if(!schc_compressor_init()) {
		exit(1);
	}

	/* compress */
	struct schc_device* device = get_device_by_id(CLIENT_DEVICE_ID);
	struct schc_compression_rule_t* schc_rule;

#if COMPRESS
	uint8_t compressed_packet[MAX_PACKET_LENGTH];
	schc_bitarray_t bit_arr				= SCHC_DEFAULT_BIT_ARRAY(MAX_PACKET_LENGTH, compressed_packet);
	schc_rule 							= schc_compress(msg, sizeof(msg), &bit_arr, CLIENT_DEVICE_ID, UP); /* first compress the packet */
#else /* do not compress */
	schc_bitarray_t bit_arr				= SCHC_DEFAULT_BIT_ARRAY(252, &msg); /* use the original message as a pointer in the bit array */
#endif

	/* initialize default fragmenter callbacks once for the constrained device */
	struct schc_fragmentation_t cb_conn;
	cb_conn.send 				= &tx_send_callback;
	cb_conn.end_rx 				= &end_rx_callback;
	cb_conn.remove_timer_entry 	= &remove_timer_entry;
	cb_conn.post_timer_task 	= &set_rx_timer_callback;
	cb_conn.dc 					= 20000; /* duty cycle timer; schedules the next state machine check */
#if DYNAMIC_MEMORY
	cb_conn.free_conn_cb		= &free_connection_callback;
#endif

	schc_fragmenter_init(&cb_conn);

	/* select a tx connection from the list of connections */
	tx_conn = schc_set_tx_connection(device, SCHC_INIT);
	if(!tx_conn) {
		DEBUG_PRINTF("main(): no free tx connection was found. Exiting. \n");
		return -1;
	}

    /* libschc configuration */
	set_connection_info(tx_conn, &bit_arr, CLIENT_DEVICE_ID);

#if CONCURRENT_TRANSMISSIONS
	/* a new dtag will be initiated when using the same rule id simultaneously; can be invoked with a second tx connection */
	schc_fragmentation_t* tx_conn2 = schc_set_tx_connection(device, SCHC_INIT);
	if(!tx_conn2) {
    	schc_free_connection(tx_conn);
		DEBUG_PRINTF("main(): no free tx connection was found. Exiting. \n");
		return -1;
	}

    /* libschc configuration */
	set_connection_info(tx_conn2, &bit_arr, CLIENT_DEVICE_ID);
#endif

	/* start fragmentation loop for first tx connection */
	int ret = schc_fragment(tx_conn);
#if CONCURRENT_TRANSMISSIONS
	ret = schc_fragment(tx_conn2);
#endif

	while(RUN && ret != SCHC_FAILURE) {
		int rc = socket_client_loop(udp);
		if(rc < 0) {
			RUN = 0;
		}
	}

	cleanup();
	finalize_timer_thread();
    socket_client_stop(udp);
    free(udp);
    schc_free_connection(tx_conn);
#if CONCURRENT_TRANSMISSIONS
    schc_free_connection(tx_conn2);
#endif

	DEBUG_PRINTF("main(): end program \n");

	return 0;
}
