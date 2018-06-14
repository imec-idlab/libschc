/*
 * (c) 2018 - idlab - UGent - imec
 *
 * Bart Moons
 *
 * This file is part of the SCHC stack implementation
 *
 */

#include <string.h>
#include <stdio.h>

#include "config.h"
#include "schc_config.h"

#include "fragmenter.h"

// keep track of the active connections
struct fragmentation_t schc_rx_conns[SCHC_CONF_RX_CONNS];
uint8_t fragmentation_buffer[MAX_MTU_LENGTH];

////////////////////////////////////////////////////////////////////////////////////
//                                LOCAL FUNCIONS                                  //
////////////////////////////////////////////////////////////////////////////////////

/**
 * Calculates the Message Integrity Check (MIC)
 * which is the 32 bit Cyclic Redundancy Check (CRC32)
 *
 * @param data pointer to the data packet
 *
 * @return checksum the computed checksum
 *
 */
static unsigned int compute_mic(fragmentation_t *conn) {
	int i, j;
	unsigned int byte, crc, mask;

	i = 0;
	crc = 0xFFFFFFFF;

	uint16_t len = (conn->tail_ptr - conn->data_ptr);

	while (i < len) {
		byte = conn->data_ptr[i - 1];
		crc = crc ^ byte;
		for (j = 7; j >= 0; j--) {    // do eight times.
			mask = -(crc & 1);
			crc = (crc >> 1) ^ (0xEDB88320 & mask);
		}
		i++;
	}

	crc = ~crc;
	uint8_t mic[4] = { ((crc & 0xFF000000) >> 24), ((crc & 0xFF0000) >> 16),
			((crc & 0xFF00) >> 8), ((crc & 0xFF)) };

	memcpy((uint8_t *) conn->MIC, mic, 4);

	DEBUG_PRINTF("compute_mic(): MIC for device %d is %d", conn->device_id, crc);

	return crc;
}

/**
 * find a connection based on a device id
 * or open a new connection if there was no connection
 * for this device yet
 *
 * @param 	device_id	the id of the device to open a connection for
 *
 * @return 	a pointer to the selected connection
 * 			0 if no free connections are available
 *
 */
fragmentation_t* get_connection(uint32_t device_id) {
	uint8_t i; fragmentation_t *conn;
	conn = 0;

	for (i = 0; i < SCHC_CONF_RX_CONNS; i++) {
		// first look for the the old connection
		if (schc_rx_conns[i].device_id == device_id) {
			conn = &schc_rx_conns[i];
			break;
		}
	}

	if (conn == 0) { // check if we were given an old connection
		for (i = 0; i < SCHC_CONF_RX_CONNS; i++) {
			if (schc_rx_conns[i].device_id == 0) { // look for an empty connection
				conn = &schc_rx_conns[i];
				break;
			}
		}
	}

	if(conn) {
		DEBUG_PRINTF("get_connection(): selected connection %d for device %d", i, device_id);
	}

	return conn;
}

/**
 * initializes a new connection for a device:
 * set the starting and ending point of the packet
 * calculate the MIC over the complete SCHC packet
 *
 * @param conn 			a pointer to the connection to initialize
 * @param data_ptr		a pointer to the compressed data packet
 * @param total_length	the total length of the compressed packet
 * @param device_id		the device id to set up the connection for
 * @param mtu			the current maximum transfer unit
 *
 * @return checksum the computed checksum
 *
 */
void init_connection(fragmentation_t* conn, uint8_t* data_ptr,
		uint16_t total_length, uint32_t device_id, uint16_t mtu) {
	conn->data_ptr = (uint8_t*) (data_ptr); // set start of packet
	conn->tail_ptr = (uint8_t*) (data_ptr + total_length); // set end of packet
	conn->device_id = device_id;
	conn->mtu = mtu;

	compute_mic(conn); // calculate MIC over compressed, unfragmented packet
}

////////////////////////////////////////////////////////////////////////////////////
//                               GLOBAL FUNCIONS                                  //
////////////////////////////////////////////////////////////////////////////////////

/**
 * Initializes the SCHC fragmenter
 *
 * @return error codes on error
 *
 */
int8_t schc_fragmenter_init(){
	uint8_t i;

	// initializes the schc connections
	for (i = 0; i < SCHC_CONF_RX_CONNS; i++) {
		schc_rx_conns[i].rule_id = 0;
		schc_rx_conns[i].data_ptr = 0;
		schc_rx_conns[i].tail_ptr = 0;
		schc_rx_conns[i].device_id = 0;
	}

	return 1;
}

/**
 * Fragments a compressed SCHC packet for a specified MTU
 * an open connection is picked for the device out of a pool of connections
 * to keep track of the original packet
 *
 * @param data			a pointer to the compressed data packet
 * @param mtu			the maximum transfer unit for the underlying technology
 * @param total_length	the total length of the compressed packet
 * @param device_id		the device it's ID, linked to it's connection
 * @param callback		a pointer to a function which will be called before
 * 						returning from the function
 *
 * @return 	 0			TBD
 *        	-1			no free connections were found
 *
 */
int8_t schc_fragment(const uint8_t *data, uint16_t mtu, uint16_t total_length,
		uint32_t device_id, void (*callback)(uint8_t* data, uint16_t length)) {
	fragmentation_t *conn;

	// get a connection for the device
	conn = get_connection(device_id);
	if(!conn) { // return if there was no connection available
		DEBUG_PRINTF("schc_fragment(): no free connections found!");
		return -1;
	}

	if(conn->data_ptr == 0){ // initialize the connection
		init_connection(conn, data, total_length, device_id, mtu);
	}

	if( (mtu + conn->data_ptr) > conn->tail_ptr) { // this is the last packet
		// prepare_packet( );
	}



	return 0;
}
