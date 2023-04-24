/*
 * (c) 2018 - 2022  - idlab - UGent - imec
 *
 * Bart Moons
 *
 * This file is part of the SCHC stack implementation
 *
 */

#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "fragmenter.h"
#include "bit_operations.h"

uint8_t ATTEMPTS = 0; // for debugging

#if CLICK
#include <click/config.h>
#endif

// keep track of the active connections
static uint8_t FRAGMENTATION_BUF[MAX_MTU_LENGTH] = { 0 };

#if DYNAMIC_MEMORY
struct schc_fragmentation_t *schc_rx_conns;
struct schc_fragmentation_t *schc_tx_conns;
#else
struct schc_fragmentation_t schc_rx_conns[SCHC_CONF_RX_CONNS];
struct schc_fragmentation_t schc_tx_conns[SCHC_CONF_TX_CONNS];
static uint32_t buf_ptr = 0;
uint8_t schc_buf[STATIC_MEMORY_BUFFER_LENGTH] = { 0 };
static struct schc_mbuf_t MBUF_POOL[SCHC_CONF_MBUF_POOL_LEN];
#endif

static schc_fragmentation_t default_conn;

/**
 * get the FCN value
 *
 * @param  fragment		a pointer to the fragment to retrieve the FCN from
 *
 * @return FCN			the FCN as indicated by the fragment
 *
 * @note   only FCN values up to 16 bits are currently supported
 *
 */
static uint16_t get_fcn_value(uint8_t* fragment, schc_fragmentation_t* conn) {
	uint8_t offset = conn->device->profile->RULE_ID_SIZE + conn->device->profile->DTAG_SIZE + conn->fragmentation_rule->WINDOW_SIZE;

	return (uint16_t) get_bits(fragment, offset, conn->fragmentation_rule->FCN_SIZE);
}


/**
 * get the ALL-1 FCN value
 *
 * @return FCN			the all-1 fcn value
 *
 * @note   only FCN values up to 16 bits are currently supported
 *
 */
static uint16_t get_max_fcn_value(schc_fragmentation_t* conn) {
	uint8_t fcn[2] = { 0 };
	set_bits(fcn, 0, conn->fragmentation_rule->FCN_SIZE);

	return (uint16_t) get_bits(fcn, 0, conn->fragmentation_rule->FCN_SIZE);
}

/**
 * get the DTag value
 *
 * @param  fragment		a pointer to the fragment to retrieve the DTag from
 * @return DTag			the DTag as indicated by the fragment
 * 
 * @note   				only DTag values up to 8 bits are currently supported
 *
 */
static int16_t get_dtag_value(uint8_t* fragment, struct schc_device* device) {
	uint8_t offset = device->profile->RULE_ID_SIZE;

	if(device->profile->DTAG_SIZE) {
		return (uint8_t) get_bits(fragment, offset, device->profile->DTAG_SIZE);
	} else {
		return SCHC_INIT;
	}
}

/**
 * get the Sender-Abort tile size
 *
 * @param  conn			a pointer to the connection
 * @return 				Sender-Abort size
 *
 */
static uint8_t get_sender_abort_size(schc_fragmentation_t* conn) {
	return (BITS_TO_BYTES(conn->device->profile->RULE_ID_SIZE + conn->device->profile->DTAG_SIZE + 
		conn->fragmentation_rule->WINDOW_SIZE + conn->fragmentation_rule->FCN_SIZE));
}

/**
 * Returns the number of bits the current header exists off
 *
 * @param  mbuf 		the mbuf to find the offset for
 *
 * @return length 		the length of the header
 *
 */
static uint8_t get_fragmentation_header_length(schc_mbuf_t *mbuf, schc_fragmentation_t* conn) {
	uint8_t offset = conn->device->profile->RULE_ID_SIZE + conn->device->profile->DTAG_SIZE 
				+ conn->fragmentation_rule->WINDOW_SIZE + conn->fragmentation_rule->FCN_SIZE;

	uint8_t fcn = get_fcn_value(mbuf->ptr, conn);

	if (fcn == get_max_fcn_value(conn)) {
		offset += BYTES_TO_BITS(conn->fragmentation_rule->RCS_SIZE_BYTES);
	}

	return offset;
}

/**
 * print the complete mbuf chain
 *
 * @param  head			the head of the list
 *
 */
static void mbuf_print(schc_mbuf_t *head) {
	uint8_t i = 0; uint8_t j;
	schc_mbuf_t *curr = head;
	while (curr != NULL) {
		DEBUG_PRINTF("%d: %p\n", curr->frag_cnt, curr->ptr);
		for (j = 0; j < curr->len; j++) {
			DEBUG_PRINTF("0x%02X ", curr->ptr[j]);
		}
		DEBUG_PRINTF("\n");
		curr = curr->next;
		i++;
	}
}

static schc_mbuf_t *mbuf_alloc(void)
{
#if !DYNAMIC_MEMORY
	uint32_t i;

	for(i = 0; i < SCHC_CONF_MBUF_POOL_LEN; i++) {
		if(MBUF_POOL[i].len == 0 && MBUF_POOL[i].ptr == NULL) {
			DEBUG_PRINTF("mbuf_alloc(): selected mbuf slot %d \n", (int) i);
			return &MBUF_POOL[i];
		}
	}
	return NULL;
#else
	schc_mbuf_t *res = malloc(sizeof(schc_mbuf_t));

	*res = (schc_mbuf_t){ .len = 0, .ptr = NULL };
	return res;
#endif
}

/**
 * add an item to the end of the mbuf list
 * if head is NULL, the first item of the list
 * will be set
 *
 * @param head			the head of the list
 * @param data			a pointer to the data pointer
 * @param len			the length of the data
 *
 * @return	-1			no free mbuf slot was found
 * 			 0			ok
 */
static int8_t mbuf_push(schc_mbuf_t **head, uint8_t* data, uint16_t len) {
	// scroll to next free mbuf slot
	schc_mbuf_t *mbuf = mbuf_alloc();

	if(mbuf == NULL) {
		DEBUG_PRINTF("mbuf_push(): no free mbuf slots found \n");
		return SCHC_FAILURE;
	}

	// check if this is a new connection
	if(*head == NULL) {
		*head = mbuf;
		(*head)->len = len;
		(*head)->ptr = (uint8_t*) (data);
		(*head)->next = NULL;
		return SCHC_SUCCESS;
	}

	mbuf->next = NULL;
	mbuf->len = len;
	mbuf->ptr = (uint8_t*) (data);

	// find the last mbuf in the chain
	schc_mbuf_t *curr = *head;
	while (curr->next != NULL) {
		curr = curr->next;
	}

	// set next in chain
	curr->next = mbuf;

	return SCHC_SUCCESS;
}

/**
 * returns the last chain in the mbuf linked list
 *
 * @param  head			the head of the list
 * @param  mbuf			the mbuf to find the previous mbuf for
 *
 * @return prev			the previous mbuf
 */
static schc_mbuf_t* get_prev_mbuf(schc_mbuf_t *head, schc_mbuf_t *mbuf) {
	schc_mbuf_t *curr = head;

	while (curr->next != mbuf) {
		DEBUG_PRINTF(
				"head is %p, looking for %p with curr %p, next is %p \n",
				(void*) head, (void*) mbuf, (void*) curr, (void*) curr->next);
		curr = curr->next;
	}

	return curr;
}

/**
 * delete a mbuf from the chain
 *
 * @param  head			the head of the list
 * @param  mbuf			the mbuf to delete
 *
 */
static void mbuf_delete(schc_mbuf_t **head, schc_mbuf_t *mbuf) {
	schc_mbuf_t *prev = NULL;

	if (!(*head) || !mbuf) {
		return;
	}
	if(mbuf->next != NULL) {
		if(mbuf == *head) {
			DEBUG_PRINTF("mbuf_delete(): set head \n");
			(*head) = mbuf->next;
		}
	} else {
		if(mbuf == *head) { // head is last fragment
			DEBUG_PRINTF("mbuf_delete(): mbuf is head, delete head \n");
			(*head) = NULL;
		} else {
			DEBUG_PRINTF("mbuf_delete(): chain next to prev \n");
			prev = get_prev_mbuf(*head, mbuf);
			prev->next = mbuf->next;
		}
	}

#if DYNAMIC_MEMORY
	DEBUG_PRINTF("mbuf_delete(): free %p \n", (void *)mbuf);
	free(mbuf->ptr);
	free(mbuf);
#else
	DEBUG_PRINTF("mbuf_delete(): clear slot %li in mbuf pool \n", mbuf - MBUF_POOL);
	memset(mbuf->ptr, 0, mbuf->len);
	mbuf->next = NULL;
	mbuf->frag_cnt = 0;
	mbuf->len = 0;
	mbuf->ptr = NULL;
#endif
}

/**
 * returns the total length of the mbuf without padding
 *
 * @param  head			the head of the list
 *
 * @return len			the total length of the fragment
 */
uint16_t get_mbuf_len(schc_fragmentation_t *conn) {
	schc_mbuf_t *curr = conn->head; uint32_t total_len = 0;
	if (conn->bit_arr) {
		/* we return a bit array without padding from the fragmenter */
		conn->bit_arr->padding = 0;
	}

	if(conn->fragmentation_rule == NULL)
		return curr->len;

	if(conn->fragmentation_rule->mode == NOT_FRAGMENTED)
		return curr->len;

	while (curr != NULL) {
		total_len += ((curr->len * 8) - get_fragmentation_header_length(curr, conn));
		curr = curr->next;
	}

	return (uint16_t) ( (total_len) / 8 );
}

/**
 * returns the last chain in the mbuf linked list
 *
 * @param  head			the head of the list
 *
 * @return tail			the last mbuf in the linked list
 */
static schc_mbuf_t* get_mbuf_tail(schc_mbuf_t *head) {
	schc_mbuf_t *curr = head;

	if(head == NULL) {
		return NULL;
	}

	while (curr->next != NULL) {
		curr = curr->next;
	}

	return curr;
}

static uint8_t mbuf_get_byte(schc_mbuf_t *prev, schc_mbuf_t *curr, schc_fragmentation_t* conn, uint32_t* offset) {
	uint32_t mbuf_bit_len = (curr->len * 8);
	uint8_t byte_arr[1] = { 0 };
	uint8_t start_offset = 0;

	if(prev == NULL && (*offset) < get_fragmentation_header_length(curr, conn)) { // cope with fragmentation header from first packet
		(*offset) = get_fragmentation_header_length(curr, conn);
	}

	int32_t remaining_bits = mbuf_bit_len - (*offset);
	// DEBUG_PRINTF("total length %d, remaining bits %d, current offset %d: ", mbuf_bit_len, remaining_bits, *offset);

	if (remaining_bits > 8) {
		copy_bits(byte_arr, start_offset, curr->ptr, (*offset), (8 - start_offset));
		*offset += (8 - start_offset);
	} else if (curr->next != NULL) { // copy remainig bits from next mbuf and set offset accordingly
		copy_bits(byte_arr, 0, curr->ptr, (*offset), remaining_bits);
		copy_bits(byte_arr, remaining_bits, curr->next->ptr,
				get_fragmentation_header_length(curr->next, conn),
				(8 - remaining_bits));
		*offset = (8 - remaining_bits) + get_fragmentation_header_length(curr->next, conn);
	} else { // final byte
		copy_bits(byte_arr, 0, curr->ptr, (*offset), remaining_bits);
		*offset = remaining_bits;
	}

	// DEBUG_PRINTF("0x%02X \n", byte_arr[0]);

	return byte_arr[0];
}

/**
 * copy the byte alligned contents of the mbuf chain to
 * the passed pointer
 *
 * @param  head			the head of the list
 * @param  ptr			the pointer to copy the contents to
 */

void mbuf_copy(schc_fragmentation_t *conn, uint8_t* ptr) {
	schc_mbuf_t *curr = conn->head;
	schc_mbuf_t *prev = NULL;

	uint8_t index = 0; uint32_t curr_bit_offset = 0;

	if ( (!conn) || (!conn->fragmentation_rule) ||
         (conn->fragmentation_rule->mode == NOT_FRAGMENTED) ) {
		int i;
		for (i = 0; i < curr->len; i++) {
			ptr[i] = curr->ptr[i];
		}
		return;
	}

	while (curr != NULL) {
		uint32_t temp_offset = curr_bit_offset;
		ptr[index] = mbuf_get_byte(prev, curr, conn, &curr_bit_offset);
		if (curr_bit_offset < temp_offset) { // partially included bits of next mbuf
			prev = curr;
			curr = curr->next;
		}
		index++;
	}
}


/**
 * delete all fragments chained in an mbuf
 *
 * @param  head			the head of the list
 */
void mbuf_clean(schc_mbuf_t **head) {
	schc_mbuf_t *curr = *head;
	schc_mbuf_t *temp = NULL;

	while (curr != NULL) {
		temp = curr->next;
		mbuf_delete(head, curr);
		curr = temp;
	}
}


/**
 * sort the complete mbuf chain based on fragment counter (fcn)
 * note: 	some packets will arrive out of order, as they
 * 			were part of a retransmission, and consequently
 * 			arrive out of order, but carry the same fcn
 *
 * @param  	head		double pointer to the head of the list
 *
 */
static void mbuf_sort(schc_mbuf_t **head) {
	schc_mbuf_t *hd = *head;
	*head = NULL;

	while (hd != NULL) {
		schc_mbuf_t **curr = &hd;
		schc_mbuf_t **next = &hd->next;
		uint8_t swapped = 0;

		while (*next != NULL) {
			if ((*next)->frag_cnt < (*curr)->frag_cnt) { // swap pointers for curr and curr->next
				schc_mbuf_t *temp = *curr;
				*curr = *next;
				*next = (schc_mbuf_t*) temp;

				temp = (*curr)->next;
				(*curr)->next = (*next)->next;
				(*next)->next = (schc_mbuf_t*) temp;

				curr = &(*curr)->next;
				swapped = 1;

			} else {   // no swap. advance both pointer-pointers
				curr = next;
				next = &(*next)->next;
			}
		}

		*next = *head;
		if (swapped) {
			*head = *curr;
			*curr = NULL;
		} else {
			*head = hd;
			break;
		}
	}
}

/**
 * Calculates the Message Integrity Check (MIC) over an unformatted mbuf chain
 * without formatting the mbuf chain, as the last window might contain corrupted fragments
 *
 * this is the 8- 16- or 32- bit Cyclic Redundancy Check (CRC)
 *
 * @param  head			the head of the list
 *
 * @return checksum 	the computed checksum
 *
 */
static unsigned int mbuf_compute_rcs(schc_fragmentation_t *conn) {
	schc_mbuf_t *curr = conn->head;
	schc_mbuf_t *prev = NULL;

	uint32_t crc, crc_mask; int8_t k = 0;

	uint8_t byte = 0; uint32_t curr_bit_offset = 0;
	crc = 0xFFFFFFFF;

	while (curr != NULL) {
		uint32_t temp_offset = curr_bit_offset;
		byte = mbuf_get_byte(prev, curr, conn, &curr_bit_offset);
		/*if (curr->next->next == NULL
				&& curr_bit_offset >= ((curr->next->len * 8) - 8)) { // last byte always contains payload + padding
			// rare case where
			curr = curr->next->next;
		}*/
		// todo
		// when mtu is very small (e.g. 6 or 7), final mbuf > second last mbuf
		// and curr_bit_offset will never be larger than temp_offset
		// resulting in an endless loop
		if ( (curr_bit_offset < temp_offset) ) { // partially included bits of next mbuf
			prev = curr;
			curr = curr->next;
		}
		crc = crc ^ byte;
		for (k = 7; k >= 0; k--) { // do eight times.
			crc_mask = -(crc & 1);
			crc = (crc >> 1) ^ (0xEDB88320 & crc_mask);
		}
		// printf("0x%02X ", byte);
	}

	// printf("\n");

	crc = ~crc;
	uint8_t mic[MAX_RCS_SIZE_BYTES] = { ((crc & 0xFF000000) >> 24),
			((crc & 0xFF0000) >> 16), ((crc & 0xFF00) >> 8), ((crc & 0xFF)) };

	memcpy((uint8_t *) conn->rcs, mic, conn->fragmentation_rule->RCS_SIZE_BYTES);

	DEBUG_PRINTF("mbuf_compute_rcs(): RCS is %02X%02X%02X%02X \n", mic[0], mic[1], mic[2],
			mic[3]);

	return crc;
}


////////////////////////////////////////////////////////////////////////////////////
//                                LOCAL FUNCIONS                                  //
////////////////////////////////////////////////////////////////////////////////////

static uint8_t calculate_byte_padding(uint32_t total_bits) {
	return (8U - (total_bits % 8U)) % 8U;
}

/**
 * Calculates the Message Integrity Check (MIC)
 * which is the 8- 16- or 32- bit Cyclic Redundancy Check (CRC)
 *
 * @param conn 			pointer to the connection
 *
 * @return checksum 	the computed checksum
 *
 */
static unsigned int compute_rcs(schc_fragmentation_t *conn, uint8_t last_tile_padding) {
	int i, j; uint8_t byte;
	unsigned int crc, mask;

	i = 0;
	crc = 0xFFFFFFFF;

	// the MIC is computed over the complete, compressed packet
	// + padding of the last tile, which may result in a non-byte aligned packet
	// so, extra padding might be added before computing the MIC
	uint8_t extra_padding = calculate_byte_padding((conn->bit_arr->len * 8) + last_tile_padding);

	DEBUG_PRINTF(
			"compute_rcs(): original packet length %d bits, last tile padding %d bits, extra padding %d bits \n",
			(int) conn->bit_arr->len * 8, last_tile_padding, extra_padding);

	uint16_t padded_length = (((conn->bit_arr->len * 8) + last_tile_padding + extra_padding) / 8);

	while (i < padded_length) {
		if (i < conn->bit_arr->len) {
			byte = conn->bit_arr->ptr[i];
		}
		else {
			byte = 0U;
		}
		crc = crc ^ byte;
		for (j = 7; j >= 0; j--) {    // do eight times.
			mask = -(crc & 1);
			crc = (crc >> 1) ^ (0xEDB88320 & mask);
		}
		i++;
		// printf("0x%02X ", byte);
	}
	// printf("\n");

	crc = ~crc;
	uint8_t mic[MAX_RCS_SIZE_BYTES] = { ((crc & 0xFF000000) >> 24), ((crc & 0xFF0000) >> 16),
			((crc & 0xFF00) >> 8), ((crc & 0xFF)) };

	memcpy((uint8_t *) conn->rcs, mic, conn->fragmentation_rule->RCS_SIZE_BYTES);

	DEBUG_PRINTF("compute_rcs(): RCS for device %d is %02X%02X%02X%02X \n",
			(int) conn->device->device_id, mic[0], mic[1], mic[2], mic[3]);

	return crc;
}

/**
 * get the window bit
 *
 * @param fragment		a pointer to the fragment to retrieve the window number from
 *
 * @return window		the window number as indicated by the fragment
 *
 */
static uint8_t get_window_bit(uint8_t* fragment, schc_fragmentation_t* conn) {
	uint8_t offset = conn->device->profile->RULE_ID_SIZE + conn->device->profile->DTAG_SIZE;

	return (uint8_t) get_bits(fragment, offset, conn->fragmentation_rule->WINDOW_SIZE);
}

/**
 * get the MIC value
 *
 * @param  fragment		a pointer to the fragment to retrieve the MIC from
 * @param  mic
 *
 */
static void get_received_rcs(uint8_t* fragment, uint8_t mic[],
		schc_fragmentation_t* conn) {
	uint8_t offset = conn->device->profile->RULE_ID_SIZE + conn->device->profile->DTAG_SIZE
			+ conn->fragmentation_rule->WINDOW_SIZE + conn->fragmentation_rule->FCN_SIZE;

	copy_bits(mic, 0, fragment, offset, BYTES_TO_BITS(conn->fragmentation_rule->RCS_SIZE_BYTES));
}

/**
 * set the fragmentation counter of the current connection
 * which is the inverse of the fcn value
 *
 * @param  conn			a pointer to the connection
 * @param  fcn			the fcn value
 *
 */
static uint8_t get_frag_cnt(schc_fragmentation_t* conn, uint8_t fcn, uint8_t window) {
	uint8_t value = (get_max_fcn_value(conn) * (window + 1)) - fcn;
	
	if(fcn == get_max_fcn_value(conn)) {
		value = (window + 1) * get_max_fcn_value(conn);
	} 

	return value;
}

/*
 * Find a rule with the correct reliability mode
 *
 * @param 	mode				the mode for which a rule should be found
 * @param 	device_id			the device to find a rule for
 *
 * @return 	fragmentation_rule	the rule that was found
 * 			NULL				if no rule was found
 *
 */
struct schc_fragmentation_rule_t* get_fragmentation_rule_by_reliability_mode(reliability_mode mode,
		uint32_t device_id) {
	struct schc_device *device = get_device_by_id(device_id);

	if (device == NULL) {
		DEBUG_PRINTF(
				"get_schc_rule(): no device was found for the id: %d\n", (int) device_id);
		return NULL;
	}

	int i;
	for (i = 0; i < device->fragmentation_rule_count; i++) {
		const struct schc_fragmentation_rule_t* curr_rule = (*device->fragmentation_context)[i];
		if (curr_rule->mode == mode) {
			return (struct schc_fragmentation_rule_t*) (curr_rule);
		}
	}

	DEBUG_PRINTF("get_schc_rule(): no fragmentation rule was found for device with id=%d\n",
				(int ) device_id);
	return NULL;
}

// todo move to schc.c generic function for both this method and get_compression_rule_by_rule_id

/*
 * Find a SCHC rule entry for a device
 *
 * @param 	rule_arr 		the rule id in uint8_t array
 * @param 	device_id		the device to find a rule for
 *
 * @return 	schc_rule		the rule that was found
 * 			NULL			if no rule was found
 *
 */
static struct schc_fragmentation_rule_t* get_fragmentation_rule_by_rule_id(uint8_t* rule_arr, struct schc_device *device) {
	int i;

	for (i = 0; i < device->fragmentation_rule_count; i++) {
		struct schc_fragmentation_rule_t* curr_rule = (struct schc_fragmentation_rule_t*) (*device->fragmentation_context)[i];
		uint8_t curr_rule_pos = get_position_in_first_byte(device->profile->RULE_ID_SIZE);
		uint8_t rule_id[4] = { 0 };
		little_end_uint8_from_uint32(rule_id, curr_rule->rule_id); /* copy the uint32_t to a uint8_t array */
		if( compare_bits_aligned(rule_id, curr_rule_pos, rule_arr, 0, device->profile->RULE_ID_SIZE)) {
			DEBUG_PRINTF("get_fragmentation_rule(): curr rule %p \n", (void*) curr_rule);
			return curr_rule;
		}
	}

	return NULL;
}

static int16_t get_next_available_dtag(schc_fragmentation_t* conn) {
	int16_t count = 0;

#if DYNAMIC_MEMORY
	schc_fragmentation_t *ptr = schc_tx_conns;
	while(ptr) {
		if(ptr != conn && ptr->fragmentation_rule) {
			if ( (ptr->fragmentation_rule->rule_id == conn->fragmentation_rule->rule_id) && (ptr->TX_STATE != INIT_TX)) { 
				/* rule in use by another active connection */
				count++;
			}
		}
		ptr = ptr->next;
	}
#else
	uint32_t i;
	for(i = 0; i < SCHC_CONF_TX_CONNS; i++) {
		if(&schc_tx_conns[i] != conn && schc_tx_conns[i].fragmentation_rule) { /* not all connections are initialized yet */
			if( (schc_tx_conns[i].fragmentation_rule->rule_id == conn->fragmentation_rule->rule_id) && (schc_tx_conns[i].TX_STATE != INIT_TX)) { 
				/* rule in use by another active connection */
				count++;
			}
		}
	}
#endif

	if(conn->device->profile->DTAG_SIZE > 0) {
		if(get_required_number_of_bits(count) <= conn->device->profile->DTAG_SIZE) { /* check if dtag value fits the available space */
			DEBUG_PRINTF("get_next_available_dtag(): tx connection=%p, dtag=%d\n", conn, count);
			return count;
		} else {
			return SCHC_FAILURE;
		}
	} else {
		if(count > 0) {
			return SCHC_INIT;
		} else {
			return 0;
		}
	}
}

/**
 * initializes a new tx transmission for a device:
 * set the starting and ending point of the packet
 * calculate the MIC over the complete SCHC packet
 *
 * @param conn 				a pointer to the connection to initialize
 *
 * @return	 1				on success
 * 			 0				on error
 * 			-1				if no fragmentation is needed
 *
 */
static int8_t init_tx_connection(schc_fragmentation_t* conn) {
	if (!conn->bit_arr->ptr) {
		DEBUG_PRINTF(
				"init_connection(): no pointer to compressed packet given \n");
		return 0;
	}
	if (!conn->bit_arr->len) {
		DEBUG_PRINTF("init_connection(): packet_length not specified \n");
		return 0;
	}
	if (conn->send == NULL) {
		DEBUG_PRINTF("init_connection(): no send function specified \n");
		return 0;
	}
	if (conn->post_timer_task == NULL) {
		DEBUG_PRINTF("init_connection(): no timer function specified \n");
		return 0;
	}
	if(conn->fragmentation_rule == NULL) {
		DEBUG_PRINTF("init_connection(): SCHC fragmentation rule not specified \n");
		return 0;
	}
	if((conn->tile_size * 8) < (conn->device->profile->RULE_ID_SIZE + conn->device->profile->DTAG_SIZE + conn->fragmentation_rule->WINDOW_SIZE
			+ conn->fragmentation_rule->FCN_SIZE + (conn->fragmentation_rule->RCS_SIZE_BYTES * 8)) ) {
		DEBUG_PRINTF(
				"init_connection(): conn->tile_size should be larger than last tile's header length \n");
		return 0;
	}

	conn->tail_ptr = (uint8_t*) (conn->bit_arr->ptr + conn->bit_arr->len); // set end of packet

	conn->window = 0;
	conn->frag_cnt = 0;
	conn->attempts = 0;
	conn->total_fragments = 0;

	if (conn->bit_arr->len < conn->tile_size
			&& conn->fragmentation_rule->mode != NOT_FRAGMENTED) { // should not fragment; change rule
		DEBUG_PRINTF(
				"init_connection(): changing rule to NOT FRAGMENTED mode \n");
		conn->fragmentation_rule = get_fragmentation_rule_by_reliability_mode(
				NOT_FRAGMENTED, conn->device_id);
		if (conn->fragmentation_rule == NULL) {
			DEBUG_PRINTF(
					"init_connection(): no matching rule found for mode specified");
			return 0;
		}
	}

	if(!conn->fragmentation_rule->inactivity_timer_ms) {
		DEBUG_PRINTF("init_connection(): inactivity timer should be set in fragmentation rule \n");
		return 0;
	}

	if(conn->fragmentation_rule->tile_size) {
		conn->tile_size = conn->fragmentation_rule->tile_size;
	}

	if(conn->tile_size > MAX_MTU_LENGTH || conn->tile_size <= 0) {
		DEBUG_PRINTF("init_connection(): tile size (%d) should be set between 0 and the maximum allowed MTU (%d)\n", conn->tile_size, MAX_MTU_LENGTH);
		return 0;
	}

	uint32_rule_id_to_uint8_buf(conn->fragmentation_rule->rule_id,
			conn->rule_id, conn->device->profile->RULE_ID_SIZE);

	if(conn->fragmentation_rule->MAX_WND_FCN >= get_max_fcn_value(conn)) {
		DEBUG_PRINTF("init_connection(): MAX_WIND_FCN must be smaller than all-1 \n");
		return 0;
	}

	if (get_number_of_bytes_from_bits(conn->fragmentation_rule->MAX_WND_FCN) > BITMAP_SIZE_BYTES) {
		DEBUG_PRINTF(
				"init_connection(): BITMAP_SIZE_BYTES must match MAX_WND_FCN \n");
		return 0;
	}

	if(conn->fragmentation_rule->MAX_WND_FCN > MAX_WINDOW_SIZE) {
		DEBUG_PRINTF(
				"init_connection(): MAX_WINDOW_SIZE must match MAX_WND_FCN \n");
		return 0;
	}

	memset(conn->window_tiles, 0, sizeof(conn->window_tiles));

	conn->fcn = conn->fragmentation_rule->MAX_WND_FCN;
	memset(conn->bitmap, 0, BITMAP_SIZE_BYTES); // clear bitmap

	/* check the list of tx connections in order to set an appropriate dtag value */
	int16_t dtag = get_next_available_dtag(conn);
	if(dtag == SCHC_FAILURE) {
		DEBUG_PRINTF("init_connection(): no more free dtag values available\n");
		return 0;
	} else {
		conn->dtag = dtag;
	}

	return 1;
}

/**
 * reset a connection
 *
 * @param conn 			a pointer to the connection to reset
 *
 */
void schc_reset(schc_fragmentation_t* conn) {
	/* reset connection variables */
	if (conn->remove_timer_entry) {
		conn->remove_timer_entry(conn);
	}
#if DYNAMIC_MEMORY
	conn->next = NULL;
#endif
	conn->device = NULL;
	conn->tail_ptr = 0;
	conn->dc = 0;
	conn->fcn = 0;
	conn->dtag = -1;
	conn->frag_cnt = 0;
	conn->fragmentation_rule = NULL;
	memset(conn->bitmap, 0, BITMAP_SIZE_BYTES);
	conn->attempts = 0;
	conn->TX_STATE = INIT_TX;
	conn->RX_STATE = RECV_WINDOW;
	conn->window = 0;
	conn->timer_flag = 0;
	conn->input = 0;
	memset(conn->rcs, 0, MAX_RCS_SIZE_BYTES);

	/* reset ack structure */
	memset(conn->ack.rule_id, 0, 4); /* rule id can be maximum of 4 bytes */
	memset(conn->ack.bitmap, 0, BITMAP_SIZE_BYTES);
	memset(conn->ack.window, 0, 1);
	memset(conn->ack.dtag, 0, 1);
	conn->ack.mic = 0;
	conn->ack.fcn = 0;
	
	conn->total_fragments = 0;
	memset(conn->window_tiles, 0, sizeof(conn->window_tiles));

	if(conn->head != NULL ){
		mbuf_clean(&conn->head);
	}
	conn->head = NULL;
}

/**
 * check if a connection has more fragments to deliver
 *
 * @param conn 					a pointer to the connection
 *
 * @return	0					the connection still has fragments to send
 * 			total_bits			the total number of packet bits already transmitted
 *
 */
static uint32_t has_no_more_fragments(schc_fragmentation_t* conn) {
	uint32_t total_bits_to_transmit = BYTES_TO_BITS(conn->bit_arr->len); /* effective payload bits */
	uint16_t header_size = (conn->device->profile->RULE_ID_SIZE + conn->device->profile->DTAG_SIZE
			+ conn->fragmentation_rule->WINDOW_SIZE + conn->fragmentation_rule->FCN_SIZE);
	uint16_t prev_header_bits = header_size * (conn->frag_cnt - 1); /* previous fragmentation overhead */

	uint32_t total_mtu_bits = BYTES_TO_BITS(conn->tile_size); // (header + packet) bits already transfered
	for(int i = 0; i < conn->frag_cnt - 1; i++) {
		total_mtu_bits += BYTES_TO_BITS(conn->window_tiles[i]);
	}

	if ( (total_mtu_bits - prev_header_bits) > total_bits_to_transmit) { // last fragment
		uint16_t mic_included_bits = (total_bits_to_transmit + prev_header_bits)
				+ (header_size + BYTES_TO_BITS(conn->fragmentation_rule->RCS_SIZE_BYTES));
		if (mic_included_bits <= total_mtu_bits) { // return the number of bits transmitted,
			// return the total number of bits transmitted if the RCS does not create an extra fragment
			uint32_t already_transmitted = total_mtu_bits - BYTES_TO_BITS(conn->tile_size) - prev_header_bits;
			return already_transmitted;
		}
	}

	return 0;
}

static uint8_t set_bare_fragmentation_header(schc_fragmentation_t* conn, uint8_t* fragmentation_buffer) {
	uint8_t bit_offset = conn->device->profile->RULE_ID_SIZE;

	 // set rule id
	uint8_t src_pos = get_position_in_first_byte(conn->device->profile->RULE_ID_SIZE);
	uint8_t fragmenter_id[4] = { 0 };
	little_end_uint8_from_uint32(fragmenter_id, conn->fragmentation_rule->rule_id); /* copy the uint32_t to a uint8_t array */
	copy_bits(fragmentation_buffer, 0, fragmenter_id, src_pos, bit_offset);

	// set dtag field
	uint8_t dtag[1] = { conn->dtag << (8 - conn->device->profile->DTAG_SIZE) };
	copy_bits(fragmentation_buffer, bit_offset, dtag, 0, conn->device->profile->DTAG_SIZE); // right after rule id

	bit_offset += conn->device->profile->DTAG_SIZE;

	// set window bit
	uint8_t window[1] = { conn->window << (8 - conn->fragmentation_rule->WINDOW_SIZE) };
	copy_bits(fragmentation_buffer, bit_offset, window, 0, conn->fragmentation_rule->WINDOW_SIZE); // right after dtag

	bit_offset += conn->fragmentation_rule->WINDOW_SIZE;

	// set fcn value
	uint8_t fcn[1] = { conn->fcn << (8 - conn->fragmentation_rule->FCN_SIZE) };
	copy_bits(fragmentation_buffer, bit_offset, fcn, 0, conn->fragmentation_rule->FCN_SIZE); // right after window bits

	bit_offset += conn->fragmentation_rule->FCN_SIZE;

	return bit_offset;
}

/**
 * set the fragmentation header and compute RCS if this is the final fragment
 *
 * @param conn 			a pointer to the connection
 * @param buffer		a pointer to the buffer to set the header
 *
 * @return bit_offset	the number of bits added to the front of the fragment
 *
 */
static uint16_t set_complete_fragmentation_header(schc_fragmentation_t* conn,
		uint8_t* fragmentation_buffer) {
	uint8_t bit_offset = set_bare_fragmentation_header(conn, fragmentation_buffer);

	uint32_t bits_transmitted = has_no_more_fragments(conn);
	if (bits_transmitted) { // all-1 fragment
		uint32_t total_bits_to_transmit = conn->bit_arr->len * 8; // effective payload bits
		// to use for RCS calculation
		int8_t bits_left_to_transmit = (total_bits_to_transmit - bits_transmitted);
		uint8_t padding = 0;
		if (bits_left_to_transmit < 0) { // RCS in separate packet
			uint16_t prev_header_bits = (conn->device->profile->RULE_ID_SIZE
					+ conn->fragmentation_rule->WINDOW_SIZE + conn->fragmentation_rule->FCN_SIZE
					+ conn->device->profile->DTAG_SIZE) * (conn->frag_cnt - 1);
			bits_left_to_transmit = (total_bits_to_transmit + prev_header_bits) % 8; // we might need some extra bits from the last byte
		}

		padding = calculate_byte_padding(bit_offset + (conn->fragmentation_rule->RCS_SIZE_BYTES * 8) + bits_left_to_transmit);

		DEBUG_PRINTF("set_complete_fragmentation_header(): padding bits of last tile %d \n", padding);
		compute_rcs(conn, padding); // calculate RCS over compressed, (possibly double) padded packet

		// shift in RCS
		copy_bits(fragmentation_buffer, bit_offset, conn->rcs, 0, (conn->fragmentation_rule->RCS_SIZE_BYTES * 8));
		bit_offset += (conn->fragmentation_rule->RCS_SIZE_BYTES * 8);
	}

	return bit_offset;
}

/**
 * sets the local bitmap at the current fragment offset
 * without encoding the bitmap
 *
 *
 * @param conn 			a pointer to the connection
 *
 */
static void set_local_bitmap(schc_fragmentation_t* conn) {
	int8_t frag = (((conn->fragmentation_rule->MAX_WND_FCN + 1) - conn->fcn) - 1);
	if(frag < 0) {
		frag = conn->fragmentation_rule->MAX_WND_FCN;
	}
	set_bits(conn->bitmap, frag, 1);

	DEBUG_PRINTF("set_local_bitmap(): for fcn %d at index %d \n", conn->fcn, frag);
	print_bitmap(conn->bitmap, conn->fragmentation_rule->MAX_WND_FCN + 1);
}

/**
 * clear the received and local bitmap
 *
 * @param conn 			a pointer to the connection
 *
 */
static void clear_bitmap(schc_fragmentation_t* conn) {
	memset(conn->bitmap, 0, BITMAP_SIZE_BYTES); // clear local bitmap
	memset(conn->ack.bitmap, 0, BITMAP_SIZE_BYTES); // clear received bitmap
}

/**
 * encode the bitmap by removing all the right
 * most contiguous BYTES in the non-encoded bitmap
 *
 * @param conn 			a pointer to the connection
 *
 */
/*static void encode_bitmap(schc_fragmentation_t* conn) {
	// ToDo
	DEBUG_PRINTF("encode_bitmap(): for device %d", (int) conn->device_id);
}*/

/**
 * reconstruct an encoded bitmap
 *
 * @param conn 			a pointer to the connection
 *
 */
/*static void decode_bitmap(schc_fragmentation_t* conn) {
	// ToDo
	DEBUG_PRINTF("decode_bitmap(): for device %d", (int) conn->device_id);
}*/

/**
 * loop over a bitmap to check if all bits are set to
 * 1, starting from MAX_WIND_FCN
 *
 * @param 	conn 		a pointer to the connection
 * @param 	len			the length of the bitmap
 * 
 * @return 	0 			bitmap contains 0
 * 			1 			every bit in the bitmap is set to 1
 *
 */
static uint8_t is_bitmap_full(schc_fragmentation_t* conn, uint8_t len) {
	uint8_t i;
	for (i = 0; i < len; i++) {
		if (!(conn->bitmap[i / 8] & 128 >> (i % 8))) {
			return 0;
		}
	}
	return 1;
}

/**
 * get the next fragment to retransmit according the fragmentation counter
 *
 * @param conn 			a pointer to the connection
 *
 * @return  frag		the next fragment to retransmit
 * 			0			no more fragments to retransmit
 *
 */
static uint16_t get_next_fragment_from_bitmap(schc_fragmentation_t* conn) {
	uint16_t i;

	uint8_t start = (conn->frag_cnt) - ((conn->fragmentation_rule->MAX_WND_FCN + 1)* conn->window);
	for (i = start; i <= conn->fragmentation_rule->MAX_WND_FCN; i++) {
		uint8_t bit = conn->ack.bitmap[i / 8] & 128 >> (i % 8);
		if(bit) {
			return (i + 1);
		}
	}

	return 0;
}
/**
 * discard a fragment
 *
 * @param conn 			a pointer to the connection
 *
 */
static void discard_fragment(schc_fragmentation_t* conn) {
	schc_mbuf_t* tail = get_mbuf_tail(conn->head); // get last received fragment
	DEBUG_PRINTF("discard_fragment(): mbuf tail=%p\n", tail);
	if(conn->head != NULL) {
		mbuf_delete(&conn->head, tail);
	}
	return;
}

/**
 * abort an ongoing transmission because the
 * inactivity timer has expired
 *
 * @param conn 			a pointer to the connection
 *
 */
static void abort_connection(schc_fragmentation_t* conn) {
	// todo
	DEBUG_PRINTF("abort_connection(): inactivity timer expired \n");
	schc_reset(conn);
	return;
}

/**
 * callback for schc_fragmentation_t::post_timer_task to time schc_fragment
 * this function is called by the retransmission timer and the duty cycle timer
 * to re-enter the fragmentation loop.
 *
 * @param   arg The argument for the callback
 */
static void schc_duty_cycle_timer_cb(void *arg) {
	schc_fragmentation_t* conn = (schc_fragmentation_t*)(arg);
	if(conn->duty_cycle_cb) {
		conn->duty_cycle_cb(conn);
	}
}

/**
 * callback for schc_fragmentation_t::post_timer_task to time schc_fragment
 *
 * @param   arg The argument for the callback
 */
static void schc_retransmission_timer_cb(void *arg) {
	schc_fragment(arg);
}

/**
 * callback for schc_fragmentation_t::post_timer_task to time schc_reassemble
 *
 * @param   arg The argument for the callback
 */
static void schc_inactivity_timer_cb(void *arg) {
	schc_reassemble(arg);
}

/**
 * sets the retransmission timer to re-enter the fragmentation loop
 * and changes the retransmission_timer flag which might get overwritten. 
 * If this happens, the fragmenter knows there is no need to retransmit the packet
 *
 * @param conn 			a pointer to the connection
 *
 */
static void set_retrans_timer(schc_fragmentation_t* conn) {
	conn->timer_flag = 1;
	DEBUG_PRINTF("set_retrans_timer(): for %d ms \n", (int) (conn->dc * 4));
	conn->post_timer_task(conn, schc_retransmission_timer_cb, conn->dc * 4, conn);
}

/**
 * sets the duty cycle timer in order to fetch the next packet
 *
 * @param conn 			a pointer to the connection
 *
 */
static void set_dc_timer(schc_fragmentation_t* conn) {
	DEBUG_PRINTF("set_dc_timer(): for %d ms \n", (int) conn->dc);
	conn->post_timer_task(conn, schc_duty_cycle_timer_cb, conn->dc, conn);
}

/**
 * sets the inactivity timer to re-enter the fragmentation loop
 * and changes the retransmission_timer flag which might get overwritten. 
 * If this happens, the reassembler knows there is no need to retransmit the packet
 * 
 * @param conn 			a pointer to the connection
 *
 */
static void set_inactivity_timer(schc_fragmentation_t* conn) {
	conn->timer_flag = 1;
	DEBUG_PRINTF("set_inactivity_timer(): for %d ms \n", (int) conn->fragmentation_rule->inactivity_timer_ms);
	conn->post_timer_task(conn, schc_inactivity_timer_cb, conn->fragmentation_rule->inactivity_timer_ms, conn);
}

/**
 * checks if the fragment inside the mbuf is
 * an all-0 empty
 *
 * @param mbuf 			a pointer to the mbuf
 *
 * @return 	0			this is not an empty all-0
 * 			1			this is an empty all-0
 *
 */
static uint8_t empty_all_0(schc_mbuf_t* mbuf, schc_fragmentation_t* conn) {
	uint8_t offset = conn->device->profile->RULE_ID_SIZE + conn->fragmentation_rule->FCN_SIZE
			+ conn->device->profile->DTAG_SIZE + conn->fragmentation_rule->WINDOW_SIZE;
	uint8_t len = (mbuf->len * 8);

	if ((len - offset) > 8) { // if number of bits is larger than 8, there was payload
		return 0;
	}
	return 1;
}

/**
 * checks if the fragment inside the mbuf is
 * an all-1 empty
 *
 * @param mbuf 			a pointer to the mbuf
 *
 * @return 	0			this is not an empty all-1
 * 			1			this is an empty all-1
 *
 */
static uint8_t empty_all_1(schc_mbuf_t* mbuf, schc_fragmentation_t* conn) {
	uint8_t offset = conn->device->profile->RULE_ID_SIZE + conn->fragmentation_rule->FCN_SIZE + conn->device->profile->DTAG_SIZE
			+ conn->fragmentation_rule->WINDOW_SIZE + BYTES_TO_BITS(conn->fragmentation_rule->RCS_SIZE_BYTES);
	uint8_t len = BYTES_TO_BITS(mbuf->len);

	if ((len - offset) > 8) { // if number of bits is larger than 8, there was payload
		return 0;
	}
	return 1;
}

/**
 * composes a packet based on the type of the packet
 * and calls the callback function to transmit the packet
 *
 * the fragmenter works on a per tile basis,
 * and therefore uses the conn->frag_cnt variable to calculate
 * the current offset and appropriate actions
 *
 * @param 	conn 			a pointer to the connection
 *
 * @ret		0				the packet was not sent
 * 			1				the packet was transmitted
 *
 */
static uint8_t send_fragment(schc_fragmentation_t* conn, bool retransmission) {
	memset(FRAGMENTATION_BUF, 0, MAX_MTU_LENGTH); /* set and reset buffer */

	uint16_t header_bits = set_complete_fragmentation_header(conn, FRAGMENTATION_BUF); /* set fragmentation header */
	uint32_t packet_bits_tx = has_no_more_fragments(conn); /* the number of bits already transmitted */
	uint16_t packet_len = 0; int32_t remaining_bits; uint32_t packet_bit_offset = 0;

	if(!packet_bits_tx) { /* normal fragment */
		if(retransmission) {
			packet_len = conn->window_tiles[conn->frag_cnt - 1];
			packet_bits_tx = BYTES_TO_BITS(conn->window_tiles[conn->frag_cnt - 1]) - header_bits;

		} else {
			packet_len = conn->tile_size;
			packet_bits_tx = BYTES_TO_BITS(conn->tile_size) - header_bits; // set packet bits to number of bits that fit in packet
		}
		
		for(int i = 0; i < conn->frag_cnt - 1; i++) {
			packet_bit_offset += BYTES_TO_BITS(conn->window_tiles[i]) - header_bits;
		}

		remaining_bits = (conn->bit_arr->len * 8) - packet_bit_offset;
		if( BITS_TO_BYTES(remaining_bits) < packet_len ) { // next packet contains RCS
			packet_bits_tx = remaining_bits - ((remaining_bits + header_bits) % 8); // some bits of last byte are included in next (last) packet
			packet_len = (remaining_bits + header_bits) / 8;
		}
	}

	if (!packet_len) { // all-1 fragment
		packet_bit_offset = packet_bits_tx;

		remaining_bits = (conn->bit_arr->len * 8) - packet_bits_tx;

		packet_bits_tx = remaining_bits;

		if(remaining_bits < 0) { // RCS in separate packet
			// which also requires padding
			header_bits = conn->device->profile->RULE_ID_SIZE + conn->fragmentation_rule->WINDOW_SIZE
					+ conn->fragmentation_rule->FCN_SIZE + conn->device->profile->DTAG_SIZE;

			uint16_t prev_header_bits = header_bits * (conn->frag_cnt - 1);
			packet_bits_tx = ((conn->bit_arr->len * 8) + prev_header_bits) % 8; // we might need some extra bits from the last byte
			packet_bit_offset = (conn->bit_arr->len * 8) - packet_bits_tx;

			header_bits += (conn->fragmentation_rule->RCS_SIZE_BYTES * 8); // include RCS bytes
		}

		remaining_bits = calculate_byte_padding(header_bits + packet_bits_tx); // padding variable (padding is already set by memset(FRAGMENTATION_BUF))

		packet_len = BITS_TO_BYTES(header_bits + remaining_bits + packet_bits_tx); // last packet length

		if(packet_len > conn->tile_size) {
			DEBUG_PRINTF("send_fragment(): mtu smaller than tile size of last packet length \n");
			packet_len = conn->tile_size;
		}
	}

	copy_bits(FRAGMENTATION_BUF, header_bits, conn->bit_arr->ptr, packet_bit_offset, packet_bits_tx); // copy bits

	DEBUG_PRINTF(
			"send_fragment(): count=%d, fcn=%d, dtag=%d, window=%d, length=%d\n",
			conn->frag_cnt, conn->fcn, conn->dtag, conn->window, packet_len);
	int j;

	for (j = 0; j < packet_len; j++) {
		DEBUG_PRINTF("0x%02X ", FRAGMENTATION_BUF[j]);
	}
	DEBUG_PRINTF("\n");
	
	if(!retransmission) {
		/* store the tile sizes of the current window */
		conn->window_tiles[conn->frag_cnt - 1] = packet_len;
		conn->total_fragments += 1;
	}

	return conn->send(FRAGMENTATION_BUF, packet_len, conn->device_id);
}

/**
 * composes an ack based on the parameters found in the connection
 * and calls the callback function to transmit the packet
 *
 * @param conn 			a pointer to the connection
 *
 * @ret		0				the packet was not sent
 * 			1				the packet was transmitted
 *
 */
static uint8_t send_ack(schc_fragmentation_t* conn) {
	uint8_t ack[RULE_SIZE_BYTES + DTAG_SIZE_BYTES + BITMAP_SIZE_BYTES] = { 0 };
	
	/* set rule id */
	uint8_t offset = conn->device->profile->RULE_ID_SIZE;
	copy_bits(ack, 0, conn->ack.rule_id, 0, offset);

	/* set dtag */
	uint8_t dtag[1] =  { conn->dtag << (8 - conn->device->profile->DTAG_SIZE) };
	copy_bits(ack, offset, dtag, 0, conn->device->profile->DTAG_SIZE);
	offset += conn->device->profile->DTAG_SIZE;

	/* set window */
	uint8_t window[1] = { conn->window << (8 - conn->fragmentation_rule->WINDOW_SIZE) };
	copy_bits(ack, offset, window, 0, conn->fragmentation_rule->WINDOW_SIZE);
	offset += conn->fragmentation_rule->WINDOW_SIZE;

	if(conn->ack.fcn == get_max_fcn_value(conn)) {
		 /* set mic bit if all-1 window */
		uint8_t c[1] = { conn->ack.mic << (8 - MIC_C_SIZE_BITS) };
		copy_bits(ack, offset, c, 0, MIC_C_SIZE_BITS);
		offset += MIC_C_SIZE_BITS;
	}

	if(!conn->ack.mic) { 
		/* send bitmap if mic c bit is 0 (zero by default) */
		DEBUG_PRINTF("send_ack(): sending bitmap \n");
		copy_bits(ack, offset, conn->bitmap, 0, conn->fragmentation_rule->MAX_WND_FCN + 1); // copy the bitmap
		offset += conn->fragmentation_rule->MAX_WND_FCN + 1; // todo must be encoded
		print_bitmap(conn->bitmap, conn->fragmentation_rule->MAX_WND_FCN + 1);
	}

	uint8_t packet_len = ((offset - 1) / 8) + 1;
	DEBUG_PRINTF("send_ack(): sending ack with length %d (%d b) - count=%d, dtag=%d, window=%d \n",
			packet_len, offset, conn->frag_cnt, conn->dtag, conn->ack.window[0]);

	int i;
	for(i = 0; i < packet_len; i++) {
		DEBUG_PRINTF("%02X ", ack[i]);
	}

	DEBUG_PRINTF("\n");

	return conn->send(ack, packet_len, conn->device_id);
}

/**
 * composes an all-empty fragment based on the parameters
 * found in the connection
 * and calls the callback function to transmit the packet
 *
 * @param conn 			a pointer to the connection
 *
 * @ret		0				the packet was not sent
 * 			1				the packet was transmitted
 *
 */
static uint8_t send_empty(schc_fragmentation_t* conn) {
	// set and reset buffer
	memset(FRAGMENTATION_BUF, 0, MAX_MTU_LENGTH);

	// set fragmentation header
	uint16_t header_offset = set_complete_fragmentation_header(conn, FRAGMENTATION_BUF);

	uint8_t padding = header_offset % 8;
	uint8_t zerobuf[1] = { 0 };
	copy_bits(FRAGMENTATION_BUF, header_offset, zerobuf, 0, padding); // add padding

	uint8_t packet_len = (padding + header_offset) / 8;

	DEBUG_PRINTF("send_empty(): sending all-x empty to device %d with length %d (%d b)\n",
			(int) conn->device_id, packet_len, header_offset);

	return conn->send(FRAGMENTATION_BUF, packet_len, conn->device_id);
}

/**
 * composes an all-empty fragment based on the parameters
 * found in the connection
 * and calls the callback function to transmit the packet
 *
 * @param conn 			a pointer to the connection
 *
 * @ret		0				the packet was not sent
 * 			1				the packet was transmitted
 *
 */
static uint8_t send_tx_empty(schc_fragmentation_t* conn) {
	DEBUG_PRINTF("send_tx_empty() to device %d \n", (int) conn->device_id);
	return 0;
}


/**
 * abort the current fragmentation sequence and transmit Send-Abort
 *
 * @param 	conn		a pointer to the tx connection structure
 *
 */
int8_t schc_send_abort(schc_fragmentation_t* conn) {
	/* set and reset buffer */
	memset(FRAGMENTATION_BUF, 0, MAX_MTU_LENGTH);
	
	conn->fcn = get_max_fcn_value(conn);
	conn->TX_STATE = ERR;
	uint8_t header_offset = set_bare_fragmentation_header(conn, FRAGMENTATION_BUF);

	/* padding is already set by memsetting the buffer */
	uint8_t packet_len = BITS_TO_BYTES(header_offset);

	DEBUG_PRINTF("schc_send_abort(): sending Send-Abort to device %d with length %d (%d b)\n",
			(int) conn->device_id, packet_len, header_offset);

	return conn->send(FRAGMENTATION_BUF, packet_len, conn->device_id);

}

#if DYNAMIC_MEMORY
static schc_fragmentation_t* alloc_connection(schc_fragmentation_t** connections) {
	schc_fragmentation_t *conn;

	conn = malloc(sizeof(schc_fragmentation_t));

	if (conn == NULL) {
		return NULL;
	}
	DEBUG_PRINTF("alloc_connection(): malloc'd %p\n", (void *)conn);
	*conn = (schc_fragmentation_t){ 0 };

	/* append to list of connections */
	while (*connections && (*connections)->next) {
		*connections = (*connections)->next;
	}
	if (*connections) {
		(*connections)->next = conn;
	}
	else {
		*connections = conn;
	}

	return conn;
}
#endif

////////////////////////////////////////////////////////////////////////////////////
//                               GLOBAL FUNCIONS                                  //
////////////////////////////////////////////////////////////////////////////////////

static schc_fragmentation_t* get_connection(struct schc_device* device, int16_t dtag, schc_fragmentation_t *ptr, uint16_t static_length) {
	uint32_t i; schc_fragmentation_t *conn = NULL;
#if DYNAMIC_MEMORY
	while (ptr) {
		if (ptr->device == device) {
			// if(dtag >= 0) {
				if(ptr->dtag == dtag) {
					conn = ptr;
					break;
				}
			// } 
			// else { /* do not consider dtag in initilization phase */
			// 	conn = ptr;
			// 	break;
			// }
		}
		ptr = ptr->next;
	}
#else
	for (i = 0; i < static_length; i++) {
		// first look for the the old connection
		if (ptr[i].device == device) {
			// if(dtag >= 0) {
				if(ptr[i].dtag == dtag) {
					conn = &ptr[i];
					break;
				}
			// } else { /* do not consider dtag in initilization phase */
			// 	conn = &ptr[i];
			// 	break;
			// }
		}
	}
#endif

	return conn;
}

schc_fragmentation_t* set_connection(struct schc_device* device, schc_fragmentation_t *ptr, uint16_t static_length) {
	schc_fragmentation_t* conn = NULL; uint32_t i;
#if DYNAMIC_MEMORY
	conn = alloc_connection(&ptr);
	if(conn) {
		conn->device = device;
	}
#else
	for (i = 0; i < static_length; i++) {
		if (ptr[i].device == NULL) { // look for an empty connection
			conn = &ptr[i];
			ptr[i].device = device;
			break;
		}
	}
#endif
	return conn;
}

/**
 * find a connection based on a device id
 * or open a new connection if there was no connection
 * for this device yet
 *
 * @param 	device		the device to open a connection for
 * @param   dtag 		the dtag to match with the device connection
 *
 * @return 	conn		a pointer to the selected connection
 * 			0 			if no free connections are available
 *
 */
schc_fragmentation_t* schc_get_rx_connection(struct schc_device* device, int16_t dtag) {
	schc_fragmentation_t *conn = NULL;
	conn = get_connection(device, dtag, schc_rx_conns, SCHC_CONF_RX_CONNS);

	if(conn) {
		DEBUG_PRINTF("get_rx_connection(): selected connection %p for device %d with dtag %d\n", (void *) conn, (int) device->device_id, (int) dtag);
	}

	return conn;
}

schc_fragmentation_t* schc_set_rx_connection(struct schc_device* device, int16_t dtag) {
	schc_fragmentation_t *conn = NULL;
	conn = schc_get_rx_connection(device, dtag);
	if(!conn) {
		conn = set_connection(device, schc_rx_conns, SCHC_CONF_RX_CONNS);
		if(!conn) {
			DEBUG_PRINTF("set_rx_connection(): no more free connections available\n");
			return NULL;
		}

		conn->dtag = dtag;
		DEBUG_PRINTF("set_rx_connection(): selected connection %p for device %d with dtag %d\n", (void *) conn, (int) device->device_id, (int) conn->dtag);
		return conn;
	} else {
		return conn;
	}

	DEBUG_PRINTF("set_rx_connection(): selected connection %p for device %d with dtag %d\n", (void *) conn, (int) device->device_id, (int) conn->dtag);

	return conn;
}

/**
 * Get a new TX connection
 *
 * @return 	conn		a pointer to the selected connection
 * 			0 			if no free connections are available
 *
 */
schc_fragmentation_t* schc_get_tx_connection(struct schc_device* device, int16_t dtag) {
	schc_fragmentation_t *conn = NULL;
	conn = get_connection(device, dtag, schc_tx_conns, SCHC_CONF_TX_CONNS);

	if(conn) {
		DEBUG_PRINTF("get_tx_connection(): selected connection %p for device %d with dtag %d\n", (void *) conn, (int) device->device_id, (int) conn->dtag);
	}

	return conn;
}

schc_fragmentation_t* schc_set_tx_connection(struct schc_device* device, int16_t dtag) {
	schc_fragmentation_t *conn = NULL;
	conn = schc_get_tx_connection(device, dtag);
	if(!conn) {
		conn = set_connection(device, schc_tx_conns, SCHC_CONF_TX_CONNS);
		if(!conn) {
			DEBUG_PRINTF("set_tx_connection(): no more free connections available\n");
			return NULL;
		}
		DEBUG_PRINTF("set_tx_connection(): selected connection %p for device %d with dtag %d\n", (void *) conn, (int) device->device_id, (int) conn->dtag);
		return conn;
	} else {
		return conn;
	}
}

/**
 * Free an SCHC connection
 * 
 * @param 	conn		a pointer to the connection
 * 
 */
void schc_free_connection(schc_fragmentation_t *conn)
{
#if DYNAMIC_MEMORY
	if(conn->free_conn_cb) {
		conn->free_conn_cb(conn);
	}
	schc_fragmentation_t *ptr = schc_rx_conns, *last = NULL;

	DEBUG_PRINTF("schc_free_connection(): trying to free %p\n", (void *)conn);
	while (ptr) {
		if (ptr == conn) {
			if (last == NULL) {
				schc_rx_conns = ptr->next;
			}
			else {
				last->next = ptr->next;
			}
			ptr->next = NULL;
			DEBUG_PRINTF("schc_free_connection(): free'd %p\n", (void *)ptr);
			free(ptr);
			break;
		}
		last = ptr;
		ptr = ptr->next;
	}
#endif
	
	conn->timer_ctx = NULL;
}

/**
 * sort the mbuf chain, find the MIC inside the last received fragment
 * and compare with the calculated one
 *
 * @param 	rx_conn		a pointer to the rx connection structure
 *
 */
static int8_t rcs_correct(schc_fragmentation_t* rx_conn) {
	uint8_t recv_mic[MAX_RCS_SIZE_BYTES] = { 0 };

	mbuf_sort(&rx_conn->head); // sort the mbuf chain

	schc_mbuf_t* tail = get_mbuf_tail(rx_conn->head); // get new tail before looking for mic

	if (tail == NULL) { // hack
		// rx_conn->timer_flag or rx_conn->input has not been changed
		abort_connection(rx_conn); // todo
		return -1;
	}

	get_received_rcs(tail->ptr, recv_mic, rx_conn);
	DEBUG_PRINTF("rcs_correct(): received RCS is %02X%02X%02X%02X\n", recv_mic[0], recv_mic[1],
			recv_mic[2], recv_mic[3]);

	mbuf_print(rx_conn->head);
	mbuf_compute_rcs(rx_conn); // compute the mic over the mbuf chain

	if (!compare_bits(rx_conn->rcs, recv_mic, (rx_conn->fragmentation_rule->RCS_SIZE_BYTES * 8))) { // mic wrong
		DEBUG_PRINTF("rcs_correct(): reassembly check sequence failed! \n");
		return 0;
	}

	return 1;
}


/**
 * the function to call when the state machine is in WAIT END state
 *
 * @param 	rx_conn		a pointer to the rx connection structure
 *
 */
static uint8_t wait_end(schc_fragmentation_t* rx_conn, schc_mbuf_t* tail) {
	uint8_t window = get_window_bit(tail->ptr, rx_conn); // the window bit from the fragment
	uint8_t fcn = get_fcn_value(tail->ptr, rx_conn); // the fcn value from the fragment

	char* mode = (rx_conn->fragmentation_rule->mode == ACK_ALWAYS) ? "Ack-Always" : "Ack-On-Error";
	DEBUG_PRINTF("schc_reassemble(): (%s) state=WAIT END\n", mode);	
	
	if (rx_conn->timer_flag && !rx_conn->input) { // inactivity timer expired
		abort_connection(rx_conn); // todo + reset connection (but first remove timer instance)
		return 0;
	}

	uint8_t rcs_check = rcs_correct(rx_conn);
	if(rcs_check < 0) { // tail is NULL
		return 0;
	} else {
		if (!rcs_check) { // mic incorrect
			DEBUG_PRINTF("schc_reassemble(): (%s) RCS check failed\n", mode);
			rx_conn->ack.mic = 0;
			rx_conn->RX_STATE = WAIT_END;
			if (window == rx_conn->window) { // expected window
				DEBUG_PRINTF("schc_reassemble(): (%s) Expected window\n", mode);
				set_local_bitmap(rx_conn);
			}
			if (fcn == get_max_fcn_value(rx_conn) && rx_conn->fragmentation_rule->mode == ACK_ALWAYS) { // all-1
				DEBUG_PRINTF("all-1");
				send_ack(rx_conn);
			}
		} else { // mic correct
			DEBUG_PRINTF("schc_reassemble(): (%s) RCS check succeeded\n", mode);
			if (window == rx_conn->window) { // expected window
				rx_conn->RX_STATE = END_RX;
				rx_conn->ack.fcn = get_max_fcn_value(rx_conn); // c bit is set when ack.fcn is max
				rx_conn->ack.mic = 1; // bitmap is not sent when mic correct
				set_local_bitmap(rx_conn);
				send_ack(rx_conn);
				rx_conn->input = 0;
				return 2; // stay alive to answer lost acks
			}
		}
	}

	if (fcn == get_max_fcn_value(rx_conn) && rx_conn->fragmentation_rule->mode == ACK_ON_ERROR) { // all-1
		DEBUG_PRINTF("all-1\n");
		if (empty_all_1(tail, rx_conn)) {
			discard_fragment(rx_conn); // remove last fragment (empty)
		}
		rx_conn->RX_STATE = WAIT_END;
		send_ack(rx_conn);
	}
	return 0;
}

/**
 * the receiver state machine
 *
 * @param 	conn		a pointer to the connection
 *
 * @return 	0			TBD
 *
 */
int8_t schc_reassemble(schc_fragmentation_t* rx_conn) {
	schc_mbuf_t* tail = get_mbuf_tail(rx_conn->head); // get last received fragment

	if (!tail) {
		// e.g. called without calling schc_input first
		DEBUG_PRINTF("connection %p contains no fragments\n", (void *)rx_conn);
		return 1;
	}

	copy_bits(rx_conn->ack.rule_id, 0, tail->ptr, 0, rx_conn->device->profile->RULE_ID_SIZE); // get the rule id from the fragment
	/* extract header information from last fragment */
	uint8_t window = get_window_bit(tail->ptr, rx_conn);
	uint8_t fcn = get_fcn_value(tail->ptr, rx_conn);

	rx_conn->fcn = fcn;
	rx_conn->ack.fcn = fcn;

	if(rx_conn->fragmentation_rule->mode == NO_ACK) { 
		rx_conn->frag_cnt++; /* can not retrieve fragment count from fcn value */
	} else {
		rx_conn->frag_cnt = get_frag_cnt(rx_conn, fcn, window);
	}

	tail->frag_cnt = rx_conn->frag_cnt; // update tail frag count

	DEBUG_PRINTF("schc_reassemble(): Received FCN=%d, W=%d (connection W=%d), count=%d\n", fcn, window, rx_conn->window, rx_conn->frag_cnt);
	
	if(rx_conn->input) { // set inactivity timer if the loop was triggered by a fragment input
		if(rx_conn->remove_timer_entry != NULL) {
			rx_conn->remove_timer_entry(rx_conn); // remove previously set inactivity timer
			set_inactivity_timer(rx_conn);
		} else {
			discard_fragment(rx_conn);
			return 1;
		}
	}
	if(tail->len == get_sender_abort_size(rx_conn)) { /* received sender-abort */
		rx_conn->RX_STATE = ABORT;
		rx_conn->input = 0; /* no input from rx connection, just re-enter reassmebly state machine */
		DEBUG_PRINTF("schc_reassemble(): Received Sender-Abort; cleaning up\n");
	}

	/*
	 * ACK ALWAYS MODE
	 */
	if (rx_conn->fragmentation_rule->mode == ACK_ALWAYS) {
		switch (rx_conn->RX_STATE) {
		case RECV_WINDOW: {
			DEBUG_PRINTF("schc_reassemble(): (Ack-Always) state=RECV WINDOW\n");
			if (rx_conn->timer_flag && !rx_conn->input) { /* inactivity timer expired */
				abort_connection(rx_conn); // todo
				break;
			}
			if (rx_conn->window != window) {
				DEBUG_PRINTF("schc_reassemble(): (Ack-Always) Unexpected window; discarding fragment\n");
				discard_fragment(rx_conn);
				rx_conn->RX_STATE = RECV_WINDOW;
				break;
			} else if (window == rx_conn->window) {
				DEBUG_PRINTF("schc_reassemble(): (Ack-Always) Expected window; ");
				if (fcn != 0 && fcn != get_max_fcn_value(rx_conn)) { // not all-x
					DEBUG_PRINTF("not all-x\n");
					set_local_bitmap(rx_conn);
					rx_conn->RX_STATE = RECV_WINDOW;
				} else if (fcn == 0) { // all-0
					DEBUG_PRINTF("all-0\n");
					set_local_bitmap(rx_conn); // indicate that we received a fragment
					rx_conn->RX_STATE = WAIT_NEXT_WINDOW;
					rx_conn->ack.mic = 0; // bitmap will be sent when c = 0
					send_ack(rx_conn); // send local bitmap
				} else if (fcn == get_max_fcn_value(rx_conn)) { // all-1
					DEBUG_PRINTF("all-1\n");
					set_local_bitmap(rx_conn);
					if(!rcs_correct(rx_conn)) {
						rx_conn->RX_STATE = WAIT_END;
						rx_conn->ack.mic = 0;
						send_ack(rx_conn);
					} else {
						rx_conn->RX_STATE = END_RX;
						rx_conn->ack.fcn = get_max_fcn_value(rx_conn); // c bit is set when ack.fcn is max
						rx_conn->ack.mic = 1; // bitmap is not sent when mic correct
						send_ack(rx_conn);
						return 2; // stay alive to answer lost acks
					}
				}
			}
			break;
		}
		case WAIT_NEXT_WINDOW: {
			DEBUG_PRINTF("schc_reassemble(): (Ack-Always) state=WAIT NEXT WINDOW\n");
			if (rx_conn->timer_flag && !rx_conn->input) { /* inactivity timer expired */
				abort_connection(rx_conn); // todo
				break;
			}
			if (window == (rx_conn->window + 1)) { /* move to next window */
				DEBUG_PRINTF("schc_reassemble(): (Ack-Always) Expected window; ");
				if (fcn != 0 && fcn != get_max_fcn_value(rx_conn)) { // not all-x
					DEBUG_PRINTF("not all-x\n");
					rx_conn->window++; // set expected window to next window
					clear_bitmap(rx_conn);
					set_local_bitmap(rx_conn);
					rx_conn->RX_STATE = RECV_WINDOW;
				} else if (fcn == 0) { // all-0
					DEBUG_PRINTF("all-0\n");
					rx_conn->window++;
					clear_bitmap(rx_conn);
					set_local_bitmap(rx_conn);
					rx_conn->ack.mic = 0; // bitmap will be sent when c = 0
					send_ack(rx_conn);
					rx_conn->RX_STATE = WAIT_NEXT_WINDOW;
				} else if (fcn == get_max_fcn_value(rx_conn)) { // all-1
					DEBUG_PRINTF("all-1\n");
					if(!rcs_correct(rx_conn)) { // mic wrong
						rx_conn->RX_STATE = WAIT_END;
						rx_conn->ack.mic = 0;
					} else { // mic right
						rx_conn->RX_STATE = END_RX;
						rx_conn->ack.fcn = get_max_fcn_value(rx_conn); // c bit is set when ack.fcn is max
						rx_conn->ack.mic = 1; // bitmap is not sent when mic correct
						send_ack(rx_conn);
						rx_conn->input = 0;
					}
					set_local_bitmap(rx_conn);
					send_ack(rx_conn);
				}
			} else if (window == rx_conn->window) { // expected window
				DEBUG_PRINTF("w == window\n");
				if (fcn == 0) { // all-0
					DEBUG_PRINTF("all-0\n");
					rx_conn->RX_STATE = WAIT_NEXT_WINDOW;
					rx_conn->ack.mic = 0; // bitmap will be sent when c = 0
					send_ack(rx_conn);
				} else if (fcn == get_max_fcn_value(rx_conn)) { // all-1
					DEBUG_PRINTF("all-1\n");
					rx_conn->RX_STATE = WAIT_NEXT_WINDOW;
					discard_fragment(rx_conn);
				} else if (fcn != 0 && fcn != get_max_fcn_value(rx_conn)) { // not all-x
					set_local_bitmap(rx_conn);
					DEBUG_PRINTF("not all-x, is bitmap full? %d\n",
							is_bitmap_full(rx_conn, (rx_conn->fragmentation_rule->MAX_WND_FCN + 1)));
					rx_conn->RX_STATE = WAIT_NEXT_WINDOW;
					if (is_bitmap_full(rx_conn, (rx_conn->fragmentation_rule->MAX_WND_FCN + 1))) { // bitmap is full; the last fragment of a retransmission is received
						rx_conn->ack.mic = 0; // bitmap will be sent when c = 0
						send_ack(rx_conn);
						rx_conn->input = 0;
					}
				}
			}
			break;
		}
		case WAIT_END: {
			uint8_t ret = wait_end(rx_conn, tail);
			if(ret) {
				return ret;
			}
			break;
		}
		case END_RX: {
			DEBUG_PRINTF("schc_reassemble(): (Ack-Always) state=END RX; ");
			if (rx_conn->timer_flag && !rx_conn->input) { // inactivity timer expired
				// end the transmission
				mbuf_sort(&rx_conn->head); // sort the mbuf chain
				rx_conn->end_rx(rx_conn); // forward to ipv6 network
				schc_reset(rx_conn);
				schc_free_connection(rx_conn);
				return 1; // end reception
			}
			if (fcn != get_max_fcn_value(rx_conn)) { // not all-1
				DEBUG_PRINTF("not all-x\n");
				discard_fragment(rx_conn);
			} else { // all-1
				DEBUG_PRINTF("all-1\n");
				send_ack(rx_conn);
				mbuf_sort(&rx_conn->head); // sort the mbuf chain
				rx_conn->input = 0;
				return 1; // end reception
			}
			break;
		}
		case WAIT_MISSING_FRAG:
			break;
		case ABORT:
			schc_reset(rx_conn);
			schc_free_connection(rx_conn);
			break;
		}
		
		rx_conn->input = 0; /* always reset input flag to capture timers */
	}
	/*
	 * NO ACK MODE
	 */
	else if (rx_conn->fragmentation_rule->mode == NO_ACK) {
		switch (rx_conn->RX_STATE) {
		case RECV_WINDOW: {
			DEBUG_PRINTF("schc_reassemble(): (No-Ack) state=RECV WINDOW\n");
			if (rx_conn->timer_flag && !rx_conn->input) { // inactivity timer expired
				rx_conn->RX_STATE = ABORT;
				break;
			}
			if (fcn == get_max_fcn_value(rx_conn)) {
				/* received final fragment */
				rx_conn->timer_flag = 0; /* clear inactivity timer */
				DEBUG_PRINTF("schc_reassemble(): (No-Ack) received All-1 fragment\n");
				if(!rcs_correct(rx_conn)) {
					rx_conn->RX_STATE = ABORT;
					rx_conn->input = 0; /* no input from rx connection, just re-enter reassmebly state machine */
					break;
				} else {
					rx_conn->RX_STATE = END_RX;
					rx_conn->ack.fcn = get_max_fcn_value(rx_conn); /* c bit is set when ack.fcn is max */
					rx_conn->ack.mic = 1; /* bitmap is not sent when mic correct */
					rx_conn->input = 0; /* no input from rx connection, just re-enter reassmebly state machine */
					return 1;
				}
			}
			break;
		}
		case END_RX: {
			DEBUG_PRINTF("schc_reassemble(): (No-Ack) state=END RX\n"); // end the transmission
			mbuf_sort(&rx_conn->head); // sort the mbuf chain
			rx_conn->end_rx(rx_conn); // forward to ipv6 network
			schc_reset(rx_conn);
			schc_free_connection(rx_conn);
			return 1; // end reception
		}

		case WAIT_NEXT_WINDOW:
		case WAIT_MISSING_FRAG:
		case WAIT_END:
			break;
		case ABORT:
			schc_reset(rx_conn);
			schc_free_connection(rx_conn);
			break;
		}
	}
	/*
	 * ACK ON ERROR MODE
	 */
	else if (rx_conn->fragmentation_rule->mode == ACK_ON_ERROR) {
		switch (rx_conn->RX_STATE) {
		case RECV_WINDOW: {
			DEBUG_PRINTF("RECV WINDOW\n");
			if (rx_conn->timer_flag && !rx_conn->input) { // inactivity timer expired
				abort_connection(rx_conn); // todo
				break;
			}
			if (rx_conn->window != window) { // unexpected window
				DEBUG_PRINTF("Unexpected window\n");
				discard_fragment(rx_conn);
				rx_conn->RX_STATE = ERR;
				break;
			} else if (window == rx_conn->window) { // expected window
				DEBUG_PRINTF("Expected window\n");
				if (fcn != 0 && fcn != get_max_fcn_value(rx_conn)) { // not all-x
					DEBUG_PRINTF("not all-x\n");
					set_local_bitmap(rx_conn);
					rx_conn->RX_STATE = RECV_WINDOW;
				} else if (fcn == 0) { // all-0
					DEBUG_PRINTF("all-0\n");
					if(empty_all_0(tail, rx_conn)) {
						send_ack(rx_conn);
						break;
					}
					set_local_bitmap(rx_conn);
					if(is_bitmap_full(rx_conn, (rx_conn->fragmentation_rule->MAX_WND_FCN + 1))) {
						clear_bitmap(rx_conn);
						rx_conn->window++;
						rx_conn->RX_STATE = RECV_WINDOW;
						break;
					} else {
						rx_conn->RX_STATE = WAIT_MISSING_FRAG;
						send_ack(rx_conn);
						break;
					}
				} else if (fcn == get_max_fcn_value(rx_conn)) { // all-1
					if (!empty_all_1(tail, rx_conn)) {
						DEBUG_PRINTF("all-1\n");
						set_local_bitmap(rx_conn);
						if (!rcs_correct(rx_conn)) { // mic wrong
							rx_conn->RX_STATE = WAIT_END;
							rx_conn->ack.mic = 0;
						} else { // mic right
							rx_conn->RX_STATE = END_RX;
							rx_conn->ack.fcn = get_max_fcn_value(rx_conn); // c bit is set when ack.fcn is max
							rx_conn->ack.mic = 1; // bitmap is not sent when mic correct
							send_ack(rx_conn);
							rx_conn->input = 0;
							return 2; // stay alive to answer lost acks
						}
					} else {
						discard_fragment(rx_conn);
					}
					send_ack(rx_conn);
				}
			}
			break;
		}
		case WAIT_MISSING_FRAG: {
			DEBUG_PRINTF("WAIT MISSING FRAGMENTS\n");
			if (window == rx_conn->window) { // expected window
				DEBUG_PRINTF("Expected window\n");
				if (fcn != 0 && fcn != get_max_fcn_value(rx_conn)) {
					set_local_bitmap(rx_conn);
					if(is_bitmap_full(rx_conn, (rx_conn->fragmentation_rule->MAX_WND_FCN + 1))) { // not all-x and bitmap full
						clear_bitmap(rx_conn);
						rx_conn->window++;
						rx_conn->RX_STATE = RECV_WINDOW;
					}
				}
				if (empty_all_0(tail, rx_conn)) {
					rx_conn->RX_STATE = WAIT_MISSING_FRAG;
					send_ack(rx_conn);
					break;
				}
				if (fcn == get_max_fcn_value(rx_conn)) { // all-1
					abort_connection(rx_conn);
					break;
				}
			}
			break;
		}
		case WAIT_END: {
			uint8_t ret = wait_end(rx_conn, tail);
			if(ret) {
				return ret;
			}
			break;
		}
		case END_RX: {
			DEBUG_PRINTF("END RX\n");
			// end the transmission
			mbuf_sort(&rx_conn->head); // sort the mbuf chain
			rx_conn->end_rx(rx_conn); // forward to ipv6 network
			schc_reset(rx_conn);
			schc_free_connection(rx_conn);
			return 1; // end reception
		}

		case WAIT_NEXT_WINDOW:
			break;
		case ABORT:
			schc_reset(rx_conn);
			schc_free_connection(rx_conn);
			break;
		}
	}

	return 0;
}

/**
 * Initializes the SCHC fragmenter
 *
 * @param tx_conn				a pointer to the tx initialization structure
 *
 * @return error codes on error
 *
 */
int8_t schc_fragmenter_init(struct schc_fragmentation_t* cb_conn) {
	uint32_t i;

#if DYNAMIC_MEMORY
	schc_rx_conns = NULL;
	schc_tx_conns = NULL;
#else
	// clear the schc rx connections
	for (i = 0; i < SCHC_CONF_RX_CONNS; i++) {
		schc_reset(&schc_rx_conns[i]);
		schc_rx_conns[i].frag_cnt = 0;
		schc_rx_conns[i].window = 0;
		schc_rx_conns[i].input = 0;
		schc_rx_conns[i].dtag = -1;
		schc_rx_conns[i].fragmentation_rule = NULL;
	}
	for(i = 0; i < SCHC_CONF_TX_CONNS; i++) {
		// clear the schc tx connections
		schc_reset(&schc_tx_conns[i]);
	}
#endif

#if !DYNAMIC_MEMORY
	// initializes the mbuf pool
	for(i = 0; i < SCHC_CONF_MBUF_POOL_LEN; i++) {
		MBUF_POOL[i].ptr = NULL;
		MBUF_POOL[i].len = 0;
		MBUF_POOL[i].next = NULL;
		MBUF_POOL[i].offset = 0;
	}
#endif

	default_conn.send = cb_conn->send;
	default_conn.end_rx = cb_conn->end_rx;
	default_conn.remove_timer_entry = cb_conn->remove_timer_entry;
#if DYNAMIC_MEMORY
	default_conn.free_conn_cb = cb_conn->free_conn_cb;
#endif

	return 1;
}

/**
 * this function can be called to change the tile size of a connection
 * note that only the tile size of the No-Ack and Ack-Always reliability mode
 * can be changed in the midst of a transmission.
 *
 * @param 	conn		a pointer to the connection structure
 * @param 	tile_size  	the desired tile size
 * 
 * @return  0 			on success
 * 			error codes otherwise
 *
 */
int8_t schc_set_tile_size(schc_fragmentation_t* conn, uint16_t tile_size) {
	if(conn->fragmentation_rule == NULL) {
		return SCHC_FAILURE;
	}
	if(conn->fragmentation_rule->mode != ACK_ON_ERROR || conn->TX_STATE == SEND) {
		conn->tile_size = tile_size;
		DEBUG_PRINTF("schc_set_tile_size(): changed tile size to %d\n", conn->tile_size);
		return SCHC_SUCCESS;
	} else {
		DEBUG_PRINTF("schc_set_tile_size(): cannot change the tile size in Ack-On-Error reliability mode or non-SEND states\n");
		return SCHC_FAILURE;
	}
}

/**
 * the function to call when the state machine is in SEND state
 *
 * @param 	tx_conn		a pointer to the tx connection structure
 *
 */
static void tx_fragment_send(schc_fragmentation_t *tx_conn) {
	uint8_t fcn = 0;
	tx_conn->frag_cnt++;
	tx_conn->attempts = 0; // reset number of attempts

	if (has_no_more_fragments(tx_conn)) {
		DEBUG_PRINTF("schc_fragment(): all-1 window\n");
		fcn = tx_conn->fcn;
		tx_conn->fcn = (pow(2, tx_conn->fragmentation_rule->FCN_SIZE) - 1); // all 1-window
		if (send_fragment(tx_conn, false)) { // only continue when packet was transmitted
			tx_conn->TX_STATE = WAIT_BITMAP;
			set_local_bitmap(tx_conn); // set bitmap according to fcn
			set_retrans_timer(tx_conn);
		} else {
			DEBUG_PRINTF("schc_fragment(): radio occupied retrying in %d ms\n",
					(int) tx_conn->dc);
			tx_conn->frag_cnt--;
			tx_conn->fcn = fcn; // reset fcn and frag_count before retrying
			set_dc_timer(tx_conn);
		}
	} else if (tx_conn->fcn == 0 && !has_no_more_fragments(tx_conn)) { // all-0 window
		DEBUG_PRINTF("schc_fragment(): all-0 window\n");
		if (send_fragment(tx_conn, false)) {
			tx_conn->TX_STATE = WAIT_BITMAP;
			set_local_bitmap(tx_conn); // set bitmap according to fcn
			tx_conn->fcn = tx_conn->fragmentation_rule->MAX_WND_FCN; // reset the FCN
			set_retrans_timer(tx_conn);
		} else {
			DEBUG_PRINTF("schc_fragment(): radio occupied retrying in %d ms\n",
					(int) tx_conn->dc);
			tx_conn->frag_cnt--;
			set_dc_timer(tx_conn);
		}
	} else if (tx_conn->fcn != 0 && !has_no_more_fragments(tx_conn)) { // normal fragment
		DEBUG_PRINTF("schc_fragment(): normal fragment\n");
		if (send_fragment(tx_conn, false)) {
			tx_conn->TX_STATE = SEND;
			set_local_bitmap(tx_conn); // set bitmap according to fcn
			tx_conn->fcn--;
		} else {
			tx_conn->frag_cnt--;
		}
		set_dc_timer(tx_conn);
	}
}

/**
 * the function to call when the state machine is in RESEND state
 *
 * @param 	tx_conn		a pointer to the tx connection structure
 *
 */
static void tx_fragment_resend(schc_fragmentation_t *tx_conn) {
	// get the next fragment offset; set frag_cnt
	uint8_t frag_cnt = tx_conn->frag_cnt;
	uint8_t last = 0;

	if (get_next_fragment_from_bitmap(tx_conn) == get_max_fcn_value(tx_conn)) {
		tx_conn->frag_cnt = tx_conn->total_fragments;
		tx_conn->fcn = get_max_fcn_value(tx_conn);
		last = 1;
	} else {
		tx_conn->frag_cnt = (((tx_conn->fragmentation_rule->MAX_WND_FCN + 1) * tx_conn->window)
				+ get_next_fragment_from_bitmap(tx_conn)); // send_fragment() uses frag_cnt to transmit a particular fragment
		tx_conn->fcn = ((tx_conn->fragmentation_rule->MAX_WND_FCN + 1) * (tx_conn->window + 1))
				- tx_conn->frag_cnt;
		if (!get_next_fragment_from_bitmap(tx_conn)) {
			last = 1;
		}
	}

	DEBUG_PRINTF("schc_fragment(): sending missing fragments for bitmap: ");
	print_bitmap(tx_conn->ack.bitmap, (tx_conn->fragmentation_rule->MAX_WND_FCN + 1));
	DEBUG_PRINTF("schc_fragment(): FCN=%d, window=%d, fragment counter=%d\n", tx_conn->fcn,
			tx_conn->window, tx_conn->frag_cnt);

	if (last) { // check if this was the last fragment
		DEBUG_PRINTF("schc_fragment(): last missing fragment to send\n");
		if (send_fragment(tx_conn, true)) { // retransmit the fragment
			tx_conn->TX_STATE = WAIT_BITMAP;
			tx_conn->frag_cnt = (tx_conn->window + 1)
					* (tx_conn->fragmentation_rule->MAX_WND_FCN + 1);
			set_retrans_timer(tx_conn);
		} else {
			tx_conn->frag_cnt = frag_cnt;
			set_dc_timer(tx_conn);
		}

	} else {
		if (send_fragment(tx_conn, true)) { // retransmit the fragment
			tx_conn->TX_STATE = RESEND;
		} else {
			tx_conn->frag_cnt = frag_cnt;
		}
		set_dc_timer(tx_conn);
	}
}

/**
 * the function to call when the state machine has to continue transmission
 *
 * @param 	tx_conn		a pointer to the tx connection structure
 *
 */
static void no_missing_fragments_more_to_come(schc_fragmentation_t *tx_conn) {
	tx_conn->timer_flag = 0; // stop retransmission timer
	clear_bitmap(tx_conn);
	tx_conn->window++; // change window
	tx_conn->fcn = tx_conn->fragmentation_rule->MAX_WND_FCN;
	tx_conn->frag_cnt = (tx_conn->window) * (tx_conn->fragmentation_rule->MAX_WND_FCN + 1);
	tx_conn->TX_STATE = SEND;
}

/**
 * the sender state machine
 *
 * @param 	tx_conn		a pointer to the tx connection structure
 *
 * @return 	 0			TBD
 *        	-1			failed to initialize the connection
 *        	-2			no fragmentation was needed for this packet
 *
 */
int8_t schc_fragment(schc_fragmentation_t *tx_conn) {
	if (tx_conn->TX_STATE == INIT_TX) {
		DEBUG_PRINTF("schc_fragment(): state=INIT_TX\n");
		int8_t ret = init_tx_connection(tx_conn);
		if (!ret) {
			return SCHC_FAILURE;
		} else if (ret < 0) {
			tx_conn->send(tx_conn->bit_arr->ptr, tx_conn->bit_arr->len,
					tx_conn->device_id); // send packet right away
			return SCHC_NO_FRAGMENTATION;
		}
		tx_conn->TX_STATE = SEND;
		schc_fragment(tx_conn);
		return SCHC_SUCCESS;
	}

	/*
	 * ACK ALWAYS MODE
	 */
	if (tx_conn->fragmentation_rule->mode == ACK_ALWAYS) {
		switch (tx_conn->TX_STATE) {
		case SEND: {
			DEBUG_PRINTF("schc_fragment(): (Ack-Always) state=SEND\n");
			tx_fragment_send(tx_conn);
			break;
		}
		case WAIT_BITMAP: {
			DEBUG_PRINTF("schc_fragment(): (Ack-Always) state=WAIT_BITMAP\n");
			uint8_t resend_window[BITMAP_SIZE_BYTES] = { 0 }; // if ack.bitmap is all-0, there are no packets to retransmit

			if (tx_conn->attempts >= MAX_ACK_REQUESTS) {
				DEBUG_PRINTF(
						"schc_fragment(): (Ack-Always) tx_conn->attempts >= MAX_ACK_REQUESTS: send abort\n"); // todo
				tx_conn->TX_STATE = ERR;
				tx_conn->timer_flag = 0; // stop retransmission timer
				schc_send_abort(tx_conn);
				schc_fragment(tx_conn);
				break;
			}
			if (tx_conn->ack.window[0] != tx_conn->window) {
				DEBUG_PRINTF("schc_fragment(): (Ack-Always) Unexpected window; discard fragment\n");
				discard_fragment(tx_conn);
				tx_conn->TX_STATE = WAIT_BITMAP;
				break;
			}
			if (tx_conn->ack.window[0] == tx_conn->window) {
				DEBUG_PRINTF("schc_fragment(): (Ack-Always) Expected window; ");
				if (!has_no_more_fragments(tx_conn)
						&& compare_bits(resend_window, tx_conn->ack.bitmap,
								(tx_conn->fragmentation_rule->MAX_WND_FCN + 1))) {
					DEBUG_PRINTF("bitmap reports no missing fragments - enter next window\n");
					no_missing_fragments_more_to_come(tx_conn);
					schc_fragment(tx_conn);
				}
				if (!compare_bits(resend_window, tx_conn->ack.bitmap,
						(tx_conn->fragmentation_rule->MAX_WND_FCN + 1))) {
					DEBUG_PRINTF("bitmap contains the missing fragments - enter retransmission phase\n");
					tx_conn->attempts++;
					tx_conn->frag_cnt = (tx_conn->window) * (tx_conn->fragmentation_rule->MAX_WND_FCN + 1);
					tx_conn->timer_flag = 0; // stop retransmission timer
					tx_conn->TX_STATE = RESEND;
					schc_fragment(tx_conn);
					break;
				}
				if (has_no_more_fragments(tx_conn)) {
					if(tx_conn->ack.mic) {
						DEBUG_PRINTF("ack reports RCS succeeded - end transmission\n");
						tx_conn->TX_STATE = END_TX;
					} else {
						DEBUG_PRINTF("ack reports RCS check failed - send abort\n");
						tx_conn->TX_STATE = ERR;
						schc_send_abort(tx_conn);
					}
					tx_conn->timer_flag = 0; // stop retransmission timer
					schc_fragment(tx_conn);
					break;
				}
			}
			if (tx_conn->timer_flag) { // timer expired
				DEBUG_PRINTF("timer expired\n"); // todo
				if (send_empty(tx_conn)) { // requests retransmission of all-x ack with empty all-x
					tx_conn->attempts++;
					set_retrans_timer(tx_conn);
				} else {
					set_dc_timer(tx_conn);
				}
				break;
			}
			break;
		}
		case RESEND: {
			DEBUG_PRINTF("schc_fragment(): (Ack-Always) state=RESEND\n");
			tx_fragment_resend(tx_conn);
			break;
		}
		case ERR: {
			DEBUG_PRINTF("ERROR\n");
			break;
		}
		case INIT_TX:
			break;
		case END_TX:
			tx_conn->timer_flag = 0;
			tx_conn->end_tx(tx_conn);
			return SCHC_END;
		}
	}
	/*
	 * NO ACK MODE
	 */
	else if (tx_conn->fragmentation_rule->mode == NO_ACK) {
		switch (tx_conn->TX_STATE) {
		case SEND: {
			DEBUG_PRINTF("SEND\n");
			tx_conn->frag_cnt++;

			if (has_no_more_fragments(tx_conn)) { // last fragment
				DEBUG_PRINTF("last fragment\n");
				tx_conn->fcn = get_max_fcn_value(tx_conn);
				tx_conn->TX_STATE = END_TX;
			} else {
				DEBUG_PRINTF("normal fragment\n");
				tx_conn->fcn = 0;
				tx_conn->TX_STATE = SEND;
			}
			if (!send_fragment(tx_conn, false)) { // only continue when packet was transmitted
				DEBUG_PRINTF(
						"schc_fragment(): radio occupied retrying in %d ms\n",
						(int) tx_conn->dc);
				tx_conn->frag_cnt--;
			}
			set_dc_timer(tx_conn); // send next fragment in dc ms or end transmission
			break;
		}
		case END_TX: {
			DEBUG_PRINTF("schc_fragment(): end transmission cycle\n");
			tx_conn->end_tx(tx_conn);
			return SCHC_END;
			break;
		}

		case INIT_TX:
		case RESEND:
		case WAIT_BITMAP:
		case ERR:
			// not handled this time
			break;
		}
	}
	/*
	 * ACK ON ERROR MODE
	 */
	else if (tx_conn->fragmentation_rule->mode == ACK_ON_ERROR) {
		switch (tx_conn->TX_STATE) {
		case SEND: {
			DEBUG_PRINTF("SEND\n");
			tx_fragment_send(tx_conn);
			break;
		}
		case WAIT_BITMAP: {
			DEBUG_PRINTF("WAIT_BITMAP\n");
			uint8_t resend_window[BITMAP_SIZE_BYTES] = { 0 }; // if ack.bitmap is all-0, there are no packets to retransmit

			if (tx_conn->attempts >= MAX_ACK_REQUESTS) {
				DEBUG_PRINTF(
						"tx_conn->attempts >= MAX_ACK_REQUESTS: send abort\n"); // todo
				tx_conn->TX_STATE = ERR;
				tx_conn->timer_flag = 0; // stop retransmission timer
				// send_abort();
				schc_fragment(tx_conn);
				break;
			}
			if (tx_conn->timer_flag && !tx_conn->input) { // timer expired
				DEBUG_PRINTF("timer expired\n"); // todo

				if (!has_no_more_fragments(tx_conn)) { // more fragments to come
					no_missing_fragments_more_to_come(tx_conn);
					schc_fragment(tx_conn);
				} else if (has_no_more_fragments(tx_conn)) {
					tx_conn->timer_flag = 0; // stop retransmission timer
					send_tx_empty(tx_conn); // todo
					tx_conn->TX_STATE = WAIT_BITMAP;
					set_dc_timer(tx_conn);
				}
				break;
			}
			if (tx_conn->ack.window[0] != tx_conn->window) { // unexpected window
				DEBUG_PRINTF("w != w, discard fragment\n");
				discard_fragment(tx_conn);
				tx_conn->TX_STATE = WAIT_BITMAP;
				break;
			}
			if (!compare_bits(resend_window, tx_conn->ack.bitmap,
					(tx_conn->fragmentation_rule->MAX_WND_FCN + 1))) { //ack.bitmap contains the missing fragments
				DEBUG_PRINTF("bitmap contains the missing fragments\n");
				tx_conn->attempts++;
				tx_conn->frag_cnt = (tx_conn->window)
						* (tx_conn->fragmentation_rule->MAX_WND_FCN + 1);
				tx_conn->timer_flag = 0; // stop retransmission timer
				tx_conn->TX_STATE = RESEND;
				schc_fragment(tx_conn);
				break;
			} else if (compare_bits(resend_window, tx_conn->ack.bitmap,
					(tx_conn->fragmentation_rule->MAX_WND_FCN + 1))) {
				DEBUG_PRINTF("received bitmap == local bitmap, ");
				if(!tx_conn->ack.mic) {
					DEBUG_PRINTF("MIC check failed; send abort\n");
					tx_conn->TX_STATE = ERR;
					// send_abort();
				}
				else {
					DEBUG_PRINTF("MIC check ok\n");
					tx_conn->TX_STATE = END_TX;
				}
				tx_conn->timer_flag = 0; // stop retransmission timer
				schc_fragment(tx_conn); // end
				break;
			}
			case RESEND:
			{
				DEBUG_PRINTF("RESEND\n");
				tx_fragment_resend(tx_conn);
				break;
			}
		}

		case INIT_TX:
		case ERR:
			break;
		case END_TX:
			tx_conn->timer_flag = 0;
			tx_conn->end_tx(tx_conn);
			return SCHC_END;
		}
	}

	tx_conn->input = 0;

	return 0;
}

/**
 * This function should be called whenever a packet is received
 *
 * @param 	data			a pointer to the received data
 * @param 	len				the length of the received packet
 * @param 	device			the device that received the data
 * 
 * @return  conn 			either a pointer to the receiving connection or the 
 * 							transmitting connection. If the returned value is the 
 * 							same as the passed connection; an acknowledgement was received.
 *
 */
schc_fragmentation_t* schc_input(uint8_t* data, uint16_t len, struct schc_device* device) {
	if (device == NULL) {
		DEBUG_PRINTF("schc_input(): no device given \n");
		return NULL;
	}

	uint8_t dtag = get_dtag_value(data, device);
	schc_fragmentation_t* tx_conn = schc_get_tx_connection(device, dtag);

	if(tx_conn) {
		schc_ack_input(data, tx_conn);
		return NULL;
	} else {
		schc_fragmentation_t* rx_conn = schc_fragment_input((uint8_t*) data, len, device);
		return rx_conn;
	}

	// if ((tx_conn->TX_STATE == WAIT_BITMAP || tx_conn->TX_STATE == RESEND)
	// 		&& compare_bits(tx_conn->rule_id, data, tx_conn->device->profile->RULE_ID_SIZE)) { // acknowledgment
	// 	/* tx connection is passed as argument */
	// 	schc_ack_input(data, tx_conn);
	// 	return NULL;
	// } else {
	// 	schc_fragmentation_t* rx_conn = schc_fragment_input((uint8_t*) data, len, tx_conn, device);
	// 	return rx_conn;

		/* all logic regarding the processing of acks and fragments should be in the state machine */
		// if(!rx_conn) {
		// 	return NULL;
		// } else {
		// 	if( (rx_conn->fragmentation_rule->mode == ACK_ON_ERROR && rx_conn->fragmentation_rule->tile_size != len)) { 
		// 		/* ACK on Error always uses same tile size */
		// 		schc_ack_input(data, tx_conn);
		// 		/* delete the ack from the connetion mbuf chain */
		// 		schc_mbuf_t* tail = get_mbuf_tail(rx_conn->head);
		// 		mbuf_delete(&rx_conn->head, tail);
		// 		return tx_conn;
		// 	} else {
		// 		return rx_conn;
		// 	}
		// }
	// }
}

/**
 * This function should be called whenever an ack is received
 *
 * @param 	data			a pointer to the received data
 * @param 	tx_conn			a pointer to the tx initialization structure
 *
 */
void schc_ack_input(uint8_t* data, schc_fragmentation_t* tx_conn) {
	uint8_t bit_offset = tx_conn->device->profile->RULE_ID_SIZE;
	tx_conn->input = 1;

	memset(tx_conn->ack.dtag, 0, DTAG_SIZE_BYTES); // clear dtag from prev reception
	copy_bits(tx_conn->ack.dtag, (8 - tx_conn->device->profile->DTAG_SIZE), (uint8_t*) data,
			bit_offset, tx_conn->device->profile->DTAG_SIZE); // get dtag
	bit_offset += tx_conn->device->profile->DTAG_SIZE;

	memset(tx_conn->ack.window, 0, WINDOW_SIZE_BYTES); // clear window from prev reception
	copy_bits(tx_conn->ack.window, (8 - tx_conn->fragmentation_rule->WINDOW_SIZE), (uint8_t*) data,
			bit_offset, tx_conn->fragmentation_rule->WINDOW_SIZE); // get window
	bit_offset += tx_conn->fragmentation_rule->WINDOW_SIZE;

	uint8_t bitmap_len = (tx_conn->fragmentation_rule->MAX_WND_FCN + 1);
	memset(tx_conn->ack.bitmap, 0, BITMAP_SIZE_BYTES); // clear bitmap from prev reception

	if(has_no_more_fragments(tx_conn)) { // all-1 window
		uint8_t mic[1] = { 0 };
		copy_bits(mic, 7, (uint8_t*) data, bit_offset, 1);
		bit_offset += 1;
		tx_conn->ack.mic = mic[0];
		bitmap_len = (BITMAP_SIZE_BYTES * 8);
		if(mic[0]) { // do not process bitmap
			schc_fragment(tx_conn);
			return;
		}
	}

	// ToDo
	// decode_bitmap(tx_conn);
	copy_bits(tx_conn->ack.bitmap, 0, (uint8_t*) data, bit_offset,
			bitmap_len);

	// copy bits for retransmit bitmap to intermediate buffer
	uint8_t resend_window[BITMAP_SIZE_BYTES] = { 0 };

	xor_bits(resend_window, tx_conn->bitmap, tx_conn->ack.bitmap,
			bitmap_len); // to indicate which fragments to retransmit

	// copy retransmit bitmap for current window to ack.bitmap
	memset(tx_conn->ack.bitmap, 0, BITMAP_SIZE_BYTES);
	copy_bits(tx_conn->ack.bitmap, 0, resend_window, 0, bitmap_len);

	// continue with state machine
	schc_fragment(tx_conn);
}


/**
 * This function should be called whenever a fragment is received
 * an open connection is picked for the device
 * out of a pool of connections to keep track of the packet
 *
 * @param 	data			a pointer to the data packet
 * @param 	len				the length of the received packet
 * @param 	device			the device from the rx source
 *
 * @return 	conn			the connection
 *
 */
schc_fragmentation_t* schc_fragment_input(uint8_t* data, uint16_t len, struct schc_device* device) {
	int16_t dtag = SCHC_INIT;

	dtag = get_dtag_value(data, device);

	/* get a connection for the device */
	schc_fragmentation_t* conn = schc_set_rx_connection(device, dtag);

	if(default_conn.send == NULL || default_conn.end_rx == NULL || default_conn.remove_timer_entry == NULL) {
		DEBUG_PRINTF("schc_fragment_input(): default callbacks not set\n");
		return NULL;
	}
	conn->send 					= default_conn.send;
	conn->end_rx 				= default_conn.end_rx;
	conn->remove_timer_entry 	= default_conn.remove_timer_entry;
#if DYNAMIC_MEMORY
	if(default_conn.free_conn_cb == NULL) {
		DEBUG_PRINTF("schc_fragment_input(): default callbacks not set\n");
		return NULL;
	}
	conn->free_conn_cb 			= default_conn.free_conn_cb;
#endif

	conn->fragmentation_rule 	= get_fragmentation_rule_by_rule_id(data, device);

	if (!conn->fragmentation_rule) { /* return if we were unable to retrieve a rule */
		DEBUG_PRINTF("schc_fragment_input(): could not retrieve a fragmentation rule\n");
		return NULL;
	}

	uint8_t* fragment;
#if DYNAMIC_MEMORY
	fragment = (uint8_t*) malloc(len); /* allocate memory for fragment */
#else
	fragment = (uint8_t*) (schc_buf + buf_ptr); /* take fixed memory block */
	buf_ptr += len;
	if(buf_ptr > STATIC_MEMORY_BUFFER_LENGTH) {
		/* todo implement ringbuffer */
		DEBUG_PRINTF("schc_fragment_input(): no more memory available from pre-allocated memory block \n");
		return NULL;
	}
#endif

	memcpy(fragment, data, len);

	int8_t err = mbuf_push(&conn->head, fragment, len);

	mbuf_print(conn->head);

	if(err != SCHC_SUCCESS) {
		schc_free_connection(conn);
		return NULL;
	}

	conn->input = 1; /* set fragment input to 1, to distinguish between inactivity callbacks */

	return conn;
}

#if CLICK
ELEMENT_PROVIDES(schcFRAGMENTER)
ELEMENT_REQUIRES(schcBIT)
#endif
