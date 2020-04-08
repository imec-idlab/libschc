/*
 * (c) 2018 - idlab - UGent - imec
 *
 * Bart Moons
 *
 * This file is part of the SCHC stack implementation
 *
 */

#include <math.h>
#include <string.h>
#include <stdio.h>

#include "schc_config.h"

#include "compressor.h"
#include "fragmenter.h"
#include "schc.h"

uint8_t ATTEMPTS = 0; // for debugging

#if CLICK
#include <click/config.h>
#endif

// keep track of the active connections
struct schc_fragmentation_t schc_rx_conns[SCHC_CONF_RX_CONNS];
static uint8_t FRAGMENTATION_BUF[MAX_MTU_LENGTH] = { 0 };

// keep track of the mbuf's
static uint32_t MBUF_PTR;
static struct schc_mbuf_t MBUF_POOL[SCHC_CONF_MBUF_POOL_LEN];

#if !DYNAMIC_MEMORY
static uint8_t buf_ptr = 0;
uint8_t schc_buf[STATIC_MEMORY_BUFFER_LENGTH] = { 0 };
#endif

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
	uint8_t offset = conn->RULE_SIZE + conn->schc_rule->DTAG_SIZE + conn->schc_rule->WINDOW_SIZE;

	return (uint16_t) get_bits(fragment, offset, conn->schc_rule->FCN_SIZE);
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
	set_bits(fcn, 0, conn->schc_rule->FCN_SIZE);

	return (uint16_t) get_bits(fcn, 0, conn->schc_rule->FCN_SIZE);
}

/**
 * get a bitmap mask for a number of bits
 *
 * @param len			the number of bits to set
 *
 * @return padding		the bitmask
 *
 */
static uint32_t get_bit_mask(uint8_t len) {
	int mask = 0; int i;

	for (i = 0; i < len; i++) {
	    mask = (1 << len) - 1;
	}

	return mask;
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
		// DEBUG_PRINTF("0x%X", curr);
		for (j = 0; j < curr->len; j++) {
			DEBUG_PRINTF("0x%02X ", curr->ptr[j]);
		}
		DEBUG_PRINTF("\n");
		curr = curr->next;
		i++;
	}
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
	uint32_t i;
	for(i = 0; i < SCHC_CONF_MBUF_POOL_LEN; i++) {
		if(MBUF_POOL[i].len == 0 && MBUF_POOL[i].ptr == NULL) {
			break;
		}
	}

	if(i == SCHC_CONF_MBUF_POOL_LEN) {
		DEBUG_PRINTF("mbuf_push(): no free mbuf slots found \n");
		return SCHC_FAILURE;
	}

	DEBUG_PRINTF("mbuf_push(): selected mbuf slot %d \n", i);

	// check if this is a new connection
	if(*head == NULL) {
		*head = &MBUF_POOL[i];
		(*head)->len = len;
		(*head)->ptr = (uint8_t*) (data);
		(*head)->next = NULL;
		(*head)->slot = i;
		return SCHC_SUCCESS;
	}

	MBUF_POOL[i].slot = i;
	MBUF_POOL[i].next = NULL;
	MBUF_POOL[i].len = len;
	MBUF_POOL[i].ptr = (uint8_t*) (data);

	// find the last mbuf in the chain
	schc_mbuf_t *curr = *head;
	while (curr->next != NULL) {
		curr = curr->next;
	}

	// set next in chain
	curr->next = (schc_mbuf_t*) (MBUF_POOL + i);

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
				head, mbuf, curr, curr->next);
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
	uint32_t slot = 0;

	slot = mbuf->slot;
	schc_mbuf_t *prev = NULL;

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

	DEBUG_PRINTF("mbuf_delete(): clear slot %d in mbuf pool \n", slot);
#if DYNAMIC_MEMORY
	free(mbuf->ptr);
#else
	memset(mbuf->ptr, 0, mbuf->len);
#endif

	// clear slot in mbuf pool
	MBUF_POOL[slot].next = NULL;
	MBUF_POOL[slot].frag_cnt = 0;
	MBUF_POOL[slot].len = 0;
	MBUF_POOL[slot].ptr = NULL;
}

/**
 * check if an mbuf with the same fragment number already exists
 * and overwrite if so
 *
 * @param  	head			the head of the list
 * @param  	frag			the fragment number to overwrite
 * @param	mbuf			the fragment to overwrite with
 *
 * @return 	0				no matching fragment found
 * 			1				overwrote a matching packet
 */
static uint8_t mbuf_overwrite(schc_mbuf_t **head, uint16_t frag, schc_mbuf_t* mbuf) {
	schc_mbuf_t *curr = *head;

	while (curr->next != NULL) {
		if(curr->frag_cnt == frag) {
			mbuf_delete(head, curr);
			return 1;
		}
		curr = curr->next;
	}

	return 0;
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
	uint32_t offset = conn->RULE_SIZE + conn->schc_rule->DTAG_SIZE + conn->schc_rule->WINDOW_SIZE
			+ conn->schc_rule->FCN_SIZE;

	uint8_t fcn = get_fcn_value(mbuf->ptr, conn);

	if (fcn == get_max_fcn_value(conn)) {
		offset += (MIC_SIZE_BYTES * 8);
	}

	return offset;
}

/**
 * returns the total length of the mbuf
 *
 * @param  head			the head of the list
 *
 * @return len			the total length of the fragment
 */
uint16_t get_mbuf_len(schc_fragmentation_t *conn) {
	schc_mbuf_t *curr = conn->head; uint32_t total_len = 0; uint32_t total_offset = 0;

	if(conn->schc_rule == NULL)
		return curr->len;

	if(conn->schc_rule->mode == NOT_FRAGMENTED)
		return curr->len;

	while (curr != NULL) {
		total_len += (curr->len * 8);
		total_offset += get_fragmentation_header_length(curr, conn);

		curr = curr->next;
	}

	total_len += conn->RULE_SIZE; // added in front of compressed packet

	return (uint16_t) ( ((total_len - total_offset) + (8 - 1)) / 8 );
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

static uint8_t mbuf_get_byte(schc_mbuf_t *mbuf, schc_fragmentation_t* conn, uint32_t* offset) {
	uint32_t mbuf_bit_len = (mbuf->len * 8);
	uint8_t byte_arr[1] = { 0 };
	uint16_t curr_offset = (*offset) + get_fragmentation_header_length(mbuf, conn);
	uint32_t remaining_offset = mbuf_bit_len - curr_offset;

	if( remaining_offset > 8 ) {
		copy_bits(byte_arr, 0, mbuf->ptr, curr_offset, 8);
		*offset += 8;
	} else if(mbuf->next != NULL) { // copy remainig bits from next mbuf and set offset accordingly
		copy_bits(byte_arr, 0, mbuf->ptr, curr_offset, remaining_offset);
		copy_bits(byte_arr, remaining_offset, mbuf->next->ptr,
				get_fragmentation_header_length(mbuf->next, conn),
				(8 - remaining_offset));
		*offset = (8 - remaining_offset);
	} else { // final byte
		copy_bits(byte_arr, 0, mbuf->ptr, curr_offset, remaining_offset);
		*offset = remaining_offset;
	}

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

	uint8_t index = 0; uint8_t first = 1; uint32_t curr_bit_offset; uint8_t byte;

	if(!conn | conn->schc_rule->mode == NOT_FRAGMENTED) {
		int i;
		for(i = 0; i < curr->len; i++) {
			ptr[i] = curr->ptr[i];
		}
		return;
	}
	while (curr != NULL) {
		byte = 0;
		if ((prev == NULL) && first) { // first byte(s) of compressed packet contain rule id
			copy_bits(ptr, 0, curr->ptr, 0, conn->RULE_SIZE);
			if (conn->RULE_SIZE <= 8) {
				curr_bit_offset = (8 - conn->RULE_SIZE);
				copy_bits(ptr, conn->RULE_SIZE, curr->ptr,
						get_fragmentation_header_length(curr, conn),
						curr_bit_offset);
				first = 0;
			} else {
				// todo non byte alligned rule id ( > 8 bits )
			}
		} else {
			// get next byte from mbuf chain
			uint32_t temp_offset = curr_bit_offset;
			byte = mbuf_get_byte(curr, conn, &curr_bit_offset);
			ptr[index] = byte;
			if (curr_bit_offset < temp_offset) { // partially included bits of next mbuf
				prev = curr;
				curr = curr->next;
			}
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
				schc_mbuf_t **temp;
				temp = *curr;
				*curr = *next;
				*next = temp;

				temp = (*curr)->next;
				(*curr)->next = (*next)->next;
				(*next)->next = temp;

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
static unsigned int mbuf_compute_mic(schc_fragmentation_t *conn) {
	schc_mbuf_t *curr = conn->head;
	schc_mbuf_t *prev = NULL;

	uint32_t crc, crc_mask; int8_t k = 0; uint8_t first = 1; uint8_t do_crc = 1;

	uint8_t byte = 0; uint8_t byte_arr[RULE_SIZE_BYTES] = { 0 }; uint32_t curr_bit_offset = 0;
	crc = 0xFFFFFFFF;

	while(curr != NULL) {
		byte = 0x00; // reset byte (which adds padding, if any)
		if( (prev == NULL) && first) { // first byte(s) of compressed packet contain rule id
			copy_bits(byte_arr, 0, curr->ptr, 0, conn->RULE_SIZE);
			if(conn->RULE_SIZE <= 8 ) {
				curr_bit_offset = (8 - conn->RULE_SIZE);
				copy_bits(byte_arr, conn->RULE_SIZE, curr->ptr,
						get_fragmentation_header_length(curr, conn),
						curr_bit_offset);
				first = 0;
			} else {
				// todo non byte alligned rule id ( > 8 bits )
			}
			byte = byte_arr[0];
		} else {
			// get next byte from mbuf chain
			uint32_t temp_offset = curr_bit_offset;
			byte = mbuf_get_byte(curr, conn, &curr_bit_offset);
			do_crc = 1;
			if(curr_bit_offset < temp_offset) { // partially included bits of next mbuf
				prev = curr;
				curr = curr->next;
				if(byte == 0 && curr == NULL){
					// remove the padding byte from the second last packet (RCS was sent separately)
					do_crc = 0;
				}
			}
		}
		if(do_crc) {
			crc = crc ^ byte;
			for (k = 7; k >= 0; k--) { // do eight times.
				crc_mask = -(crc & 1);
				crc = (crc >> 1) ^ (0xEDB88320 & crc_mask);
			}
			// printf("0x%02X ", byte);
		}
	}
	// printf("\n");

	crc = ~crc;
	uint8_t mic[MIC_SIZE_BYTES] = { ((crc & 0xFF000000) >> 24),
			((crc & 0xFF0000) >> 16), ((crc & 0xFF00) >> 8), ((crc & 0xFF)) };

	memcpy((uint8_t *) conn->mic, mic, MIC_SIZE_BYTES);

	DEBUG_PRINTF("mbuf_compute_mic(): MIC is %02X%02X%02X%02X \n", mic[0], mic[1], mic[2],
			mic[3]);

	return crc;
}


////////////////////////////////////////////////////////////////////////////////////
//                                LOCAL FUNCIONS                                  //
////////////////////////////////////////////////////////////////////////////////////

/**
 * Calculates the Message Integrity Check (MIC)
 * which is the 8- 16- or 32- bit Cyclic Redundancy Check (CRC)
 *
 * @param conn 			pointer to the connection
 *
 * @return checksum 	the computed checksum
 *
 */
static unsigned int compute_mic(schc_fragmentation_t *conn, uint8_t padding) {
	int i, j; uint8_t byte;
	unsigned int crc, mask;

	// ToDo
	// check conn->mic length
	// and calculate appropriate crc

	i = 0;
	crc = 0xFFFFFFFF;

	uint16_t len = conn->bit_arr->len;
	if(padding)
		len++;

	while (i < len) {
		if(padding && ((i + 1) == len) ) { // padding of last tile
			byte = 0x00;
		} else {
			byte = conn->bit_arr->ptr[i];
		}
		crc = crc ^ byte;
		for (j = 7; j >= 0; j--) {    // do eight times.
			mask = -(crc & 1);
			crc = (crc >> 1) ^ (0xEDB88320 & mask);
		}
		i++;
		printf("0x%02X ", byte);
	}
	printf("\n");

	crc = ~crc;
	uint8_t mic[MIC_SIZE_BYTES] = { ((crc & 0xFF000000) >> 24), ((crc & 0xFF0000) >> 16),
			((crc & 0xFF00) >> 8), ((crc & 0xFF)) };

	memcpy((uint8_t *) conn->mic, mic, MIC_SIZE_BYTES);

	DEBUG_PRINTF("compute_mic(): MIC for device %d is %02X%02X%02X%02X \n",
			conn->device_id, mic[0], mic[1], mic[2], mic[3]);

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
	uint8_t offset = conn->RULE_SIZE + conn->schc_rule->DTAG_SIZE;

	return (uint8_t) get_bits(fragment, offset, conn->schc_rule->WINDOW_SIZE);
}

/**
 * get the MIC value
 *
 * @param  fragment		a pointer to the fragment to retrieve the MIC from
 * @param  mic
 *
 */
static void get_received_mic(uint8_t* fragment, uint8_t mic[],
		schc_fragmentation_t* conn) {
	uint8_t offset = conn->RULE_SIZE + conn->schc_rule->DTAG_SIZE
			+ conn->schc_rule->WINDOW_SIZE + conn->schc_rule->FCN_SIZE;

	copy_bits(mic, 0, fragment, offset, (MIC_SIZE_BYTES * 8));
}

/**
 * set the fragmentation counter of the current connection
 * which is the inverse of the fcn value
 *
 * @param  conn			a pointer to the connection
 * @param  frag			the fcn value
 *
 */
static void set_conn_frag_cnt(schc_fragmentation_t* conn, uint8_t frag) {
	uint8_t value = conn->schc_rule->MAX_WND_FCN - frag;
	if(frag == get_max_fcn_value(conn)) {
		value = (conn->window_cnt + 1) * get_max_fcn_value(conn);
	} else {
		value += (conn->window_cnt * (conn->schc_rule->MAX_WND_FCN + 1));
	}

	DEBUG_PRINTF("value is %d frag is %d, window count is %d \n", value, frag, conn->window_cnt);

	conn->frag_cnt = value;
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
	if (!conn->mtu) {
		DEBUG_PRINTF("init_connection(): no mtu specified \n");
		return 0;
	}
	if (conn->mtu > MAX_MTU_LENGTH) {
		DEBUG_PRINTF(
				"init_connection(): conn->mtu cannot exceed MAX_MTU_LENGTH \n");
		return 0;
	}
	if (!conn->bit_arr->len) {
		DEBUG_PRINTF("init_connection(): packet_length not specified \n");
		return 0;
	}
	if(conn->bit_arr->len < conn->mtu) {
		DEBUG_PRINTF("init_connection(): no fragmentation needed \n");
		return -1;
	}
	if (conn->send == NULL) {
		DEBUG_PRINTF("init_connection(): no send function specified \n");
		return 0;
	}
	if (conn->post_timer_task == NULL) {
		DEBUG_PRINTF("init_connection(): no timer function specified \n");
		return 0;
	}
	if(conn->schc_rule == NULL) {
		DEBUG_PRINTF("init_connection(): SCHC rule not specified \n");
		return 0;
	}
	if(!conn->MODE) {
		DEBUG_PRINTF("init_connection(): no reliability mode specified \n");
		return 0;
	}
	if((conn->mtu * 8) < (conn->RULE_SIZE + conn->schc_rule->DTAG_SIZE + conn->schc_rule->WINDOW_SIZE
			+ conn->schc_rule->FCN_SIZE + (MIC_SIZE_BYTES * 8)) ) {
		DEBUG_PRINTF(
				"init_connection(): conn->mtu should be larger than last tile's header length \n");
		return 0;
	}

	conn->tail_ptr = (uint8_t*) (conn->bit_arr->ptr + conn->bit_arr->len); // set end of packet

	conn->window = 0;
	conn->window_cnt = 0;
	conn->frag_cnt = 0;
	conn->attempts = 0;

	if (conn->bit_arr->len > conn->mtu) { // should fragment, change rule
		// select a similar rule based on a reliability mode
		conn->schc_rule = get_schc_rule_by_reliability_mode(
				conn->schc_rule, conn->MODE, conn->device_id);
	} else { // do not fragment
		conn->schc_rule = get_schc_rule_by_reliability_mode(
				conn->schc_rule, NOT_FRAGMENTED, conn->device_id);
	}

	// todo
	// can not select a rule when uncompressed

	if (conn->schc_rule == NULL) {
		DEBUG_PRINTF(
				"init_connection(): no matching rule found for mode specified \n");
		return 0;
	}

	if(conn->schc_rule->MAX_WND_FCN >= get_max_fcn_value(conn)) {
		DEBUG_PRINTF("init_connection(): MAX_WIND_FCN must be smaller than all-1 \n");
		return 0;
	}

	conn->fcn = conn->schc_rule->MAX_WND_FCN;
	memset(conn->bitmap, 0, BITMAP_SIZE_BYTES); // clear bitmap
	set_rule_id(conn->schc_rule, conn->bit_arr->ptr);

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
	conn->device_id = 0;
	conn->tail_ptr = 0;
	conn->dc = 0;
	conn->mtu = 0;
	conn->fcn = 0;
	conn->dtag = 0;
	conn->frag_cnt = 0;
	conn->schc_rule = NULL;
	memset(conn->bitmap, 0, BITMAP_SIZE_BYTES);
	conn->attempts = 0;
	conn->TX_STATE = INIT_TX;
	conn->RX_STATE = RECV_WINDOW;
	conn->window = 0;
	conn->window_cnt = 0;
	conn->timer_flag = 0;
	conn->input = 0;
	memset(conn->mic, 0, MIC_SIZE_BYTES);

	/* reset ack structure */
	memset(conn->ack.rule_id, 0, RULE_SIZE_BYTES);
	memset(conn->ack.bitmap, 0, BITMAP_SIZE_BYTES);
	memset(conn->ack.window, 0, 1);
	memset(conn->ack.dtag, 0, 1);
	conn->ack.mic = 0;
	conn->ack.fcn = 0;

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
	uint32_t total_bits_to_transmit = (BYTES_TO_BITS(conn->bit_arr->len)
			- conn->bit_arr->padding - conn->RULE_SIZE); // effective packet bits
	uint16_t header_size = (conn->RULE_SIZE + conn->schc_rule->DTAG_SIZE
			+ conn->schc_rule->WINDOW_SIZE + conn->schc_rule->FCN_SIZE);
	uint16_t prev_header_bits = header_size * (conn->frag_cnt - 1); // previous fragmentation overhead
	uint32_t total_mtu_bits = BYTES_TO_BITS(conn->mtu)
			* (conn->frag_cnt); // (header + packet) bits already transfered
	uint32_t mtu_bits = BYTES_TO_BITS(conn->mtu);

	if ((total_bits_to_transmit + prev_header_bits) < total_mtu_bits) { // last fragment
		uint16_t mic_included_bits = (total_bits_to_transmit + prev_header_bits)
				+ (header_size + BYTES_TO_BITS(MIC_SIZE_BYTES));
		if (mic_included_bits <= total_mtu_bits) { // return the number of bits transmitted,
			// if the RCS does not create an extra fragment
			uint32_t already_transmitted = ((BYTES_TO_BITS(conn->mtu)
					* (conn->frag_cnt - 1)) - prev_header_bits);
			return already_transmitted;
		}
	}

	return 0;
}

/**
 * set the fragmentation header
 *
 * @param conn 			a pointer to the connection
 * @param buffer		a pointer to the buffer to set the header
 *
 * @return bit_offset	the number of bits added to the front of the fragment
 *
 */
static uint16_t set_fragmentation_header(schc_fragmentation_t* conn,
		uint8_t* fragmentation_buffer) {
	uint8_t bit_offset = conn->RULE_SIZE;

	 // set rule id
	uint8_t src_pos = get_position_in_first_byte(conn->RULE_SIZE);
	copy_bits(fragmentation_buffer, 0, conn->schc_rule->id, src_pos, bit_offset);

	// set dtag field
	uint8_t dtag[1] = { conn->dtag << (8 - conn->schc_rule->DTAG_SIZE) };
	copy_bits(fragmentation_buffer, bit_offset, dtag, 0, conn->schc_rule->DTAG_SIZE); // right after rule id

	bit_offset += conn->schc_rule->DTAG_SIZE;

	// set window bit
	uint8_t window[1] = { conn->window << (8 - conn->schc_rule->WINDOW_SIZE) };
	copy_bits(fragmentation_buffer, bit_offset, window, 0, conn->schc_rule->WINDOW_SIZE); // right after dtag

	bit_offset += conn->schc_rule->WINDOW_SIZE;

	// set fcn value
	uint8_t fcn[1] = { conn->fcn << (8 - conn->schc_rule->FCN_SIZE) };
	copy_bits(fragmentation_buffer, bit_offset, fcn, 0, conn->schc_rule->FCN_SIZE); // right after window bits

	bit_offset += conn->schc_rule->FCN_SIZE;

	uint32_t bits_transmitted = has_no_more_fragments(conn);
	if (bits_transmitted) { // all-1 fragment
		uint32_t total_bits_to_transmit = BYTES_TO_BITS(conn->bit_arr->len)
				- conn->RULE_SIZE - conn->bit_arr->padding; // effective packet bits
		// to use for RCS calculation
		int8_t bits_left_to_transmit = (total_bits_to_transmit
				- bits_transmitted); uint8_t padding = 0;
		if( bits_left_to_transmit < 0) { // RCS in separate packet
			padding = ((bit_offset + (MIC_SIZE_BYTES * 8)) % 8); // RCS padding
		}

		compute_mic(conn, padding); // calculate RCS over compressed, double padded packet

		// shift in RCS
		copy_bits(fragmentation_buffer, bit_offset, conn->mic, 0, (MIC_SIZE_BYTES * 8));
		bit_offset += (MIC_SIZE_BYTES * 8);
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
	int8_t frag = (((conn->schc_rule->MAX_WND_FCN + 1) - conn->fcn) - 1);
	if(frag < 0) {
		frag = conn->schc_rule->MAX_WND_FCN;
	}
	set_bits(conn->bitmap, frag, 1);

	DEBUG_PRINTF("set_local_bitmap(): for fcn %d at index %d \n", conn->fcn, frag);
	print_bitmap(conn->bitmap, conn->schc_rule->MAX_WND_FCN + 1);
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
static void encode_bitmap(schc_fragmentation_t* conn) {
	// ToDo
}

/**
 * reconstruct an encoded bitmap
 *
 * @param conn 			a pointer to the connection
 *
 */
static void decode_bitmap(schc_fragmentation_t* conn) {
	// ToDo
}

/**
 * loop over a bitmap to check if all bits are set to
 * 1, starting from MAX_WIND_FCN
 *
 * @param conn 			a pointer to the connection
 * @param len			the length of the bitmap
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

	uint8_t start = (conn->frag_cnt) - ((conn->schc_rule->MAX_WND_FCN + 1)* conn->window_cnt);
	for (i = start; i <= conn->schc_rule->MAX_WND_FCN; i++) {
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
	DEBUG_PRINTF("discard_fragment(): \n");
	schc_mbuf_t* tail = get_mbuf_tail(conn->head); // get last received fragment
	mbuf_delete(&conn->head, tail);
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
	conn->remove_timer_entry(conn->device_id);
	schc_reset(conn);
	return;
}

/**
 * sets the retransmission timer to re-enter the fragmentation loop
 * and changes the retransmission_timer flag
 *
 * @param conn 			a pointer to the connection
 *
 */
static void set_retrans_timer(schc_fragmentation_t* conn) {
	conn->timer_flag = 1;
	DEBUG_PRINTF("set_retrans_timer(): for %d ms \n", conn->dc * 4);
	conn->post_timer_task(&schc_fragment, conn->device_id, conn->dc * 4, conn);
}

/**
 * sets the duty cycle timer to re-enter the fragmentation loop
 *
 * @param conn 			a pointer to the connection
 *
 */
static void set_dc_timer(schc_fragmentation_t* conn) {
	DEBUG_PRINTF("set_dc_timer(): for %d ms \n", conn->dc);
	conn->post_timer_task(&schc_fragment, conn->device_id, conn->dc, conn);
}

/**
 * sets the inactivity timer to re-enter the fragmentation loop
 * and changes the retransmission_timer flag
 *
 * @param conn 			a pointer to the connection
 *
 */
static void set_inactivity_timer(schc_fragmentation_t* conn) {
	conn->timer_flag = 1;
	DEBUG_PRINTF("set_inactivity_timer(): for %d ms \n", conn->dc);
	conn->post_timer_task(&schc_reassemble, conn->device_id, conn->dc, conn);
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
	uint8_t offset = conn->RULE_SIZE + conn->schc_rule->FCN_SIZE
			+ conn->schc_rule->DTAG_SIZE + conn->schc_rule->WINDOW_SIZE;
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
	uint8_t offset = conn->RULE_SIZE + conn->schc_rule->FCN_SIZE + conn->schc_rule->DTAG_SIZE
			+ conn->schc_rule->WINDOW_SIZE + (MIC_SIZE_BYTES * 8);
	uint8_t len = (mbuf->len * 8);

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
static uint8_t send_fragment(schc_fragmentation_t* conn) {
	memset(FRAGMENTATION_BUF, 0, MAX_MTU_LENGTH); // set and reset buffer

	uint16_t header_bits = set_fragmentation_header(conn, FRAGMENTATION_BUF); // set fragmentation header
	uint32_t packet_bits_tx = has_no_more_fragments(conn); // the number of bits already transmitted

	uint16_t packet_len = 0; uint32_t packet_bit_offset = 0; int32_t remaining_bits;

	if(!packet_bits_tx) { // normal fragment
		packet_len = conn->mtu;
		packet_bits_tx = ((conn->mtu * 8) - header_bits); // set packet bits to number of bits that fit in packet
		packet_bit_offset = (packet_bits_tx * (conn->frag_cnt - 1)); // offset to start copying from
		remaining_bits = (BYTES_TO_BITS(conn->bit_arr->len)
						- conn->bit_arr->padding) - packet_bit_offset;
		if( remaining_bits < (packet_len * 8)  ) { // next packet contains RCS
			// checked by packet_bits that this is not the last one
			// padding is added by memsetting the FRAGMENTATION_BUF
			packet_bits_tx = remaining_bits;
			packet_len = (remaining_bits + header_bits) / 8;
		}
	}

	if (!packet_len) { // all-1 fragment
		uint32_t next_total_mtu_bits = BYTES_TO_BITS(conn->mtu)
					* (conn->frag_cnt);

		packet_bit_offset = packet_bits_tx;

		remaining_bits = (BYTES_TO_BITS(conn->bit_arr->len)
				- conn->bit_arr->padding - conn->RULE_SIZE) - packet_bits_tx;

		packet_bits_tx = remaining_bits;

		if(remaining_bits < 0) { // RCS in separate packet
			// which also requires padding
			header_bits = conn->RULE_SIZE + conn->schc_rule->WINDOW_SIZE
					+ conn->schc_rule->FCN_SIZE + conn->schc_rule->DTAG_SIZE
					+ (MIC_SIZE_BYTES * 8);
			packet_bits_tx = 0; // header offset is included in packet bits now

			uint8_t zerobuf[1] = { 0 };
			remaining_bits = (8 - (header_bits % 8)); // padding variable
			copy_bits(FRAGMENTATION_BUF, header_bits, zerobuf, 0, remaining_bits); // add padding
		}

		packet_len = ((header_bits + remaining_bits) + (8 - 1)) / 8; // last packet length

		if(packet_len > conn->mtu) {
			DEBUG_PRINTF("send_fragment(): mtu smaller than last packet length \n");
			packet_len = conn->mtu;
		}
	}

	copy_bits(FRAGMENTATION_BUF, header_bits, conn->bit_arr->ptr,
			(packet_bit_offset + conn->RULE_SIZE), packet_bits_tx); // copy bits, do not include rule id of compressed packet

	DEBUG_PRINTF(
			"send_fragment(): sending fragment %d with length %d to device %d \n",
			conn->frag_cnt, packet_len, conn->device_id);

	int j;
	for (j = 0; j < packet_len; j++) {
		DEBUG_PRINTF("0x%02X ", FRAGMENTATION_BUF[j]);
	}
	DEBUG_PRINTF("\n");

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
	uint8_t offset = conn->RULE_SIZE;

	copy_bits(ack, 0, conn->ack.rule_id, 0, offset); // set rule id
	copy_bits(ack, offset, conn->ack.dtag, 0, conn->schc_rule->DTAG_SIZE); // set dtag
	offset += conn->schc_rule->DTAG_SIZE;

	uint8_t window[1] = { conn->window << (8 - conn->schc_rule->WINDOW_SIZE) }; // set window
	copy_bits(ack, offset, window, 0, conn->schc_rule->WINDOW_SIZE);
	offset += conn->schc_rule->WINDOW_SIZE;

	if(conn->ack.fcn == get_max_fcn_value(conn)) { // all-1 window
		uint8_t c[1] = { conn->ack.mic << (8 - MIC_C_SIZE_BITS) }; // set mic c bit
		copy_bits(ack, offset, c, 0, MIC_C_SIZE_BITS);
		offset += MIC_C_SIZE_BITS;
	}

	if(!conn->ack.mic) { // if mic c bit is 0 (zero by default)
		DEBUG_PRINTF("send_ack(): sending bitmap \n");
		copy_bits(ack, offset, conn->bitmap, 0, conn->schc_rule->MAX_WND_FCN + 1); // copy the bitmap
		offset += conn->schc_rule->MAX_WND_FCN + 1; // todo must be encoded
		print_bitmap(conn->bitmap, conn->schc_rule->MAX_WND_FCN + 1);
	}

	uint8_t packet_len = ((offset - 1) / 8) + 1;
	DEBUG_PRINTF("send_ack(): sending ack to device %d for fragment %d with length %d (%d b) \n",
			conn->device_id, conn->frag_cnt + 1, packet_len, offset);

	int i;
	for(i = 0; i < packet_len; i++) {
		printf("%02X ", ack[i]);
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
	uint16_t header_offset = set_fragmentation_header(conn, FRAGMENTATION_BUF);

	uint8_t padding = header_offset % 8;
	uint8_t zerobuf[1] = { 0 };
	copy_bits(FRAGMENTATION_BUF, header_offset, zerobuf, 0, padding); // add padding

	uint8_t packet_len = (padding + header_offset) / 8;

	DEBUG_PRINTF("send_empty(): sending all-x empty to device %d with length %d (%d b)\n",
			conn->device_id, packet_len, header_offset);

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
	DEBUG_PRINTF("send_tx_empty()\n");
	return 0;
}

////////////////////////////////////////////////////////////////////////////////////
//                               GLOBAL FUNCIONS                                  //
////////////////////////////////////////////////////////////////////////////////////

/**
 * find a connection based on a device id
 * or open a new connection if there was no connection
 * for this device yet
 *
 * @param 	device_id	the id of the device to open a connection for
 *
 * @return 	conn		a pointer to the selected connection
 * 			0 			if no free connections are available
 *
 */
schc_fragmentation_t* schc_get_connection(uint32_t device_id) {
	uint32_t i; schc_fragmentation_t *conn;
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
				schc_rx_conns[i].device_id = device_id;
				break;
			}
		}
	}

	if(conn) {
		DEBUG_PRINTF("schc_get_connection(): selected connection %d for device %d\n", i, device_id);
	}

	return conn;
}


/**
 * sort the mbuf chain, find the MIC inside the last received fragment
 * and compare with the calculated one
 *
 * @param 	rx_conn		a pointer to the rx connection structure
 *
 */
static int8_t mic_correct(schc_fragmentation_t* rx_conn) {
	uint8_t recv_mic[MIC_SIZE_BYTES] = { 0 };

	mbuf_sort(&rx_conn->head); // sort the mbuf chain

	schc_mbuf_t* tail = get_mbuf_tail(rx_conn->head); // get new tail before looking for mic

	if (tail == NULL) { // hack
		// rx_conn->timer_flag or rx_conn->input has not been changed
		abort_connection(rx_conn); // todo
		return -1;
	}

	get_received_mic(tail->ptr, recv_mic, rx_conn);
	DEBUG_PRINTF("mic_correct(): received MIC is %02X%02X%02X%02X\n", recv_mic[0], recv_mic[1],
			recv_mic[2], recv_mic[3]);

	mbuf_print(rx_conn->head);
	mbuf_compute_mic(rx_conn); // compute the mic over the mbuf chain

	if (!compare_bits(rx_conn->mic, recv_mic, (MIC_SIZE_BYTES * 8))) { // mic wrong
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

	DEBUG_PRINTF("WAIT END\n");
	if (rx_conn->timer_flag && !rx_conn->input) { // inactivity timer expired
		abort_connection(rx_conn); // todo + reset connection (but first remove timer instance)
		return 0;
	}

	if (mic_correct(rx_conn) < 0) { // tail is NULL
		return 0;
	} else {
		if (!mic_correct(rx_conn)) { // mic incorrect
			DEBUG_PRINTF("mic wrong\n");
			rx_conn->ack.mic = 0;
			rx_conn->RX_STATE = WAIT_END;
			if (window == rx_conn->window) { // expected window
				DEBUG_PRINTF("expected window\n");
				set_local_bitmap(rx_conn);
			}
			if (fcn == get_max_fcn_value(rx_conn) && rx_conn->schc_rule->mode == ACK_ALWAYS) { // all-1
				DEBUG_PRINTF("all-1");
				if (empty_all_1(tail, rx_conn)) {
					discard_fragment(rx_conn); // remove last fragment (empty)
				}
				send_ack(rx_conn);
			}
		} else { // mic right
			DEBUG_PRINTF("mic correct\n");
			if (window == rx_conn->window) { // expected window
				DEBUG_PRINTF("expected window\n");
				rx_conn->RX_STATE = END_RX;
				rx_conn->ack.fcn = get_max_fcn_value(rx_conn); // c bit is set when ack.fcn is max
				rx_conn->ack.mic = 1; // bitmap is not sent when mic correct
				set_local_bitmap(rx_conn);
				send_ack(rx_conn);
				return 2; // stay alive to answer lost acks
			}
		}
	}

	if (fcn == get_max_fcn_value(rx_conn) && rx_conn->schc_rule->mode == ACK_ON_ERROR) { // all-1
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
	uint8_t recv_mic[MIC_SIZE_BYTES] = { 0 };
	schc_mbuf_t* tail = get_mbuf_tail(rx_conn->head); // get last received fragment

	copy_bits(rx_conn->ack.rule_id, 0, tail->ptr, 0, rx_conn->RULE_SIZE); // get the rule id from the fragment
	uint8_t window = get_window_bit(tail->ptr, rx_conn); // the window bit from the fragment
	uint8_t fcn = get_fcn_value(tail->ptr, rx_conn); // the fcn value from the fragment

	DEBUG_PRINTF("fcn is %d, window is %d\n", fcn, window);

	rx_conn->fcn = fcn;
	rx_conn->ack.fcn = fcn;

	if (window == (!rx_conn->window)) {
		rx_conn->window_cnt++;
	}

	if(rx_conn->schc_rule->mode == NO_ACK) { // can not find fragment from fcn value
		rx_conn->frag_cnt++; // update fragment counter
	} else {
		set_conn_frag_cnt(rx_conn, fcn);
	}

	tail->frag_cnt = rx_conn->frag_cnt; // update tail frag count

	if(rx_conn->input) { // set inactivity timer if the loop was triggered by a fragment input
		set_inactivity_timer(rx_conn);
	}

	/*
	 * ACK ALWAYS MODE
	 */
	if (rx_conn->schc_rule->mode == ACK_ALWAYS) {
		switch (rx_conn->RX_STATE) {
		case RECV_WINDOW: {
			DEBUG_PRINTF("RECV WINDOW\n");
			if (rx_conn->timer_flag && !rx_conn->input) { // inactivity timer expired
				abort_connection(rx_conn); // todo
				break;
			}
			if (rx_conn->window != window) { // unexpected window
				DEBUG_PRINTF("w != window\n");
				discard_fragment(rx_conn);
				rx_conn->RX_STATE = RECV_WINDOW;
				break;
			} else if (window == rx_conn->window) { // expected window
				DEBUG_PRINTF("w == window\n");
				if (fcn != 0 && fcn != get_max_fcn_value(rx_conn)) { // not all-x
					DEBUG_PRINTF("not all-x\n");
					set_local_bitmap(rx_conn);
					rx_conn->RX_STATE = RECV_WINDOW;
				} else if (fcn == 0) { // all-0
					DEBUG_PRINTF("all-0\n");
					if (!empty_all_0(tail, rx_conn)) {
						set_local_bitmap(rx_conn); // indicate that we received a fragment
					} else {
						discard_fragment(rx_conn);
					}
					rx_conn->RX_STATE = WAIT_NEXT_WINDOW;
					rx_conn->ack.mic = 0; // bitmap will be sent when c = 0
					send_ack(rx_conn); // send local bitmap
				} else if (fcn == get_max_fcn_value(rx_conn)) { // all-1
					if (!empty_all_1(tail, rx_conn)) {
						DEBUG_PRINTF("all-1\n");
						set_local_bitmap(rx_conn);
						if(!mic_correct(rx_conn)) { // mic wrong
							rx_conn->RX_STATE = WAIT_END;
							rx_conn->ack.mic = 0;
						} else { // mic right
							rx_conn->RX_STATE = END_RX;
							rx_conn->ack.fcn = get_max_fcn_value(rx_conn); // c bit is set when ack.fcn is max
							rx_conn->ack.mic = 1; // bitmap is not sent when mic correct
							send_ack(rx_conn);
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
		case WAIT_NEXT_WINDOW: {
			DEBUG_PRINTF("WAIT NEXT WINDOW\n");
			if (rx_conn->timer_flag && !rx_conn->input) { // inactivity timer expired
				abort_connection(rx_conn); // todo
				break;
			}
			if (window == (!rx_conn->window)) { // next window
				DEBUG_PRINTF("w != window\n");
				if (fcn != 0 && fcn != get_max_fcn_value(rx_conn)) { // not all-x
					DEBUG_PRINTF("not all-x\n");
					rx_conn->window = !rx_conn->window; // set expected window to next window
					clear_bitmap(rx_conn);
					set_local_bitmap(rx_conn);
					rx_conn->RX_STATE = RECV_WINDOW; // return to receiving window
				} else if (fcn == 0) { // all-0
					DEBUG_PRINTF("all-0\n");
					if (empty_all_0(tail, rx_conn)) {
						discard_fragment(rx_conn); // remove last fragment (empty)
					} else {
						rx_conn->window = !rx_conn->window;
						clear_bitmap(rx_conn);
						set_local_bitmap(rx_conn);
					}
					rx_conn->ack.mic = 0; // bitmap will be sent when c = 0
					send_ack(rx_conn);
				} else if (fcn == get_max_fcn_value(rx_conn)) { // all-1
					DEBUG_PRINTF("all-1\n");
					if (empty_all_1(tail, rx_conn)) {
						discard_fragment(rx_conn); // remove last fragment (empty)
					} else {
						if(!mic_correct(rx_conn)) { // mic wrong
							rx_conn->RX_STATE = WAIT_END;
							rx_conn->ack.mic = 0;
						} else { // mic right
							rx_conn->RX_STATE = END_RX;
							rx_conn->ack.fcn = get_max_fcn_value(rx_conn); // c bit is set when ack.fcn is max
							rx_conn->ack.mic = 1; // bitmap is not sent when mic correct
							send_ack(rx_conn);
							return 2; // stay alive to answer lost acks
						}
						set_local_bitmap(rx_conn);
					}
					send_ack(rx_conn);
				}
			} else if (window == rx_conn->window) { // expected window
				DEBUG_PRINTF("w == window\n");
				if (fcn == 0) { // all-0
					if (empty_all_0(tail, rx_conn)) {
						discard_fragment(rx_conn);
					} else {
						DEBUG_PRINTF("all-0\n");
						rx_conn->RX_STATE = WAIT_NEXT_WINDOW;
					}
					rx_conn->ack.mic = 0; // bitmap will be sent when c = 0
					send_ack(rx_conn);
				} else if (fcn == get_max_fcn_value(rx_conn)) { // all-1
					DEBUG_PRINTF("all-1\n");
					rx_conn->RX_STATE = WAIT_NEXT_WINDOW;
					discard_fragment(rx_conn);
				} else if (fcn != 0 && fcn != get_max_fcn_value(rx_conn)) { // not all-x
					set_local_bitmap(rx_conn);
					DEBUG_PRINTF("not all-x, is bitmap full? %d\n",
							is_bitmap_full(rx_conn, (rx_conn->schc_rule->MAX_WND_FCN + 1)));
					rx_conn->RX_STATE = WAIT_NEXT_WINDOW;
					if (is_bitmap_full(rx_conn, (rx_conn->schc_rule->MAX_WND_FCN + 1))) { // bitmap is full; the last fragment of a retransmission is received
						rx_conn->ack.mic = 0; // bitmap will be sent when c = 0
						send_ack(rx_conn);
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
			DEBUG_PRINTF("END RX\n");
			if (rx_conn->timer_flag && !rx_conn->input) { // inactivity timer expired
				// end the transmission
				mbuf_sort(&rx_conn->head); // sort the mbuf chain
				rx_conn->end_rx(rx_conn); // forward to ipv6 network
				schc_reset(rx_conn);
				return 1; // end reception
			}
			if (fcn != get_max_fcn_value(rx_conn)) { // not all-1
				DEBUG_PRINTF("not all-x\n");
				discard_fragment(rx_conn);
			} else { // all-1
				DEBUG_PRINTF("all-1\n");
				send_ack(rx_conn);
				mbuf_sort(&rx_conn->head); // sort the mbuf chain
				return 1; // end reception
			}
			break;
		}
		}
	}
	/*
	 * NO ACK MODE
	 */
	else if (rx_conn->schc_rule->mode == NO_ACK) {
		switch (rx_conn->RX_STATE) {
		case RECV_WINDOW: {
			if (rx_conn->timer_flag && !rx_conn->input) { // inactivity timer expired
				abort_connection(rx_conn);
				// todo send abort
				break;
			}
			if (fcn == get_max_fcn_value(rx_conn)) { // all-1
				// clear inactivity timer
				rx_conn->timer_flag = 0;
				if(!mic_correct(rx_conn)) { // mic wrong
					abort_connection(rx_conn);
					// todo send abort
					return 1;
				} else { // mic correct
					rx_conn->RX_STATE = END_RX;
					rx_conn->ack.fcn = get_max_fcn_value(rx_conn); // c bit is set when ack.fcn is max
					rx_conn->ack.mic = 1; // bitmap is not sent when mic correct

					mbuf_sort(&rx_conn->head); // sort the mbuf chain

					return 1;
				}
			}
			break;
		}
		case END_RX: {
			DEBUG_PRINTF("END RX\n"); // end the transmission
			mbuf_sort(&rx_conn->head); // sort the mbuf chain
			rx_conn->end_rx(rx_conn); // forward to ipv6 network
			schc_reset(rx_conn);
			return 1; // end reception
		}
		}
	}
	/*
	 * ACK ON ERROR MODE
	 */
	else if (rx_conn->schc_rule->mode == ACK_ON_ERROR) {
		switch (rx_conn->RX_STATE) {
		case RECV_WINDOW: {
			DEBUG_PRINTF("RECV WINDOW\n");
			if (rx_conn->timer_flag && !rx_conn->input) { // inactivity timer expired
				abort_connection(rx_conn); // todo
				break;
			}
			if (rx_conn->window != window) { // unexpected window
				DEBUG_PRINTF("w != window\n");
				discard_fragment(rx_conn);
				rx_conn->RX_STATE = ERR;
				break;
			} else if (window == rx_conn->window) { // expected window
				DEBUG_PRINTF("w == window\n");
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
					if(is_bitmap_full(rx_conn, (rx_conn->schc_rule->MAX_WND_FCN + 1))) {
						clear_bitmap(rx_conn);
						rx_conn->window = !rx_conn->window;
						rx_conn->window_cnt++;
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
						if (!mic_correct(rx_conn)) { // mic wrong
							rx_conn->RX_STATE = WAIT_END;
							rx_conn->ack.mic = 0;
						} else { // mic right
							rx_conn->RX_STATE = END_RX;
							rx_conn->ack.fcn = get_max_fcn_value(rx_conn); // c bit is set when ack.fcn is max
							rx_conn->ack.mic = 1; // bitmap is not sent when mic correct
							send_ack(rx_conn);
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
			if (window == rx_conn->window) { // expected window
				DEBUG_PRINTF("w == window\n");
				if (fcn != 0 && fcn != get_max_fcn_value(rx_conn)
						&& is_bitmap_full(rx_conn, rx_conn->schc_rule->MAX_WND_FCN)) { // not all-x and bitmap not full
					set_local_bitmap(rx_conn);
					rx_conn->window = !rx_conn->window;
					rx_conn->RX_STATE = RECV_WINDOW;
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
			return 1; // end reception
		}
		}
	}

	return 0;
}

/**
 * Initializes the SCHC fragmenter
 *
 * @param tx_conn				a pointer to the tx initialization structure
 * @param send					a pointer to the send callback
 * @param end_rx				this function is called to indicate that
 * 								the last rx timer has expired
 * @param remove_timer_entry	some scheduler implementations need a callback
 * 								to remove a timer entry for a certain device
 *
 * @return error codes on error
 *
 */
int8_t schc_fragmenter_init(schc_fragmentation_t* tx_conn,
		uint8_t (*send)(uint8_t* data, uint16_t length, uint32_t device_id),
		void (*end_rx)(schc_fragmentation_t* conn),
		void (*remove_timer_entry)(uint32_t device_id)) {
	uint32_t i;

	// initializes the schc tx connection
	tx_conn->head = NULL;
	schc_reset(tx_conn);

	// initializes the schc rx connections
	for (i = 0; i < SCHC_CONF_RX_CONNS; i++) {
		schc_reset(&schc_rx_conns[i]);
		schc_rx_conns[i].send = send;
		schc_rx_conns[i].end_rx = end_rx;
		schc_rx_conns[i].remove_timer_entry = remove_timer_entry;
		schc_rx_conns[i].frag_cnt = 0;
		schc_rx_conns[i].window_cnt = 0;
		schc_rx_conns[i].input = 0;
		schc_rx_conns[i].schc_rule = NULL;
		// in case these parameters were not configured properly
		schc_rx_conns[i].RULE_SIZE = RULE_SIZE_BITS;
	}

	// initializes the mbuf pool
	MBUF_PTR = 0;
	for(i = 0; i < SCHC_CONF_MBUF_POOL_LEN; i++) {
		MBUF_POOL[i].ptr = NULL;
		MBUF_POOL[i].len = 0;
		MBUF_POOL[i].next = NULL;
		MBUF_POOL[i].offset = 0;
	}

	return 1;
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
		tx_conn->fcn = (pow(2, tx_conn->schc_rule->FCN_SIZE) - 1); // all 1-window
		if (send_fragment(tx_conn)) { // only continue when packet was transmitted
			tx_conn->TX_STATE = WAIT_BITMAP;
			set_local_bitmap(tx_conn); // set bitmap according to fcn
			set_retrans_timer(tx_conn);
		} else {
			DEBUG_PRINTF("schc_fragment(): radio occupied retrying in %d ms\n",
					tx_conn->dc);
			tx_conn->frag_cnt--;
			tx_conn->fcn = fcn; // reset fcn and frag_count before retrying
			set_dc_timer(tx_conn);
		}
	} else if (tx_conn->fcn == 0 && !has_no_more_fragments(tx_conn)) { // all-0 window
		DEBUG_PRINTF("schc_fragment(): all-0 window\n");
		if (send_fragment(tx_conn)) {
			tx_conn->TX_STATE = WAIT_BITMAP;
			set_local_bitmap(tx_conn); // set bitmap according to fcn
			tx_conn->fcn = tx_conn->schc_rule->MAX_WND_FCN; // reset the FCN
			set_retrans_timer(tx_conn);
		} else {
			DEBUG_PRINTF("schc_fragment(): radio occupied retrying in %d ms\n",
					tx_conn->dc);
			tx_conn->frag_cnt--;
			set_dc_timer(tx_conn);
		}
	} else if (tx_conn->fcn != 0 && !has_no_more_fragments(tx_conn)) { // normal fragment
		DEBUG_PRINTF("schc_fragment(): normal fragment\n");
		if (send_fragment(tx_conn)) {
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
		tx_conn->frag_cnt = ((tx_conn->tail_ptr - tx_conn->bit_arr->ptr)
				/ tx_conn->mtu) + 1;
		tx_conn->fcn = get_max_fcn_value(tx_conn);
		last = 1;
	} else {
		tx_conn->frag_cnt = (((tx_conn->schc_rule->MAX_WND_FCN + 1) * tx_conn->window_cnt)
				+ get_next_fragment_from_bitmap(tx_conn)); // send_fragment() uses frag_cnt to transmit a particular fragment
		tx_conn->fcn = ((tx_conn->schc_rule->MAX_WND_FCN + 1) * (tx_conn->window_cnt + 1))
				- tx_conn->frag_cnt;
		if (!get_next_fragment_from_bitmap(tx_conn)) {
			last = 1;
		}
	}

	DEBUG_PRINTF("schc_fragment(): sending missing fragments for bitmap: \n");
	print_bitmap(tx_conn->ack.bitmap, (tx_conn->schc_rule->MAX_WND_FCN + 1));
	DEBUG_PRINTF("with FCN %d, window count %d, frag count %d\n", tx_conn->fcn,
			tx_conn->window_cnt, tx_conn->frag_cnt);

	if (last) { // check if this was the last fragment
		DEBUG_PRINTF("schc_fragment(): last missing fragment to send\n");
		if (send_fragment(tx_conn)) { // retransmit the fragment
			tx_conn->TX_STATE = WAIT_BITMAP;
			tx_conn->frag_cnt = (tx_conn->window_cnt + 1)
					* (tx_conn->schc_rule->MAX_WND_FCN + 1);
			set_retrans_timer(tx_conn);
		} else {
			tx_conn->frag_cnt = frag_cnt;
			set_dc_timer(tx_conn);
		}

	} else {
		if (send_fragment(tx_conn)) { // retransmit the fragment
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
	DEBUG_PRINTF("no missing fragments & more fragments to come\n");
	tx_conn->timer_flag = 0; // stop retransmission timer
	clear_bitmap(tx_conn);
	tx_conn->window = !tx_conn->window; // change window
	tx_conn->window_cnt++;
	tx_conn->fcn = tx_conn->schc_rule->MAX_WND_FCN;
	tx_conn->frag_cnt = (tx_conn->window_cnt) * (tx_conn->schc_rule->MAX_WND_FCN + 1);
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
	uint8_t fcn = 0;
	uint8_t frag_cnt = 0;

	if (tx_conn->TX_STATE == INIT_TX) {
		DEBUG_PRINTF("INIT_TX\n");
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

	if (tx_conn->TX_STATE == END_TX) {
		DEBUG_PRINTF("schc_fragment(): end transmission cycle\n");
		tx_conn->timer_flag = 0;
		tx_conn->end_tx();
		schc_reset(tx_conn); // todo ??
		return SCHC_END;
	}

	/*
	 * ACK ALWAYS MODE
	 */
	if (tx_conn->schc_rule->mode == ACK_ALWAYS) {
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
			if (tx_conn->ack.window[0] != tx_conn->window) { // unexpected window
				DEBUG_PRINTF("w != w, discard fragment\n");
				discard_fragment(tx_conn);
				tx_conn->TX_STATE = WAIT_BITMAP;
				break;
			}
			if (tx_conn->ack.window[0] == tx_conn->window) {
				DEBUG_PRINTF("w == w\n");
				if (!has_no_more_fragments(tx_conn)
						&& compare_bits(resend_window, tx_conn->ack.bitmap,
								(tx_conn->schc_rule->MAX_WND_FCN + 1))) { // no missing fragments & more fragments
					no_missing_fragments_more_to_come(tx_conn);
					schc_fragment(tx_conn);
				}
				if (has_no_more_fragments(tx_conn) && tx_conn->ack.mic) { // mic and bitmap check succeeded
					DEBUG_PRINTF("no more fragments, MIC ok\n");
					tx_conn->timer_flag = 0; // stop retransmission timer
					tx_conn->TX_STATE = END_TX;
					schc_fragment(tx_conn);
					break;
				}
			}
			if (!compare_bits(resend_window, tx_conn->ack.bitmap,
					(tx_conn->schc_rule->MAX_WND_FCN + 1))) { //ack.bitmap contains the missing fragments
				DEBUG_PRINTF("bitmap contains the missing fragments\n");
				tx_conn->attempts++;
				tx_conn->frag_cnt = (tx_conn->window_cnt)
						* (tx_conn->schc_rule->MAX_WND_FCN + 1);
				tx_conn->timer_flag = 0; // stop retransmission timer
				tx_conn->TX_STATE = RESEND;
				schc_fragment(tx_conn);
				break;
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
			DEBUG_PRINTF("RESEND\n");
			tx_fragment_resend(tx_conn);
			break;
		}
		case ERR: {
			DEBUG_PRINTF("ERROR\n");
			break;
		}
		}
	}
	/*
	 * NO ACK MODE
	 */
	else if (tx_conn->schc_rule->mode == NO_ACK) {
		switch (tx_conn->TX_STATE) {
		case SEND: {
			DEBUG_PRINTF("SEND\n");
			tx_conn->frag_cnt++;

			if (has_no_more_fragments(tx_conn)) { // last fragment
				DEBUG_PRINTF("last fragment\n");
				tx_conn->fcn = 1;
				tx_conn->TX_STATE = END_TX;
			} else {
				DEBUG_PRINTF("normal fragment\n");
				tx_conn->fcn = 0;
				tx_conn->TX_STATE = SEND;
			}
			if (!send_fragment(tx_conn)) { // only continue when packet was transmitted
				DEBUG_PRINTF(
						"schc_fragment(): radio occupied retrying in %d ms\n",
						tx_conn->dc);
				tx_conn->frag_cnt--;
			}
			set_dc_timer(tx_conn); // send next fragment in dc ms or end transmission
			break;
		}
		case END_TX: {
			DEBUG_PRINTF("schc_fragment(): end transmission cycle\n");
			tx_conn->end_tx();
			schc_reset(tx_conn);
			return SCHC_END;
			break;
		}
		}
	}
	/*
	 * ACK ON ERROR MODE
	 */
	else if (tx_conn->schc_rule->mode == ACK_ON_ERROR) {
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
					(tx_conn->schc_rule->MAX_WND_FCN + 1))) { //ack.bitmap contains the missing fragments
				DEBUG_PRINTF("bitmap contains the missing fragments\n");
				tx_conn->attempts++;
				tx_conn->frag_cnt = (tx_conn->window_cnt)
						* (tx_conn->schc_rule->MAX_WND_FCN + 1);
				tx_conn->timer_flag = 0; // stop retransmission timer
				tx_conn->TX_STATE = RESEND;
				schc_fragment(tx_conn);
				break;
			} else if (compare_bits(resend_window, tx_conn->ack.bitmap,
					(tx_conn->schc_rule->MAX_WND_FCN + 1))) {
				DEBUG_PRINTF("received bitmap == local bitmap\n");
				tx_conn->timer_flag = 0; // stop retransmission timer
				tx_conn->TX_STATE = END_TX;
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
 * @param 	tx_conn			a pointer to the tx initialization structure
 * @param 	device_id		the device id from the rx source
 *
 */
schc_fragmentation_t* schc_input(uint8_t* data, uint16_t len, schc_fragmentation_t* tx_conn,
		uint32_t device_id) {
	if ((tx_conn->TX_STATE == WAIT_BITMAP || tx_conn->TX_STATE == RESEND)
			&& compare_bits(tx_conn->schc_rule->id, data, tx_conn->RULE_SIZE)) { // acknowledgment
		schc_ack_input(data, len, tx_conn, device_id);
		return tx_conn;
	} else {
		schc_fragmentation_t* rx_conn = schc_fragment_input((uint8_t*) data, len, device_id);
		return rx_conn;
	}
}

/**
 * This function should be called whenever an ack is received
 *
 * @param 	data			a pointer to the received data
 * @param 	len				the length of the received packet
 * @param 	tx_conn			a pointer to the tx initialization structure
 * @param   device_id		the device id from the rx source
 *
 */
void schc_ack_input(uint8_t* data, uint16_t len, schc_fragmentation_t* tx_conn,
		uint32_t device_id) {
	uint8_t bit_offset = tx_conn->RULE_SIZE;
	tx_conn->input = 1;

	memset(tx_conn->ack.dtag, 0, 1); // clear dtag from prev reception
	copy_bits(tx_conn->ack.dtag, (8 - tx_conn->schc_rule->DTAG_SIZE), (uint8_t*) data,
			bit_offset, tx_conn->schc_rule->DTAG_SIZE); // get dtag
	bit_offset += tx_conn->schc_rule->DTAG_SIZE;

	memset(tx_conn->ack.window, 0, 1); // clear window from prev reception
	copy_bits(tx_conn->ack.window, (8 - tx_conn->schc_rule->WINDOW_SIZE), (uint8_t*) data,
			bit_offset, tx_conn->schc_rule->WINDOW_SIZE); // get window
	bit_offset += tx_conn->schc_rule->WINDOW_SIZE;

	uint8_t bitmap_len = (tx_conn->schc_rule->MAX_WND_FCN + 1);

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
	memset(tx_conn->ack.bitmap, 0, 1); // clear bitmap from prev reception
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
 * @param 	device_id		the device id from the rx source
 *
 * @return 	conn			the connection
 *
 */
schc_fragmentation_t* schc_fragment_input(uint8_t* data, uint16_t len,
		uint32_t device_id) {
	schc_fragmentation_t *conn;

	// get a connection for the device
	conn = schc_get_connection(device_id);
	if (!conn) { // return if there was no connection available
		DEBUG_PRINTF("schc_fragment_input(): no free connections found!\n");
		return NULL;
	}

	conn->schc_rule = get_schc_rule_by_rule_id(data, device_id);

	// todo
	// if no rule was found
	// this is a null pointer -> return function will get confused (checks for rule->mode)

	uint8_t* fragment;
#if DYNAMIC_MEMORY
	fragment = (uint8_t*) malloc(len); // allocate memory for fragment
#else
	fragment = (uint8_t*) (schc_buf + buf_ptr); // take fixed memory block
	buf_ptr += len;
#endif

	memcpy(fragment, data, len);

	int8_t err = mbuf_push(&conn->head, fragment, len);

	mbuf_print(conn->head);

	if(err != SCHC_SUCCESS) {
		return NULL;
	}

	conn->input = 1; // set fragment input to 1, to distinguish between inactivity callbacks

	return conn;
}

#if CLICK
ELEMENT_PROVIDES(schcFRAGMENTER)
ELEMENT_REQUIRES(schcBIT)
#endif
