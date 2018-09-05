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

#include "config.h"
#include "schc_config.h"

#include "fragmenter.h"

#if CLICK
#include <click/config.h>
#endif

// keep track of the active connections
struct schc_fragmentation_t schc_rx_conns[SCHC_CONF_RX_CONNS];
static uint8_t fragmentation_buffer[MAX_MTU_LENGTH];

// keep track of the mbuf's
static uint32_t MBUF_PTR;
static struct schc_mbuf_t MBUF_POOL[SCHC_CONF_MBUF_POOL_LEN];

#if !DYNAMIC_MEMORY
static uint8_t buf_ptr = 0;
uint8_t schc_buf[SCHC_BUFSIZE] = { 0 };
#endif

// ToDo
// create file bit_array.c?
// compressor will need this too

/**
 * sets bits at a certain position in a bit array
 * big endian
 *
 * @param A				the bit array
 * @param pos			which bit to set
 * @param len			the number of consecutive bits to set
 *
 */
static void set_bits(uint8_t A[], uint32_t pos, uint32_t len) {
	uint32_t i;
	for(i = pos; i < (len + pos); i++) {
		A[i / 8] |= 128 >> (i % 8);
	}
}

/**
 * get bits at a certain position in a bit array
 *
 * @param A				the bit array
 * @param pos			the position to start from
 * @param len			the number of consecutive bits to get
 *
 * @note  limited to 32 consecutive bits
 *
 */
static uint32_t get_bits(uint8_t A[], uint32_t pos, uint8_t len) {
	uint32_t i; uint32_t j = (len - 1); uint32_t number = 0;

	for(i = pos; i < (len + pos); i++) {
		uint8_t bit = A[i / 8] & 128 >> (i % 8);
		number |= (!!bit << j);
		j--;
	}

	return number;
}

/**
 * clear bits at a certain position in a bit array
 * big endian
 *
 * @param A				the bit array
 * @param pos			which bit to clear
 * @param len			the number of consecutive bits to clear
 *
 */
static void clear_bits(uint8_t A[], uint32_t pos, uint32_t len) {
	uint32_t i;
	for(i = pos; i < (len + pos); i++) {
		A[i / 8] &= ~(128 >> (i % 8));
	}
}

/**
 * copy bits to a certain position in a bit array
 * from another array
 * big endian
 *
 * @param DST			the array to copy to
 * @param dst_pos		which bit to start from
 * @param SRC			the array to copy from
 * @param src_pos		which bit to start from
 * @param len			the number of consecutive bits to set
 *
 */
static void copy_bits(uint8_t DST[], uint32_t dst_pos, uint8_t SRC[], uint32_t src_pos,
		uint32_t len) {
	uint32_t i;
	uint32_t k = 0;

	for(i = 0; i < len; i++) { // for each bit
		uint8_t src_val = ((128 >> ( (k + src_pos) % 8)) & SRC[((k + src_pos) / 8)]);
		if(src_val) {
			// DEBUG_PRINTF("set bits for %d at position %d len is %d", DST[i+dst_pos], i+dst_pos, len);
			set_bits(DST, i + dst_pos, 1);
		}
		k++;
	}
}

/**
 * compare two bit arrays
 *
 * @param 	SRC1		the array to compare
 * @param 	SRC2		the array to compare with
 * @param 	len			the number of consecutive bits to compare
 *
 * @return	1			both arrays match
 * 			0			the arrays differ
 *
 */
static uint8_t compare_bits(uint8_t SRC1[], uint8_t SRC2[], uint32_t len) {
	uint32_t i;

	for (i = 0; i < len; i++) {
		if ( (SRC1[i / 8] & (128 >> (i % 8) )) != (SRC2[i / 8] & (128 >> (i % 8) )) ) {
			return 0;
		}
	}

	return 1;
}

/**
 * shift a number of bits to the left
 *
 * @param 	SRC			the array to shift
 * @param	len			the length of the array
 * @param 	shift		the number of consecutive bits to shift
 *
 */
static void shift_bits_left(uint8_t SRC[], uint16_t len, uint32_t shift) {
	uint32_t i = 0; uint32_t j = 0;

	uint8_t start = shift / 8;
	uint8_t rest = shift % 8;

	for(i = start; i < len; i++) {
		uint8_t value = (SRC[i] << rest) | (SRC[i + 1] >> (8 - rest));
		SRC[j] = value;
		j++;
	}

}

/**
 * shift a number of bits to the right
 *
 * @param 	SRC			the array to shift
 * @param	len			the length of the array
 * @param 	shift		the number of consecutive bits to shift
 *
 */
static void shift_bits_right(uint8_t SRC[], uint16_t len, uint32_t shift) {
	uint32_t i = 0;

	uint8_t start = shift / 8;
	uint8_t rest = shift % 8;
	uint8_t previous = 0;

	for(i = 0; i < len; i++) {
		if(start <= i) {
			previous = SRC[i - start];
		}
		uint8_t value = (previous << (8 - rest)) | SRC[i + start] >> rest;
		SRC[i + start] = value;
	}
}

/**
 * logical XOR two bit arrays
 *
 * @param 	DST			the array to save the result in
 * @param 	SRC1		the array to compare with
 * @param 	SRC2		the array to compare with
 * @param 	len			the number of consecutive bits to compare
 *
 */
static void xor_bits(uint8_t DST[], uint8_t SRC1[], uint8_t SRC2[], uint32_t len) {
	uint32_t i;

	for(i = 0; i < len; i++) {
		DST[i / 8] |= (SRC1[i / 8] & (128 >> (i % 8) )) ^ (SRC2[i / 8] & (128 >> (i % 8) ));
	}
}

/**
 * logical AND two bit arrays
 *
 * @param 	DST			the array to save the result in
 * @param 	SRC1		the array to compare with
 * @param 	SRC2		the array to compare with
 * @param 	len			the number of consecutive bits to compare
 *
 */
static void and_bits(uint8_t DST[], uint8_t SRC1[], uint8_t SRC2[], uint32_t len) {
	uint32_t i;

	for(i = 0; i < len; i++) {
		DST[i / 8] |= (SRC1[i / 8] & (128 >> (i % 8) )) & (SRC2[i / 8] & (128 >> (i % 8) ));
	}
}

/**
 * print a bitmap
 *
 * @param bitmap		the bit array
 * @param len			the number of consecutive bits to print
 *
 */
static void print_bitmap(uint8_t bitmap[], uint32_t length) {
	uint32_t i;
	for (i = 0; i < length; i++) {
		uint8_t bit = bitmap[i / 8] & 128 >> (i % 8);
		printf("%d ", bit ? 1 : 0);
	}
	printf("\n"); // flush buffer
}

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
static uint16_t get_fcn_value(uint8_t* fragment) {
	uint8_t offset = RULE_SIZE_BITS + DTAG_SIZE_BITS + WINDOW_SIZE_BITS;

	return (uint16_t) get_bits(fragment, offset, FCN_SIZE_BITS);
}

/**
 * get the ALL-1 FCN value
 *
 * @return FCN			the FCN as indicated by the fragment
 *
 * @note   only FCN values up to 16 bits are currently supported
 *
 */
static uint16_t get_max_fcn_value() {
	uint8_t fcn[2] = { 0 };
	set_bits(fcn, 0, FCN_SIZE_BITS);

	return (uint16_t) get_bits(fcn, 0, FCN_SIZE_BITS);
}

/**
 * get the number of zero bits added to the end of the buffer
 *
 * @param byte			the byte to investigate
 *
 * @return padding		the length of the padding
 *
 */
static uint8_t get_padding_length(uint8_t byte) {
	uint8_t counter = 0; uint8_t i;
	for(i = 0; i < 8; i++) {
		if( !(byte & 1 << (i % 8)) ) {
			counter++;
		} else {
			break;
		}
	}

	return counter;
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
	uint16_t i;
	for(i = 0; i < SCHC_CONF_MBUF_POOL_LEN; i++) {
		if(MBUF_POOL[i].len == 0 && MBUF_POOL[i].ptr == NULL) {
			break;
		}
	}

	if(i == SCHC_CONF_MBUF_POOL_LEN) {
		DEBUG_PRINTF("mbuf_push(): no free mbuf slots found");
		return SCHC_FAILURE;
	}

	DEBUG_PRINTF("mbuf_push(): selected mbuf slot %d", i);

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
 *
 * @return tail			the last mbuf in the linked list
 */
static schc_mbuf_t* get_mbuf_tail(schc_mbuf_t *head) {
	schc_mbuf_t *curr = head;

	while (curr->next != NULL) {
		curr = curr->next;
	}

	return curr;
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
				"head is 0x%x, looking for 0x%x with curr 0x%x, next is 0x%x",
				head, mbuf, curr, curr->next);
		curr = curr->next;
	}

	return curr;
}

/**
 * sort the complete mbuf chain based on fragment counter
 *
 * @param  head			double pointer to the head of the list
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
 * remove the fragmentation headers and
 * concat the data bits of the complete mbuf chain
 *
 * @param  head			double pointer to the head of the list
 *
 */
static void mbuf_format(schc_mbuf_t **head) {
	schc_mbuf_t **curr = &(*head);
		schc_mbuf_t **next = &((*head)->next);
		schc_mbuf_t **prev = NULL;

		uint8_t i = 0; uint8_t counter = 1; uint16_t total_bits_shifted = 0;

		while (*curr != NULL) {
			uint8_t fcn = get_fcn_value((*curr)->ptr);
			uint32_t offset = RULE_SIZE_BITS + DTAG_SIZE_BITS + WINDOW_SIZE_BITS
					+ FCN_SIZE_BITS; uint8_t overflow = 0;


			if(prev == NULL) { // first
				(*curr)->offset = offset - RULE_SIZE_BITS;

				uint8_t rule_id[RULE_SIZE_BYTES] = { 0 }; // get rule id
				copy_bits(rule_id, 0, (*curr)->ptr, 0, RULE_SIZE_BITS);

				shift_bits_left((*curr)->ptr, (*curr)->len, (*curr)->offset); // shift left

				clear_bits((*curr)->ptr, 0, RULE_SIZE_BITS); // set rule id at first position
				copy_bits((*curr)->ptr, 0, rule_id, 0, RULE_SIZE_BITS);

				total_bits_shifted += (*curr)->offset;
			} else { // normal
				if (fcn == get_max_fcn_value()) {
					offset += (MIC_SIZE_BYTES * 8);
					DEBUG_PRINTF("last packet in chain 0x%x \n", *curr);
				}

				int16_t start = ((*prev)->len * 8) - (*prev)->offset;
				int16_t room_left = ((*prev)->len * 8) - start;
				int16_t bits_to_copy = (*curr)->len * 8 - offset;

				// copy (part of) curr buffer to prev
				clear_bits((*prev)->ptr, ((*prev)->len * 8) -  (*prev)->offset, (*prev)->offset);
				copy_bits((*prev)->ptr, ((*prev)->len * 8) -  (*prev)->offset, (*curr)->ptr, offset, (*prev)->offset);

				if(room_left > bits_to_copy) {
					// do not advance pointer and merge prev and curr in one buffer
					(*prev)->offset = start + offset;
					if((*curr)->next != NULL) {
						(*prev)->next = (*curr)->next;
						curr = next;
					}
					overflow = 1;
				} else {
					// shift bits left
					shift_bits_left((*curr)->ptr, (*curr)->len, offset + (*prev)->offset); // shift left to remove headers and bits that were copied
					overflow = 0;
				}

				(*curr)->offset = offset + (*prev)->offset;
			}

			if(!overflow) { // do not advance prev if this contains parts of 3 fragments
				if(prev != NULL) {
					prev = &(*prev)->next; // could be that we skipped a buffer
				} else {
					prev = curr;
				}
			}

			i++;

			curr = next; // advance both pointer-pointers
			next = &(*next)->next;
		}
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
		// DEBUG_PRINTF("%d: 0x%X", curr->frag_cnt, curr->ptr);
		DEBUG_PRINTF("0x%X", curr);
		for (j = 0; j < curr->len; j++) {
			printf("0x%02X ", curr->ptr[j]);
		}
		printf("\n");
		curr = curr->next;
		i++;
	}
}


/**
 * Returns the number of bits the current header exists off
 *
 * @param  mbuf 		the mbuf to find th offset for
 *
 * @return length 		the length of the header
 *
 */
static uint32_t get_header_length(schc_mbuf_t *mbuf) {
	uint32_t offset = RULE_SIZE_BITS + DTAG_SIZE_BITS + WINDOW_SIZE_BITS
			+ FCN_SIZE_BITS;

	uint8_t fcn = get_fcn_value(mbuf->ptr);

	if (fcn == get_max_fcn_value()) {
		offset += (MIC_SIZE_BYTES * 8);
	}

	return offset;
}

/**
 * Calculates the Message Integrity Check (MIC) over an unformatted mbuf chain
 * which is the 8- 16- or 32- bit Cyclic Redundancy Check (CRC)
 *
 * @param  head			the head of the list
 *
 * @return checksum 	the computed checksum
 *
 */
static unsigned int mbuf_compute_mic(schc_fragmentation_t *conn) {
	schc_mbuf_t *curr = conn->head;
	schc_mbuf_t *prev = NULL;

	int i, j, k;
	uint32_t offset = 0;
	uint8_t first = 1;
	uint16_t len;
	uint8_t start, rest, byte;
	uint8_t prev_offset = 0;
	uint32_t crc, crc_mask;

	crc = 0xFFFFFFFF;

	while (curr != NULL) {
		uint8_t fcn = get_fcn_value(curr->ptr);
		uint8_t cont = 1;
		offset = (get_header_length(curr) + prev_offset);

		i = offset;
		len = (curr->len * 8);
		start = offset / 8;
		rest = offset % 8;
		j = start;

		while (cont) {
			if (prev == NULL && first) { // first
				byte = (curr->ptr[0] << (8 - RULE_SIZE_BITS))
						| (curr->ptr[1] >> RULE_SIZE_BITS);
				first = 0;
			} else {
				i += 8;
				if (i >= len) {
					prev_offset = (i - len);
					if (curr->next != NULL) {
						uint32_t next_offset = get_header_length(curr->next);
						uint8_t start_next = next_offset / 8;

						uint32_t mask = get_bit_mask(rest);
						byte = (curr->ptr[j] << rest)
								| (curr->next->ptr[start_next] & mask);
					}
					cont = 0;
				} else {
					byte = (curr->ptr[j] << rest)
							| (curr->ptr[j + 1] >> (8 - rest));
				}

				j++;
			}
			if (fcn != get_max_fcn_value()) { // this has something to do with the padding added to the end??
				crc = crc ^ byte;
				for (k = 7; k >= 0; k--) {    // do eight times.
					crc_mask = -(crc & 1);
					crc = (crc >> 1) ^ (0xEDB88320 & crc_mask);
				}
				// DEBUG_PRINTF("0x%02X ", byte);
			}
		}

		prev = curr;
		curr = curr->next;
	}

	crc = ~crc;
	uint8_t mic[MIC_SIZE_BYTES] = { ((crc & 0xFF000000) >> 24),
			((crc & 0xFF0000) >> 16), ((crc & 0xFF00) >> 8), ((crc & 0xFF)) };

	memcpy((uint8_t *) conn->mic, mic, MIC_SIZE_BYTES);

	DEBUG_PRINTF("compute_mic(): MIC is %02X%02X%02X%02X \n", mic[0], mic[1], mic[2],
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
static unsigned int compute_mic(schc_fragmentation_t *conn) {
	int i, j; uint8_t byte;
	unsigned int crc, mask;

	// ToDo
	// check conn->mic length
	// and calculate appropriate crc

	i = 0;
	crc = 0xFFFFFFFF;

	uint16_t len = (conn->tail_ptr - conn->data_ptr);

	while (i < len) {
		byte = conn->data_ptr[i];
		crc = crc ^ byte;
		for (j = 7; j >= 0; j--) {    // do eight times.
			mask = -(crc & 1);
			crc = (crc >> 1) ^ (0xEDB88320 & mask);
		}
		i++;
	}

	crc = ~crc;
	uint8_t mic[MIC_SIZE_BYTES] = { ((crc & 0xFF000000) >> 24), ((crc & 0xFF0000) >> 16),
			((crc & 0xFF00) >> 8), ((crc & 0xFF)) };

	memcpy((uint8_t *) conn->mic, mic, MIC_SIZE_BYTES);

	DEBUG_PRINTF("compute_mic(): MIC for device %d is %02X%02X%02X%02X \n",
			conn->device_id, mic[0], mic[1], mic[2], mic[3]);

	return crc;
}

/**
 * set the fragmentation bit in the layered rule id
 *
 * @param conn 			a pointer to the connection
 *
 * @return rule_id		a pointer to a buffer containing the rule id
 *
 */
static void set_fragmentation_bit(schc_fragmentation_t* conn) {
	// set fragmentation bit to 1
	set_bits(conn->rule_id, FRAG_POS, 1);
}

/**
 * get the window bit
 *
 * @param fragment		a pointer to the fragment to retrieve the window number from
 *
 * @return window		the window number as indicated by the fragment
 *
 */
static uint8_t get_window_bit(uint8_t* fragment) {
	uint8_t offset = RULE_SIZE_BITS + DTAG_SIZE_BITS;

	return (uint8_t) get_bits(fragment, offset, WINDOW_SIZE_BITS);
}

/**
 * get the MIC value
 *
 * @param  fragment		a pointer to the fragment to retrieve the MIC from
 * @param  mic
 *
 */
static void get_received_mic(uint8_t* fragment, uint8_t mic[]) {
	uint8_t offset = RULE_SIZE_BITS + DTAG_SIZE_BITS + WINDOW_SIZE_BITS + FCN_SIZE_BITS;

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
	uint8_t value = get_max_fcn_value() - frag - 1;
	if(frag == get_max_fcn_value()) {
		value = get_max_fcn_value();
	}

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
	if (!conn->data_ptr) {
		DEBUG_PRINTF(
				"init_connection(): no pointer to compressed packet given");
		return 0;
	}
	if (!conn->mtu) {
		DEBUG_PRINTF("init_connection(): no mtu specified");
		return 0;
	}
	if (conn->mtu > MAX_MTU_LENGTH) {
		DEBUG_PRINTF(
				"init_connection(): MAX_MTU_LENGTH should be set according to conn->mtu");
		return 0;
	}
	if (!conn->packet_len) {
		DEBUG_PRINTF("init_connection(): packet_length not specified");
		return 0;
	}
	if(conn->packet_len < conn->mtu) {
		DEBUG_PRINTF("init_connection(): no fragmentation needed");
		return -1;
	}
	if (conn->send == NULL) {
		DEBUG_PRINTF("init_connection(): no send function specified");
		return 0;
	}
	if (conn->post_timer_task == NULL) {
		DEBUG_PRINTF("init_connection(): no timer function specified");
		return 0;
	}

	memcpy(conn->rule_id, (uint8_t*) (conn->data_ptr + 0), RULE_SIZE_BYTES); // set rule id
	// set_fragmentation_bit(conn); // set fragmentation bit in the rule id

	conn->tail_ptr = (uint8_t*) (conn->data_ptr + conn->packet_len); // set end of packet

	conn->window = 0;
	conn->window_cnt = 0;
	memset(conn->bitmap, 0, BITMAP_SIZE_BYTES); // clear bitmap
	conn->fcn = MAX_WIND_FCN;
	conn->frag_cnt = 0;
	conn->attempts = 0;

	compute_mic(conn); // calculate MIC over compressed, unfragmented packet

	return 1;
}

/**
 * reset a connection
 *
 * @param conn 			a pointer to the connection to reset
 *
 */
static void reset_connection(schc_fragmentation_t* conn) {
	/* reset connection variables */
	conn->mtu = 0;
	conn->fcn = 0;
	conn->data_ptr = 0;
	conn->tail_ptr = 0;
	conn->device_id = 0;
	conn->packet_len = 0;
	conn->dtag = 0;
	conn->window = 0;
	conn->window_cnt = 0;
	conn->dc = 0;
	conn->frag_cnt = 0;
	conn->attempts = 0;
	conn->timer_flag = 0;
	memset(conn->rule_id, 0, RULE_SIZE_BYTES);
	memset(conn->mic, 0, MIC_SIZE_BYTES);
	memset(conn->bitmap, 0, BITMAP_SIZE_BYTES);
	/* reset function callbacks */
	conn->send = NULL;
	conn->post_timer_task = NULL;
	conn->TX_STATE = INIT_TX;
	conn->RX_STATE = RECV_WINDOW;
	/* reset ack structure */
	memset(conn->ack.bitmap, 0, BITMAP_SIZE_BYTES);
	memset(conn->ack.window, 0, 1);
	memset(conn->ack.dtag, 0, 1);
	conn->ack.mic = 0;
	conn->head = NULL;
}

/**
 * check if a connection has more fragments to deliver
 *
 * @param conn 					a pointer to the connection
 *
 * @return	0					the connection still has fragments to send
 * 			total_bit_offset	the total bit offset inside the packet
 *
 */
static uint32_t has_no_more_fragments(schc_fragmentation_t* conn) {
	uint8_t total_fragments = ((conn->tail_ptr - conn->data_ptr) / conn->mtu);

	if (conn->frag_cnt > total_fragments) { // this is the last packet
		uint16_t bit_offset = RULE_SIZE_BITS + DTAG_SIZE_BITS + WINDOW_SIZE_BITS
				+ FCN_SIZE_BITS + (MIC_SIZE_BYTES * 8); // fragmentation header bits
		uint32_t total_bit_offset = ((conn->mtu * 8)
				- (RULE_SIZE_BITS + DTAG_SIZE_BITS + WINDOW_SIZE_BITS
						+ FCN_SIZE_BITS)) * (conn->frag_cnt - 1); // packet bit offset
		uint16_t total_byte_offset = total_bit_offset / 8;
		uint8_t remaining_bit_offset = total_bit_offset % 8;

		uint16_t packet_len = conn->tail_ptr - (conn->data_ptr
				+ total_byte_offset)
				+ (ceil((bit_offset + remaining_bit_offset) / 8));

		if (packet_len <= conn->mtu) { // if fragmentation header is small enough
			return total_bit_offset;
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
	uint8_t bit_offset = RULE_SIZE_BITS;

	 // set rule id
	copy_bits(fragmentation_buffer, 0, conn->rule_id, 0, bit_offset);

	// set dtag field
	uint8_t dtag[1] = { conn->dtag << (8 - DTAG_SIZE_BITS) };
	copy_bits(fragmentation_buffer, bit_offset, dtag, 0, DTAG_SIZE_BITS); // right after rule id

	bit_offset += DTAG_SIZE_BITS;

	// set window bit
	uint8_t window[1] = { conn->window << (8 - WINDOW_SIZE_BITS) };
	copy_bits(fragmentation_buffer, bit_offset, window, 0, WINDOW_SIZE_BITS); // right after dtag

	bit_offset += WINDOW_SIZE_BITS;

	// set fcn value
	uint8_t fcn[1] = { conn->fcn << (8 - FCN_SIZE_BITS) };
	copy_bits(fragmentation_buffer, bit_offset, fcn, 0, FCN_SIZE_BITS); // right after window bits

	bit_offset += FCN_SIZE_BITS;

	if (has_no_more_fragments(conn)) { // all-1 fragment
		// shift in MIC
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
	DEBUG_PRINTF("set_local_bitmap(): fcn is %d \n", conn->fcn);
	set_bits(conn->bitmap, conn->frag_cnt, 1);
	print_bitmap(conn->bitmap, MAX_WIND_FCN + 1);
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
 *
 */
static uint8_t is_bitmap_full(schc_fragmentation_t* conn) {
	uint8_t i;
	for (i = 0; i < MAX_WIND_FCN; i++) {
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
static uint8_t get_next_fragment_from_bitmap(schc_fragmentation_t* conn) {
	uint32_t i;

	for (i = conn->frag_cnt; i <= MAX_WIND_FCN; i++) {
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
static void discard_fragment() {
	// todo
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
	DEBUG_PRINTF("abort_connection(): inactivity timer expired");
	// conn->RX_STATE = END_RX;
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
	DEBUG_PRINTF("set_retrans_timer(): for %d ms", conn->dc * 4);
	conn->post_timer_task(&schc_fragment, conn->device_id, conn->dc * 4, conn);
}

/**
 * sets the duty cycle timer to re-enter the fragmentation loop
 *
 * @param conn 			a pointer to the connection
 *
 */
static void set_dc_timer(schc_fragmentation_t* conn) {
	DEBUG_PRINTF("set_dc_timer(): for %d ms", conn->dc);
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
	DEBUG_PRINTF("set_inactivity_timer(): for %d ms", conn->dc);
	conn->post_timer_task(&schc_reassemble, conn->device_id, conn->dc, conn);
}

/**
 * composes a packet based on the type of the packet
 * and calls the callback function to transmit the packet
 *
 * @param conn 			a pointer to the connection
 *
 */
static void send_fragment(schc_fragmentation_t* conn) {
	// set and reset buffer
	memset(fragmentation_buffer, 0, MAX_MTU_LENGTH);

	// set fragmentation header
	uint16_t header_offset = set_fragmentation_header(conn, fragmentation_buffer);

	uint16_t packet_bit_offset = has_no_more_fragments(conn);
	uint16_t packet_len = 0; uint16_t total_byte_offset; uint8_t remaining_bit_offset;

	if(!packet_bit_offset) { // normal fragment
		packet_len = conn->mtu;
		packet_bit_offset = ((conn->mtu * 8) - header_offset)
				* (conn->frag_cnt - 1); // the number of bits left to copy
	}

	uint32_t packet_bits = ((packet_len * 8) - header_offset);

	total_byte_offset = packet_bit_offset / 8;
	remaining_bit_offset = (packet_bit_offset % 8);

	if (!packet_len) { // all-1 fragment
		packet_bits = (((conn->tail_ptr - conn->data_ptr) * 8)
				- ((total_byte_offset * 8) + remaining_bit_offset))
				- RULE_SIZE_BITS; // rule was not sent and is thus deducted from the total length

		// todo
		// check if last byte contains 0x0
		// because padding is added

		uint8_t padding = (8 - ((header_offset + packet_bits) % 8));
		uint8_t zerobuf[1] = { 0 };
		copy_bits(fragmentation_buffer, header_offset + packet_bits, zerobuf, 0, padding); // add padding

		packet_len = (padding + header_offset + packet_bits) / 8; // last packet length
	}

	copy_bits(fragmentation_buffer, header_offset,
			(conn->data_ptr + total_byte_offset),
			(remaining_bit_offset + RULE_SIZE_BITS), packet_bits); // copy bits

	DEBUG_PRINTF("send_fragment(): sending fragment %d with length %d to device %d",
			conn->frag_cnt, packet_len, conn->device_id);

	conn->send(fragmentation_buffer, packet_len, conn->device_id);
}

/**
 * composes an ack based on the parameters found in the connection
 * and calls the callback function to transmit the packet
 *
 * @param conn 			a pointer to the connection
 *
 */
static void send_ack(schc_fragmentation_t* conn) {
	uint8_t ack[RULE_SIZE_BYTES + DTAG_SIZE_BYTES + BITMAP_SIZE_BYTES] = { 0 };
	uint8_t offset = RULE_SIZE_BITS;

	copy_bits(ack, 0, conn->ack.rule_id, 0, offset); // set rule id
	copy_bits(ack, offset, conn->ack.dtag, 0, DTAG_SIZE_BITS); // set dtag
	offset += DTAG_SIZE_BITS;

	uint8_t window[1] = { conn->window << (8 - WINDOW_SIZE_BITS) }; // set window
	copy_bits(ack, offset, window, 0, WINDOW_SIZE_BITS);
	offset += WINDOW_SIZE_BITS;

	if(conn->ack.fcn == get_max_fcn_value()) { // all-1 window
		uint8_t c[1] = { conn->ack.mic << (8 - MIC_C_SIZE_BITS) }; // set mic c bit
		copy_bits(ack, offset, c, 0, MIC_C_SIZE_BITS);
		offset += MIC_C_SIZE_BITS;
	}

	if(!conn->ack.mic) { // if mic c bit is 0 (zero by default)
		DEBUG_PRINTF("ack.bitmap is");
		print_bitmap(conn->bitmap, (BITMAP_SIZE_BYTES * 8));

		copy_bits(ack, offset, conn->bitmap, 0, (MAX_WIND_FCN + 1)); // copy the bitmap
		offset += (MAX_WIND_FCN + 1); // todo must be encoded
	}

	uint8_t packet_len = ((offset - 1) / 8) + 1;
	DEBUG_PRINTF("send_ack(): sending ack to device %d for fragment %d with length %d (%d b)",
			conn->device_id, conn->frag_cnt, packet_len, offset);
	print_bitmap(ack, offset);
	conn->send(ack, packet_len, conn->device_id);
}

/**
 * composes an all-empty fragment based on the parameters
 * found in the connection
 * and calls the callback function to transmit the packet
 *
 * @param conn 			a pointer to the connection
 *
 */
static void send_empty(schc_fragmentation_t* conn) {
	// set and reset buffer
	memset(fragmentation_buffer, 0, MAX_MTU_LENGTH);

	// set fragmentation header
	uint16_t header_offset = set_fragmentation_header(conn, fragmentation_buffer);

	uint8_t padding = header_offset % 8;
	uint8_t zerobuf[1] = { 0 };
	copy_bits(fragmentation_buffer, header_offset, zerobuf, 0, padding); // add padding

	uint8_t packet_len = (padding + header_offset) / 8;

	DEBUG_PRINTF("send_empty(): sending all-x empty to device %d with length %d (%d b)",
			conn->device_id, packet_len, header_offset);

	conn->send(fragmentation_buffer, packet_len, conn->device_id);

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
	uint8_t i; schc_fragmentation_t *conn;
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
		DEBUG_PRINTF("schc_get_connection(): selected connection %d for device %d", i, device_id);
	}

	return conn;
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

	copy_bits(rx_conn->ack.rule_id, 0, tail->ptr, 0, RULE_SIZE_BITS); // set the connection it's rule id
	uint8_t window = get_window_bit(tail->ptr); // the window bit from the fragment
	uint8_t fcn = get_fcn_value(tail->ptr); // the fcn value from the fragment
	DEBUG_PRINTF("fcn is %d, window is %d", fcn, window);
	rx_conn->ack.fcn = fcn;

	set_conn_frag_cnt(rx_conn, fcn); // set rx_conn->frag_cnt

	if (window == (!rx_conn->window)) {
		DEBUG_PRINTF("window_cnt++ \n");
		rx_conn->window_cnt++;
	}
	tail->frag_cnt = (rx_conn->frag_cnt + (get_max_fcn_value() * rx_conn->window_cnt)); // set frag_cnt belonging to mbuf

	if(rx_conn->RX_STATE != END_RX) {
		set_inactivity_timer(rx_conn);
	}

	switch (rx_conn->RX_STATE) {
	case RECV_WINDOW: {
		DEBUG_PRINTF("RECV WINDOW");
		if(rx_conn->timer_flag && !rx_conn->fragment_input) { // inactivity timer expired
			abort_connection(rx_conn); break;
		}
		if(rx_conn->window != window) { // unexpected window
			DEBUG_PRINTF("w != window");
			discard_fragment();
			rx_conn->RX_STATE = RECV_WINDOW;
		} else if(window == rx_conn->window) { // expected window
			set_local_bitmap(rx_conn); // indicate that we received a fragment
			DEBUG_PRINTF("w == window");
			if(fcn != 0 && fcn != get_max_fcn_value()) { // not all-x
				DEBUG_PRINTF("not all-x");
				rx_conn->RX_STATE = RECV_WINDOW;
			} else if(fcn == 0) { // all-0
				DEBUG_PRINTF("all-0");
				rx_conn->RX_STATE = WAIT_NEXT_WINDOW;
				rx_conn->ack.mic = 0; // bitmap will be sent when c = 0
				send_ack(rx_conn); // send local bitmap
			} else if(fcn == get_max_fcn_value()) { // all-1
				DEBUG_PRINTF("all-1");
				get_received_mic(tail->ptr, recv_mic);

				mbuf_sort(&rx_conn->head); // sort the mbuf chain
				mbuf_print(rx_conn->head);
				mbuf_compute_mic(rx_conn); // compute the mic over the mbuf chain

				if (!compare_bits(rx_conn->mic, recv_mic,
						(MIC_SIZE_BYTES * 8))) { // mic wrong
					rx_conn->RX_STATE = WAIT_END;
					rx_conn->ack.mic = 0;
				} else { // mic right
					rx_conn->RX_STATE = END_RX;
					rx_conn->ack.mic = 1;
				}
				send_ack(rx_conn);
			}
		}
		break;
	}
	case WAIT_NEXT_WINDOW: {
		DEBUG_PRINTF("WAIT NEXT WINDOW");
		if(rx_conn->timer_flag && !rx_conn->fragment_input) { // inactivity timer expired
			abort_connection(rx_conn); break;
		}
		if (window == (!rx_conn->window)) { // next window
			DEBUG_PRINTF("w != window");
			if(fcn != 0 && fcn != get_max_fcn_value()) { // not all-x
				DEBUG_PRINTF("not all-x");
				rx_conn->window = !rx_conn->window; // set expected window to next window
				clear_bitmap(rx_conn);
				set_local_bitmap(rx_conn);
				rx_conn->RX_STATE = RECV_WINDOW; // return to receiving window
			} else if(fcn == 0) { // all-0
				DEBUG_PRINTF("all-0");
				rx_conn->window = !rx_conn->window;
				clear_bitmap(rx_conn);
				set_local_bitmap(rx_conn);
				rx_conn->ack.mic = 0; // bitmap will be sent when c = 0
				send_ack(rx_conn);
			} else if(fcn == get_max_fcn_value()) { // all-1
				DEBUG_PRINTF("all-1");
				get_received_mic(tail->ptr, recv_mic);

				mbuf_sort(&rx_conn->head); // sort the mbuf chain
				mbuf_print(rx_conn->head);
				mbuf_compute_mic(rx_conn->head); // compute the mic over the mbuf chain

				if (!compare_bits(rx_conn->mic, recv_mic,
						(MIC_SIZE_BYTES * 8))) { // mic wrong
					rx_conn->RX_STATE = WAIT_END;
					rx_conn->ack.mic = 0;
				} else { // mic right
					rx_conn->RX_STATE = END_RX;
					rx_conn->ack.mic = 1;
				}
				set_local_bitmap(rx_conn);
				send_ack(rx_conn);
			}
		} else if(window == rx_conn->window) { // expected window
			DEBUG_PRINTF("w == window");
			if(fcn == 0) { // all-0
				DEBUG_PRINTF("all-0");
				rx_conn->RX_STATE = WAIT_NEXT_WINDOW;
				rx_conn->ack.mic = 0; // bitmap will be sent when c = 0
				send_ack(rx_conn);
			} else if(fcn == get_max_fcn_value()) { // all-1
				DEBUG_PRINTF("all-1");
				rx_conn->RX_STATE = WAIT_NEXT_WINDOW;
				discard_fragment();
			} else if(fcn != 0 && fcn != get_max_fcn_value()) { // not all-x
				set_local_bitmap(rx_conn);
				DEBUG_PRINTF("not all-x, bitmap is full? %d", is_bitmap_full(rx_conn));
				rx_conn->RX_STATE = WAIT_NEXT_WINDOW;
				if(is_bitmap_full(rx_conn)) { // bitmap is full, i.e. the last fragment is received
					rx_conn->ack.mic = 0; // bitmap will be sent when c = 0
					send_ack(rx_conn);
				}
			}
		}
		break;
	}
	case WAIT_END: {
		DEBUG_PRINTF("WAIT END");
		if(rx_conn->timer_flag && !rx_conn->fragment_input) { // inactivity timer expired
			abort_connection(rx_conn); break;
		}
		get_received_mic(tail->ptr, recv_mic);

		mbuf_sort(&rx_conn->head); // sort the mbuf chain
		mbuf_print(rx_conn->head);
		mbuf_compute_mic(rx_conn->head); // compute the mic over the mbuf chain

		if (!compare_bits(rx_conn->mic, recv_mic, (MIC_SIZE_BYTES * 8))) { // mic wrong
			rx_conn->ack.mic = 0;
			rx_conn->RX_STATE = WAIT_END;
			if (window == rx_conn->window) { // expected window
				set_local_bitmap(rx_conn);
			}
			if (fcn == get_max_fcn_value()) { // all-1
				DEBUG_PRINTF("all-1");
				send_ack(rx_conn);
			}
		} else { // mic right
			if (window == rx_conn->window) { // expected window
				rx_conn->RX_STATE = END_RX;
				rx_conn->ack.mic = 1;
				set_local_bitmap(rx_conn);
				send_ack(rx_conn);
			}
		}

	} break;
	case END_RX: {
		DEBUG_PRINTF("END RX");
		if (fcn != get_max_fcn_value()) { // not all-1
			DEBUG_PRINTF("not all-x");
			discard_fragment();
		} else { // all-1
			DEBUG_PRINTF("all-1");
			send_ack(rx_conn);
			mbuf_sort(&rx_conn->head); // sort the mbuf chain
			mbuf_format(&rx_conn->head); // remove headers to pass to application
		}
		break;
	}
	}

	DEBUG_PRINTF("BITMAP: ");
	print_bitmap(rx_conn->bitmap, (get_max_fcn_value() + 1));
	rx_conn->fragment_input = 0;

	// todo
	// after each fragment has been received
	// the inactivity timer should be initialized

	// ToDo
	// free connection if last fragment
	// set the mbuf chain (len & ptr) to 0
	// set head to NULL
	// SHOULD BE DONE BY APPLICATION
	// notify application about last fragment
	// then application should loop over mbuf chain
	// create a new packet
	// forward to the network
	// and free buffers
	// by calling mbuf_chain_free()

	return 0;
}

/**
 * Initializes the SCHC fragmenter
 *
 * @param tx_conn		a pointer to the tx initialization structure
 *
 * @return error codes on error
 *
 */
int8_t schc_fragmenter_init(schc_fragmentation_t* tx_conn,
		void (*send)(uint8_t* data, uint16_t length, uint32_t device_id)) {
	uint32_t i;

	// initializes the schc tx connection
	reset_connection(tx_conn);

	// initializes the schc rx connections
	for (i = 0; i < SCHC_CONF_RX_CONNS; i++) {
		reset_connection(&schc_rx_conns[i]);
		schc_rx_conns[i].send = send;
		schc_rx_conns[i].frag_cnt = 0;
		schc_rx_conns[i].window_cnt = 0;
		schc_rx_conns[i].fragment_input = 0;
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
	DEBUG_PRINTF("schc_fragment(): timer flag %d", tx_conn->timer_flag);
	switch(tx_conn->TX_STATE) {
	case INIT_TX: {
		DEBUG_PRINTF("INIT_TX");
		int8_t ret = init_tx_connection(tx_conn);
		if (!ret) {
			return SCHC_FAILURE;
		} else if (ret < 0) {
			tx_conn->send(tx_conn->data_ptr,
					(tx_conn->tail_ptr - tx_conn->data_ptr),
					tx_conn->device_id); // send packet right away
			return SCHC_NO_FRAGMENTATION;
		}
		tx_conn->TX_STATE = SEND;
		schc_fragment(tx_conn);
		break;
	}
	case SEND: {
		DEBUG_PRINTF("SEND, fcn is %d", tx_conn->fcn);

		set_local_bitmap(tx_conn);
		tx_conn->frag_cnt++;

		if(has_no_more_fragments(tx_conn)) {
			DEBUG_PRINTF("schc_fragment(): all-1 window");
			tx_conn->fcn = (pow(2, FCN_SIZE_BITS) - 1); // all 1-window
			tx_conn->TX_STATE = WAIT_BITMAP;
			set_retrans_timer(tx_conn);
			send_fragment(tx_conn);
		} else if(tx_conn->fcn == 0 && !has_no_more_fragments(tx_conn)) { // all-0 window
			DEBUG_PRINTF("schc_fragment(): all-0 window");
			tx_conn->TX_STATE = WAIT_BITMAP;
			send_fragment(tx_conn);
			tx_conn->fcn = MAX_WIND_FCN; // reset the FCN
			set_retrans_timer(tx_conn);
		} else if(tx_conn->fcn != 0 && !has_no_more_fragments(tx_conn)) { // normal fragment
			DEBUG_PRINTF("schc_fragment(): normal fragment");
			tx_conn->TX_STATE = SEND;
			send_fragment(tx_conn);
			tx_conn->fcn--;
			set_dc_timer(tx_conn);
		}

		break;
	}
	case WAIT_BITMAP: {
		DEBUG_PRINTF("WAIT_BITMAP");
		uint8_t resend_window[BITMAP_SIZE_BYTES] = { 0 }; // if ack.bitmap is all-0, there are no packets to retransmit

		DEBUG_PRINTF("resend_window");
		print_bitmap(resend_window, (MAX_WIND_FCN + 1));

		DEBUG_PRINTF("LOCAL BITMAP");
		print_bitmap(tx_conn->bitmap, (MAX_WIND_FCN + 1));

		DEBUG_PRINTF("tx_conn->ack.bitmap");
		print_bitmap(tx_conn->ack.bitmap, (MAX_WIND_FCN + 1));

		if ((tx_conn->ack.window[0] == tx_conn->window)
				&& compare_bits(resend_window, tx_conn->ack.bitmap,
						(MAX_WIND_FCN + 1))) {
			DEBUG_PRINTF("w == w && bitmap = local bitmap");
			if (!has_no_more_fragments(tx_conn)) { // no missing fragments & more fragments
				DEBUG_PRINTF("no missing fragments & more fragments to come");
				tx_conn->timer_flag = 0; // stop retransmission timer
				clear_bitmap(tx_conn);
				tx_conn->window = !tx_conn->window; // change window
				tx_conn->window_cnt++;
				tx_conn->TX_STATE = SEND;
				schc_fragment(tx_conn);
			} else if (has_no_more_fragments(tx_conn) && tx_conn->ack.mic) {
				DEBUG_PRINTF("no more fragments, MIC ok");
				tx_conn->timer_flag = 0;
				tx_conn->TX_STATE = END_TX;
				schc_fragment(tx_conn);
			}
			break;
		}
		else if (tx_conn->ack.window[0] != tx_conn->window) { // unexpected window
			DEBUG_PRINTF("w != w, discard fragment"); // todo
			discard_fragment();
			tx_conn->TX_STATE = WAIT_BITMAP;
		}

		if (tx_conn->attempts >= MAX_ACK_REQUESTS) {
			DEBUG_PRINTF("tx_conn->attempts >= MAX_ACK_REQUESTS: send abort"); // todo
			tx_conn->TX_STATE = ERROR;
			tx_conn->timer_flag = 0; // stop retransmission timer
			schc_fragment(tx_conn);
		}

		else if (!compare_bits(resend_window, tx_conn->ack.bitmap,
				(MAX_WIND_FCN + 1))) { //ack.bitmap contains the missing fragments
			DEBUG_PRINTF("bitmap contains the missing fragments");
			tx_conn->attempts++;
			tx_conn->frag_cnt = 0;
			tx_conn->timer_flag = 0; // stop retransmission timer
			tx_conn->TX_STATE = RESEND;
			schc_fragment(tx_conn);
		}
		if (tx_conn->timer_flag) { // timer expired
			DEBUG_PRINTF("timer expired"); // todo
			tx_conn->attempts++;
			set_retrans_timer(tx_conn);
			send_empty(tx_conn); // requests retransmission of all-x ack with empty all-x
		}
		// else if() { // mic and bitmap check succeeded
		  //tx_conn->TX_STATE = END_TX;
		  //}
		break;
	}
	case RESEND: {
		DEBUG_PRINTF("RESEND");
		// get the next fragment offset
		tx_conn->frag_cnt = get_next_fragment_from_bitmap(tx_conn); // send_fragment() uses frag_cnt to transmit a particular fragment
		if (!tx_conn->frag_cnt) { // no more missing fragments to send
			DEBUG_PRINTF("no more missing fragments to send");
			clear_bitmap(tx_conn);
			tx_conn->TX_STATE = WAIT_BITMAP;
			tx_conn->frag_cnt = (tx_conn->window_cnt + 1) * (MAX_WIND_FCN + 1);
			set_retrans_timer(tx_conn);
		} else {
			DEBUG_PRINTF("schc_fragment(): sending missing fragments for bitmap: ");
			print_bitmap(tx_conn->ack.bitmap, (MAX_WIND_FCN + 1));
			tx_conn->fcn = ((MAX_WIND_FCN + 1) * (tx_conn->window_cnt + 1))
					- tx_conn->frag_cnt;
			tx_conn->TX_STATE = RESEND;
			send_fragment(tx_conn); // retransmit the fragment
			set_dc_timer(tx_conn);
		}
		break;
	}
	case END_TX: {
		DEBUG_PRINTF("schc_fragment(): end transmission cycle");
		tx_conn->timer_flag = 0;
		// ToDo
		// stay alive to answer empty all-1 fragments, indicating lost ack(s)
		return SCHC_SUCCESS;
	}
	case ERROR: {
		DEBUG_PRINTF("ERROR");
	}
	}

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
	if ( (tx_conn->TX_STATE == WAIT_BITMAP || tx_conn->TX_STATE == RESEND)
					&& compare_bits(tx_conn->rule_id, data, RULE_SIZE_BITS)) { // acknowledgment
		schc_ack_input(data, len, tx_conn, device_id);
		return tx_conn;
	} else {
		schc_fragmentation_t* rx_conn = schc_fragment_input((uint8_t*) data, len, device_id);
		return rx_conn;
	}

	// todo
	// how to return if last fragment received??
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
	uint8_t bit_offset = RULE_SIZE_BITS;

	copy_bits(tx_conn->ack.dtag, (8 - DTAG_SIZE_BITS), (uint8_t*) data,
			bit_offset, DTAG_SIZE_BITS); // get dtag
	bit_offset += DTAG_SIZE_BITS;

	copy_bits(tx_conn->ack.window, (8 - WINDOW_SIZE_BITS), (uint8_t*) data,
			bit_offset, WINDOW_SIZE_BITS); // get window
	bit_offset += WINDOW_SIZE_BITS;

	if(has_no_more_fragments(tx_conn)) {
		uint8_t mic[1] = { 0 };
		copy_bits(mic, 7, (uint8_t*) data, bit_offset, 1);
		bit_offset += 1;
		tx_conn->ack.mic = mic[0];
		if(mic[0]) { // do not process bitmap
			schc_fragment(tx_conn);
			return;
		}
	}

	// ToDo
	// decode_bitmap(tx_conn);
	uint8_t fcn_bits = ((MAX_WIND_FCN / 8) + 1) * 8;
	copy_bits(tx_conn->ack.bitmap, 0, (uint8_t*) data, bit_offset,
			(MAX_WIND_FCN + 1));

	DEBUG_PRINTF("ACK BITMAP");
	print_bitmap(tx_conn->ack.bitmap, (MAX_WIND_FCN + 1));

	DEBUG_PRINTF("BITMAP");
	print_bitmap(tx_conn->bitmap, (MAX_WIND_FCN + 1));


	// copy bits for retransmit bitmap to intermediate buffer
	uint8_t resend_window[BITMAP_SIZE_BYTES] = { 0 };
	xor_bits(resend_window, tx_conn->bitmap, tx_conn->ack.bitmap,
			(MAX_WIND_FCN + 1)); // to indicate which fragments to retransmit

	DEBUG_PRINTF("RESEND WINDOW");
	print_bitmap(resend_window, (MAX_WIND_FCN + 1));

	// copy retransmit bitmap for current window to ack.bitmap
	memset(tx_conn->ack.bitmap, 0, BITMAP_SIZE_BYTES);
	copy_bits(tx_conn->ack.bitmap, 0, resend_window, 0, (MAX_WIND_FCN + 1));

	DEBUG_PRINTF("BITMAP");
	print_bitmap(tx_conn->ack.bitmap, (MAX_WIND_FCN + 1));

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
 * @param 	tx_conn			a pointer to the tx initialization structure
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
		DEBUG_PRINTF("schc_fragment_input(): no free connections found!");
		return NULL;
	}

	uint8_t* fragment;
#if DYNAMIC_MEMORY
	fragment = (uint8_t*) malloc(len); // allocate memory for fragment
#else
	fragment = (uint8_t*) (schc_buf + buf_ptr); // take fixed memory block
	buf_ptr += len;
#endif

	memcpy(fragment, data, len);

	int8_t err = mbuf_push(&conn->head, fragment, len);
	if(err != SCHC_SUCCESS) {
		return NULL;
	}

	conn->fragment_input = 1; // set fragment input to 1, to distinguish between inactivity callbacks

	return conn;
}

#if CLICK
ELEMENT_PROVIDES(schcFRAGMENTER)
#endif
