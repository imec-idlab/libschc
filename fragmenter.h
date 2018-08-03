/* (c) 2018 - idlab - UGent - imec
 *
 * Bart Moons
 *
 * This file is part of the SCHC stack implementation
 *
 */

#ifndef __SCHCFRAGMENTER_H__
#define __SCHCFRAGMENTER_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "schc_config.h"

/**
 * Return code: Indicator. Generic indication that a fragment was received
 */
#define SCHC_FRAG_INPUT			2

/**
 * Return code: Indicator. Generic indication that an acknowledgment was received
 */
#define SCHC_ACK_INPUT			1

/**
 * Return code: No error. Indicates successful completion of an SCHC
 * operation.
 */
#define SCHC_SUCCESS 			0

/**
 * Return code: Error. Generic indication that an SCHC operation went wrong
 */
#define SCHC_FAILURE			-1

/**
 * Return code: Error. Generic indication that no fragmentation was needed
 */
#define SCHC_NO_FRAGMENTATION	-2


typedef enum {
	INIT_TX = 0, SEND = 1, RESEND = 2, WAIT_BITMAP = 3, END_TX = 4, ERROR = 5
} tx_state;

typedef enum {
	RECV_WINDOW = 0, WAIT_NEXT_WINDOW = 1, WAIT_END = 2, END_RX = 3, ABORT = 4
} rx_state;

typedef struct schc_mbuf_t {
	/* the selected slot */
	uint8_t slot;
	/* start of memory block */
	uint8_t* ptr;
	/* length of the fragment */
	uint16_t len;
	/* the fragment to which the mbuf belongs to */
	uint8_t frag_cnt;
	/* the bit offset when formatted */
	uint8_t offset;
	/* pointer to the next fragment*/
	struct schc_mbuf_t *next;
} schc_mbuf_t;
	

typedef struct schc_fragmentation_ack_t {
	/* the rule id included in the ack */
	uint8_t rule_id[RULE_SIZE_BYTES];
	/* the encoded bitmap included in the ack */
	uint8_t bitmap[BITMAP_SIZE_BYTES];
	/* the window included in the ack */
	uint8_t window[1];
	/* the DTAG received in the ack */
	uint8_t dtag[1];
	/* the MIC bit received in the ack */
	uint8_t mic;
	/* the fcn value this ack belongs to */
	uint8_t fcn;

} schc_fragmentation_ack_t;

typedef struct schc_fragmentation_t {
	/* the device id of the connection */
	uint32_t device_id;
	/* the length of the packet */
	uint16_t packet_len;
	/* a pointer to the start of the unfragmented, compressed packet */
	const uint8_t* data_ptr;
	/* the start of the packet + the total length */
	const uint8_t* tail_ptr;
	/* the rule which will be applied to the header */
	uint8_t rule_id[RULE_SIZE_BYTES];
	/* the maximum transfer unit of this connection */
	uint16_t mtu;
	/* the duty cycle in ms */
	uint32_t dc;
	/* the message integrity check over the full, compressed packet */
	uint8_t mic[MIC_SIZE_BYTES];
	/* the fragment counter in the current window
	 * ToDo: we only support fixed FCN length
	 * */
	uint8_t fcn;
	/* the current window */
	uint8_t window;
	/* the total number of windows transmitted */
	uint8_t window_cnt;
	/* the current DTAG */
	uint8_t dtag;
	/* the total number of fragments sent */
	uint8_t frag_cnt;
	/* the bitmap of the fragments sent */
	uint8_t bitmap[BITMAP_SIZE_BYTES];
	/* the number of transmission attempts */
	uint8_t attempts;
	/* the current state for the sending device */
	tx_state TX_STATE;
	/* the current state for the receiving device */
	rx_state RX_STATE;
	/* the function to call when the fragmenter has something to send */
	void (*send)(uint8_t* data, uint16_t length);
	/* the timer task */
	void (*post_timer_task)(void (*timer_task)(), uint16_t time_ms, void *arg);
	/* indicates whether the retransmission timer is running */
	uint8_t rtrm_timer_state;
	/* the last received ack */
	schc_fragmentation_ack_t ack;
	/* the start of the mbuf chain */
	schc_mbuf_t *head;
} schc_fragmentation_t;



int8_t schc_fragmenter_init(schc_fragmentation_t* tx_conn, void (*send)(uint8_t* data, uint16_t length));
int8_t schc_fragment(void *c);
int8_t schc_reassemble(schc_fragmentation_t* rx_conn);

int8_t schc_input(uint8_t* data, uint16_t len, schc_fragmentation_t* rx_conn,
		uint8_t device_id);
void schc_ack_input(uint8_t* data, uint16_t len, schc_fragmentation_t* tx_conn,
		uint8_t device_id);
int8_t schc_fragment_input(uint8_t* data, uint16_t len, uint8_t device_id);

#ifdef __cplusplus
}
#endif

#endif
