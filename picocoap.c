
#include <stddef.h>
#include <string.h>
#include "picocoap.h"
#include "config.h"

#if CLICK
#include <click/config.h>
#endif

//
// Getters
//

coap_error coap_validate_pkt(coap_pdu *pdu) //uint8_t *pkt, size_t pkt_len)
{
	coap_error err;
	size_t ol;
	uint8_t *ov;

	if (pdu->len > pdu->max)
		return CE_INVALID_PACKET;

	if (pdu->len < 4)
		return CE_INVALID_PACKET;

	// Check Version
	if (coap_get_version(pdu) != 1)
		return CE_INVALID_PACKET;

	// Check TKL
	if (coap_get_tkl(pdu) > 8)
		return CE_INVALID_PACKET;

	// Check Options
	ov = pdu->buf + 4 + coap_get_tkl(pdu);
	ol = 0;
	while((err = coap_decode_option(ov + ol, pdu->len-(ov-pdu->buf), NULL, &ol, &ov)) != 0){
		if (err == CE_NONE){
			continue;
		} else if (err == CE_END_OF_PACKET){
			break;
		} else if (err == CE_FOUND_PAYLOAD_MARKER){
			// Payload Marker, but No Payload
			if (pdu->len == (ov + ol - pdu->buf)){
				return CE_INVALID_PACKET;
			} else {
				break;
			}
		} else {
			return err;
		}
	}

	return CE_NONE;
}

uint8_t coap_get_token(coap_pdu *pdu, uint8_t* ptr)
{
	uint8_t tkl;

	// Extract TKL.
	tkl = pdu->buf[0] & 0x0F;

	// Check that we were given enough packet.
	if (pdu->len < 4 + tkl)
		return 0;

	// Set token.
	memcpy(ptr, &pdu->buf[4], tkl);

	return 1;
}

coap_option coap_get_option(coap_pdu *pdu, coap_option *last)
{
	uint8_t *opt_ptr;
	coap_option option;
	coap_error err;

	if (last != NULL && last->num != 0){
		option.num = last->num;
		option.len = 0;
		option.val = NULL;

		opt_ptr = last->val + last->len;
	} else {
		option.num = 0;
		option.len = 0;
		option.val = NULL;

		opt_ptr = pdu->buf + 4 + coap_get_tkl(pdu);
	}

	// If opt_ptr is outside pkt range, put it at first opt.
	if (opt_ptr > (pdu->buf + pdu->len) || opt_ptr <= pdu->buf){
		opt_ptr = pdu->buf + 4 + coap_get_tkl(pdu);
	}

	err = coap_decode_option(opt_ptr, pdu->len-(opt_ptr-pdu->buf), &option.num, &option.len, &option.val);

	if (err != CE_NONE){
		if (err == CE_FOUND_PAYLOAD_MARKER){
			if (option.num == 0){
				option.val = opt_ptr + 1;
				option.len = pdu->len-(opt_ptr-pdu->buf) - 1;
			} else {
				option.val = option.val + option.len;
				option.len = pdu->len - (option.val - pdu->buf);
			}
		} else {
			option.val = NULL;
			option.len = 0;
		}
		option.num = 0;
	}

	opt_ptr = option.val + option.len;

	return option;
}


coap_option coap_get_option_by_num(coap_pdu *pdu, coap_option_number num, uint8_t occ)
{
	coap_option option;
	uint8_t i = 0;

	option.num = 0;

	do {
		option = coap_get_option(pdu, &option);

		if (option.num == num) {
			i++;
		} else if (option.num > num) {
			option.num = 0;
			option.len = 0;
			option.val = NULL;
			break;
		} else if (option.num == 0) {
			break;
		}
	} while (i <= occ);

	return option;
}


//
// Decoding Functions (Intended for Internal Use)
//

coap_error coap_decode_option(uint8_t *pkt_ptr, size_t pkt_len,
	                           uint16_t *option_number, size_t *option_length, uint8_t **value)
{
	uint8_t *ptr = pkt_ptr;
	uint16_t delta, length;

	// Check for end of Packet
	if (pkt_len == 0){
		return CE_END_OF_PACKET;
	}

	// Check for Payload Marker
	if (ptr != NULL && *ptr == 0xFF){
		return CE_FOUND_PAYLOAD_MARKER;
	}

	// Get Base Delta and Length
	delta = *ptr >> 4;
	length = *ptr & 0x0F;
	ptr++;

	// Check for and Get Extended Delta
	if (delta < 13) {
		//delta = delta;
	}else if (delta == 13) {
		delta = *ptr + 13;
		ptr += 1;
	}else if (delta == 14) {
		delta = (*ptr << 8) + *(ptr+1) + 269;
		ptr += 2;
	}else{
		return CE_INVALID_PACKET;
	}

	// Check for and Get Extended Length
	if (length < 13) {
		//length = length;
	}else if (length == 13) {
		length = *ptr + 13;
		ptr += 1;
	}else if (length == 14) {
		length = (*ptr << 8) + *(ptr+1) + 269;
		ptr += 2;
	}else{
		return CE_INVALID_PACKET;
	}

	if (option_number != NULL)
		*option_number += delta;

	if (option_length != NULL)
		*option_length = length;

	if (value != NULL)
		*value = ptr;

	return CE_NONE;
}


coap_payload coap_get_payload(coap_pdu *pdu)
{
	
	size_t offset = 4 + coap_get_tkl(pdu);
	coap_option option;
	coap_payload payload;
	coap_error err;

	// Defaults
	payload.len = 0;
	payload.val = NULL;

	// Find Last Option

	do {
		err = coap_decode_option(pdu->buf+offset, pdu->len-offset, NULL, &option.len, &option.val);
		if (err == CE_FOUND_PAYLOAD_MARKER || err == CE_END_OF_PACKET)
			break;

		if (err != CE_NONE)
			return payload;

		// Add this option header and value length to offset.
		offset += (option.val - (pdu->buf+offset)) + option.len;
	} while (1);

	if (err == CE_FOUND_PAYLOAD_MARKER){
		payload.len = pdu->len - offset - 1;
		payload.val = pdu->buf + offset + 1;
	}

	return payload;
}


//
// Setters
//

coap_error coap_init_pdu(coap_pdu *pdu)
{
	// Check that we were given enough packet.
	if (pdu->max < 4)
		return CE_INSUFFICIENT_BUFFER;

	pdu->len = 0;
	memset(pdu->buf, 0, 4);

	coap_set_version(pdu, COAP_V1);
	coap_set_type(pdu, CT_RST);
	uint8_t token[8] = { 0 };
	coap_set_token(pdu, &token, 0);
	coap_set_code(pdu, CC_EMPTY);
	coap_set_mid(pdu, 0);

	return CE_NONE;
}

coap_error coap_set_version(coap_pdu *pdu, coap_version ver)
{
	// Check that we were given enough packet.
	if (pdu->max < 1)
		return CE_INSUFFICIENT_BUFFER;

	pdu->buf[0] = (ver << 6) | (pdu->buf[0] & 0x3F);

	if (pdu->len < 1)
		pdu->len = 1;

	return CE_NONE;
}

coap_error coap_set_type(coap_pdu *pdu, coap_type mtype)
{
	// Check that we were given enough packet.
	if (pdu->max < 1)
		return CE_INSUFFICIENT_BUFFER;

	pdu->buf[0] = (mtype << 4) | (pdu->buf[0] & 0xCF);

	if (pdu->len < 1)
		pdu->len = 1;

	return CE_NONE;
}

coap_error coap_set_code(coap_pdu *pdu, coap_code code)
{
	// Check that we were given enough packet.
	if (pdu->max < 2)
		return CE_INSUFFICIENT_BUFFER;

	pdu->buf[1] = code;

	if (pdu->len < 2)
		pdu->len = 2;

	return CE_NONE;
}

coap_error coap_set_mid(coap_pdu *pdu, uint16_t mid)
{
	// Check that we were given enough packet.
	if (pdu->max < 4)
		return CE_INSUFFICIENT_BUFFER;

	pdu->buf[2] = mid >> 8;
	pdu->buf[3] = mid & 0xFF;

	if (pdu->len < 4)
		pdu->len = 4;

	return CE_NONE;
}

coap_error coap_set_token(coap_pdu *pdu, uint8_t *token, uint8_t tkl)
{
	// Check that we were given enough buffer.
	if (pdu->max < 4 + tkl)
		return CE_INSUFFICIENT_BUFFER;

	// Check token length for spec.
	if (tkl > 8)
		return CE_INVALID_PACKET;

	// Check if we may need to make or take room.
	if (pdu->len > 4){
		// Check that we were given enough buffer.
		if (pdu->max < pdu->len + (tkl - coap_get_tkl(pdu)))
			return CE_INSUFFICIENT_BUFFER;

		// Move rest of packet to make room or take empty space.
		memmove(pdu->buf + 4 + tkl, pdu->buf + 4 + coap_get_tkl(pdu), pdu->len - 4 - coap_get_tkl(pdu));
	}

	// Set token.
	memcpy(pdu->buf+4, token, tkl);

	pdu->len += tkl - coap_get_tkl(pdu);

	pdu->buf[0] = (tkl & 0x0F) | (pdu->buf[0] & 0xF0);

	return CE_NONE;
}

coap_error coap_add_option(coap_pdu *pdu, int32_t opt_num, uint8_t* value, uint16_t opt_len)
{
	uint8_t *pkt_ptr, *fopt_val, nopt_hdr_len;
	uint16_t fopt_num, lopt_num;
	size_t fopt_len, opts_len;
	coap_error err;

	// Set pointer to "zeroth option's value" which is really first option header.
	fopt_val = pdu->buf + 4 + coap_get_tkl(pdu); // ptr to start of options
	fopt_len = 0;

	// Option number delta starts at zero.
	fopt_num = 0;

	// Find insertion point
	do{
		pkt_ptr = fopt_val + fopt_len;
		lopt_num = fopt_num;
		err = coap_decode_option(pkt_ptr, (pdu->len)-(pkt_ptr-pdu->buf), &fopt_num, &fopt_len, &fopt_val);
	} while (err == CE_NONE && fopt_num <= opt_num && (pkt_ptr-pdu->buf) + fopt_len < pdu->len);

	if (err != CE_FOUND_PAYLOAD_MARKER && err != CE_END_OF_PACKET && err != CE_NONE)
		return err;

	// Build New Header
	nopt_hdr_len = coap_compute_option_header_len(opt_num - lopt_num, opt_len);

	// Check that we were given enough buffer.
	if (pdu->max < pdu->len + nopt_hdr_len + opt_len)
		return CE_INSUFFICIENT_BUFFER;

	// Check if we're adding an option in the middle of a packet.
	// But seriously, don't do this.
	if (pdu->len != pkt_ptr- pdu->buf){
		// Slide packet tail to make room.
		memmove(pkt_ptr + nopt_hdr_len + opt_len, pkt_ptr, pdu->len - (pkt_ptr - pdu->buf));
		pdu->len += nopt_hdr_len + opt_len;

		// Find Current Length of Remaining Options
		opts_len = pdu->len - (pkt_ptr-pdu->buf);

		// Adjust the option deltas for the rest of the options.
		coap_adjust_option_deltas(pkt_ptr + nopt_hdr_len + opt_len, 
		                          &opts_len, pdu->max - (pkt_ptr - pdu->buf),
		                          lopt_num - opt_num);

		// Update Total Packet Length
		pdu->len += opts_len - (pdu->len - (pkt_ptr-pdu->buf));
	}else{
		// Update Packet Length
		pdu->len = pdu->len + nopt_hdr_len + opt_len;
	}

	// Insert the Header
	coap_build_option_header(pkt_ptr, nopt_hdr_len, opt_num - lopt_num, opt_len);

	// Insert the Value
	memcpy(pkt_ptr + nopt_hdr_len, value, opt_len);

	return CE_NONE;
}

coap_error coap_set_payload(coap_pdu *pdu, uint8_t *payload, size_t payload_len){
	uint8_t *pkt_ptr, *fopt_val;
	uint16_t fopt_num;
	size_t fopt_len;
	coap_error err;

	// Set pointer to "zeroth option's value" which is really first option header.
	fopt_val = pdu->buf + 4 + coap_get_tkl(pdu);
	fopt_len = 0;

	// Option number delta starts at zero.
	fopt_num = 0;

	// Find insertion point
	do{
		pkt_ptr = fopt_val + fopt_len;
		err = coap_decode_option(pkt_ptr, (pdu->len)-(pkt_ptr-pdu->buf), &fopt_num, &fopt_len, &fopt_val);
	}while (err == CE_NONE && (pkt_ptr-pdu->buf) + fopt_len < pdu->len);

	if (err != CE_FOUND_PAYLOAD_MARKER && err != CE_END_OF_PACKET && err != CE_NONE)
		return err;

	if (err == CE_END_OF_PACKET){
		// Check that we were given enough buffer.
		if (pdu->max < pdu->len + payload_len + 1)
			return CE_INSUFFICIENT_BUFFER;

		*(pkt_ptr++) = 0xFF;
	}else if (err == CE_FOUND_PAYLOAD_MARKER){
		// Check that we were given enough buffer.
		if (pdu->max < pdu->len + payload_len)
			return CE_INSUFFICIENT_BUFFER;	
	}

	pdu->len = (pkt_ptr - pdu->buf) + payload_len;
	memcpy(pkt_ptr, payload, payload_len);

	return CE_NONE;
}

coap_error coap_adjust_option_deltas(uint8_t *opts_start, size_t *opts_len, size_t max_len, int32_t offset)
{
	uint8_t *ptr, *fopt_val;
	uint16_t fopt_num, nopt_num;
	size_t fopt_len;
	int8_t nhdr_len, fhdr_len;
	coap_error err;

	fopt_val = opts_start;
	fopt_len = 0;
	fopt_num = 0;

	do{
		ptr = fopt_val + fopt_len;
		if (ptr - opts_start  > *opts_len)
			break;

		err = coap_decode_option(ptr, *opts_len-(ptr-opts_start), &fopt_num, &fopt_len, &fopt_val);

		if (err == CE_FOUND_PAYLOAD_MARKER || err == CE_END_OF_PACKET)
			break;
		else if (err != CE_NONE)
			return err;

		// New Option Number
		nopt_num = fopt_num + offset;

		// Find the length of the found header.
		fhdr_len = fopt_val - ptr;

		// Compute the length of the new header.
		nhdr_len = coap_compute_option_header_len(nopt_num, fopt_len);

		// Make/Take room for new header size
		if (fhdr_len != nhdr_len){
			if (max_len < *opts_len + (nhdr_len - fhdr_len))
				return CE_INSUFFICIENT_BUFFER;

			memmove(fopt_val + (nhdr_len - fhdr_len), fopt_val, fopt_len);

			// Adjust Options Length
			*opts_len += (nhdr_len - fhdr_len);
		}

		// Write New Header
		nhdr_len = coap_build_option_header(ptr, nhdr_len, nopt_num, fopt_len);

	}while (1);

	return CE_NONE;

}

int8_t coap_build_option_header(uint8_t *buf, size_t max_len, int32_t opt_delta, int32_t opt_len)
{
	uint8_t *ptr, base_num, base_len;

	if (max_len < 1)
		return CE_INSUFFICIENT_BUFFER;

	ptr = buf+1;

	if (opt_delta < 13) {
		base_num = opt_delta;
	}else if (opt_delta < 269) {
		if (max_len < ptr-buf + 1)
			return CE_INSUFFICIENT_BUFFER;

		base_num = 13;
		*(ptr++) = opt_delta - 13;
	}else {
		if (max_len < ptr-buf + 2)
			return CE_INSUFFICIENT_BUFFER;

		base_num = 14;
		*(ptr++) = (opt_delta - 269) >> 8;
		*(ptr++) = (opt_delta - 269) & 0xFF;
	}

	if (opt_len < 13) {
		base_len = opt_len;
	}else if (opt_len < 269) {
		if (max_len < ptr-buf + 1)
			return CE_INSUFFICIENT_BUFFER;

		base_len = 13;
		*(ptr++) = opt_len - 13;
	}else {
		if (max_len < ptr-buf + 2)
			return CE_INSUFFICIENT_BUFFER;

		base_len = 14;
		*(ptr++) = (opt_len - 269) >> 8;
		*(ptr++) = (opt_len - 269) & 0xFF;
	}

	buf[0] = (base_num << 4) | base_len;


	// Return the length of the new header.
	return ptr-buf;

}

int8_t coap_compute_option_header_len(int32_t opt_delta, int32_t opt_len)
{
	int8_t len = 1;

	if (opt_delta < 13) {
	}else if (opt_delta < 269) {
		len += 1;
	}else {
		len += 2;
	}

	if (opt_len < 13) {
	}else if (opt_len < 269) {
		len += 1;
	}else {
		len += 2;
	}

	return len;

}
#if CLICK
ELEMENT_PROVIDES(schcCOAP)
#endif
