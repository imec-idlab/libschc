/*
 * (c) 2020 - idlab - UGent - imec
 *
 * Bart Moons
 *
 * This file is part of the SCHC stack implementation
 *
 */

#include "bit_operations.h"

#if CLICK
#include <click/config.h>
#endif

/**
 * sets bits at a certain position in a bit array
 * big endian
 *
 * @param A				the bit array
 * @param pos			which bit to set
 * @param len			the number of consecutive bits to set
 *
 */
void set_bits(uint8_t A[], uint32_t pos, uint32_t len) {
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
uint32_t get_bits(const uint8_t A[], uint32_t pos, uint8_t len) {
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
void clear_bits(uint8_t A[], uint32_t pos, uint32_t len) {
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
 * @param len			the number of consecutive bits to check
 *
 */
void copy_bits(uint8_t DST[], uint32_t dst_pos, const uint8_t SRC[], uint32_t src_pos,
		uint32_t len) {
	uint32_t i;
	uint32_t k = 0;

	for(i = 0; i < len; i++) { // for each bit
		uint8_t src_val = ((128 >> ( (k + src_pos) % 8)) & SRC[((k + src_pos) / 8)]);
		if(src_val) {
			// DEBUG_PRINTF("set bits for %d at position %d len is %d \n", DST[i+dst_pos], i+dst_pos, len);
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
uint8_t compare_bits(const uint8_t SRC1[], const uint8_t SRC2[], uint32_t len) {
	uint32_t i;

	for (i = 0; i < len; i++) {
		if ( (SRC1[i / 8] & (128 >> (i % 8) )) != (SRC2[i / 8] & (128 >> (i % 8) )) ) {
			return 0;
		}
	}

	return 1;
}

/**
 * compare two bit arrays with starting point
 *
 * @param 	SRC1		the array to compare
 * @param	pos1		position to start for src1
 * @param 	SRC2		the array to compare with
 * @param 	pos2		position to start for src2
 * @param 	len			the number of consecutive bits to compare
 *
 * @return	1			both arrays match
 * 			0			the arrays differ
 *
 */
uint8_t compare_bits_aligned(const uint8_t SRC1[], uint16_t pos1,
		const uint8_t SRC2[], uint16_t pos2, uint32_t len) {
	uint32_t i; uint32_t src1_pos, src2_pos; uint8_t shift1, shift2;

	shift1 = pos1 % 8;
	shift2 = pos2 % 8;

	// todo no copy
	uint8_t SRC1_copy[MAX_FIELD_LENGTH] = { 0 };
	uint8_t SRC2_copy[MAX_FIELD_LENGTH] = { 0 };

	copy_bits(SRC1_copy, 0, SRC1, shift1, len);
	copy_bits(SRC2_copy, 0, SRC2, shift2, len);

	return compare_bits(SRC1_copy, SRC2_copy, len);
}

// remain backward compatible

/**
 * compare two bit arrays starting from right to left
 *
*  @return	1			both arrays match
* 			0			the arrays differ
*
*/
uint8_t compare_bits_BIG_END(uint8_t* SRC1, uint8_t* SRC2, uint32_t len) {
	uint32_t i;

	uint8_t pos = get_position_in_first_byte(len);
	for (i = pos; i < (len + pos); i++) {
		if ((SRC1[i / 8] & (128 >> (i % 8))) != (SRC2[i / 8] & (128 >> (i % 8)))) {
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
void shift_bits_left(uint8_t SRC[], uint16_t len, uint32_t shift) {
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
void shift_bits_right(uint8_t SRC[], uint16_t len, uint32_t shift) {
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
void xor_bits(uint8_t DST[], uint8_t SRC1[], uint8_t SRC2[], uint32_t len) {
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
void and_bits(uint8_t DST[], uint8_t SRC1[], uint8_t SRC2[], uint32_t len) {
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
void print_bitmap(const uint8_t bitmap[], uint32_t length) {
	uint32_t i;
	for (i = 0; i < length; i++) {
		uint8_t bit = bitmap[i / 8] & 128 >> (i % 8);
		DEBUG_PRINTF("%d ", bit ? 1 : 0);
	}
	DEBUG_PRINTF("\n"); // flush buffer
}

/**
 * get the number of bytes required to store this amount of bits
 *
 * @param 	number_of_bits		the number of bits to find the number of bytes for
 *
 */
uint8_t get_number_of_bytes_from_bits(uint16_t number_of_bits) {
	if (!(number_of_bits % 8)) { // ceil if needed
		return (number_of_bits / 8);
	} else {
		return (((number_of_bits) / 8) + 1);
	}
}

/**
 * get the number of bits required to store a value
 *
 * @param 	value		the value to count the number of bits for
 *
 */
uint32_t get_required_number_of_bits(uint32_t n) {
	int count = 0, store = -1;
	while (n != 0) {
		if (n & 1 == 1) //if current bit is set
			store = count; //update store
		n = n >> 1; //right shift
		count++; //increase count
	}
	return count;
}

/**
 * get the starting bit of a value
 *
 * @param 	value		the value to count the number of bits for
 *
 */
uint8_t get_position_in_first_byte(uint8_t value) {
	uint8_t src_pos = 0;
	if (value % 8) { // position in first byte
		src_pos = 8 - (value % 8);
	}
	return src_pos;
}

/**
 * remove padding
 *
 * @param 	bit_arr		the bit array to return padding for
 *
 * @return 	padding		number of padded bits
 * 			0			word aligned
 *
 */
uint8_t padded(schc_bitarray_t* bit_array) {
	if( (bit_array->offset % 8) ) {
		return (8 - (bit_array->offset % 8));
	}

	return 0;
}

#if CLICK
ELEMENT_PROVIDES(schcBIT)
#endif
