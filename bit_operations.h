/*
 * (c) 2018 - idlab - UGent - imec
 *
 * Bart Moons
 *
 * This file is part of the SCHC stack implementation
 *
 */
#ifndef _SCHC_BIT_H_
#define _SCHC_BIT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "schc.h"

#define BYTES_TO_BITS(x)	(x * 8)
#define BITS_TO_BYTES(x)	(((x) == 0) ? 0 : (((x) - 1) / 8 + 1)) // bytes required for a number of bits

// sets bits at a certain position in a bit array
void set_bits(uint8_t A[], uint32_t pos, uint32_t len);

// get bits at a certain position in a bit array
uint32_t get_bits(const uint8_t A[], uint32_t pos, uint8_t len);

// clear bits at a certain position in a bit array
void clear_bits(uint8_t A[], uint32_t pos, uint32_t len);

// copy bits to a certain position in a bit array from another array
void copy_bits(uint8_t DST[], uint32_t dst_pos, const uint8_t SRC[], uint32_t src_pos, uint32_t len);
// void copy_bits_BIG_END(uint8_t DST[], uint32_t dst_pos, const uint8_t SRC[], uint32_t src_pos, uint32_t len);

// compare two bit arrays
uint8_t compare_bits(const uint8_t SRC1[], const uint8_t SRC2[], uint32_t len);
uint8_t compare_bits_aligned(const uint8_t SRC1[], uint16_t pos1, const uint8_t SRC2[], uint16_t pos2, uint32_t len);
uint8_t compare_bits_BIG_END(uint8_t SRC1[], uint8_t SRC2[], uint32_t len);

// shift a number of bits to the left
void shift_bits_left(uint8_t SRC[], uint16_t len, uint32_t shift);

 // shift a number of bits to the right
void shift_bits_right(uint8_t SRC[], uint16_t len, uint32_t shift);

// logic xor two bit arrays
void xor_bits(uint8_t DST[], uint8_t SRC1[], uint8_t SRC2[], uint32_t len);

// logic and two bit arrays
void and_bits(uint8_t DST[], uint8_t SRC1[], uint8_t SRC2[], uint32_t len);

// print an array of bits
void print_bitmap(const uint8_t bitmap[], uint32_t length);

// get the ceiled length in bytes
uint8_t get_number_of_bytes_from_bits(uint16_t number_of_bits);

// return the number of 1-bits in the value
uint32_t get_required_number_of_bits(uint32_t value);

// return the starting bit of a value
uint8_t get_position_in_first_byte(uint8_t value);

// remove padding
uint8_t padded(schc_bitarray_t* bit_array);


#ifdef __cplusplus
}
#endif

#endif
