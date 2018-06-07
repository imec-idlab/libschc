#ifndef __SCHCCOMPRESSOR_H__
#define __SCHCCOMPRESSOR_H__

// the total rule size in bytes
#define RULE_SIZE_BYTES			1
#define MAX_HEADER_LENGTH		128

uint8_t schc_init(uint8_t src[16]);
int16_t schc_compress(const uint8_t *data, uint8_t* buf, uint16_t total_length);

uint16_t schc_construct_header(unsigned char* data, unsigned char *header,
		uint32_t device_id, uint16_t total_length, uint8_t* header_offset);

uint16_t compute_length(unsigned char *data, uint16_t data_len);
uint16_t compute_checksum(unsigned char *data);

#endif
