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

int8_t schc_fragmenter_init();
int8_t schc_fragment(const uint8_t *data, uint16_t mtu, uint16_t total_length,
		uint32_t device_id, void (*callback)(uint8_t* data, uint16_t length));

#ifdef __cplusplus
}
#endif

#endif
