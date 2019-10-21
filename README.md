# libschc: A C implementation of the Static Context Header Compression

Copyright (C) 2018-2019 by Bart Moons <bamoons.moons@ugent.be>

## ABOUT LIBSCHC

libschc is a C implementation of the Static Context Header Compression, drafted by the IETF.
It is a header compression technique, used in Low Power Wide Area Networks in order to enable 
tiny low-power microcontrollers to have an end-to-end IPv6 connection. 
This repository contains both the compression aswell as the fragmentation mechanism.
For further information related to SCHC, see <https://datatracker.ietf.org/doc/draft-ietf-lpwan-ipv6-static-context-hc/>.

## LIMITATIONS
As this implementation is work in progress, there are some limitations you should keep in mind.
The library has been designed in such a way, that it can be used on top of a constrained device,
as well as on a more powerful server side device. 
As a consequence, memory allocation and memory intensive calculations are avoided.
I tended to use fixed point arithmetic for 8-bit mircoprocessors, however some optimizations are possible.

The `schc-config.h` file contains a definition for dynamic memory allocation, used by fragmenter.

The current implementation is based on draft-ietf-lpwan-ipv6-static-context-hc-18 (<https://datatracker.ietf.org/doc/draft-ietf-lpwan-ipv6-static-context-hc/18/>), some naming conventions are therefore not in line with the current specification.

## DOCUMENTATION
### Configuration
First copy the configuration file 
```
mv schc_config_example.h schc_config.h
```
and edit the definitions according to your platform.

### Rules
As the rules tend to consume a large part of memory, and

Currently, I only have been working with rules for a single device. However, as the server application will have to keep track of multiple devices, this should be implemented in a decoupled way.
The rules are implemented in a layered fashion and should be combined with a rule map to use different layers in a single ID. This map could then be reused for different devices.

In `rules.h`, several rules can be defined
```
struct schc_rule {
	uint16_t rule_id;
	uint8_t up;
	uint8_t down;
	uint8_t length;
	struct schc_field content[COAP_FIELDS];
};
```
Where the number of fields with Field Direction UP and DOWN are set and the total number of fields in the rule
The rule is therefore constructed of different `schc_field`:
```
struct schc_field {
	char field[32];
	uint8_t msb_length;
	uint8_t field_length;
	uint8_t field_pos;
	direction dir;
	unsigned char target_value[MAX_COAP_FIELD_LENGTH];
	uint8_t (*MO)(struct schc_field* target_field, unsigned char* field_value);
	CDA action;
};
```
- `field` holds a string of the field name (i.e. the human-readability of the rules). 
- the `msb_length` is used in combination with the Matching Operator `MSB`, but should be removed in coming releases.
- the `field_length` indicates the length of **bytes**, but should be bits in coming releases. Field Position is only used for headers where multiple fields can exist for the same entry (e.g. CoAP uri-path).
- `dir` indicates the direction (`UP`, `DOWN` or `BI`) and will have an impact on how the rules behave while compressing/decompressing. Depending on the `#define SERVER` in `schc_config.h`, the source and destination in the `decompress_ipv6_rule` and `generate_ip_header_fields` will be swapped, to ensure a single rule for server and end device.
- `target_value` holds a `char` array in order to support larger values. The downside of this approach is the `MAX_COAP_FIELD_LENGTH` definition, which should be set to the largest defined Target Value in order to save as much memory as possible.
- the `MO` is a pointer to the Matching Operator functions (defined in `config.h`) 
- `CDA` contains the Compression/Decompression action (`enum` in `config.h`)

Once all the rules are set up for a device, these can be saved and added to the device definition
```
struct schc_device {
	uint32_t id;
	uint8_t ipv6_count;
	const struct schc_rule* ipv6_rules;
	uint8_t udp_count;
	const struct schc_rule* udp_rules;
	uint8_t coap_count;
	const struct schc_rule* coap_rules;
};
```
This is all done very statically and needs further enhancements.

The `rules.h` file should contain enough information to try out different settings.

### Compressor
The compressor performs all actions to compress the given protocol headers.
First, the compressesor should be initialized with the node it's source IP address (8 bit array):
```
uint8_t schc_compressor_init(uint8_t src[16]);
```

In order to compress a CoAP/UDP/IP packet, the following function can be called. This requires a buffer (`uint8_t *buf`) to which the compressed packet may be returned.
```
int16_t schc_compress(const uint8_t *data, uint8_t* buf, uint16_t total_length);
```

The reverse can be done by calling:
```
uint16_t schc_construct_header(unsigned char* data, unsigned char *header,
	uint32_t device_id, uint16_t total_length, uint8_t *header_offset);
```
This requires a buffer to which the decompressed headers can be returned (`unsigned char *header`), a pointer to the complete original data packet (`unsigned char *data`), the device id and total length and finally a pointer to an integer (`uint8_t *header_offset`), which will return the compressed header size (i.e. the position in the buffer where the actual data starts). The function will return the decompressed header length.

Once the decompressed packet has been constructed, the UDP length and checksum may be calculated (this is still an open issue, as these functions should be called from the `construct_header` function itself).
```
uint16_t compute_length(unsigned char *data, uint16_t data_len);
uint16_t compute_checksum(unsigned char *data);
```

The result should be a complete decompressed packet.

### Fragmenter

```
int8_t schc_fragmenter_init(schc_fragmentation_t* tx_conn, 
		void (*send)(uint8_t* data, uint16_t length, uint32_t device_id),
		void (*end_rx)(schc_fragmentation_t* conn),
		void (*remove_timer_entry)(uint32_t device_id))
```

## LICENSE