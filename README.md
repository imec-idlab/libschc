# libschc: A C implementation of the Static Context Header Compression
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
and edit the definitions according to your platform and preferences.

### Rules
Currently, I only have been working with rules for a single device. However, as the server application will have to keep track of multiple devices, this should be implemented in a decoupled way.
The rules are implemented in a layered fashion and should be combined with a rule map to use different layers in a single ID. This map could then be reused for different devices.

The rules are implemented in a human readable fashion, which does add a lot of overhead. Additional research/implementation is required there.

In `rules.h`, several rules can be defined
```C
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
```C
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
```C
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
```C
uint8_t schc_compressor_init(uint8_t src[16]);
```

In order to compress a CoAP/UDP/IP packet, the following function can be called. This requires a buffer (`uint8_t *buf`) to which the compressed packet may be returned.
```C
int16_t schc_compress(const uint8_t *data, uint8_t* buf, uint16_t total_length);
```

The reverse can be done by calling:
```C
uint16_t schc_construct_header(unsigned char* data, unsigned char *header,
	uint32_t device_id, uint16_t total_length, uint8_t *header_offset);
```
This requires a buffer to which the decompressed headers can be returned (`unsigned char *header`), a pointer to the complete original data packet (`unsigned char *data`), the device id and total length and finally a pointer to an integer (`uint8_t *header_offset`), which will return the compressed header size (i.e. the position in the buffer where the actual data starts). The function will return the decompressed header length.

Once the decompressed packet has been constructed, the UDP length and checksum may be calculated (this is still an open issue, as these functions should be called from the `construct_header` function itself).
```C
uint16_t compute_length(unsigned char *data, uint16_t data_len);
uint16_t compute_checksum(unsigned char *data);
```

The result should be a complete decompressed packet.

### Fragmenter
The fragmenter and compressor are decoupled and require seperate initialization.
```C
int8_t schc_fragmenter_init(schc_fragmentation_t* tx_conn, 
		void (*send)(uint8_t* data, uint16_t length, uint32_t device_id),
		void (*end_rx)(schc_fragmentation_t* conn),
		void (*remove_timer_entry)(uint32_t device_id))
```
The initilization function takes the following arguments:
- `tx_conn`, which can be an empty `schc_fragmentation_t` struct, to hold the information of the sending device.
- `send` requires a pointer to a callback function, which will transmit the fragment over any interface and requires a platform specific implementation
- `end_rx` is called once the complete packet has been received (more information bellow)
- `remove_timer_entry` had to be added for some platforms to remove timers once the complete transmission has been completed

#### mbuf
The fragmenter is built around the `mbuf` principle, derived from the BSD OS, where every fragment is part of a linked list. The fragmenter holds a preallocated number of slots, defined in `schc_config.h` with `#define SCHC_CONF_RX_CONNS`.
Every received packet is added to the `MBUF_POOL`, containing a linked list of fragments for a particular connection.
Once a transmission has been ended, the fragmenter will then glue together the different fragments.

#### Reassembly
Upon reception of a fragment, the following function should be called:
```C
schc_fragmentation_t* schc_input(uint8_t* data, uint16_t len, schc_fragmentation_t* tx_conn, uint32_t device_id)
```
- the `tx_conn` structure is used to check if the received frame was an acknowledgment and will return the `tx_conn` if so
- the `device_id` is used to find out if the current device is involved in an ongoing transmission and will return the `rx_conn` if so

These return values can be used in the application to perform corresponding actions, e.g:
```C
uint8_t ret = 0;

if (conn != &tx_conn) {
	conn->mode = NO_ACK;// todo get from rule
	if(conn->mode == NO_ACK) { // todo get from rule
		conn->FCN_SIZE = 1;
		conn->WINDOW_SIZE = 0;
	}
	conn->post_timer_task = &set_rx_timer;
	conn->dc = 50000; // duty cycle
	ret = schc_reassemble(conn);
}

if(ret == 1) { // reception finished
	packet_to_ip6(conn);
}
```
The above example is application code of the server, receiving a compressed, fragmented packet.
By calling `schc_reassemble`, the fragmenter will take care of adding fragments to the `MBUF_POOL`.

Once the reception is finished, `packet_to_ip6` is called, where the `mbuf` can be reassembled to a regular packet.
First we want to get the length of the packet:
```C
uint16_t get_mbuf_len(schc_mbuf_t *head); // call with conn->head as argument
```
Next, a buffer can be allocated with the appropriate length (the return value of `get_mbuf_len`). The reassmbled packet can then be copied to the pointer passed to the following function:
```C
void mbuf_copy(schc_mbuf_t *head, uint8_t* ptr); // call with conn->head and pointer to allocated buffer
```
The result will be a compressed packet, which can be decompressed by using the decompressor.

Don't forget to reset the connection.
```C
void schc_reset(schc_fragmentation_t* conn);
```

#### Fragmentation
After compressing a packet, the return value of `schc_compress` can be used to check whether a packet should be fragmented or not.
In order to fragment a packet, the parameters of the connection should be set according to your preferences.

```C
tx_conn.mode = ACK_ON_ERROR;
tx_conn.mtu = current_network_driver->mtu; // the maximum length of each fragment
tx_conn.dc = 20000; // duty cycle

tx_conn.data_ptr = &compressed_packet; // the pointer to the compressed packet
tx_conn.packet_len = err; // the total length of the packet
tx_conn.send = &network_driver_send; // callback function to call for transmission
tx_conn.FCN_SIZE = 3; // todo get from rule
tx_conn.MAX_WND_FCN = 6; // todo will be removed?
tx_conn.WINDOW_SIZE = 1; // todo support multiple window sizes
tx_conn.DTAG_SIZE = 0; // todo no support yet
tx_conn.RULE_SIZE = 8; // todo get from rule

tx_conn.post_timer_task = &set_tx_timer;

schc_fragment((schc_fragmentation_t*) &tx_conn); // start the fragmentation
```

#### Timers
As you can see in the above examples, the library has no native support for timers and requires callback functions from the main application to schedule transmissions and to time out.
Therefore, 2 function callbacks are required. The following is based on the OSS-7 platform.
```C
/*
 * The timer used by the SCHC library to schedule the transmission of fragments
 */
static void set_tx_timer(void (*callback)(void* conn), uint32_t device_id, uint32_t delay, void *arg) {
	timer_post_task_prio(callback, timer_get_counter_value() + delay, DEFAULT_PRIORITY, arg);
}
```

As the server has to keep track of multiple devices and connections, a vector is used to keep track of multiple devices.
The following is part of a C++ implementation, which makes use of the C library.
```C
/*
 * The timer used by the SCHC library to time out the reception of fragments
 */
static void set_rx_timer(void (*callback)(void* conn), uint32_t device_id, uint32_t delay, void *arg) {
	add_device(device_id, delay, callback);
}
```

## LICENSE
Licensed under the GNU General Public License, Version 3 (the "License"): You may not use these files except in compliance with the License. You may obtain a copy of the License at <https://www.gnu.org/licenses/gpl-3.0.nl.html>

See the License for the specific language governing permissions and limitations under the License.

© Copyright 2018-2019, Bart Moons <bamoons.moons@ugent.be> and Ghent University