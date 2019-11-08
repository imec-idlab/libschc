# libschc: A C implementation of the Static Context Header Compression
## ABOUT LIBSCHC

libschc is a C implementation of the Static Context Header Compression, drafted by the IETF.
It is a header compression technique, used in Low Power Wide Area Networks in order to enable 
tiny low-power microcontrollers to have an end-to-end IPv6 connection. 
This repository contains both the compression aswell as the fragmentation mechanism.
For further information related to SCHC, see <https://datatracker.ietf.org/doc/draft-ietf-lpwan-ipv6-static-context-hc/>.

## LIMITATIONS
As this implementation is work in progress, there are some limitations you should keep in mind.

The library has been designed in such a way that it can be used on top of a constrained device, as well as on a more powerful server side device. As a consequence, memory allocation and memory intensive calculations are avoided.
I tended to use fixed point arithmetic for 8-bit mircoprocessors, however some optimizations are possible.
As such, the rules are constructed of 8-bit arrays, availble on all devices.

The `schc-config.h` file contains a definition for dynamic memory allocation, used by fragmenter.

The current implementation is based on draft-ietf-lpwan-ipv6-static-context-hc-18 (<https://datatracker.ietf.org/doc/draft-ietf-lpwan-ipv6-static-context-hc/18/>), some naming conventions are therefore not in line with the current specification.

Please keep in mind that the library works, but is still very experimental!
## EXAMPLES
### Running the examples
In the folder examples are both basic compression and fragmentation examples provided. The fragmentation example makes use of POSIX timer API's and should be adapted to your platform (see [Fragmentation](#fragmentation) and the examples folder).

## DOCUMENTATION
### Configuration
First copy the configuration file 
```
mv schc_config_example.h schc_config.h
```
and edit the definitions according to your platform and preferences.

In order to use a single, generic `compress()` function, each protocol layer is copied to an `unsigned char` array before compression, which can be compared to the rule fields' `usigned char` array, containing the target value. This adds memory overhead, as a buffer is required for each protocol layer, however, requires less computational memory and saves code space.
Therefore, it is important to change the following definitions according to the largest rules:
* `#define layer_FIELDS` should be set to the maximum number of header fields in a protocol rule
* `#define MAX_layer_FIELD_LENGTH` should be set to the maximum number of bytes a field contains (i.e. target value)

### Rules
The rules are implemented in a layered fashion and are be combined with a rule map to use different layers in a single ID. This map may be reused by different devices.
```
+----------------+       +----------------------+       +-------------------------+
|    IP_RULE_T 1 |--+    |  COMPRESSION_RULE_T  |---+   |       SCHC_RULE_T       |
|    IP_RULE_T 2 |  |    +----------------------+   |   +-------------------------+
|    IP_RULE_T 3 |  +--->|         &(IP_RULE_T) |   |   |                 RULE_ID |
|    IP RULE_T 4 |  +--->|        &(UDP_RULE_T) |   +-->|   &(COMPRESSION_RULE_T) |
|    IP RULE_T 5 |  | +->|       &(COAP_RULE_T) |       |        RELIABILITY_MODE |
+----------------+  | |  +----------------------+       |                FCN_SIZE |
                    | |                                 |             WINDOW_SIZE |
+----------------+  | |                                 |               DTAG_SIZE |
|   UDP_RULE_T 1 |  | |                                 |    RETRANSMISSION_TIMER |
|   UDP_RULE_T 2 |--+ |                                 |        INACTIVITY_TIMER |
+----------------+    |                                 |         MAX_ACK_REQUEST |
                      |                                 +-------------------------|
+----------------+    |
|  COAP_RULE_T 1 |    |
|  COAP_RULE_T 2 |    |
|  COAP_RULE_T 3 |    |
|  COAP_RULE_T 4 |----+
+----------------+
```

The rules are implemented in a human readable fashion, which does add some overhead. Additional research/implementation around proper encoding is required here.

In `rules.h`, several rules can be defined (`schc_coap_rule_t`, `schc_udp_rule_t` or `schc_ipv6_rule_t`)
```C
struct schc_coap_rule_t {
	uint16_t rule_id;
	uint8_t up;
	uint8_t down;
	uint8_t length;
	struct schc_field content[COAP_FIELDS];
};
```
Where the number of fields with Field Direction UP and DOWN are set and the total number of fields in the rule.
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

Next, the seperate protocol rules must be combinened in a `schc_compression_rule_t`:
```C
struct schc_compression_rule_t {
	/* a pointer to the IPv6 rule */
	const struct schc_ipv6_rule_t* ipv6_rule;
	/* a pointer to the UDP rule */
	const struct schc_udp_rule_t* udp_rule;
	/* a pointer to the CoAP rule */
	const struct schc_coap_rule_t* coap_rule;
};
```
A set of layered rules in combination with fragmentation parameters constructs an `schc_rule_t`. The `reliability_mode` can also define whether a packet was fragmented or not.
```C
struct schc_rule_t {
	/* the rule id */
	uint8_t id;
	/* a pointer to the SCHC rule */
	const struct schc_compression_rule_t *schc_rule;
	/* the reliability mode */
	reliability_mode mode;
	/* the fcn size in bits */
	uint8_t FCN_SIZE;
	/* the maximum number of fragments per window */
	uint8_t MAX_WND_FCN;
	/* the window size in bits */
	uint8_t WINDOW_SIZE;
	/* the dtag size in bits */
	uint8_t DTAG_SIZE;
};
```

Once all the rules are set up for a device, these can be saved and added to the device definition
```C
struct schc_device {
	/* the device id (e.g. EUI) */
	uint32_t device_id;
	/* the total number of rules for a device */
	uint8_t rule_count;
	/* a pointer to the collection of rules for a device */
	const struct schc_rule_t* device_rules[];
};
```

The `rules.h` file should contain enough information to try out different settings.

### Compression
The compressor performs all actions to compress the given protocol headers.
First, the compressesor should be initialized with the node it's source IP address (8 bit array):
```C
uint8_t schc_compressor_init(uint8_t src[16]);
```

In order to compress a CoAP/UDP/IP packet, the following function can be called. This requires a buffer (`uint8_t *buf`) to which the compressed packet may be returned. The direction can either be `UP` (from LPWA network to IPv6 network) or `DOWN` (from IPv6 network to LPWA network). Also the device type (`NETWORK_GATEWAY` or `DEVICE`) should be set, in order to determine whether the packet is being forwarded from the network gateway, or compressed at an end-point.
```C
int16_t schc_compress(const uint8_t *data, uint8_t* buf, uint16_t total_length, uint32_t device_id, direction dir, device_type device_type);
```

The reverse can be done by calling:
```C
uint16_t schc_decompress(const unsigned char* data, unsigned char *buf, uint32_t device_id, uint16_t total_length, direction dir, device_type device_type);
```
This requires a buffer to which the decompressed packet can be returned (`unsigned char *buf`), a pointer to the complete original data packet (`unsigned char *data`), the device id, the total length, the direction and device type. The function will return the decompressed header length.

### Fragmentation
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

#### Fragmentation
After compressing a packet, the return value of `schc_compress` can be used to check whether a packet should be fragmented or not.
In order to fragment a packet, the parameters of the connection should be set according to your preferences.

```C
schc_fragmentation_t tx_conn; // keep track of the tx state

tx_conn.mode = ACK_ON_ERROR;
tx_conn.mtu = current_network_driver->mtu; // the maximum length of each fragment
tx_conn.dc = 20000; // duty cycle

tx_conn.data_ptr = &compressed_packet; // the pointer to the compressed packet
tx_conn.packet_len = err; // the total length of the packet
tx_conn.send = &network_driver_send; // callback function to call for transmission
tx_conn.FCN_SIZE = 3;
tx_conn.MAX_WND_FCN = 6;
tx_conn.WINDOW_SIZE = 1;
tx_conn.DTAG_SIZE = 0;
tx_conn.RULE_SIZE = 8;

tx_conn.post_timer_task = &set_tx_timer;

schc_fragment(&tx_conn); // start the fragmentation
```

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

An example is provided in the examples folder, where a timer library is used and the callbacks are adapted to this library.

## LIMITATIONS
Here the main concerns are listed which leave room for optimization
* there is no consistency in the data type for rule id's. Currently a device can have a maximum of 256 rules. However, as of the specification, this should be configurable at bit level. As a consequence, the compressor and decompressor do not make use of bitshifts
* under issues, mainly optimization issues are listed
* the library offers `#ifdef` definitions for use with layers, but is not implemented properly


## LICENSE
Licensed under the GNU General Public License, Version 3 (the "License"): You may not use these files except in compliance with the License. You may obtain a copy of the License at <https://www.gnu.org/licenses/gpl-3.0.nl.html>

See the License for the specific language governing permissions and limitations under the License.

© Copyright 2018-2019, Bart Moons <bamoons.moons@ugent.be> and Ghent University