# DOCUMENTATION
## Static Context Header Compression
Static Context Header Compression or SCHC defines a mechanism to compress protocol headers by using contexts, which are both known to the sender and the translating gateway.
The contexts represent possible header configurations, stored in a rule and identifed by an id. This id and possible 'residue' (header leftovers added by a rule configuration to add more flexibility) are exchanged between 2 SCHC-devices.
The receiver will be able to reconstruct the original header by using the exact same rule.
As this technique is aimed at technologies with limited bandwidth capbilities possibly limited by a duty cycle, a fragmentation mechanism is also defined to ensure (reliable) larger packet transfers and to support the IPv6 1280 bytes MTU requirement.

#### Table of Contents  
* [Rules](#rules)
* [Compression](#compression) 
* [Fragmentation](#fragmentation)
* [Configuration](#configuration)

### Rules
As proposed in draft-22, every technology should define a profile to set the parameters according to the properties of that technology.
The profile includes the rules with their corresponding parameters, a pointer to the protocol layer definitions and the rule id.
Protocol layers are defined and use static definitions for the size of every protocol layer defintion as `malloc()` functions are omitted. The structure of these definitions however, are generic and ensure scalability.
A representation of the implementation is shown in the following figure:

```
+---------------+      +----------------------+      +-------------------------+      +-------------------+ 
|   ip_rule_t 1 |---+  |  compression_rule_t  |---+  |       schc_rule_t       |<-+   |   schc_device_t   |
|   ip_rule_t 2 |   |  +----------------------+   |  +-------------------------+  |   +-------------------+
|   ip_rule_t 3 |   +->|         &(ip_rule_t) |   |  |                 RULE_ID |  |   |         DEVICE_ID |
|   ip_rule_t 4 | +--->|        &(udp_rule_t) |   +->|   &(compression_rule_t) |  +---|     *(*context)[] |
|   ip_rule_t 5 | | +->|       &(coap_rule_t) |      |        RELIABILITY_MODE |      +-------------------+
+---------------+ | |  +----------------------+      |                FCN_SIZE |
                  | |                                |             WINDOW_SIZE |
+---------------+ | |                                |               DTAG_SIZE |
|  udp_rule_t 1 | | |                                |    RETRANSMISSION_TIMER |
|  udp_rule_t 2 |-+ |                                |        INACTIVITY_TIMER |
+---------------+   |                                |         MAX_ACK_REQUEST |
                    |                                +-------------------------|
+---------------+   |
| coap_rule_t 1 |   |
| coap_rule_t 2 |   |
| coap_rule_t 3 |   |
| coap_rule_t 4 |---+
+---------------+
```

The rules are layer specific and are combined in a `compression_rule_t` structure to ensure reusage over different rule ID's. The resulting `schc_rule_t` can be combined with similar definitions to form a context. This context may be reused over different devices. 

An example implementation of the rules can be found in `rules_example.h` and should be copied to `rules.h`.

#### Implementation
*Note: the human readability of the implementation adds overhead and requires additional research to perform proper encoding.*

Each rule is constructed of different `schc_field`:
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
- the `MO_param_length` indicates the amount of bits that were sent, when used in combination with the Matching Operator `MSB` or with the Decompression Action `LSB`. When used in combination with the `match-map` MO, it represents the length of the list
- the `field_length` indicates the field length in bits. 
- `field_pos` is only used for headers where multiple fields can exist for the same entry (e.g. CoAP uri-path).
- `dir` indicates the direction (`UP`, `DOWN` or `BI`) and will have an impact on how the rules behave while compressing/decompressing. Depending on the direction of the flow and which device is performing the (de)compression, the source and destination in the `decompress_ipv6_rule` and `generate_ip_header_fields` will be swapped, to ensure a single rule for server and end device.
- `target_value` holds a `char` array in order to support larger values. The downside of this approach is the `MAX_COAP_FIELD_LENGTH` definition, which should be set to the largest defined Target Value in order to save as much memory as possible.
- the `MO` is a pointer to the Matching Operator functions (defined in `config.h`) 
- `CDA` contains the Compression/Decompression action (`enum` in `config.h`)

Next, every rule is defined by means of protocol layers (i.e. `schc_coap_rule_t`, `schc_udp_rule_t` or `schc_ipv6_rule_t`). An id is only used for debugging purposes. As the total length of the rules over the different protocol layers can be variable, a static definition of the vertical length of the largest rule possible is required (e.g. the `COAP_FIELDS` definition). Every rule should set the total number of fields (`length`). `up`  and `down` define the number of rule entries for the respective order of the flow to save compare cycles.
```C
struct schc_coap_rule_t {
	uint16_t rule_id;
	uint8_t up;
	uint8_t down;
	uint8_t length;
	struct schc_field content[COAP_FIELDS];
};
```

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
A set of layered rules in combination with fragmentation parameters constructs an `schc_rule_t`. The `reliability_mode` can also define whether a packet was fragmented or not (`NOT_FRAGMENTED`).
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
	const struct schc_rule_t *(*context)[];
};
```

The `rules.h` file should contain enough information to try out different settings.

### Compression
The compressor performs all actions to compress the given protocol headers.
First, the compressesor should be initialized with the node it's source IP address (8 bit array):
```C
uint8_t schc_compressor_init(uint8_t src[16]);
```

In order to compress a CoAP/UDP/IP packet, `schc_compress()` should be called. This requires a buffer (`uint8_t *buf`) to which the compressed packet can be returned. The direction can either be `UP` (from LPWA network to IPv6 network) or `DOWN` (from IPv6 network to LPWA network).
The schc rule is returned.
```C
struct schc_rule_t* schc_compress(const uint8_t *data, uint8_t* buf, uint16_t total_length, uint32_t device_id, direction dir);
```

The reverse can be done by calling:
```C
uint16_t schc_decompress(const unsigned char* data, unsigned char *buf, uint32_t device_id, uint16_t total_length, direction dir);
```
Again, a buffer is required to which the decompressed packet can be returned (`uint8_t *buf`), a pointer to the complete original data packet (`uint8_t *data`), the device id, the total length, the direction and device type. The function will return the original, decompressed packet length.

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
- `send` requires a pointer to a callback to transmit the fragment over an interface and requires a platform specific implementation
- `end_rx` is called once the complete packet has been received (more information bellow)
- `remove_timer_entry` had to be added for some platforms to remove timers once the complete transmission has been completed

#### mbuf
The fragmenter is built around the `mbuf` principle, derived from the BSD OS, where every fragment is part of a linked list. The fragmenter holds a preallocated number of slots, defined in `schc_config.h` by `#define SCHC_CONF_RX_CONNS`.
Every received packet is added to the `MBUF_POOL`, containing a linked list of fragments for a particular connection.
Once a transmission has been ended, the fragmenter will glue together the different fragments.

#### Fragmentation
After compressing a packet, the return value of `schc_compress` can be used to check whether a packet should be fragmented or not.
In order to fragment a packet, the parameters of the connection should be set according to your preferences.

```C
// compress packet
struct schc_rule_t* schc_rule;
schc_bitarray_t bit_arr;
bit_arr.ptr = (uint8_t*) (compressed_packet);

schc_rule = schc_compress(msg, sizeof(msg), &bit_arr, device_id, DOWN);

tx_conn.mtu = 12; // network driver MTU
tx_conn.dc = 5000; // 5 seconds duty cycle
tx_conn.device_id = 0x01; // the device id of the connection

tx_conn.bit_arr = &bit_arr;
tx_conn.send = &tx_send_callback;
tx_conn.end_tx = &end_tx;

tx_conn.schc_rule = schc_rule;
tx_conn.RULE_SIZE = RULE_SIZE_BITS;
tx_conn.MODE = ACK_ON_ERROR;

tx_conn.post_timer_task = &set_tx_timer;

int ret = schc_fragment(&tx_conn);
```

#### Reassembly
Upon reception of a fragment or an acknowledgement, the following function should be called:
```C
schc_fragmentation_t* schc_input(uint8_t* data, uint16_t len, schc_fragmentation_t* tx_conn, uint32_t device_id)
```
- the `tx_conn` structure is used to check if the received frame was an acknowledgment and will return the `tx_conn` if so
- the `device_id` is used to find out if the current device is involved in an ongoing transmission and will return the `rx_conn` if so

These return values can be used in the application to perform corresponding actions, e.g:
```C
// get active connection and set the correct rule for this connection
schc_fragmentation_t *conn = schc_input((uint8_t*) data, length, &tx_conn_ngw, device_id); 

if (conn != &tx_conn_ngw) { // if returned value is tx_conn: acknowledgement is received
	conn->post_timer_task = &set_rx_timer;
	conn->dc = 20000; // retransmission timer: used for timeouts

	if (conn->schc_rule->mode == NOT_FRAGMENTED) { // packet was not fragmented
		end_rx(conn);
	} else {
		int ret = schc_reassemble(conn);
		if(ret && conn->schc_rule->mode == NO_ACK){ // use the connection to reassemble
			end_rx(conn); // final packet arrived
		}
	}
}
```
The above example is application code of the server, receiving a compressed, fragmented packet.
By calling `schc_reassemble`, the fragmenter will take care of adding fragments to the `MBUF_POOL`.

Once the reception is finished, `end_rx` is called, where the `mbuf` can be reassembled to a regular packet.
First we want to get the length of the packet:
```C
uint16_t get_mbuf_len(schc_mbuf_t *head); // call with conn->head as argument
```
Next, a buffer can be allocated with the appropriate length (the return value of `get_mbuf_len`). The reassmbled packet can then be copied to the pointer passed to the following function:
```C
void mbuf_copy(schc_mbuf_t *head, uint8_t* ptr); // call with conn->head and pointer to allocated buffer
```
The result will be a compressed packet, which can be decompressed by using the decompressor.

## Configuration
First copy the configuration and rules file 
```
cp schc_config_example.h schc_config.h && cp rules/rules_example.h rules/rules.h && cp rules/rule_config_example.h rules/rule_config.h
```
and edit the definitions according to your platform and preferences.

In order to use a single, generic `compress()` function, each protocol layer is copied to an `unsigned char` array before compression, which can be compared to the rule fields' `usigned char` array, containing the target value. This adds memory overhead, as a buffer is required for each protocol layer, however, requires less computational memory and saves code space.
Therefore, it is important to change the following definitions according to the largest rules:
* `#define layer_FIELDS` should be set to the maximum number of header fields in a protocol rule
* `#define MAX_layer_FIELD_LENGTH` should be set to the maximum number of bytes a field contains (i.e. target value)

### Timers
As you can see in the examples, the library has no on-board support for timers to avoid complex integration and requires callback functions from the main application to schedule transmissions and to time out.
Therefore, 2 function callbacks are required.
```C
/*
 * The timer used by the SCHC library to schedule the transmission of fragments
 */
static void set_tx_timer(void (*callback)(void* conn), uint32_t device_id, uint32_t delay, void *arg) {
}
```

As the server has to keep track of multiple devices and connections, a vector is used to keep track of multiple devices.
```C
/*
 * The timer used by the SCHC library to time out the reception of fragments
 */
static void set_rx_timer(void (*callback)(void* conn), uint32_t device_id, uint32_t delay, void *arg) {
}
```

An example is provided in the examples folder, where a timer library is used and the callbacks are adapted to this library.

## Limitations
Most of the limitations are listed under issues and may be fixed in coming releases.