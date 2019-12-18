# EXAMPLES
*Note: as the examples are executable in a single terminal, some issues arise as the same fragmenter instance is used for two different devices. As I did not have much more time to work on the examples, I did not try to look for a better solution. If you get a segmentation fault at the end of a fragmentation loop, it is as expected. However, the output and the code should be relatively easy to follow in order to deploy the library on 2 devices.*
```
cd examples
make all
```
## Compression
This file shows a basic exmple on compressing a packet.
```
make compress
./compress
```

## Fragmentation
Because the fragmenter of the network gateway will search for an mbuf collection based on the id of the constrained device when calling fragment_input(), `ACK_ALWAYS` and `ACK_ON_ERROR` won't work properly in this example.
As the device id will be the same for an incoming fragment or an outgoing acknowledgement, the fragmenter will get confused and will use the same mbuf collection for both devices.
However, with the example provided, it is easy to deploy two physically separated devices.

### No-Ack
The fragmentation examples make use of a timer library and implements the `timer_handler` as an API between the library and the application and is platform specific.

`fragment.c` presents an example where the different fragmentation modes can be tested. In order to test the different fragmentation modes, change the following line to the desired reliability mode.
```C
if(compressed_len > tx_conn.mtu) { // should fragment, change rule
	// select a similar rule based on a reliability mode
	schc_rule = get_schc_rule_by_reliability_mode(schc_rule, NO_ACK, device_id); // <-- change this line
}
```
Then build and execute
```
make fragment
./fragment
```
### Ack-on-Error
By changing the reliability mode to `ACK_ON_ERROR`, the receiver will acknowledge each erroneous window.

### Ack-Always
By changing the reliability mode to `ACK_ALWAYS`, all windows will be acknowledged.
