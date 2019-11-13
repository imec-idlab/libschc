# EXAMPLES
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
By changing the reliability mode to `ACK_ON_ERROR`, the receiver will make use of the bitmap mechanism, of which you will see output in the terminal.

### Ack-Always
By changing the reliability mode to `ACK_ALWAYS`, all windows will be acknowledged. As there is no function implemented for the receiver to transmit any packets (acknowledgements) to the sender, the acknowledgements will get lost and the reliability mode will time out after 3 tries.
