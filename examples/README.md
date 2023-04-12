# EXAMPLES
First make sure that the rule file is configured correctly. Copy the examples file and set the include directive to use the `rules_example.h`.
```
cp rules/rule_config_example.h rules/rule_config.h
nano rules/rule_config.h
```
Next, copy the configuration file and configure it to taste, or leave it untouched to run the examples.
```
cp schc_config_example.h schc_config.h
```

Now you can compile and run the examples.
```
cd examples
make all
```
## Compression
This file shows a basic example on compressing a packet.
```
make compress
./compress
```

## Fragmentation
### No-Ack
The fragmentation examples make use of a timer library and implements the `timer_handler` as an API between the library and the application and is platform specific.

`fragment.c` presents an example where the `NO_ACK` mode can be tested.

```
make fragment
./fragment
```

### Ack-on-Error
In order to test the different fragmentation modes, an example is provided with two terminals that communicate over a UDP socket. In order for this example to work, you will have to build both `gateway.c` and `client.c` using the respective `make` commands `make gateway` and `make client`. Change the following line to the desired reliability mode.
```C
tx_conn.fragmentation_rule = get_fragmentation_rule_by_reliability_mode(schc_rule, NO_ACK, device_id);
```
Then build and execute.

By changing the reliability mode to `ACK_ON_ERROR`, the receiver will acknowledge each erroneous window.

### Ack-Always
By changing the reliability mode to `ACK_ALWAYS`, all windows will be acknowledged.
