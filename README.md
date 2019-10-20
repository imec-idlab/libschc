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

The `schc-config.h` file contains a definition for dynamic memory allocation, used by fragmenter.

The current implementation is based on draft-ietf-lpwan-ipv6-static-context-hc-18 (<https://datatracker.ietf.org/doc/draft-ietf-lpwan-ipv6-static-context-hc/18/>), some naming conventions are therefore not in line with the current specification.

## DOCUMENTATION
### Configuration
First copy the configuration file 
```
mv schc_config_example.h schc_config.h
```
and edit the definitions according to your platform.

### Compressor
The compressor performs all actions to compress the given protocol headers.

### Fragmenter

### Rules
As the rules tend to consume a large part of memory, and
