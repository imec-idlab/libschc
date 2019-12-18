# libschc: A C implementation of the Static Context Header Compression
## ABOUT LIBSCHC

libschc is a C implementation of the Static Context Header Compression, drafted by the IETF.
It is a header compression technique, used in Low Power Wide Area Networks in order to enable 
tiny low-power microcontrollers to have an end-to-end IPv6 connection. 
This repository contains both the compression as well as the fragmentation mechanism.
For further information related to SCHC, see <https://datatracker.ietf.org/doc/draft-ietf-lpwan-ipv6-static-context-hc/>.

See the [docs](/docs) for more information on the implemenation and configuration.

### ACKNOWLEDGEMENT

libschc has been developed partially with the support of VLAIO, FWO and imec. It is also part of the IoT middleware stack, being developed for the European Union’s Horizon 2020 PortForward project, where, amongst others, LwM2M will be integrated with this library in order to deliver open standards-based sensor-Cloud connectivity.

## LIMITATIONS
As this implementation is work in progress, there are some limitations you should keep in mind.

The library has been designed in such a way that it can be used on top of a constrained device, as well as on a more powerful server side device. As a consequence, memory allocation and memory intensive calculations are avoided.
Fixed point arithmetic is used for 8-bit mircoprocessors, however some optimizations are possible. Consequently, the rules are constructed of 8-bit arrays, available on all devices. Dynamic memory allocation is omitted as memory fragmentation would occur and performance would suffer, since many MCUs are not equipped with Memory Management Units (MMU).
For the network gateway however, dynamic memory allocation should be implemented for several functions to avoid large memory pre-allocation.

The current implementation is based on draft-ietf-lpwan-ipv6-static-context-hc-18 (<https://datatracker.ietf.org/doc/draft-ietf-lpwan-ipv6-static-context-hc/18/>), some naming conventions are therefore not in line with the current specification.

Please keep in mind that the library works, but is still very experimental!

## EXAMPLES
In the folder examples are both basic compression and fragmentation examples provided. The fragmentation example makes use of a timer library and should be adapted to your platform (see [Fragmentation](/docs#fragmentation) and the examples folder).

Please read the [example docs](/examples#fragmentation) carefully, as no proper fragmentation example for a single cli has been provided so far.

## LICENSE
libschc has dual licenses. The GNU General Public License, Version 3 (the "License") is the open source license: You may not use these files except in compliance with the License. You may obtain a copy of the License at <https://www.gnu.org/licenses/gpl-3.0.nl.html>

See the License for the specific language governing permissions and limitations under the License.

For non-open source licenses, please contact Ilse Bracke <ilse.bracke@imec.be>.

© Copyright 2018-2019, Bart Moons <bamoons.moons@ugent.be>, imec and Ghent University
