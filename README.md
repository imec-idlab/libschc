# libschc: A C implementation of the Static Context Header Compression
## ABOUT LIBSCHC

libschc is a C implementation of the Static Context Header Compression, drafted by the IETF.
It is a header compression technique, used in Low Power Wide Area Networks in order to enable 
tiny low-power microcontrollers to have an end-to-end IPv6 connection. 
This repository contains both the compression aswell as the fragmentation mechanism.
For further information related to SCHC, see <https://datatracker.ietf.org/doc/draft-ietf-lpwan-ipv6-static-context-hc/>.

See the [docs](#/docs) for more information on the implemenation.

## LIMITATIONS
As this implementation is work in progress, there are some limitations you should keep in mind.

The library has been designed in such a way that it can be used on top of a constrained device, as well as on a more powerful server side device. As a consequence, memory allocation and memory intensive calculations are avoided.
I tended to use fixed point arithmetic for 8-bit mircoprocessors, however some optimizations are possible.
As such, the rules are constructed of 8-bit arrays, availble on all devices.

The `schc-config.h` file contains a definition for dynamic memory allocation, used by fragmenter.

The current implementation is based on draft-ietf-lpwan-ipv6-static-context-hc-18 (<https://datatracker.ietf.org/doc/draft-ietf-lpwan-ipv6-static-context-hc/18/>), some naming conventions are therefore not in line with the current specification.

Please keep in mind that the library works, but is still very experimental!
## EXAMPLES
In the folder examples are both basic compression and fragmentation examples provided. The fragmentation example makes use of a timer library and should be adapted to your platform (see [Fragmentation](#/docs/fragmentation) and the examples folder).

## LICENSE
Licensed under the GNU General Public License, Version 3 (the "License"): You may not use these files except in compliance with the License. You may obtain a copy of the License at <https://www.gnu.org/licenses/gpl-3.0.nl.html>

See the License for the specific language governing permissions and limitations under the License.

© Copyright 2018-2019, Bart Moons <bamoons.moons@ugent.be> and Ghent University