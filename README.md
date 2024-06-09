# wolfssl rpi pico

build and use wolfssl in raspberry pi pico

## install dependencies

for ubuntu, just run `sudo apt install openssl git cmake gcc-arm-none-eabi libnewlib-arm-none-eabi libstdc++-arm-none-eabi-newlib build-essential python3 ripgrep -y`

for others,

1. download [Arm GNU Toolchain](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads) for ARM 32bit (`arm-gnu-toolchain-xx.x.Relx-x86_64-arm-none-eabi`) and set appropriate `$PATH` environment variable.
2. download other build dependencies like `openssl make cmake python3 git`

## build config for wolfssl

1. apply patch `wolfssl-patch-benchmark.patch` in wolfssl  
   `cd woldssl; git reset --hard; patch -p1 ../wolfssl-patch-benchmark.patch`
3. `mkdir credentials; cd credentials; mkdir certs wolfssl; cd ..`
4. in `credentials` folder, create `credentials.sh` as follows:
   ```bash
   export WIFI_SSID=<wifi SSID>
   export WIFI_PASSWORD=<wifi PASSWORD>
   export TEST_TCP_SERVER_IP=<host server IP address used for connection and digital signature. you have to run "ifconfig" or "ip address" to obtain machine ip address>
   export TEST_TCP_SERVER_NAME=<host domain name for digital signature>
   ```
6. generate CA certificate and server certificate  
   `sh certs-ca.sh; sh certs-server.sh;`
5. build via docker `sh build-wolf-docker.sh` or directly run `sh build-wolf.sh`
6. plug raspberry pi pico w to the host computer, while pressing BOOTSEL button.
7. mount the raspberry pi drive, and put `build/tls_Client.uf2` there.
8. run `sh server.sh` to set up the local server
9. run `sh tty.sh` to connect to raspberry pi debug IO
9. if you use gvfs/udisks2, `sh build-wolf-rpi.sh` to build, install the image to raspberry pi, connect to debug IO automatically.

## build config for liboqs

1. Apply `liboqs-pico-patch.patch` in liboqs.  
   `cd liboqs; git reset --hard; patch -p1 ../liboqs-pico-patch.patch`
2. run `sh build-oqs.sh`

## license informations

wolfSSL (formerly known as CyaSSL) and wolfCrypt are either licensed for use
under the GPLv2 (or at your option any later version) or a standard commercial
license. For our users who cannot use wolfSSL under GPLv2
(or any later version), a commercial license to wolfSSL and wolfCrypt is
available.

Please contact wolfSSL Inc. directly at:

Email: licensing@wolfssl.com
Phone: +1 425 245-8247

More information can be found on the wolfSSL website at www.wolfssl.com.

***

Raspberry Pi Pico SDK license

Copyright 2020 (c) 2020 Raspberry Pi (Trading) Ltd.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
   disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
   disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
