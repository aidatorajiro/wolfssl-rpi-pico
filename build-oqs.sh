rm -rf build-oqs
mkdir build-oqs
cd build-oqs
export CC=arm-none-eabi-gcc
export PICO_SDK_PATH=$(pwd)/../pico-sdk
export PICO_EXTRAS_PATH=$(pwd)/../pico-extras
cmake -DOQS_USE_OPENSSL=OFF -DPICO_BOARD=pico_w -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON ../liboqs
make -j