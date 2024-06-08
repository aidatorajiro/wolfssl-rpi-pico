. credentials/credentials.sh

rm -rf build
mkdir build
cd build
export WOLFSSL_ROOT=$(pwd)/../wolfssl
export PICO_SDK_PATH=$(pwd)/../pico-sdk
export PICO_EXTRAS_PATH=$(pwd)/../pico-extras
cmake -DPICO_BOARD=pico_w \
      -DWIFI_SSID=$WIFI_SSID \
      -DWIFI_PASSWORD=$WIFI_PASSWORD \
      -DTEST_TCP_SERVER_IP=$TEST_TCP_SERVER_IP \
      ../RPi-Pico
make -j