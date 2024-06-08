FROM ubuntu:24.04
RUN apt update
RUN apt upgrade -y
RUN apt install git cmake gcc-arm-none-eabi libnewlib-arm-none-eabi libstdc++-arm-none-eabi-newlib build-essential python3 ripgrep -y