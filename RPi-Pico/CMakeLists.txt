cmake_minimum_required(VERSION 3.13)

# Pull in Pico and FreeRTOS
include(pico_sdk_import.cmake)
include(pico_extras_import.cmake)
# include($ENV{FREERTOS_KERNEL_PATH}/portable/ThirdParty/GCC/RP2040/FreeRTOS_Kernel_import.cmake)


if(PICO_SDK_VERSION_STRING VERSION_LESS "1.3.0")
    message(FATAL_ERROR "Raspberry Pi Pico SDK version 1.3.0 (or later) required. Your version is ${PICO_SDK_VERSION_STRING}")
endif()

project(wolf_pico_examples C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Initialize the SDK
pico_sdk_init()


### Global Include Path
    include_directories(config)
    include_directories(include)
    include_directories(${PICO_SDK_PATH}/src/rp2_common/pico_lwip/include)
    include_directories(${PICO_SDK_PATH}/lib/lwip/contrib/ports/freertos/include)
    include_directories(${PICO_SDK_PATH}/lib/lwip/src/include)
    include_directories(${PICO_SDK_PATH}/src/rp2_common/pico_async_context/include)

    set(WOLFSSL_ROOT $ENV{WOLFSSL_ROOT})
    include_directories(${WOLFSSL_ROOT})
### End of Global Include Path


### wolfSSL/wolfCrypt library
    file(GLOB_RECURSE WOLFSSL_SRC
        "${WOLFSSL_ROOT}/src/*.c"
        "${WOLFSSL_ROOT}/wolfcrypt/src/*.c"
    )
    list(REMOVE_ITEM WOLFSSL_SRC EXCLUDE REGEX
        "${WOLFSSL_ROOT}/src/bio.c"
        "${WOLFSSL_ROOT}/src/conf.c"
        "${WOLFSSL_ROOT}/src/pk.c"
        "${WOLFSSL_ROOT}/src/ssl_asn1.c"
        "${WOLFSSL_ROOT}/src/ssl_bn.c"
        "${WOLFSSL_ROOT}/src/ssl_misc.c"
        "${WOLFSSL_ROOT}/src/x509.c"
        "${WOLFSSL_ROOT}/src/x509_str.c"
        "${WOLFSSL_ROOT}/wolfcrypt/src/evp.c"
        "${WOLFSSL_ROOT}/wolfcrypt/src/misc.c"
    )

    add_library(wolfssl STATIC
        ${WOLFSSL_SRC}
    )

    target_compile_definitions(wolfssl PUBLIC
        WOLFSSL_USER_SETTINGS
    )
### End of wolfSSL/wolfCrypt library


### TLS Client
    add_executable(tls_Client
        src/blink.c
        src/wifi.c
        src/tcp.c
        src/tlsClient_main.c
    )

    target_compile_definitions(tls_Client PRIVATE
        WIFI_SSID=\"${WIFI_SSID}\"
        WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
        TEST_TCP_SERVER_IP=\"${TEST_TCP_SERVER_IP}\"
        PICO_CYW43_ARCH_POLL
        NO_SYS=1
    )

    target_link_libraries(tls_Client
        pico_stdlib
        pico_rand
        pico_lwip
        pico_cyw43_arch
        pico_lwip_nosys
        pico_async_context_poll
        wolfssl
    )

    pico_enable_stdio_usb(tls_Client 1)
    pico_enable_stdio_uart(tls_Client 0)

    pico_add_extra_outputs(tls_Client)
### End of TLS Client