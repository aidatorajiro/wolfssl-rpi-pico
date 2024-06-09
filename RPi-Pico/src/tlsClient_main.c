/* tcpClient_main.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#define USE_CERT_BUFFERS_256
#define USE_CERT_BUFFERS_2048
#define TCP_PORT 11111

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/ssl.h"

#include "wolf/common.h"
#include "wolf/tcp.h"
#include "wolf/wifi.h"
#include "wolf/blink.h"

#include "lwip/tcp.h"
#include "lwip/dns.h"
#include "lwip/pbuf.h"
#include "lwip/udp.h"

#include "../credentials/wolfssl/mycerts.h"

// BEGIN NTP client code derived from https://github.com/raspberrypi/pico-examples/blob/654aabc6869c80b4b05739e764528907c2d30d7e/pico_w/wifi/ntp_client/picow_ntp_client.c
typedef struct NTP_T_ {
    ip_addr_t ntp_server_address;
    bool dns_request_sent;
    struct udp_pcb *ntp_pcb;
    absolute_time_t ntp_test_time;
    alarm_id_t ntp_resend_alarm;
} NTP_T;

#define NTP_SERVER "pool.ntp.org"
#define NTP_MSG_LEN 48
#define NTP_PORT 123
#define NTP_DELTA 2208988800 // seconds between 1 Jan 1900 and 1 Jan 1970
#define NTP_TEST_TIME (30 * 1000)
#define NTP_RESEND_TIME (10 * 1000)

time_t ntp_time = 0;

// Called with results of operation
static void ntp_result(NTP_T* state, int status, time_t *result) {
    if (status == 0 && result) {
        struct tm *utc = gmtime(result);
        printf("got ntp response: %02d/%02d/%04d %02d:%02d:%02d\n", utc->tm_mday, utc->tm_mon + 1, utc->tm_year + 1900,
               utc->tm_hour, utc->tm_min, utc->tm_sec);
        ntp_time = *result;
    }

    if (state->ntp_resend_alarm > 0) {
        cancel_alarm(state->ntp_resend_alarm);
        state->ntp_resend_alarm = 0;
    }
    state->ntp_test_time = make_timeout_time_ms(NTP_TEST_TIME);
    state->dns_request_sent = false;
}

static int64_t ntp_failed_handler(alarm_id_t id, void *user_data);

// Make an NTP request
static void ntp_request(NTP_T *state) {
    // cyw43_arch_lwip_begin/end should be used around calls into lwIP to ensure correct locking.
    // You can omit them if you are in a callback from lwIP. Note that when using pico_cyw_arch_poll
    // these calls are a no-op and can be omitted, but it is a good practice to use them in
    // case you switch the cyw43_arch type later.
    cyw43_arch_lwip_begin();
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, NTP_MSG_LEN, PBUF_RAM);
    uint8_t *req = (uint8_t *) p->payload;
    memset(req, 0, NTP_MSG_LEN);
    req[0] = 0x1b;
    udp_sendto(state->ntp_pcb, p, &state->ntp_server_address, NTP_PORT);
    pbuf_free(p);
    cyw43_arch_lwip_end();
}

static int64_t ntp_failed_handler(alarm_id_t id, void *user_data)
{
    NTP_T* state = (NTP_T*)user_data;
    printf("ntp request failed\n");
    ntp_result(state, -1, NULL);
    return 0;
}

// Call back with a DNS result
static void ntp_dns_found(const char *hostname, const ip_addr_t *ipaddr, void *arg) {
    NTP_T *state = (NTP_T*)arg;
    if (ipaddr) {
        state->ntp_server_address = *ipaddr;
        printf("ntp address %s\n", ipaddr_ntoa(ipaddr));
        ntp_request(state);
    } else {
        printf("ntp dns request failed\n");
        ntp_result(state, -1, NULL);
    }
}

// NTP data received
static void ntp_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port) {
    NTP_T *state = (NTP_T*)arg;
    uint8_t mode = pbuf_get_at(p, 0) & 0x7;
    uint8_t stratum = pbuf_get_at(p, 1);

    // Check the result
    if (ip_addr_cmp(addr, &state->ntp_server_address) && port == NTP_PORT && p->tot_len == NTP_MSG_LEN &&
        mode == 0x4 && stratum != 0) {
        uint8_t seconds_buf[4] = {0};
        pbuf_copy_partial(p, seconds_buf, sizeof(seconds_buf), 40);
        uint32_t seconds_since_1900 = seconds_buf[0] << 24 | seconds_buf[1] << 16 | seconds_buf[2] << 8 | seconds_buf[3];
        uint32_t seconds_since_1970 = seconds_since_1900 - NTP_DELTA;
        time_t epoch = seconds_since_1970;
        ntp_result(state, 0, &epoch);
    } else {
        printf("invalid ntp response\n");
        ntp_result(state, -1, NULL);
    }
    pbuf_free(p);
}

// Perform initialisation
static NTP_T* ntp_init(void) {
    NTP_T *state = (NTP_T*)calloc(1, sizeof(NTP_T));
    if (!state) {
        printf("failed to allocate state\n");
        return NULL;
    }
    state->ntp_pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
    if (!state->ntp_pcb) {
        printf("failed to create pcb\n");
        free(state);
        return NULL;
    }
    udp_recv(state->ntp_pcb, ntp_recv, state);
    return state;
}

// Runs ntp test forever
void ntp_sync(void) {
    NTP_T *state = ntp_init();
    if (!state)
        return;
    while(ntp_time == 0) {
        if (absolute_time_diff_us(get_absolute_time(), state->ntp_test_time) < 0 && !state->dns_request_sent) {
            // Set alarm in case udp requests are lost
            state->ntp_resend_alarm = add_alarm_in_ms(NTP_RESEND_TIME, ntp_failed_handler, state, true);

            // cyw43_arch_lwip_begin/end should be used around calls into lwIP to ensure correct locking.
            // You can omit them if you are in a callback from lwIP. Note that when using pico_cyw_arch_poll
            // these calls are a no-op and can be omitted, but it is a good practice to use them in
            // case you switch the cyw43_arch type later.
            cyw43_arch_lwip_begin();
            int err = dns_gethostbyname(NTP_SERVER, &state->ntp_server_address, ntp_dns_found, state);
            cyw43_arch_lwip_end();

            state->dns_request_sent = true;
            if (err == ERR_OK) {
                ntp_request(state); // Cached result
            } else if (err != ERR_INPROGRESS) { // ERR_INPROGRESS means expect a callback
                printf("dns request failed\n");
                ntp_result(state, -1, NULL);
            }
        }
        // if you are using pico_cyw43_arch_poll, then you must poll periodically from your
        // main loop (not from a timer interrupt) to check for Wi-Fi driver or lwIP work that needs to be done.
        cyw43_arch_poll();
        // you can poll as often as you like, however if you have nothing else to do you can
        // choose to sleep until either a specified time, or cyw43_arch_poll() has work to do:
        cyw43_arch_wait_for_work_until(state->dns_request_sent ? at_the_end_of_time : state->ntp_test_time);
    }
    udp_remove(state->ntp_pcb);
    free(state);
}
// END ntp code

int wolf_cb_TCPwrite(WOLFSSL *ssl, const unsigned char *buff, long unsigned int len, void *ctx)
{
    (void)ssl;
    unsigned long ret;
    WOLF_SOCKET_T sock = (WOLF_SOCKET_T)ctx;
    ret = wolf_TCPwrite(sock, buff, len);
    return ret;
}

int wolf_cb_TCPread(WOLFSSL *ssl, unsigned char *buff, long unsigned int len, void *ctx)
{
    (void)ssl;
    WOLF_SOCKET_T sock = (WOLF_SOCKET_T)ctx;
    int ret;

    ret = wolf_TCPread(sock, buff, len);
    return ret;
}

void tlsClient_test(void)
{
    int i;
    int ret;
    #define BUFF_SIZE 2048
    static char buffer[BUFF_SIZE];
    char msg[] = "Hello Server";

    WOLF_SOCKET_T sock;
    struct sockaddr_in servAddr;

    WOLFSSL_CTX *ctx    = NULL;
    WOLFSSL     *ssl    = NULL;

    /* Initialize wolfSSL */
    printf("Init WolfSSL.\n");
    wolfSSL_Init();
    wolfSSL_Debugging_ON();

    printf("Create Context.\n");

    if ((ctx = wolfSSL_CTX_new((wolfTLSv1_2_client_method()))) == NULL) {
        printf("ERROR:wolfSSL_CTX_new()\n");
        return;
    }

    printf("Load CA Cert.\n");

    /* Load client certificates into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_load_verify_buffer(ctx, my_cert_rsa,
            sizeof_my_cert_rsa, SSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS) {
        printf("ERROR: failed to load CA cert. %d\n", ret);
        goto exit;
    }

    printf("Cert Loaded.\n");

    wolfSSL_SetIORecv(ctx, (CallbackIORecv)wolf_cb_TCPread);
    wolfSSL_SetIOSend(ctx, (CallbackIOSend)wolf_cb_TCPwrite);

    sock = wolf_TCPsocket();
    if (!sock)
    {
        printf("ERROR:wolf_TCPsocke()\n");
        return;
    }

    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;           /* using IPv4      */
    servAddr.sin_port = htons(TCP_PORT); /* on DEFAULT_PORT */

    if (wolf_inet_pton(AF_INET, TEST_TCP_SERVER_IP, &servAddr.sin_addr) != 1) {
        fprintf(stderr, "ERROR: invalid address\n");
        goto exit;
    }

    if (wolf_TCPconnect(sock,(struct sockaddr*) &servAddr, sizeof(servAddr)) != WOLF_SUCCESS) {
        printf("ERROR:wolf_TCPconnect()\n");
        goto exit;
    }


    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        ret = -1; 
        goto exit;
    }

    wolfSSL_SetIOReadCtx(ssl, sock);
    wolfSSL_SetIOWriteCtx(ssl, sock);

    printf("TLS Connecting\n");
    if ((ret = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to connect to wolfSSL(%d)\n",
            wolfSSL_get_error(ssl, ret));
        goto exit;
    }

    printf("Writing to server: %s\n", msg);
    ret = wolfSSL_write(ssl, msg, strlen(msg));
    if (ret < 0) {
        DEBUG_printf("Failed to write data. err=%d\n", ret);
        goto exit;
    }

    ret = wolfSSL_read(ssl, buffer, BUFF_SIZE);
    if (ret < 0) {
        DEBUG_printf("Failed to read data. err=%d\n", ret);
        goto exit;
    }
    printf("Message: %s\n", buffer);


exit:
    if (ssl)
        wolfSSL_free(ssl);      /* Free the wolfSSL object              */
    if (sock)
        free(sock);              /* Close the connection to the server   */
    if (ctx)
        wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();          /* Cleanup the wolfSSL environment          */

}

void main(void)
{
    blink(20, 1);

    cyw43_arch_enable_sta_mode();
    printf("Connecting to Wi-Fi...\n");
    printf("WIFI_SSID=%s, WIFI_PASSWORD=%s\n", WIFI_SSID, WIFI_PASSWORD);
    if (wolf_wifiConnect(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 30000)) {
        printf("failed to connect.\n");
        return;
    } else {
        printf("Wifi connected.\n");
    }
    
    printf("Sync Time.\n");
    ntp_sync();
    printf("Current Time: %lld\n", ntp_time);

    cyw43_arch_lwip_begin();
    printf("Starting TLS client\n");
    tlsClient_test();
    printf("End of TLS client\n");
    cyw43_arch_lwip_end();

    cyw43_arch_deinit();
    printf("Wifi disconnected\n");
}

void lwip_example_app_platform_assert(const char *msg, int line, const char *file)
{
    printf("Assertion \"%s\" failed at line %d in %s\n", msg, line, file);
    fflush(NULL);
}

#include <time.h>
time_t myTime(time_t *t)
{
    time_t tret;
    
    if (ntp_time != 0) {
        tret = ntp_time;
    } else {
        tret = 1717859260;
    }

    if (t != NULL) {
        *t = tret;
    }
    return tret;
}