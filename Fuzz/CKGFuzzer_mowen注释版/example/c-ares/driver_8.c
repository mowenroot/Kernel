#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size, size_t max_len) {
    size_t len = size < max_len ? size : max_len;
    char* str = (char*)malloc(len + 1);
    if (str == NULL) {
        return NULL;
    }
    memcpy(str, data, len);
    str[len] = '\0';
    return str;
}

// Function to safely copy a buffer from fuzz input
void* safe_memdup(const uint8_t* data, size_t size, size_t max_len) {
    size_t len = size < max_len ? size : max_len;
    void* buf = malloc(len);
    if (buf == NULL) {
        return NULL;
    }
    memcpy(buf, data, len);
    return buf;
}

// Callback function for ares_query
void query_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
    // Handle the callback, but for fuzzing purposes, we don't need to do anything here
    (void)arg;
    (void)status;
    (void)timeouts;
    (void)abuf;
    (void)alen;
}

// Callback function for ares_getaddrinfo
void addrinfo_callback(void *arg, int status, int timeouts, struct ares_addrinfo *addrinfo) {
    // Handle the callback, but for fuzzing purposes, we don't need to do anything here
    (void)arg;
    (void)status;
    (void)timeouts;
    (void)addrinfo;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize ares channel
    ares_channel channel;
    ares_init(&channel);

    // ares_query
    if (size > 0) {
        char* name = safe_strndup(data, size, 255);
        if (name != NULL) {
            ares_query(channel, name, C_IN, T_A, query_callback, NULL);
            free(name);
        }
    }

    // ares_process
    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    ares_process(channel, &read_fds, &write_fds);

    // ares_getaddrinfo
    if (size > 0) {
        char* name = safe_strndup(data, size, 255);
        if (name != NULL) {
            struct ares_addrinfo_hints hints = {0};
            ares_getaddrinfo(channel, name, NULL, &hints, addrinfo_callback, NULL);
            free(name);
        }
    }

    // ares_send
    if (size > 0) {
        void* qbuf = safe_memdup(data, size, 512); // Limit to 512 bytes to prevent excessive memory usage
        if (qbuf != NULL) {
            ares_send(channel, qbuf, size, query_callback, NULL);
            free(qbuf);
        }
    }

    // ares_set_local_ip6
    if (size >= 16) { // IPv6 address is 16 bytes
        ares_set_local_ip6(channel, data);
    }

    // Cleanup
    ares_destroy(channel);

    return 0;
}
