#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/in.h>  // Include for struct sockaddr_in

// Callback function for ares_gethostbyname
void host_callback(void *arg, int status, int timeouts, struct hostent *host) {
    // No-op callback for fuzzing purposes
}

// Callback function for ares_getaddrinfo
void addrinfo_callback(void *arg, int status, struct ares_addrinfo *addrinfo) {
    // No-op callback for fuzzing purposes
}

// Callback function for ares_getnameinfo
void nameinfo_callback(void *arg, int status, char *node, char *service) {
    // No-op callback for fuzzing purposes
}

// Fuzz driver function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for processing
    if (size < sizeof(int) + sizeof(char) + sizeof(struct sockaddr_in)) {
        return 0;
    }

    // Initialize ares channel
    ares_channel channel;
    if (ares_init(&channel) != ARES_SUCCESS) {
        return 0;
    }

    // Extract necessary data from the fuzz input
    const char *hostname = (const char *)data;
    int family = *(int *)(data + sizeof(char));  // Adjusted offset
    struct sockaddr_in sa;
    memcpy(&sa, data + sizeof(char) + sizeof(int), sizeof(struct sockaddr_in));  // Adjusted offset

    // Perform ares_gethostbyname
    ares_gethostbyname(channel, hostname, family, host_callback, NULL);

    // Perform ares_getaddrinfo
    struct ares_addrinfo_hints hints = { ARES_AI_CANONNAME, family, 0, 0 };
    ares_getaddrinfo(channel, hostname, NULL, &hints, addrinfo_callback, NULL);

    // Perform ares_gethostbyaddr
    ares_gethostbyaddr(channel, &sa.sin_addr, sizeof(sa.sin_addr), family, host_callback, NULL);

    // Perform ares_getnameinfo
    ares_getnameinfo(channel, (struct sockaddr *)&sa, sizeof(sa), 0, nameinfo_callback, NULL);

    // Perform ares_gethostbyname_file
    struct hostent *host;
    int status = ares_gethostbyname_file(channel, hostname, family, &host);
    if (status == ARES_SUCCESS) {
        ares_free_hostent(host);
    }

    // Cleanup ares channel
    ares_destroy(channel);

    return 0;
}
