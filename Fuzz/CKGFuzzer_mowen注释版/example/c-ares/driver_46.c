#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to handle the callback for ares_search_dnsrec
void callback_dnsrec(void *arg, ares_status_t status, int timeouts, ares_dns_record_t *dnsrec) {
    if (dnsrec) {
        ares_dns_record_destroy(dnsrec);
    }
}

// Fuzz driver function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ares_channel_t *channel = NULL; // Use a pointer to ares_channel_t
    struct ares_addr_node *servers = NULL;
    ares_dns_record_t *dnsrec = NULL;
    ares_status_t status;

    // Initialize the channel
    if (ares_init(&channel) != ARES_SUCCESS) {
        return 0;
    }

    // Call ares_get_servers
    if (ares_get_servers(channel, &servers) != ARES_SUCCESS) {
        ares_destroy(channel);
        return 0;
    }

    // Free the servers list
    ares_free_data(servers);

    // Create a DNS record
    unsigned short id = (unsigned short)(data[0] << 8 | data[1]);
    unsigned short flags = (unsigned short)(data[2] << 8 | data[3]);
    ares_dns_opcode_t opcode = (ares_dns_opcode_t)data[4];
    ares_dns_rcode_t rcode = (ares_dns_rcode_t)data[5];

    status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        ares_destroy(channel);
        return 0;
    }

    // Call ares_search_dnsrec
    status = ares_search_dnsrec(channel, dnsrec, callback_dnsrec, NULL);
    if (status != ARES_SUCCESS) {
        ares_dns_record_destroy(dnsrec);
        ares_destroy(channel);
        return 0;
    }

    // Parse the DNS response
    size_t buf_len = size > 512 ? 512 : size; // Limit buffer size to prevent excessive memory usage
    unsigned char *buf = (unsigned char *)malloc(buf_len);
    if (!buf) {
        ares_dns_record_destroy(dnsrec);
        ares_destroy(channel);
        return 0;
    }
    memcpy(buf, data, buf_len);

    ares_dns_record_t *parsed_dnsrec = NULL;
    status = ares_dns_parse(buf, buf_len, 0, &parsed_dnsrec);
    free(buf);

    if (status == ARES_SUCCESS && parsed_dnsrec) {
        ares_dns_record_destroy(parsed_dnsrec);
    }

    // Clean up
    ares_dns_record_destroy(dnsrec);
    ares_destroy(channel);

    return 0;
}
