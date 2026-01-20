#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to handle the callback for DNS record search
void dnsrec_callback(void *arg, ares_status_t status, int timeouts, ares_dns_record_t *dnsrec) {
    // Handle the callback, but for fuzzing purposes, we don't need to do anything here
    if (dnsrec) {
        ares_dns_record_destroy(dnsrec);
    }
}

// Fuzz driver function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ares_channel_t *channel = NULL; // Change to pointer type
    ares_dns_record_t *dnsrec = NULL;
    ares_dns_record_t *dnsrec_dup = NULL;
    ares_status_t status;
    unsigned short id, flags;
    ares_dns_opcode_t opcode;
    ares_dns_rcode_t rcode;
    const char *name;
    ares_dns_class_t dnsclass;
    ares_dns_rec_type_t type;
    unsigned short qid;

    // Initialize the channel (assuming ares_init_channel is available)
    if (ares_init_channel(&channel) != ARES_SUCCESS) { // Use ares_init_channel with pointer
        return 0;
    }

    // Ensure size is sufficient for input parsing
    if (size < sizeof(id) + sizeof(flags) + sizeof(opcode) + sizeof(rcode) + sizeof(name) + sizeof(dnsclass) + sizeof(type)) {
        ares_destroy_channel(channel); // Use ares_destroy_channel with pointer
        return 0;
    }

    // Extract inputs from fuzz data
    id = *(unsigned short *)data;
    flags = *(unsigned short *)(data + sizeof(id));
    opcode = *(ares_dns_opcode_t *)(data + sizeof(id) + sizeof(flags));
    rcode = *(ares_dns_rcode_t *)(data + sizeof(id) + sizeof(flags) + sizeof(opcode));
    name = (const char *)(data + sizeof(id) + sizeof(flags) + sizeof(opcode) + sizeof(rcode));
    dnsclass = *(ares_dns_class_t *)(data + sizeof(id) + sizeof(flags) + sizeof(opcode) + sizeof(rcode) + strlen(name) + 1);
    type = *(ares_dns_rec_type_t *)(data + sizeof(id) + sizeof(flags) + sizeof(opcode) + sizeof(rcode) + strlen(name) + 1 + sizeof(dnsclass));

    // Create a DNS record
    status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        ares_destroy_channel(channel); // Use ares_destroy_channel with pointer
        return 0;
    }

    // Search for the DNS record
    status = ares_search_dnsrec(channel, dnsrec, dnsrec_callback, NULL);
    if (status != ARES_SUCCESS) {
        ares_dns_record_destroy(dnsrec);
        ares_destroy_channel(channel); // Use ares_destroy_channel with pointer
        return 0;
    }

    // Duplicate the DNS record
    dnsrec_dup = ares_dns_record_duplicate(dnsrec);
    if (dnsrec_dup) {
        ares_dns_record_destroy(dnsrec_dup);
    }

    // Query the DNS record
    status = ares_query_dnsrec(channel, name, dnsclass, type, dnsrec_callback, NULL, &qid);
    if (status != ARES_SUCCESS) {
        ares_dns_record_destroy(dnsrec);
        ares_destroy_channel(channel); // Use ares_destroy_channel with pointer
        return 0;
    }

    // Send the DNS query
    ares_send(channel, data, size, NULL, NULL);

    // Clean up
    ares_dns_record_destroy(dnsrec);
    ares_destroy_channel(channel); // Use ares_destroy_channel with pointer

    return 0;
}
