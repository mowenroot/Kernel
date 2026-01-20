#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
static char* safe_strndup(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    char *str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely get a short value from fuzz input
static unsigned short safe_get_short(const uint8_t *data, size_t size, size_t offset) {
    if (offset + 1 >= size) return 0;
    return (unsigned short)((data[offset] << 8) | data[offset + 1]);
}

// Function to safely get an int value from fuzz input
static int safe_get_int(const uint8_t *data, size_t size, size_t offset) {
    if (offset + 3 >= size) return 0;
    return (int)((data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]);
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    ares_dns_record_t *dnsrec = NULL;
    unsigned char *query_buf = NULL;
    int query_len = 0;
    char *name = NULL;
    int dnsclass, type, rd, max_udp_size;
    unsigned short id, flags;
    ares_dns_opcode_t opcode;
    ares_dns_rcode_t rcode;
    ares_status_t status;

    // Ensure we have enough data to proceed
    if (size < 16) return 0;

    // Extract values from fuzz input
    name = safe_strndup(data, size / 4);
    dnsclass = safe_get_int(data, size, size / 4);
    type = safe_get_int(data, size, size / 2);
    id = safe_get_short(data, size, size / 2 + 4);
    flags = safe_get_short(data, size, size / 2 + 6);
    opcode = (ares_dns_opcode_t)safe_get_short(data, size, size / 2 + 8);
    rcode = (ares_dns_rcode_t)safe_get_short(data, size, size / 2 + 10);
    rd = safe_get_int(data, size, size / 2 + 12);
    max_udp_size = safe_get_int(data, size, size / 2 + 14);

    // Create DNS record
    status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        free(name);
        return 0;
    }

    // Get opcode and ID from the DNS record
    ares_dns_opcode_t retrieved_opcode = ares_dns_record_get_opcode(dnsrec);
    unsigned short retrieved_id = ares_dns_record_get_id(dnsrec);

    // Create a DNS query
    int create_query_status = ares_create_query(name, dnsclass, type, id, rd, &query_buf, &query_len, max_udp_size);
    if (create_query_status != ARES_SUCCESS) {
        ares_dns_record_destroy(dnsrec);
        free(name);
        return 0;
    }

    // Clean up
    ares_dns_record_destroy(dnsrec);
    free(name);
    free(query_buf);

    return 0;
}
