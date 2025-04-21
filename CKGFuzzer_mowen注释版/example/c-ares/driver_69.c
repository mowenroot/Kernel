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

// Function to safely extract an integer from fuzz input
static int safe_extract_int(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset + sizeof(int) > size) return 0;
    int value = *(int*)(data + *offset);
    *offset += sizeof(int);
    return value;
}

// Function to safely extract a short from fuzz input
static unsigned short safe_extract_short(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset + sizeof(unsigned short) > size) return 0;
    unsigned short value = *(unsigned short*)(data + *offset);
    *offset += sizeof(unsigned short);
    return value;
}

// Function to safely extract a byte from fuzz input
static unsigned char safe_extract_byte(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset >= size) return 0;
    unsigned char value = data[*offset];
    *offset += 1;
    return value;
}

// Fuzz driver function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ares_channel_t *channel = NULL;
    ares_dns_record_t *dnsrec = NULL;
    char *name = NULL;
    int dnsclass, type;
    unsigned short id, flags;
    unsigned char opcode, rcode;
    size_t offset = 0;

    // Initialize ares channel
    if (ares_init(&channel) != ARES_SUCCESS) {
        return 0;
    }

    // Extract inputs from fuzz data
    name = safe_strndup(data, size);
    if (!name) goto cleanup;

    offset = strlen(name);
    dnsclass = safe_extract_int(data, size, &offset);
    type = safe_extract_int(data, size, &offset);
    id = safe_extract_short(data, size, &offset);
    flags = safe_extract_short(data, size, &offset);
    opcode = safe_extract_byte(data, size, &offset);
    rcode = safe_extract_byte(data, size, &offset);

    // Create DNS record
    if (ares_dns_record_create(&dnsrec, id, flags, (ares_dns_opcode_t)opcode, (ares_dns_rcode_t)rcode) != ARES_SUCCESS) {
        goto cleanup;
    }

    // Perform ares_search
    ares_search(channel, name, dnsclass, type, NULL, NULL);

    // Perform ares_query
    ares_query(channel, name, dnsclass, type, NULL, NULL);

    // Perform ares_send
    ares_send(channel, (const unsigned char*)data, size, NULL, NULL);

    // Perform ares_process
    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    ares_process(channel, &read_fds, &write_fds);

cleanup:
    // Free resources
    if (dnsrec) ares_dns_record_destroy(dnsrec);
    if (name) free(name);
    if (channel) ares_destroy(channel);

    return 0;
}
