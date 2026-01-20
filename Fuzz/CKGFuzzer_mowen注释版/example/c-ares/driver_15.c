#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
static const char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return NULL;
    char* str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely extract a short value from fuzz input
static unsigned short safe_extract_short(const uint8_t* data, size_t* offset) {
    if (*offset + sizeof(unsigned short) > SIZE_MAX) return 0;
    unsigned short value = *(unsigned short*)(data + *offset);
    *offset += sizeof(unsigned short);
    return value;
}

// Function to safely extract an int value from fuzz input
static int safe_extract_int(const uint8_t* data, size_t* offset) {
    if (*offset + sizeof(int) > SIZE_MAX) return 0;
    int value = *(int*)(data + *offset);
    *offset += sizeof(int);
    return value;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    int version;
    const char* version_str = ares_version(&version);
    if (!version_str) return 0; // Handle error

    // Extract inputs from fuzz data
    size_t offset = 0;
    const char* name = safe_strndup(data, size);
    if (!name) return 0; // Handle error

    unsigned short id = safe_extract_short(data, &offset);
    unsigned short flags = safe_extract_short(data, &offset);
    int dnsclass = safe_extract_int(data, &offset);
    int type = safe_extract_int(data, &offset);

    // Create a DNS record
    ares_dns_record_t* dnsrec = NULL;
    ares_status_t status = ares_dns_record_create(&dnsrec, id, flags, ARES_OPCODE_QUERY, ARES_RCODE_NOERROR);
    if (status != ARES_SUCCESS) {
        free((void*)name);
        return 0; // Handle error
    }

    // Parse DNS response data (simulated)
    unsigned char* buf = (unsigned char*)data + offset;
    size_t buf_len = size - offset;
    ares_dns_record_t* parsed_dnsrec = NULL;
    status = ares_dns_parse(buf, buf_len, 0, &parsed_dnsrec);
    if (status != ARES_SUCCESS) {
        ares_dns_record_destroy(dnsrec);
        free((void*)name);
        return 0; // Handle error
    }

    // Perform a search operation (simulated)
    ares_channel_t* channel = NULL;
    struct ares_options options = {0}; // Initialize options to zero
    int optmask = 0;
    ares_init_options(&channel, &options, optmask); // Initialize channel
    if (channel) {
        ares_search(channel, name, dnsclass, type, NULL, NULL);
        ares_destroy(channel);
    }

    // Clean up resources
    ares_dns_record_destroy(dnsrec);
    ares_dns_record_destroy(parsed_dnsrec);
    free((void*)name);

    return 0;
}
