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

// Function to safely extract a short value from fuzz input
static unsigned short safe_extract_short(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset + sizeof(unsigned short) > size) {
        return 0; // Return 0 if not enough data
    }
    unsigned short value = *(unsigned short*)(data + *offset);
    *offset += sizeof(unsigned short);
    return value;
}

// Function to safely extract an int value from fuzz input
static int safe_extract_int(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset + sizeof(int) > size) {
        return 0; // Return 0 if not enough data
    }
    int value = *(int*)(data + *offset);
    *offset += sizeof(int);
    return value;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    ares_channel_t *channel = NULL;
    ares_dns_record_t *dnsrec = NULL;
    char *csv_servers = NULL;
    char *hostname = NULL;
    int result;
    size_t offset = 0;

    // Initialize the channel
    if (ares_init(&channel) != ARES_SUCCESS) {
        return 0;
    }

    // Extract and set DNS servers from CSV string
    csv_servers = safe_strndup(data, size);
    if (csv_servers) {
        result = ares_set_servers_csv(channel, csv_servers);
        if (result != ARES_SUCCESS) {
            free(csv_servers);
            ares_destroy(channel);
            return 0;
        }
        free(csv_servers);
    }

    // Extract DNS record parameters
    unsigned short id = safe_extract_short(data, size, &offset);
    unsigned short flags = safe_extract_short(data, size, &offset);
    ares_dns_opcode_t opcode = (ares_dns_opcode_t)safe_extract_int(data, size, &offset);
    ares_dns_rcode_t rcode = (ares_dns_rcode_t)safe_extract_int(data, size, &offset);

    // Create DNS record
    result = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (result != ARES_SUCCESS) {
        ares_destroy(channel);
        return 0;
    }

    // Extract hostname for ares_gethostbyaddr
    hostname = safe_strndup(data + offset, size - offset);
    if (hostname) {
        // Perform DNS lookup
        ares_gethostbyaddr(channel, hostname, strlen(hostname), AF_INET, NULL, NULL);
        free(hostname);
    }

    // Destroy DNS record
    ares_dns_record_destroy(dnsrec);

    // Destroy the channel
    ares_destroy(channel);

    return 0;
}
