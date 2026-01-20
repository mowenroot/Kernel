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
    if (*offset + sizeof(unsigned short) > size) return 0;
    unsigned short value = *(unsigned short*)(data + *offset);
    *offset += sizeof(unsigned short);
    return value;
}

// Function to safely extract an opcode from fuzz input
static ares_dns_opcode_t safe_extract_opcode(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset + sizeof(ares_dns_opcode_t) > size) return 0;
    ares_dns_opcode_t opcode = *(ares_dns_opcode_t*)(data + *offset);
    *offset += sizeof(ares_dns_opcode_t);
    return opcode;
}

// Function to safely extract an rcode from fuzz input
static ares_dns_rcode_t safe_extract_rcode(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset + sizeof(ares_dns_rcode_t) > size) return 0;
    ares_dns_rcode_t rcode = *(ares_dns_rcode_t*)(data + *offset);
    *offset += sizeof(ares_dns_rcode_t);
    return rcode;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    ares_dns_record_t *dnsrec = NULL;
    ares_dns_record_t *dnsrec_dup = NULL;
    struct hostent *host = NULL;
    ares_channel_t *channel = NULL;
    unsigned short flags = 0;
    unsigned short id = 0;
    ares_dns_opcode_t opcode = 0;
    ares_dns_rcode_t rcode = 0;
    size_t offset = 0;

    // Extract values from fuzz input
    id = safe_extract_short(data, size, &offset);
    flags = safe_extract_short(data, size, &offset);
    opcode = safe_extract_opcode(data, size, &offset);
    rcode = safe_extract_rcode(data, size, &offset);

    // Create a DNS record
    ares_status_t status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // Get flags from the DNS record
    flags = ares_dns_record_get_flags(dnsrec);

    // Duplicate the DNS record
    dnsrec_dup = ares_dns_record_duplicate(dnsrec);
    if (dnsrec_dup) {
        // Destroy the duplicated record
        ares_dns_record_destroy(dnsrec_dup);
    }

    // Destroy the original DNS record
    ares_dns_record_destroy(dnsrec);

    // Extract hostname from fuzz input
    char *hostname = safe_strndup(data + offset, size - offset);
    if (hostname) {
        // Perform a hostname lookup
        int result = ares_gethostbyname_file(channel, hostname, AF_INET, &host);
        if (result == ARES_SUCCESS && host) {
            // Free the hostent structure
            ares_free_hostent(host);
        }
        free(hostname);
    }

    return 0;
}
