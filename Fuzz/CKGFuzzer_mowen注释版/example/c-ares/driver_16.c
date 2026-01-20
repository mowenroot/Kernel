#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a uint16_t from the fuzz input
uint16_t extract_uint16(const uint8_t *data, size_t *offset, size_t max_input_size) {
    if (*offset + sizeof(uint16_t) > max_input_size) {
        return 0; // Return a default value if out of bounds
    }
    uint16_t value = (data[*offset] << 8) | data[*offset + 1];
    *offset += sizeof(uint16_t);
    return value;
}

// Function to safely extract a uint8_t from the fuzz input
uint8_t extract_uint8(const uint8_t *data, size_t *offset, size_t max_input_size) {
    if (*offset >= max_input_size) {
        return 0; // Return a default value if out of bounds
    }
    uint8_t value = data[*offset];
    *offset += sizeof(uint8_t);
    return value;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Define a maximum input size to prevent excessive memory usage
    const size_t MAX_INPUT_SIZE = 1024;
    if (size > MAX_INPUT_SIZE) {
        return 0; // Ignore inputs larger than the maximum size
    }

    // Initialize variables
    ares_dns_record_t *dnsrec = NULL;
    ares_dns_record_t *dnsrec_dup = NULL;
    unsigned short flags = 0;
    ares_dns_opcode_t opcode = 0;
    ares_status_t status = ARES_SUCCESS;
    size_t offset = 0;

    // Extract values from fuzz input
    uint16_t id = extract_uint16(data, &offset, MAX_INPUT_SIZE);
    flags = extract_uint16(data, &offset, MAX_INPUT_SIZE);
    opcode = extract_uint8(data, &offset, MAX_INPUT_SIZE);
    ares_dns_rcode_t rcode = extract_uint8(data, &offset, MAX_INPUT_SIZE);

    // Create a DNS record
    status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        goto cleanup; // Handle error and cleanup
    }

    // Get flags and opcode from the DNS record
    flags = ares_dns_record_get_flags(dnsrec);
    opcode = ares_dns_record_get_opcode(dnsrec);

    // Duplicate the DNS record
    dnsrec_dup = ares_dns_record_duplicate(dnsrec);
    if (dnsrec_dup == NULL) {
        goto cleanup; // Handle error and cleanup
    }

    // Perform a nameinfo lookup (dummy implementation as ares_getnameinfo requires a callback)
    // This is a placeholder to demonstrate the API usage
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ares_getnameinfo(NULL, (struct sockaddr *)&sa, sizeof(sa), 0, NULL, NULL);

cleanup:
    // Free allocated resources
    if (dnsrec != NULL) {
        ares_free(dnsrec);
    }
    if (dnsrec_dup != NULL) {
        ares_free(dnsrec_dup);
    }

    return 0; // Return 0 to indicate success
}
