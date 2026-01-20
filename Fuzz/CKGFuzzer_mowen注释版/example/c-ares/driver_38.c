#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a 16-bit unsigned integer from the fuzz input
unsigned short extract_u16(const uint8_t *data, size_t *offset) {
    if (*offset + 2 > SIZE_MAX) {
        return 0;
    }
    unsigned short val = (data[*offset] << 8) | data[*offset + 1];
    *offset += 2;
    return val;
}

// Function to safely extract an 8-bit unsigned integer from the fuzz input
unsigned char extract_u8(const uint8_t *data, size_t *offset) {
    if (*offset >= SIZE_MAX) {
        return 0;
    }
    unsigned char val = data[*offset];
    *offset += 1;
    return val;
}

// Function to safely extract a 32-bit unsigned integer from the fuzz input
unsigned int extract_u32(const uint8_t *data, size_t *offset) {
    if (*offset + 4 > SIZE_MAX) {
        return 0;
    }
    unsigned int val = (data[*offset] << 24) | (data[*offset + 1] << 16) |
                       (data[*offset + 2] << 8) | data[*offset + 3];
    *offset += 4;
    return val;
}

// Fuzz driver function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < 8) {
        return 0;
    }

    // Initialize variables
    ares_dns_rr_t *dns_rr = NULL;
    ares_dns_rr_key_t key1 = 0; // Replace with actual key value
    ares_dns_rr_key_t key2 = 0; // Replace with actual key value
    ares_dns_rr_key_t key3 = 0; // Replace with actual key value
    ares_dns_rr_key_t key4 = 0; // Replace with actual key value
    ares_dns_rr_key_t key5 = 0; // Replace with actual key value

    // Allocate memory for the DNS resource record
    dns_rr = ares_dns_rr_create();
    if (dns_rr == NULL) {
        return 0;
    }

    // Extract values from fuzz input
    size_t offset = 0;
    unsigned short u16_val = extract_u16(data, &offset);
    unsigned char u8_val = extract_u8(data, &offset);
    unsigned int u32_val = extract_u32(data, &offset);

    // Set values using the API functions
    ares_status_t status;

    status = ares_dns_rr_set_u16(dns_rr, key1, u16_val);
    if (status != ARES_SUCCESS) {
        ares_dns_rr_destroy(dns_rr);
        return 0;
    }

    status = ares_dns_rr_set_u8(dns_rr, key2, u8_val);
    if (status != ARES_SUCCESS) {
        ares_dns_rr_destroy(dns_rr);
        return 0;
    }

    status = ares_dns_rr_set_u32(dns_rr, key3, u32_val);
    if (status != ARES_SUCCESS) {
        ares_dns_rr_destroy(dns_rr);
        return 0;
    }

    // Get values using the API functions
    unsigned short retrieved_u16 = ares_dns_rr_get_u16(dns_rr, key1);
    unsigned char retrieved_u8 = ares_dns_rr_get_u8(dns_rr, key2);
    unsigned int retrieved_u32 = ares_dns_rr_get_u32(dns_rr, key3);

    // Clean up
    ares_dns_rr_destroy(dns_rr);

    // Return 0 to indicate success
    return 0;
}
