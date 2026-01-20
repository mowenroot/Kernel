#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a 16-bit unsigned integer from the fuzz input
unsigned short safe_get_u16(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset + sizeof(unsigned short) > size) {
        return 0; // Return 0 if not enough data
    }
    unsigned short val = *(unsigned short *)(data + *offset);
    *offset += sizeof(unsigned short);
    return val;
}

// Function to safely extract an 8-bit unsigned integer from the fuzz input
unsigned char safe_get_u8(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset + sizeof(unsigned char) > size) {
        return 0; // Return 0 if not enough data
    }
    unsigned char val = *(unsigned char *)(data + *offset);
    *offset += sizeof(unsigned char);
    return val;
}

// Function to safely extract a 32-bit unsigned integer from the fuzz input
unsigned int safe_get_u32(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset + sizeof(unsigned int) > size) {
        return 0; // Return 0 if not enough data
    }
    unsigned int val = *(unsigned int *)(data + *offset);
    *offset += sizeof(unsigned int);
    return val;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    ares_dns_rr_t *dns_rr = NULL;
    ares_dns_rr_key_t key = 0; // Assuming key is an integer type
    size_t offset = 0;

    // Allocate memory for DNS resource record using ares_dns_rr_create
    dns_rr = ares_dns_rr_create();
    if (!dns_rr) {
        return 0; // Memory allocation failed
    }

    // Extract values from fuzz input
    unsigned short u16_val = safe_get_u16(data, size, &offset);
    unsigned char u8_val = safe_get_u8(data, size, &offset);
    unsigned int u32_val = safe_get_u32(data, size, &offset);

    // Set values in DNS resource record
    ares_status_t status;

    status = ares_dns_rr_set_u16(dns_rr, key, u16_val);
    if (status != ARES_SUCCESS) {
        ares_dns_rr_destroy(dns_rr);
        return 0; // Error handling
    }

    status = ares_dns_rr_set_u8(dns_rr, key, u8_val);
    if (status != ARES_SUCCESS) {
        ares_dns_rr_destroy(dns_rr);
        return 0; // Error handling
    }

    status = ares_dns_rr_set_u32(dns_rr, key, u32_val);
    if (status != ARES_SUCCESS) {
        ares_dns_rr_destroy(dns_rr);
        return 0; // Error handling
    }

    // Retrieve and verify values from DNS resource record
    unsigned short retrieved_u16 = ares_dns_rr_get_u16(dns_rr, key);
    unsigned char retrieved_u8 = ares_dns_rr_get_u8(dns_rr, key);
    unsigned int retrieved_u32 = ares_dns_rr_get_u32(dns_rr, key);

    // Free allocated memory using ares_dns_rr_destroy
    ares_dns_rr_destroy(dns_rr);

    // Return 0 to indicate success
    return 0;
}
