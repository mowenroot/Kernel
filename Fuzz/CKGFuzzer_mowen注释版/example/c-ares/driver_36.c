#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Define the maximum input size to prevent excessive memory usage
#define MAX_INPUT_SIZE 1024  // Example size, adjust as needed

// Function to safely extract a 16-bit unsigned integer from the fuzz input
unsigned short extract_u16(const uint8_t *data, size_t *offset) {
    if (*offset + sizeof(unsigned short) > MAX_INPUT_SIZE) {
        return 0; // Return a default value if out of bounds
    }
    unsigned short val = *(unsigned short *)(data + *offset);
    *offset += sizeof(unsigned short);
    return val;
}

// Function to safely extract a 32-bit unsigned integer from the fuzz input
unsigned int extract_u32(const uint8_t *data, size_t *offset) {
    if (*offset + sizeof(unsigned int) > MAX_INPUT_SIZE) {
        return 0; // Return a default value if out of bounds
    }
    unsigned int val = *(unsigned int *)(data + *offset);
    *offset += sizeof(unsigned int);
    return val;
}

// Function to safely extract a string from the fuzz input
const char *extract_str(const uint8_t *data, size_t *offset, size_t size) {
    if (*offset >= size) {
        return NULL; // Return NULL if out of bounds
    }
    const char *str = (const char *)(data + *offset);
    *offset += strlen(str) + 1; // Move offset past the string and null terminator
    return str;
}

// Function to safely extract binary data from the fuzz input
const unsigned char *extract_bin(const uint8_t *data, size_t *offset, size_t size, size_t *len) {
    if (*offset >= size) {
        return NULL; // Return NULL if out of bounds
    }
    *len = size - *offset;
    const unsigned char *bin = data + *offset;
    *offset = size; // Move offset to the end of the input
    return bin;
}

// Function to safely extract an IPv4 address from the fuzz input
const struct in_addr *extract_addr(const uint8_t *data, size_t *offset) {
    if (*offset + sizeof(struct in_addr) > MAX_INPUT_SIZE) {
        return NULL; // Return NULL if out of bounds
    }
    const struct in_addr *addr = (const struct in_addr *)(data + *offset);
    *offset += sizeof(struct in_addr);
    return addr;
}

// Function to safely extract an IPv6 address from the fuzz input
const struct ares_in6_addr *extract_addr6(const uint8_t *data, size_t *offset) {
    if (*offset + sizeof(struct ares_in6_addr) > MAX_INPUT_SIZE) {
        return NULL; // Return NULL if out of bounds
    }
    const struct ares_in6_addr *addr = (const struct ares_in6_addr *)(data + *offset);
    *offset += sizeof(struct ares_in6_addr);
    return addr;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > MAX_INPUT_SIZE) {
        return 0;
    }

    // Initialize variables
    ares_dns_rr_t *dns_rr = NULL;
    ares_status_t status;
    size_t offset = 0;

    // Allocate memory for the DNS resource record
    dns_rr = ares_dns_rr_create();
    if (dns_rr == NULL) {
        return 0; // Memory allocation failed
    }

    // Extract and set a 16-bit unsigned integer
    unsigned short u16_val = extract_u16(data, &offset);
    status = ares_dns_rr_set_u16(dns_rr, ARES_RR_A_ADDR, u16_val);
    if (status != ARES_SUCCESS) {
        goto cleanup;
    }

    // Extract and set a 32-bit unsigned integer
    unsigned int u32_val = extract_u32(data, &offset);
    status = ares_dns_rr_set_u32(dns_rr, ARES_RR_AAAA_ADDR, u32_val);
    if (status != ARES_SUCCESS) {
        goto cleanup;
    }

    // Extract and set an IPv4 address
    const struct in_addr *addr = extract_addr(data, &offset);
    if (addr != NULL) {
        status = ares_dns_rr_set_addr(dns_rr, ARES_RR_A_ADDR, addr);
        if (status != ARES_SUCCESS) {
            goto cleanup;
        }
    }

    // Extract and set an IPv6 address
    const struct ares_in6_addr *addr6 = extract_addr6(data, &offset);
    if (addr6 != NULL) {
        status = ares_dns_rr_set_addr6(dns_rr, ARES_RR_AAAA_ADDR, addr6);
        if (status != ARES_SUCCESS) {
            goto cleanup;
        }
    }

    // Extract and set a string
    const char *str_val = extract_str(data, &offset, size);
    if (str_val != NULL) {
        status = ares_dns_rr_set_str(dns_rr, ARES_RR_A_ADDR, str_val);
        if (status != ARES_SUCCESS) {
            goto cleanup;
        }
    }

    // Extract and set binary data
    size_t bin_len;
    const unsigned char *bin_val = extract_bin(data, &offset, size, &bin_len);
    if (bin_val != NULL) {
        status = ares_dns_rr_set_bin(dns_rr, ARES_RR_AAAA_ADDR, bin_val, bin_len);
        if (status != ARES_SUCCESS) {
            goto cleanup;
        }
    }

cleanup:
    // Free the allocated DNS resource record
    ares_dns_rr_destroy(dns_rr);

    return 0;
}
