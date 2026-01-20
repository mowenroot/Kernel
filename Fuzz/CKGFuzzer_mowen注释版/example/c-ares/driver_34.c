#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a uint16_t from the fuzz input
uint16_t extract_u16(const uint8_t *data, size_t *offset) {
    if (*offset + sizeof(uint16_t) > SIZE_MAX) {
        return 0; // Default value if not enough data
    }
    uint16_t value = (uint16_t)((data[*offset] << 8) | data[*offset + 1]);
    *offset += sizeof(uint16_t);
    return value;
}

// Function to safely extract a uint32_t from the fuzz input
uint32_t extract_u32(const uint8_t *data, size_t *offset) {
    if (*offset + sizeof(uint32_t) > SIZE_MAX) {
        return 0; // Default value if not enough data
    }
    uint32_t value = (uint32_t)((data[*offset] << 24) | (data[*offset + 1] << 16) |
                                (data[*offset + 2] << 8) | data[*offset + 3]);
    *offset += sizeof(uint32_t);
    return value;
}

// Function to safely extract a string from the fuzz input
const char *extract_string(const uint8_t *data, size_t *offset, size_t size) {
    if (*offset + 1 > size) return NULL; // Ensure there's at least one byte for the length
    size_t len = data[*offset];
    if (*offset + 1 + len > size) return NULL; // Ensure the string fits within the remaining data
    const char *str = (const char *)&data[*offset + 1];
    *offset += 1 + len;
    return str;
}

// Function to safely extract a binary blob from the fuzz input
const uint8_t *extract_binary(const uint8_t *data, size_t *offset, size_t size, size_t *len) {
    if (*offset + 1 > size) return NULL; // Ensure there's at least one byte for the length
    *len = data[*offset];
    if (*offset + 1 + *len > size) return NULL; // Ensure the blob fits within the remaining data
    const uint8_t *blob = &data[*offset + 1];
    *offset += 1 + *len;
    return blob;
}

// Function to safely extract an IPv4 address from the fuzz input
struct in_addr extract_in_addr(const uint8_t *data, size_t *offset) {
    struct in_addr addr;
    if (*offset + sizeof(struct in_addr) > SIZE_MAX) {
        memset(&addr, 0, sizeof(struct in_addr)); // Default to zero address
    } else {
        memcpy(&addr, &data[*offset], sizeof(struct in_addr));
        *offset += sizeof(struct in_addr);
    }
    return addr;
}

// Function to safely extract an IPv6 address from the fuzz input
struct ares_in6_addr extract_in6_addr(const uint8_t *data, size_t *offset) {
    struct ares_in6_addr addr;
    if (*offset + sizeof(struct ares_in6_addr) > SIZE_MAX) {
        memset(&addr, 0, sizeof(struct ares_in6_addr)); // Default to zero address
    } else {
        memcpy(&addr, &data[*offset], sizeof(struct ares_in6_addr));
        *offset += sizeof(struct ares_in6_addr);
    }
    return addr;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ares_dns_rr_t *dns_rr = ares_dns_rr_create(NULL);
    if (!dns_rr) return 0; // Early exit if allocation fails

    size_t offset = 0;

    // Extract and set a 16-bit unsigned integer
    uint16_t u16_val = extract_u16(data, &offset);
    ares_dns_rr_set_u16(dns_rr, ARES_RR_RAW_RR_TYPE, u16_val); // Fixed identifier

    // Extract and set a 32-bit unsigned integer
    uint32_t u32_val = extract_u32(data, &offset);
    ares_dns_rr_set_u32(dns_rr, ARES_RR_RAW_RR_DATA, u32_val); // Fixed identifier

    // Extract and set a string
    const char *str_val = extract_string(data, &offset, size);
    if (str_val) {
        ares_dns_rr_set_str(dns_rr, ARES_RR_RAW_RR_DATA, str_val); // Fixed identifier
    }

    // Extract and set a binary blob
    size_t bin_len;
    const uint8_t *bin_val = extract_binary(data, &offset, size, &bin_len);
    if (bin_val) {
        ares_dns_rr_set_bin(dns_rr, ARES_RR_RAW_RR_DATA, bin_val, bin_len); // Fixed identifier
    }

    // Extract and set an IPv4 address
    struct in_addr in_addr_val = extract_in_addr(data, &offset);
    ares_dns_rr_set_addr(dns_rr, ARES_RR_RAW_RR_DATA, &in_addr_val); // Fixed identifier

    // Extract and set an IPv6 address
    struct ares_in6_addr in6_addr_val = extract_in6_addr(data, &offset);
    ares_dns_rr_set_addr6(dns_rr, ARES_RR_RAW_RR_DATA, &in6_addr_val); // Fixed identifier

    // Clean up
    ares_dns_rr_destroy(dns_rr, NULL);

    return 0;
}
