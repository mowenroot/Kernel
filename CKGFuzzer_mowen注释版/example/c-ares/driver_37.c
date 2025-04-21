#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h> // Include for struct in_addr and ares_in6_addr

// Function to safely extract a uint16_t from the fuzz input
uint16_t extract_uint16(const uint8_t *data, size_t *offset) {
    if (*offset + 2 > SIZE_MAX) {
        return 0; // Prevent overflow
    }
    uint16_t value = (uint16_t)((data[*offset] << 8) | data[*offset + 1]);
    *offset += 2;
    return value;
}

// Function to safely extract a size_t from the fuzz input
size_t extract_size_t(const uint8_t *data, size_t *offset) {
    if (*offset + sizeof(size_t) > SIZE_MAX) {
        return 0; // Prevent overflow
    }
    size_t value = 0;
    memcpy(&value, data + *offset, sizeof(size_t));
    *offset += sizeof(size_t);
    return value;
}

// Function to safely extract a string from the fuzz input
const uint8_t *extract_string(const uint8_t *data, size_t *offset, size_t size) {
    if (*offset + size > SIZE_MAX) {
        return NULL; // Prevent overflow
    }
    const uint8_t *str = data + *offset;
    *offset += size;
    return str;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ares_dns_rr_t *dns_rr = NULL;
    ares_status_t status;
    size_t offset = 0;

    // Initialize dns_rr (assuming ares_dns_rr_init exists, otherwise use appropriate initialization)
    dns_rr = ares_dns_rr_init();
    if (!dns_rr) {
        return 0; // Initialization failed
    }

    // Extract inputs from fuzz data
    uint16_t opt = extract_uint16(data, &offset);
    size_t val_len = extract_size_t(data, &offset);
    const uint8_t *val = extract_string(data, &offset, val_len);

    // Call ares_dns_rr_set_opt
    status = ares_dns_rr_set_opt(dns_rr, opt, opt, val, val_len); // Fixed identifier
    if (status != ARES_SUCCESS) {
        ares_dns_rr_destroy(dns_rr);
        return 0; // Error handling
    }

    // Call ares_dns_rr_get_opt_cnt
    size_t opt_cnt = ares_dns_rr_get_opt_cnt(dns_rr, opt); // Fixed identifier

    // Call ares_dns_rr_get_opt
    const unsigned char *opt_val;
    size_t opt_val_len;
    unsigned short retrieved_opt = ares_dns_rr_get_opt(dns_rr, opt, 0, &opt_val, &opt_val_len); // Fixed identifier
    if (retrieved_opt == 65535) {
        ares_dns_rr_destroy(dns_rr);
        return 0; // Error handling
    }

    // Call ares_dns_rr_get_opt_byid
    const unsigned char *opt_byid_val;
    size_t opt_byid_val_len;
    ares_bool_t found = ares_dns_rr_get_opt_byid(dns_rr, opt, opt, &opt_byid_val, &opt_byid_val_len); // Fixed identifier
    if (!found) {
        ares_dns_rr_destroy(dns_rr);
        return 0; // Error handling
    }

    // Extract IPv4 address from fuzz data
    struct in_addr ipv4_addr;
    if (offset + sizeof(struct in_addr) <= size) {
        memcpy(&ipv4_addr, data + offset, sizeof(struct in_addr));
        offset += sizeof(struct in_addr);

        // Call ares_dns_rr_set_addr
        status = ares_dns_rr_set_addr(dns_rr, ARES_RR_A_ADDR, &ipv4_addr); // Fixed identifier
        if (status != ARES_SUCCESS) {
            ares_dns_rr_destroy(dns_rr);
            return 0; // Error handling
        }
    }

    // Extract IPv6 address from fuzz data
    struct ares_in6_addr ipv6_addr;
    if (offset + sizeof(struct ares_in6_addr) <= size) {
        memcpy(&ipv6_addr, data + offset, sizeof(struct ares_in6_addr));
        offset += sizeof(struct ares_in6_addr);

        // Call ares_dns_rr_set_addr6
        status = ares_dns_rr_set_addr6(dns_rr, ARES_RR_AAAA_ADDR, &ipv6_addr); // Fixed identifier
        if (status != ARES_SUCCESS) {
            ares_dns_rr_destroy(dns_rr);
            return 0; // Error handling
        }
    }

    // Clean up
    ares_dns_rr_destroy(dns_rr);
    return 0;
}
