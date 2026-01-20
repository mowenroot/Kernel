#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h" // Include this to get the full definition of ares_dns_rr_t
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to fuzz the ares_dns_rr_* APIs
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(ares_dns_rr_key_t) + sizeof(unsigned short) + sizeof(size_t)) {
        return 0;
    }

    // Initialize variables
    ares_dns_rr_t *dns_rr = NULL;
    ares_dns_rr_key_t key;
    unsigned short opt;
    size_t val_len;
    const unsigned char *val = NULL;
    ares_status_t status;

    // Extract key, opt, and val_len from the fuzz input
    memcpy(&key, data, sizeof(ares_dns_rr_key_t));
    memcpy(&opt, data + sizeof(ares_dns_rr_key_t), sizeof(unsigned short));
    memcpy(&val_len, data + sizeof(ares_dns_rr_key_t) + sizeof(unsigned short), sizeof(size_t));

    // Ensure val_len is within bounds
    if (val_len > size - (sizeof(ares_dns_rr_key_t) + sizeof(unsigned short) + sizeof(size_t))) {
        val_len = size - (sizeof(ares_dns_rr_key_t) + sizeof(unsigned short) + sizeof(size_t));
    }

    // Set the value pointer to the appropriate location in the fuzz input
    val = data + sizeof(ares_dns_rr_key_t) + sizeof(unsigned short) + sizeof(size_t);

    // Allocate memory for dns_rr using ares_dns_rr_create
    dns_rr = ares_dns_rr_create();
    if (dns_rr == NULL) {
        return 0; // Memory allocation failed
    }

    // Call ares_dns_rr_set_opt
    status = ares_dns_rr_set_opt(dns_rr, key, opt, val, val_len);
    if (status != ARES_SUCCESS) {
        ares_dns_rr_destroy(dns_rr);
        return 0; // Error in setting option
    }

    // Call ares_dns_rr_get_opt_byid
    const unsigned char *retrieved_val = NULL;
    size_t retrieved_val_len = 0;
    ares_bool_t result = ares_dns_rr_get_opt_byid(dns_rr, key, opt, &retrieved_val, &retrieved_val_len);
    if (!result) {
        ares_dns_rr_destroy(dns_rr);
        return 0; // Option not found
    }

    // Call ares_dns_rr_get_opt
    unsigned short retrieved_opt = ares_dns_rr_get_opt(dns_rr, key, 0, &retrieved_val, &retrieved_val_len);
    if (retrieved_opt == 65535) {
        ares_dns_rr_destroy(dns_rr);
        return 0; // Option not found
    }

    // Call ares_dns_rr_key_tostr
    const char *key_str = ares_dns_rr_key_tostr(key);
    if (key_str == NULL) {
        ares_dns_rr_destroy(dns_rr);
        return 0; // Key to string conversion failed
    }

    // Call ares_dns_rr_key_datatype
    ares_dns_datatype_t datatype = ares_dns_rr_key_datatype(key);
    if (datatype == 0) {
        ares_dns_rr_destroy(dns_rr);
        return 0; // Invalid datatype
    }

    // Call ares_dns_rr_key_to_rec_type
    ares_dns_rec_type_t rec_type = ares_dns_rr_key_to_rec_type(key);
    if (rec_type == 0) {
        ares_dns_rr_destroy(dns_rr);
        return 0; // Invalid record type
    }

    // Free allocated resources
    ares_dns_rr_destroy(dns_rr);

    return 0;
}
