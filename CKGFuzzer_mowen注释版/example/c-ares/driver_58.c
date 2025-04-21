#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to create a dummy ares_dns_record_t structure from fuzz input
ares_dns_record_t* create_dummy_dns_record(const uint8_t *data, size_t size) {
    if (size < 6) { // Minimum size required for id, flags, opcode, rcode
        return NULL;
    }

    unsigned short id = (data[0] << 8) | data[1];
    unsigned short flags = (data[2] << 8) | data[3];
    ares_dns_opcode_t opcode = (ares_dns_opcode_t)data[4];
    ares_dns_rcode_t rcode = (ares_dns_rcode_t)data[5];

    ares_dns_record_t *dnsrec = NULL;
    ares_status_t status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        return NULL;
    }

    return dnsrec;
}

// Function to create a dummy ares_dns_rr_key_t and opt value from fuzz input
void create_dummy_key_opt(const uint8_t *data, size_t size, ares_dns_rr_key_t *key, unsigned short *opt) {
    if (size < sizeof(ares_dns_rr_key_t) + sizeof(unsigned short)) {
        *key = ARES_RR_OPT_OPTIONS;
        *opt = 0;
        return;
    }

    // Initialize the key and opt with data from the fuzz input
    memcpy(key, data, sizeof(ares_dns_rr_key_t));
    memcpy(opt, data + sizeof(ares_dns_rr_key_t), sizeof(unsigned short));
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for the operations
    if (size < 6 + sizeof(ares_dns_rr_key_t) + sizeof(unsigned short)) { // Minimum size required for id, flags, opcode, rcode, key, opt
        return 0;
    }

    // Create a dummy DNS record
    ares_dns_record_t *dnsrec = create_dummy_dns_record(data, size);
    if (!dnsrec) {
        return 0;
    }

    // Create dummy key and opt values
    ares_dns_rr_key_t key;
    unsigned short opt;
    create_dummy_key_opt(data + 6, size - 6, &key, &opt);

    // Call the APIs with the dummy data
    unsigned short flags = ares_dns_record_get_flags(dnsrec);
    ares_dns_opcode_t opcode = ares_dns_record_get_opcode(dnsrec);
    ares_dns_rcode_t rcode = ares_dns_record_get_rcode(dnsrec);
    const char *opt_name = ares_dns_opt_get_name(key, opt);
    unsigned short id = ares_dns_record_get_id(dnsrec);

    // Handle the results (for now, just print them, but in a real fuzzer, this would be more complex)
    (void)flags;
    (void)opcode;
    (void)rcode;
    (void)opt_name;
    (void)id;

    // Free the allocated memory
    ares_dns_record_destroy(dnsrec);

    return 0;
}
