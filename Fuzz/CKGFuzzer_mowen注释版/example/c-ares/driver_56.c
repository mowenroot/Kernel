#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to handle the fuzzing input
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    ares_dns_record_t *dnsrec = NULL;
    ares_dns_record_t *dnsrec_dup = NULL;
    struct ares_naptr_reply *naptr_reply = NULL;
    ares_status_t status;
    int result;

    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024) {
        size = 1024;
    }

    // Parse the input data into a DNS record
    status = ares_dns_parse(data, size, 0, &dnsrec);
    if (status != ARES_SUCCESS) {
        goto cleanup;
    }

    // Retrieve the opcode from the DNS record
    ares_dns_opcode_t opcode = ares_dns_record_get_opcode(dnsrec);
    if (opcode == 0) {
        goto cleanup;
    }

    // Duplicate the DNS record
    dnsrec_dup = ares_dns_record_duplicate(dnsrec);
    if (dnsrec_dup == NULL) {
        goto cleanup;
    }

    // Parse the NAPTR reply from the duplicated DNS record
    result = ares_parse_naptr_reply((const unsigned char *)data, size, &naptr_reply);
    if (result != ARES_SUCCESS) {
        goto cleanup;
    }

    // Clean up allocated resources
    if (naptr_reply) {
        ares_free_data(naptr_reply);
    }

    // Free the duplicated DNS record
    ares_dns_record_destroy(dnsrec_dup);

cleanup:
    // Free the original DNS record
    if (dnsrec) {
        ares_dns_record_destroy(dnsrec);
    }

    return 0;
}
