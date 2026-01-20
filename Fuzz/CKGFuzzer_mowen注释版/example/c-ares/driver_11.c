#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely duplicate a DNS record
ares_dns_record_t* safe_dns_record_duplicate(const ares_dns_record_t *dnsrec) {
    if (dnsrec == NULL) {
        return NULL;
    }
    return ares_dns_record_duplicate(dnsrec);
}

// Function to safely create a DNS record
ares_status_t safe_dns_record_create(ares_dns_record_t **dnsrec,
                                     unsigned short id, unsigned short flags,
                                     ares_dns_opcode_t opcode,
                                     ares_dns_rcode_t  rcode) {
    if (dnsrec == NULL) {
        return ARES_EFORMERR;
    }
    return ares_dns_record_create(dnsrec, id, flags, opcode, rcode);
}

// Function to safely parse DNS data
ares_status_t safe_dns_parse(const unsigned char *buf, size_t buf_len,
                             unsigned int flags, ares_dns_record_t **dnsrec) {
    if (buf == NULL || buf_len == 0 || dnsrec == NULL) {
        return ARES_EFORMERR;
    }
    return ares_dns_parse(buf, buf_len, flags, dnsrec);
}

// Function to safely destroy a DNS record
void safe_dns_record_destroy(ares_dns_record_t *dnsrec) {
    if (dnsrec != NULL) {
        ares_dns_record_destroy(dnsrec);
    }
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ares_dns_record_t *dnsrec = NULL;
    ares_dns_record_t *dnsrec_dup = NULL;
    ares_status_t status;

    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024) {
        return 0;
    }

    // Parse the DNS record from the fuzzer input
    status = safe_dns_parse(data, size, 0, &dnsrec);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // Duplicate the parsed DNS record
    dnsrec_dup = safe_dns_record_duplicate(dnsrec);
    if (dnsrec_dup == NULL) {
        safe_dns_record_destroy(dnsrec);
        return 0;
    }

    // Clean up resources
    safe_dns_record_destroy(dnsrec);
    safe_dns_record_destroy(dnsrec_dup);

    return 0;
}
