#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to fuzz the ares library using the provided APIs
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Declare variables for the DNS record and URI reply
    ares_dns_record_t *dnsrec = NULL;
    struct ares_uri_reply *uri_reply = NULL;

    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024) {
        size = 1024;
    }

    // Parse the DNS response from the fuzzer input
    ares_status_t status = ares_dns_parse(data, size, 0, &dnsrec);
    if (status != ARES_SUCCESS) {
        // If parsing fails, clean up and return
        if (dnsrec) {
            ares_dns_record_destroy(dnsrec);
        }
        return 0;
    }

    // Attempt to parse the URI reply from the DNS record
    int parse_status = ares_parse_uri_reply((const unsigned char *)data, (int)size, &uri_reply);
    if (parse_status != ARES_SUCCESS) {
        // If parsing fails, clean up and return
        ares_dns_record_destroy(dnsrec);
        if (uri_reply) {
            ares_free_data(uri_reply);
        }
        return 0;
    }

    // Iterate through the URI replies and extract u16 values from the DNS records
    struct ares_uri_reply *current_uri = uri_reply;
    while (current_uri) {
        // Retrieve the DNS resource record associated with the current URI reply
        const ares_dns_rr_t *rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ANSWER, 0);
        if (rr) {
            // Extract u16 values from the DNS resource record
            unsigned short priority = ares_dns_rr_get_u16(rr, ARES_RR_URI_PRIORITY);
            unsigned short weight = ares_dns_rr_get_u16(rr, ARES_RR_URI_WEIGHT);

            // Use the extracted values (for example, print them or perform some operation)
            // Note: In a real fuzz driver, you might want to perform more operations here
        }

        // Move to the next URI reply in the linked list
        current_uri = current_uri->next;
    }

    // Clean up allocated resources
    ares_dns_record_destroy(dnsrec);
    if (uri_reply) {
        ares_free_data(uri_reply);
    }

    return 0;
}
