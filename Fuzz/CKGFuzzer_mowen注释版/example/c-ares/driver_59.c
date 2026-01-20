#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to fuzz the ares library using the provided APIs
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024 * 1024) {
        return 0;
    }

    // Variables to hold the results of the API calls
    struct ares_uri_reply *uri_reply = NULL;
    struct ares_soa_reply *soa_reply = NULL;
    struct ares_mx_reply *mx_reply = NULL;
    ares_dns_record_t *dnsrec = NULL;

    // Temporary buffer to hold the input data
    unsigned char *abuf = (unsigned char *)malloc(size);
    if (!abuf) {
        return 0; // Out of memory
    }
    memcpy(abuf, data, size);

    // Parse URI reply
    int status = ares_parse_uri_reply(abuf, (int)size, &uri_reply);
    if (status != ARES_SUCCESS) {
        free(abuf);
        return 0; // Error in parsing URI reply
    }

    // Parse SOA reply
    status = ares_parse_soa_reply(abuf, (int)size, &soa_reply);
    if (status != ARES_SUCCESS) {
        ares_free_data(uri_reply);
        free(abuf);
        return 0; // Error in parsing SOA reply
    }

    // Parse MX reply
    status = ares_parse_mx_reply(abuf, (int)size, &mx_reply);
    if (status != ARES_SUCCESS) {
        ares_free_data(uri_reply);
        ares_free_data(soa_reply);
        free(abuf);
        return 0; // Error in parsing MX reply
    }

    // Get DNS record flags and ID
    unsigned short flags = ares_dns_record_get_flags(dnsrec);
    unsigned short id = ares_dns_record_get_id(dnsrec);

    // Clean up
    ares_free_data(uri_reply);
    ares_free_data(soa_reply);
    ares_free_data(mx_reply);
    free(abuf);

    return 0;
}
