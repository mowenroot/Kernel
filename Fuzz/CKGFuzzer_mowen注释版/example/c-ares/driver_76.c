#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
static char* safe_strndup(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    char *str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert fuzz input to a numeric type
static ares_dns_rcode_t safe_rcode_from_data(const uint8_t *data, size_t size) {
    if (size == 0) return ARES_RCODE_NOERROR;
    return (ares_dns_rcode_t)(data[0] % 20); // Assuming 20 is the number of rcode types
}

// Function to safely convert fuzz input to a numeric type
static ares_dns_opcode_t safe_opcode_from_data(const uint8_t *data, size_t size) {
    if (size == 0) return ARES_OPCODE_QUERY;
    return (ares_dns_opcode_t)(data[0] % 5); // Assuming 5 is the number of opcode types
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for all operations
    if (size < 10) return 0;

    // Initialize variables
    ares_dns_rcode_t rcode;
    ares_dns_rec_type_t rec_type;
    ares_dns_opcode_t opcode;
    ares_dns_class_t dns_class;
    char *str_rcode, *str_rec_type, *str_opcode, *str_dns_class;

    // Extract and convert fuzz input to appropriate types
    rcode = safe_rcode_from_data(data, 1);
    opcode = safe_opcode_from_data(data + 1, 1);
    str_rec_type = safe_strndup(data + 2, 5);
    str_dns_class = safe_strndup(data + 7, 3);

    // Perform API calls and handle errors
    const char *rcode_str = ares_dns_rcode_tostr(rcode);
    if (!rcode_str) return 0; // Handle potential error

    const char *opcode_str = ares_dns_opcode_tostr(opcode);
    if (!opcode_str) return 0; // Handle potential error

    if (!ares_dns_rec_type_fromstr(&rec_type, str_rec_type)) {
        free(str_rec_type);
        return 0; // Handle potential error
    }
    free(str_rec_type);

    const char *rec_type_str = ares_dns_rec_type_tostr(rec_type);
    if (!rec_type_str) return 0; // Handle potential error

    if (!ares_dns_class_fromstr(&dns_class, str_dns_class)) {
        free(str_dns_class);
        return 0; // Handle potential error
    }
    free(str_dns_class);

    const char *dns_class_str = ares_dns_class_tostr(dns_class);
    if (!dns_class_str) return 0; // Handle potential error

    // Clean up and return
    return 0;
}
