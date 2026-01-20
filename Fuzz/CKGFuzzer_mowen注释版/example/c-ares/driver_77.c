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

// Function to safely convert fuzz input to ares_dns_rcode_t
static ares_dns_rcode_t safe_rcode_from_data(const uint8_t *data, size_t size) {
    if (size == 0) return ARES_RCODE_NOERROR;
    return (ares_dns_rcode_t)(data[0] % (ARES_RCODE_BADCOOKIE + 1));
}

// Function to safely convert fuzz input to ares_dns_opcode_t
static ares_dns_opcode_t safe_opcode_from_data(const uint8_t *data, size_t size) {
    if (size == 0) return ARES_OPCODE_QUERY;
    return (ares_dns_opcode_t)(data[0] % (ARES_OPCODE_UPDATE + 1));
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    ares_dns_rec_type_t rec_type = ARES_REC_TYPE_A;
    ares_dns_class_t dns_class = ARES_CLASS_IN;
    char *str_type = NULL, *str_class = NULL;
    const char *rcode_str = NULL, *opcode_str = NULL, *class_str = NULL, *type_str = NULL;

    // Safely allocate and copy strings from fuzz input
    str_type = safe_strndup(data, size / 2);
    str_class = safe_strndup(data + (size / 2), size - (size / 2));

    // Call ares_dns_rec_type_fromstr
    if (str_type) {
        ares_dns_rec_type_fromstr(&rec_type, str_type);
        free(str_type);
    }

    // Call ares_dns_class_fromstr
    if (str_class) {
        ares_dns_class_fromstr(&dns_class, str_class);
        free(str_class);
    }

    // Call ares_dns_rcode_tostr
    ares_dns_rcode_t rcode = safe_rcode_from_data(data, size);
    rcode_str = ares_dns_rcode_tostr(rcode);

    // Call ares_dns_opcode_tostr
    ares_dns_opcode_t opcode = safe_opcode_from_data(data, size);
    opcode_str = ares_dns_opcode_tostr(opcode);

    // Call ares_dns_rec_type_tostr
    type_str = ares_dns_rec_type_tostr(rec_type);

    // Call ares_dns_class_tostr
    class_str = ares_dns_class_tostr(dns_class);

    // Ensure all allocated resources are freed
    // (Note: rcode_str, opcode_str, class_str, and type_str are not dynamically allocated)

    return 0;
}
