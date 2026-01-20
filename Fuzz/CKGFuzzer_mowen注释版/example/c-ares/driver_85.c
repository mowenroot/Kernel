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

// Function to safely convert fuzz input to ares_dns_opcode_t
static ares_dns_opcode_t safe_opcode_from_data(const uint8_t *data, size_t size) {
    if (size == 0) return ARES_OPCODE_QUERY; // Default to QUERY if no data
    return (ares_dns_opcode_t)(data[0] % 5); // Assuming 5 opcodes, modulo to stay within bounds
}

// Function to safely convert fuzz input to ares_dns_class_t
static ares_dns_class_t safe_class_from_data(const uint8_t *data, size_t size) {
    if (size == 0) return ARES_CLASS_IN; // Default to IN if no data
    return (ares_dns_class_t)(data[0] % 5); // Assuming 5 classes, modulo to stay within bounds
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    struct ares_options options = {0};
    ares_dns_opcode_t opcode;
    ares_dns_class_t qclass;
    char *class_str = NULL;
    const char *opcode_str = NULL;
    const char *opt_name = NULL;
    ares_dns_opt_datatype_t opt_datatype;

    // Safely derive opcode from fuzz input
    opcode = safe_opcode_from_data(data, size);
    opcode_str = ares_dns_opcode_tostr(opcode);

    // Safely derive class from fuzz input
    qclass = safe_class_from_data(data, size);
    class_str = safe_strndup((const uint8_t*)ares_dns_class_tostr(qclass), strlen(ares_dns_class_tostr(qclass)));

    // Safely derive DNS option name and datatype from fuzz input
    opt_name = ares_dns_opt_get_name(ARES_RR_OPT_OPTIONS, (unsigned short)(data[0] % 256));
    opt_datatype = ares_dns_opt_get_datatype(ARES_RR_OPT_OPTIONS, (unsigned short)(data[0] % 256));

    // Cleanup allocated resources
    free(class_str);
    ares_destroy_options(&options);

    return 0;
}
