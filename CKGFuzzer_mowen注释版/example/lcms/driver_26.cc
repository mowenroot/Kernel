#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert a portion of fuzz input to a double
cmsFloat64Number safe_strntod(const uint8_t* data, size_t size) {
    char* str = safe_strndup(data, size);
    if (!str) return 0.0;
    char* endptr;
    cmsFloat64Number result = strtod(str, &endptr);
    free(str);
    return result;
}

// Function to safely convert a portion of fuzz input to an integer
cmsUInt32Number safe_strntoul(const uint8_t* data, size_t size) {
    char* str = safe_strndup(data, size);
    if (!str) return 0;
    char* endptr;
    cmsUInt32Number result = strtoul(str, &endptr, 10);
    free(str);
    return result;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 1) return 0;

    // Create an IT8 handle
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL); // Passing NULL as the context is common for default context
    if (!hIT8) return 0;

    // Use RAII to ensure the IT8 handle is freed
    struct IT8HandleRAII {
        cmsHANDLE handle;
        IT8HandleRAII(cmsHANDLE h) : handle(h) {}
        ~IT8HandleRAII() { if (handle) cmsIT8Free(handle); }
    } raiiIT8(hIT8);

    // Extract sub-portions of the input data for different API calls
    size_t str_size = size / 6;
    size_t hex_size = size / 6;
    size_t dbl_size = size / 6;
    size_t multi_size = size / 6;
    size_t sheet_size = size / 6;
    size_t uncooked_size = size - (str_size + hex_size + dbl_size + multi_size + sheet_size);

    // Ensure sizes are valid
    if (str_size == 0 || hex_size == 0 || dbl_size == 0 || multi_size == 0 || sheet_size == 0 || uncooked_size == 0) {
        return 0;
    }

    // Call cmsIT8SetPropertyStr
    char* str_key = safe_strndup(data, str_size);
    char* str_val = safe_strndup(data + str_size, str_size);
    if (str_key && str_val) {
        cmsIT8SetPropertyStr(hIT8, str_key, str_val);
    }
    free(str_key);
    free(str_val);

    // Call cmsIT8SetPropertyHex
    char* hex_key = safe_strndup(data + 2 * str_size, hex_size);
    cmsUInt32Number hex_val = safe_strntoul(data + 2 * str_size + hex_size, hex_size);
    if (hex_key) {
        cmsIT8SetPropertyHex(hIT8, hex_key, hex_val);
    }
    free(hex_key);

    // Call cmsIT8SetPropertyDbl
    char* dbl_key = safe_strndup(data + 3 * str_size + hex_size, dbl_size);
    cmsFloat64Number dbl_val = safe_strntod(data + 3 * str_size + hex_size + dbl_size, dbl_size);
    if (dbl_key) {
        cmsIT8SetPropertyDbl(hIT8, dbl_key, dbl_val);
    }
    free(dbl_key);

    // Call cmsIT8SetPropertyMulti
    char* multi_key = safe_strndup(data + 4 * str_size + hex_size + dbl_size, multi_size);
    char* multi_subkey = safe_strndup(data + 4 * str_size + hex_size + dbl_size + multi_size, multi_size);
    char* multi_buffer = safe_strndup(data + 4 * str_size + 2 * hex_size + 2 * dbl_size + multi_size, multi_size);
    if (multi_key && multi_subkey && multi_buffer) {
        cmsIT8SetPropertyMulti(hIT8, multi_key, multi_subkey, multi_buffer);
    }
    free(multi_key);
    free(multi_subkey);
    free(multi_buffer);

    // Call cmsIT8SetSheetType
    char* sheet_type = safe_strndup(data + 5 * str_size + 2 * hex_size + 2 * dbl_size + multi_size, sheet_size);
    if (sheet_type) {
        cmsIT8SetSheetType(hIT8, sheet_type);
    }
    free(sheet_type);

    // Call cmsIT8SetPropertyUncooked
    char* uncooked_key = safe_strndup(data + 5 * str_size + 2 * hex_size + 2 * dbl_size + 2 * multi_size, uncooked_size);
    char* uncooked_buffer = safe_strndup(data + 5 * str_size + 2 * hex_size + 2 * dbl_size + 2 * multi_size + uncooked_size, uncooked_size);
    if (uncooked_key && uncooked_buffer) {
        cmsIT8SetPropertyUncooked(hIT8, uncooked_key, uncooked_buffer);
    }
    free(uncooked_key);
    free(uncooked_buffer);

    return 0;
}
