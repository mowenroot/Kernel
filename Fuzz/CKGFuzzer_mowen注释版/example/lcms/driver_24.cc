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

// Function to safely convert a double from fuzz input
bool safe_double_from_bytes(const uint8_t* data, size_t size, double* out) {
    if (size < sizeof(double)) return false;
    memcpy(out, data, sizeof(double));
    return true;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 1) return 0;

    // Create an IT8 container
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL); // Passing NULL as the context is common for default context
    if (!hIT8) return 0;

    // Use RAII to ensure cleanup
    struct IT8Container {
        cmsHANDLE hIT8;
        IT8Container(cmsHANDLE h) : hIT8(h) {}
        ~IT8Container() { cmsIT8Free(hIT8); }
    } container(hIT8);

    // Extract key and value strings from fuzz input
    size_t key_size = data[0];
    size_t value_size = (size > key_size + 1) ? data[key_size + 1] : 0;
    if (key_size + value_size + 2 > size) return 0;

    char* key = safe_strndup(data + 1, key_size);
    char* value = safe_strndup(data + key_size + 2, value_size);

    if (!key || !value) {
        free(key);
        free(value);
        return 0;
    }

    // Call cmsIT8SetPropertyStr
    if (!cmsIT8SetPropertyStr(hIT8, key, value)) {
        free(key);
        free(value);
        return 0;
    }

    // Call cmsIT8SetComment
    if (!cmsIT8SetComment(hIT8, value)) {
        free(key);
        free(value);
        return 0;
    }

    // Call cmsIT8SetPropertyDbl
    double dbl_value;
    if (safe_double_from_bytes(data + key_size + value_size + 2, size - (key_size + value_size + 2), &dbl_value)) {
        if (!cmsIT8SetPropertyDbl(hIT8, key, dbl_value)) {
            free(key);
            free(value);
            return 0;
        }
    }

    // Call cmsIT8SetPropertyMulti
    if (!cmsIT8SetPropertyMulti(hIT8, key, key, value)) {
        free(key);
        free(value);
        return 0;
    }

    // Call cmsIT8SetSheetType
    if (!cmsIT8SetSheetType(hIT8, value)) {
        free(key);
        free(value);
        return 0;
    }

    // Call cmsIT8SetPropertyUncooked
    if (!cmsIT8SetPropertyUncooked(hIT8, key, value)) {
        free(key);
        free(value);
        return 0;
    }

    // Clean up allocated strings
    free(key);
    free(value);

    return 0;
}
