#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely copy a string from fuzz input
char* SafeStrndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert a portion of fuzz input to a uint32_t
cmsUInt32Number SafeConvertToUInt32(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    char buffer[11]; // Max length for a uint32_t in decimal + null terminator
    size_t copy_size = size < 10 ? size : 10;
    memcpy(buffer, data, copy_size);
    buffer[copy_size] = '\0';
    return strtoul(buffer, nullptr, 10);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for at least one API call
    if (size < 1) return 0;

    // Create an IT8 handler
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL); // Pass NULL as the context for default context
    if (!hIT8) return 0;

    // Use a smart pointer to ensure proper cleanup
    std::unique_ptr<void, decltype(&cmsIT8Free)> it8_guard(hIT8, cmsIT8Free);

    // Extract strings and values from fuzz input
    char* key = SafeStrndup(data, size / 4);
    char* val = SafeStrndup(data + (size / 4), size / 4);
    char* subkey = SafeStrndup(data + (size / 2), size / 4);
    cmsUInt32Number hex_val = SafeConvertToUInt32(data + (3 * size / 4), size / 4);

    // Use smart pointers for automatic cleanup
    std::unique_ptr<char, decltype(&free)> key_guard(key, free);
    std::unique_ptr<char, decltype(&free)> val_guard(val, free);
    std::unique_ptr<char, decltype(&free)> subkey_guard(subkey, free);

    // Call each API at least once
    if (key && val) {
        cmsIT8SetPropertyStr(hIT8, key, val);
    }

    if (key && hex_val != 0) {
        cmsIT8SetPropertyHex(hIT8, key, hex_val);
    }

    if (key && subkey && val) {
        cmsIT8SetPropertyMulti(hIT8, key, subkey, val);
    }

    if (key) {
        cmsIT8SetDataFormat(hIT8, 0, key);
    }

    if (key && val) {
        cmsIT8SetPropertyUncooked(hIT8, key, val);
    }

    if (key && val) {
        cmsIT8SetData(hIT8, key, "SAMPLE_ID", val);
    }

    return 0;
}
