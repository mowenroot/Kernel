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

// Function to safely convert a double from fuzz input
bool SafeDouble(const uint8_t* data, size_t size, cmsFloat64Number* val) {
    char* str = SafeStrndup(data, size);
    if (!str) return false;
    char* endptr;
    *val = strtod(str, &endptr);
    free(str);
    return (*endptr == '\0');
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for at least one API call
    if (size < 1) return 0;

    // Create an IT8 handle
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL); // Fixed: Added NULL as the ContextID argument
    if (!hIT8) return 0;

    // Use a unique_ptr for automatic cleanup
    std::unique_ptr<void, void(*)(void*)> it8_guard(hIT8, [](void* h) { cmsIT8Free(h); }); // Fixed: Changed type to void*

    // Extract data for API calls
    size_t offset = 0;
    size_t chunk_size = size / 6; // Divide input into 6 parts for 6 API calls

    // 1. cmsIT8SetPropertyStr
    if (offset + chunk_size <= size) {
        char* key = SafeStrndup(data + offset, chunk_size);
        char* val = SafeStrndup(data + offset + chunk_size, chunk_size);
        if (key && val) {
            cmsIT8SetPropertyStr(hIT8, key, val);
        }
        free(key);
        free(val);
        offset += 2 * chunk_size;
    }

    // 2. cmsIT8SetComment
    if (offset + chunk_size <= size) {
        char* comment = SafeStrndup(data + offset, chunk_size);
        if (comment) {
            cmsIT8SetComment(hIT8, comment);
        }
        free(comment);
        offset += chunk_size;
    }

    // 3. cmsIT8SetDataDbl
    if (offset + chunk_size <= size) {
        char* patch = SafeStrndup(data + offset, chunk_size);
        char* sample = SafeStrndup(data + offset + chunk_size, chunk_size);
        cmsFloat64Number val;
        if (patch && sample && SafeDouble(data + offset + 2 * chunk_size, chunk_size, &val)) {
            cmsIT8SetDataDbl(hIT8, patch, sample, val);
        }
        free(patch);
        free(sample);
        offset += 3 * chunk_size;
    }

    // 4. cmsIT8SetSheetType
    if (offset + chunk_size <= size) {
        char* type = SafeStrndup(data + offset, chunk_size);
        if (type) {
            cmsIT8SetSheetType(hIT8, type);
        }
        free(type);
        offset += chunk_size;
    }

    // 5. cmsIT8SetDataFormat
    if (offset + chunk_size <= size) {
        char* format = SafeStrndup(data + offset, chunk_size);
        if (format) {
            cmsIT8SetDataFormat(hIT8, 0, format); // Assuming index 0 for simplicity
        }
        free(format);
        offset += chunk_size;
    }

    // 6. cmsIT8SetData
    if (offset + chunk_size <= size) {
        char* patch = SafeStrndup(data + offset, chunk_size);
        char* sample = SafeStrndup(data + offset + chunk_size, chunk_size);
        char* value = SafeStrndup(data + offset + 2 * chunk_size, chunk_size);
        if (patch && sample && value) {
            cmsIT8SetData(hIT8, patch, sample, value);
        }
        free(patch);
        free(sample);
        free(value);
    }

    return 0;
}
