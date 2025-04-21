#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* SafeStrndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert fuzz input to a uint32_t
cmsUInt32Number SafeConvertToUInt32(const uint8_t* data, size_t size) {
    if (size < sizeof(cmsUInt32Number)) return 0;
    cmsUInt32Number value;
    memcpy(&value, data, sizeof(cmsUInt32Number));
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < sizeof(cmsUInt32Number) + 1) return 0;

    // Allocate an IT8 handle
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL);
    if (!hIT8) return 0;

    // Safely extract the table count and sheet type from the fuzz input
    cmsUInt32Number tableCount = SafeConvertToUInt32(data, sizeof(cmsUInt32Number));
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);

    char* sheetType = SafeStrndup(data, size);
    if (!sheetType) {
        cmsIT8Free(hIT8);
        return 0;
    }

    // Set the sheet type
    if (!cmsIT8SetSheetType(hIT8, sheetType)) {
        free(sheetType);
        cmsIT8Free(hIT8);
        return 0;
    }

    // Set the table
    if (cmsIT8SetTable(hIT8, tableCount) < 0) {
        free(sheetType);
        cmsIT8Free(hIT8);
        return 0;
    }

    // Retrieve and print the sheet type and table count
    const char* retrievedSheetType = cmsIT8GetSheetType(hIT8);
    cmsUInt32Number retrievedTableCount = cmsIT8TableCount(hIT8);

    // Clean up
    free(sheetType);
    cmsIT8Free(hIT8);

    return 0;
}
