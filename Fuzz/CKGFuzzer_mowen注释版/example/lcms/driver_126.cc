#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    char* str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely allocate memory for a string
char* safe_stralloc(size_t size) {
    char* str = (char*)malloc(size);
    if (!str) return NULL;
    memset(str, 0, size);
    return str;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < 1) return 0;

    // Initialize variables
    cmsHANDLE hIT8 = NULL;
    cmsUInt32Number tableCount = 0;
    const char* sheetType = NULL;
    cmsUInt32Number bytesNeeded = 0;
    char* memPtr = NULL;
    char* newSheetType = NULL;

    // Load IT8 data from memory
    hIT8 = cmsIT8LoadFromMem(NULL, data, size);
    if (!hIT8) {
        // Handle error: unable to load IT8 data
        return 0;
    }

    // Get the number of tables
    tableCount = cmsIT8TableCount(hIT8);
    if (tableCount == 0) {
        // Handle error: no tables found
        cmsIT8Free(hIT8);
        return 0;
    }

    // Set the active table to the first one
    if (cmsIT8SetTable(hIT8, 0) < 0) {
        // Handle error: unable to set table
        cmsIT8Free(hIT8);
        return 0;
    }

    // Get the sheet type of the first table
    sheetType = cmsIT8GetSheetType(hIT8);
    if (!sheetType) {
        // Handle error: unable to get sheet type
        cmsIT8Free(hIT8);
        return 0;
    }

    // Set a new sheet type based on the fuzz input
    newSheetType = safe_strndup(data, size);
    if (!newSheetType) {
        // Handle error: memory allocation failed
        cmsIT8Free(hIT8);
        return 0;
    }
    if (!cmsIT8SetSheetType(hIT8, newSheetType)) {
        // Handle error: unable to set new sheet type
        free(newSheetType);
        cmsIT8Free(hIT8);
        return 0;
    }
    free(newSheetType);

    // Save the IT8 object to memory
    if (!cmsIT8SaveToMem(hIT8, NULL, &bytesNeeded)) {
        // Handle error: unable to calculate bytes needed
        cmsIT8Free(hIT8);
        return 0;
    }

    // Allocate memory for the saved IT8 object
    memPtr = safe_stralloc(bytesNeeded);
    if (!memPtr) {
        // Handle error: memory allocation failed
        cmsIT8Free(hIT8);
        return 0;
    }

    // Save the IT8 object to the allocated memory
    if (!cmsIT8SaveToMem(hIT8, memPtr, &bytesNeeded)) {
        // Handle error: unable to save IT8 object
        free(memPtr);
        cmsIT8Free(hIT8);
        return 0;
    }

    // Clean up
    free(memPtr);
    cmsIT8Free(hIT8);

    return 0;
}
