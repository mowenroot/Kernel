#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely allocate memory and initialize it
void* safeMalloc(size_t size) {
    void* ptr = malloc(size);
    if (ptr) {
        memset(ptr, 0, size);
    }
    return ptr;
}

// Function to safely free memory
void safeFree(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Function to safely copy data from fuzz input
void safeCopy(void* dest, const uint8_t* src, size_t size) {
    if (dest && src && size > 0) {
        memcpy(dest, src, size);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < sizeof(cmsCIExyY) + sizeof(cmsHANDLE)) {
        return 0;
    }

    // Initialize variables
    cmsHPROFILE hProfile = NULL;
    cmsHANDLE hDict = NULL;
    const cmsDICTentry* entryList = NULL;
    const cmsDICTentry* currentEntry = NULL;
    cmsCIExyY whitePoint;

    // Extract white point from fuzz input
    safeCopy(&whitePoint, data, sizeof(cmsCIExyY));
    data += sizeof(cmsCIExyY);
    size -= sizeof(cmsCIExyY);

    // Create a Lab 4 profile
    hProfile = cmsCreateLab4ProfileTHR(NULL, &whitePoint);
    if (!hProfile) {
        return 0;
    }

    // Check if the profile is a matrix shaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);

    // Detect TAC for the profile
    cmsFloat64Number tac = cmsDetectTAC(hProfile);

    // Extract dictionary handle from fuzz input
    safeCopy(&hDict, data, sizeof(cmsHANDLE));
    data += sizeof(cmsHANDLE);
    size -= sizeof(cmsHANDLE);

    // Get the entry list from the dictionary
    entryList = cmsDictGetEntryList(hDict);
    if (entryList) {
        currentEntry = entryList;
        while (currentEntry) {
            // Traverse the dictionary entries
            currentEntry = cmsDictNextEntry(currentEntry);
        }
    }

    // Clean up resources
    if (hProfile) {
        cmsCloseProfile(hProfile);
    }

    return 0;
}
