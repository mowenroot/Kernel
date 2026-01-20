#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy data from fuzz input to a buffer
void safe_copy(void* dest, const uint8_t* src, size_t size) {
    if (size > 0) {
        memcpy(dest, src, size);
    }
}

// Function to safely allocate memory and copy data from fuzz input
void* safe_alloc_and_copy(const uint8_t* src, size_t size) {
    void* dest = malloc(size);
    if (dest) {
        safe_copy(dest, src, size);
    }
    return dest;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 32) {
        return 0;
    }

    // Create a profile handle
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) {
        return 0;
    }

    // Extract data for API inputs
    cmsUInt32Number flags = *reinterpret_cast<const cmsUInt32Number*>(data);
    cmsUInt64Number attributes = *reinterpret_cast<const cmsUInt64Number*>(data + 8);
    cmsUInt8Number profileID[16];
    safe_copy(profileID, data + 16, 16);

    // Call cmsSetHeaderFlags
    cmsSetHeaderFlags(hProfile, flags);

    // Call cmsSetHeaderAttributes
    cmsSetHeaderAttributes(hProfile, attributes);

    // Call cmsSetHeaderProfileID
    cmsSetHeaderProfileID(hProfile, profileID);

    // Call cmsGetHeaderAttributes
    cmsUInt64Number retrievedAttributes;
    cmsGetHeaderAttributes(hProfile, &retrievedAttributes);

    // Call cmsIsMatrixShaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}
