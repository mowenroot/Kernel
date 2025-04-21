#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <iostream>
#include <memory>

// Function to safely extract a uint32_t from the fuzz input
uint32_t ExtractUInt32(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(uint32_t) > size) {
        return 0; // Return a default value if not enough data
    }
    uint32_t value;
    memcpy(&value, data + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    return value;
}

// Function to safely extract a uint64_t from the fuzz input
uint64_t ExtractUInt64(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(uint64_t) > size) {
        return 0; // Return a default value if not enough data
    }
    uint64_t value;
    memcpy(&value, data + offset, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    return value;
}

// Function to safely extract a struct tm from the fuzz input
bool ExtractTm(const uint8_t* data, size_t& offset, size_t size, struct tm* dest) {
    if (offset + sizeof(struct tm) > size) {
        return false; // Return false if not enough data
    }
    memcpy(dest, data + offset, sizeof(struct tm));
    offset += sizeof(struct tm);
    return true;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(uint32_t) + sizeof(uint64_t) + sizeof(struct tm)) {
        return 0;
    }

    // Create a profile handle
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL); // Pass NULL for default context
    if (!hProfile) {
        return 0; // Failed to create profile
    }

    // Use a unique_ptr to manage the profile handle
    std::unique_ptr<void, void(*)(cmsHPROFILE)> profilePtr(hProfile, [](cmsHPROFILE p) { cmsCloseProfile(p); });

    // Extract data from fuzz input
    size_t offset = 0;
    uint32_t flags = ExtractUInt32(data, offset, size);
    uint64_t attributes;
    struct tm creationDateTime;

    // Set the encoded ICC version
    cmsSetEncodedICCversion(hProfile, flags);

    // Get the header flags
    uint32_t retrievedFlags = cmsGetHeaderFlags(hProfile);

    // Get the creation date and time
    if (!ExtractTm(data, offset, size, &creationDateTime)) {
        return 0; // Failed to extract creation date and time
    }
    cmsGetHeaderCreationDateTime(hProfile, &creationDateTime);

    // Get the header attributes
    cmsGetHeaderAttributes(hProfile, &attributes);

    // Get the profile version
    cmsFloat64Number profileVersion = cmsGetProfileVersion(hProfile);

    // Get the encoded ICC version
    uint32_t encodedVersion = cmsGetEncodedICCversion(hProfile);

    // Ensure all operations were successful
    if (retrievedFlags != flags || encodedVersion != flags) {
        return 0; // Mismatch in retrieved data
    }

    return 0;
}
