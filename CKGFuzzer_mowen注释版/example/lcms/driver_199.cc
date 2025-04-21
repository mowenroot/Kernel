#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely extract a uint32_t from the fuzzer input
uint32_t SafeExtractUInt32(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(uint32_t) > size) {
        return 0; // Return a default value if not enough data
    }
    uint32_t value;
    memcpy(&value, data + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    return value;
}

// Function to safely extract a cmsCIExyY from the fuzzer input
bool SafeExtractCIExyY(const uint8_t* data, size_t size, size_t& offset, cmsCIExyY& xyY) {
    if (offset + sizeof(cmsCIExyY) > size) {
        return false; // Not enough data
    }
    memcpy(&xyY, data + offset, sizeof(cmsCIExyY));
    offset += sizeof(cmsCIExyY);
    return true;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsCIExyY whitePoint;
    cmsHPROFILE profileLab4 = nullptr;
    cmsHPROFILE profileLab2 = nullptr;
    cmsHPROFILE profileXYZ = nullptr;
    cmsHTRANSFORM transform = nullptr;
    cmsContext context = nullptr;

    // Extract white point from fuzzer input
    if (!SafeExtractCIExyY(data, size, offset, whitePoint)) {
        return 0; // Not enough data to proceed
    }

    // Create Lab4 profile
    profileLab4 = cmsCreateLab4Profile(&whitePoint);
    if (!profileLab4) {
        return 0; // Failed to create profile
    }

    // Create Lab2 profile
    profileLab2 = cmsCreateLab2Profile(&whitePoint);
    if (!profileLab2) {
        cmsCloseProfile(profileLab4);
        return 0; // Failed to create profile
    }

    // Create XYZ profile
    profileXYZ = cmsCreateXYZProfile();
    if (!profileXYZ) {
        cmsCloseProfile(profileLab4);
        cmsCloseProfile(profileLab2);
        return 0; // Failed to create profile
    }

    // Extract additional parameters from fuzzer input
    uint32_t inputFormat = SafeExtractUInt32(data, size, offset);
    uint32_t outputFormat = SafeExtractUInt32(data, size, offset);
    uint32_t intent = SafeExtractUInt32(data, size, offset);
    uint32_t flags = SafeExtractUInt32(data, size, offset);

    // Create transform
    transform = cmsCreateTransform(profileLab4, inputFormat, profileXYZ, outputFormat, intent, flags);
    if (!transform) {
        cmsCloseProfile(profileLab4);
        cmsCloseProfile(profileLab2);
        cmsCloseProfile(profileXYZ);
        return 0; // Failed to create transform
    }

    // Create context
    context = cmsCreateContext(nullptr, nullptr);
    if (!context) {
        cmsDeleteTransform(transform);
        cmsCloseProfile(profileLab4);
        cmsCloseProfile(profileLab2);
        cmsCloseProfile(profileXYZ);
        return 0; // Failed to create context
    }

    // Clean up resources
    cmsDeleteContext(context);
    cmsDeleteTransform(transform);
    cmsCloseProfile(profileLab4);
    cmsCloseProfile(profileLab2);
    cmsCloseProfile(profileXYZ);

    return 0;
}
