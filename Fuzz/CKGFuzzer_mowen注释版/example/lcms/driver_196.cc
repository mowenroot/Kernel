#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a uint32_t from the fuzzer input
uint32_t extractUint32(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(uint32_t) > size) {
        return 0; // Return a default value if not enough data
    }
    uint32_t value;
    memcpy(&value, data + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    return value;
}

// Function to safely extract a cmsCIExyY from the fuzzer input
cmsCIExyY extractCIExyY(const uint8_t* data, size_t& offset, size_t size) {
    cmsCIExyY xyY;
    if (offset + sizeof(cmsCIExyY) > size) {
        memset(&xyY, 0, sizeof(cmsCIExyY)); // Initialize to zero if not enough data
        return xyY;
    }
    memcpy(&xyY, data + offset, sizeof(cmsCIExyY));
    offset += sizeof(cmsCIExyY);
    return xyY;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsContext context = nullptr;
    cmsHPROFILE profileLab4 = nullptr;
    cmsHPROFILE profileLab2 = nullptr;
    cmsHPROFILE profileXYZ = nullptr;
    cmsHPROFILE profilePlaceholder = nullptr;
    cmsHPROFILE profileSRGB = nullptr;

    // Create a context for memory management
    context = cmsCreateContext(nullptr, nullptr);
    if (!context) {
        return 0; // Failed to create context
    }

    // Extract data from fuzzer input
    size_t offset = 0;
    cmsCIExyY whitePoint = extractCIExyY(data, offset, size);

    // Create profiles using the extracted data
    profileLab4 = cmsCreateLab4ProfileTHR(context, &whitePoint);
    profileLab2 = cmsCreateLab2ProfileTHR(context, &whitePoint);
    profileXYZ = cmsCreateXYZProfileTHR(context);
    profilePlaceholder = cmsCreateProfilePlaceholder(context);
    profileSRGB = cmsCreate_sRGBProfileTHR(context);

    // Check if any profile creation failed
    if (!profileLab4 || !profileLab2 || !profileXYZ || !profilePlaceholder || !profileSRGB) {
        // Clean up profiles if any creation failed
        if (profileLab4) cmsCloseProfile(profileLab4);
        if (profileLab2) cmsCloseProfile(profileLab2);
        if (profileXYZ) cmsCloseProfile(profileXYZ);
        if (profilePlaceholder) cmsCloseProfile(profilePlaceholder);
        if (profileSRGB) cmsCloseProfile(profileSRGB);
        cmsDeleteContext(context);
        return 0; // Exit if any profile creation failed
    }

    // Clean up resources
    cmsCloseProfile(profileLab4);
    cmsCloseProfile(profileLab2);
    cmsCloseProfile(profileXYZ);
    cmsCloseProfile(profilePlaceholder);
    cmsCloseProfile(profileSRGB);
    cmsDeleteContext(context);

    return 0; // Success
}
