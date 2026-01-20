#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert fuzz input to a cmsHPROFILE handle
cmsHPROFILE CreateProfileFromInput(const uint8_t* data, size_t size) {
    // Ensure the input size is within a reasonable limit
    if (size < sizeof(cmsHPROFILE)) {
        return nullptr;
    }

    // Create a new profile handle from the input data
    cmsHPROFILE hProfile = reinterpret_cast<cmsHPROFILE>(malloc(sizeof(cmsHPROFILE)));
    if (!hProfile) {
        return nullptr;
    }

    // Copy the input data to the profile handle
    memcpy(hProfile, data, sizeof(cmsHPROFILE));

    return hProfile;
}

// Function to safely convert fuzz input to a cmsColorSpaceSignature
cmsColorSpaceSignature CreateColorSpaceFromInput(const uint8_t* data, size_t size) {
    // Ensure the input size is within a reasonable limit
    if (size < sizeof(cmsColorSpaceSignature)) {
        return cmsSigXYZData; // Default to a known color space
    }

    // Create a color space signature from the input data
    cmsColorSpaceSignature colorSpace = *reinterpret_cast<const cmsColorSpaceSignature*>(data);

    return colorSpace;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit
    if (size < sizeof(cmsHPROFILE) + sizeof(cmsColorSpaceSignature)) {
        return 0;
    }

    // Create a profile handle from the fuzz input
    cmsHPROFILE hProfile = CreateProfileFromInput(data, size);
    if (!hProfile) {
        return 0;
    }

    // Create a color space signature from the fuzz input
    cmsColorSpaceSignature colorSpace = CreateColorSpaceFromInput(data + sizeof(cmsHPROFILE), size - sizeof(cmsHPROFILE));

    // Call cmsGetColorSpace and handle errors
    cmsColorSpaceSignature retrievedColorSpace = cmsGetColorSpace(hProfile);
    if (retrievedColorSpace == cmsSigXYZData) {
        // Handle error, e.g., log or return
    }

    // Call cmsGetTagCount and handle errors
    cmsInt32Number tagCount = cmsGetTagCount(hProfile);
    if (tagCount < 0) {
        // Handle error, e.g., log or return
    }

    // Call cmsChannelsOf and handle errors
    cmsUInt32Number channels = cmsChannelsOf(colorSpace);
    if (channels == 0) {
        // Handle error, e.g., log or return
    }

    // Call cmsGetProfileVersion and handle errors
    cmsFloat64Number profileVersion = cmsGetProfileVersion(hProfile);
    if (profileVersion < 0.0) {
        // Handle error, e.g., log or return
    }

    // Call cmsGetDeviceClass and handle errors
    cmsProfileClassSignature deviceClass = cmsGetDeviceClass(hProfile);
    if (deviceClass == cmsSigInputClass) {
        // Handle error, e.g., log or return
    }

    // Call cmsGetPCS and handle errors
    cmsColorSpaceSignature pcs = cmsGetPCS(hProfile);
    if (pcs == cmsSigXYZData) {
        // Handle error, e.g., log or return
    }

    // Free the allocated profile handle
    free(hProfile);

    return 0;
}
