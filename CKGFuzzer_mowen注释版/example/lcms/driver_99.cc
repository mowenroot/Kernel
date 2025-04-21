#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely convert a uint8_t array to a cmsCIELab structure
bool safeConvertToLab(const uint8_t* data, size_t size, cmsCIELab& lab) {
    if (size < 3 * sizeof(cmsFloat64Number)) return false;

    lab.L = *reinterpret_cast<const cmsFloat64Number*>(data);
    lab.a = *reinterpret_cast<const cmsFloat64Number*>(data + sizeof(cmsFloat64Number));
    lab.b = *reinterpret_cast<const cmsFloat64Number*>(data + 2 * sizeof(cmsFloat64Number));

    return true;
}

// Function to safely create a cmsHPROFILE from fuzz input
cmsHPROFILE safeCreateProfile(const uint8_t* data, size_t size) {
    if (size < sizeof(cmsHPROFILE)) return nullptr;

    // Assuming the profile handle is stored as a uint64_t for simplicity
    cmsHPROFILE hProfile = *reinterpret_cast<const cmsHPROFILE*>(data);
    return hProfile;
}

// Function to safely create a cmsToneCurve from fuzz input
cmsToneCurve* safeCreateToneCurve(const uint8_t* data, size_t size) {
    if (size < sizeof(void*)) return nullptr; // Changed sizeof(cmsToneCurve) to sizeof(void*)

    // Assuming the tone curve handle is stored as a pointer for simplicity
    // Cast away the const qualifier before reinterpret_cast
    cmsToneCurve* toneCurve = *reinterpret_cast<cmsToneCurve**>(const_cast<uint8_t*>(data));
    return toneCurve;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for all operations
    if (size < 3 * sizeof(cmsFloat64Number) + 2 * sizeof(cmsHPROFILE) + sizeof(void*)) return 0; // Changed sizeof(cmsToneCurve) to sizeof(void*)

    // Initialize variables
    cmsCIELab lab;
    cmsUInt16Number encodedLab[3] = {0};
    cmsHPROFILE hProfile = nullptr;
    cmsHPROFILE hProfile2 = nullptr;
    cmsToneCurve* toneCurve = nullptr;
    cmsCIEXYZ blackPoint;
    cmsFloat64Number lambda = 0.5; // Example lambda value for smoothing
    wchar_t profileInfoBuffer[256] = {0};
    cmsUInt32Number bufferSize = sizeof(profileInfoBuffer) / sizeof(profileInfoBuffer[0]);

    // Step 1: Convert fuzz input to cmsCIELab structure
    if (!safeConvertToLab(data, size, lab)) return 0;

    // Step 2: Call cmsFloat2LabEncodedV2
    cmsFloat2LabEncodedV2(encodedLab, &lab);

    // Step 3: Create profiles from fuzz input
    hProfile = safeCreateProfile(data + 3 * sizeof(cmsFloat64Number), size - 3 * sizeof(cmsFloat64Number));
    hProfile2 = safeCreateProfile(data + 3 * sizeof(cmsFloat64Number) + sizeof(cmsHPROFILE), size - 3 * sizeof(cmsFloat64Number) - sizeof(cmsHPROFILE));

    // Step 4: Call cmsIsMatrixShaper
    if (hProfile) {
        cmsIsMatrixShaper(hProfile);
    }

    // Step 5: Call cmsDetectDestinationBlackPoint
    if (hProfile2) {
        cmsDetectDestinationBlackPoint(&blackPoint, hProfile2, INTENT_PERCEPTUAL, 0);
    }

    // Step 6: Create tone curve from fuzz input
    toneCurve = safeCreateToneCurve(data + 3 * sizeof(cmsFloat64Number) + 2 * sizeof(cmsHPROFILE), size - 3 * sizeof(cmsFloat64Number) - 2 * sizeof(cmsHPROFILE));

    // Step 7: Call cmsSmoothToneCurve
    if (toneCurve) {
        cmsSmoothToneCurve(toneCurve, lambda);
    }

    // Step 8: Call cmsGetProfileInfo
    if (hProfile) {
        cmsGetProfileInfo(hProfile, cmsInfoDescription, "en", "US", profileInfoBuffer, bufferSize);
    }

    // Clean up resources
    if (hProfile) cmsCloseProfile(hProfile);
    if (hProfile2) cmsCloseProfile(hProfile2);
    if (toneCurve) cmsFreeToneCurve(toneCurve);

    return 0;
}
