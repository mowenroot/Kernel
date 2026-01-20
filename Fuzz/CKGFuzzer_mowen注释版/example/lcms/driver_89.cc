#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely convert fuzz input to a cmsUInt32Number
cmsUInt32Number safe_convert_to_cmsUInt32Number(const uint8_t* data, size_t size, size_t index) {
    if (index >= size) {
        return 0; // Default value if out of bounds
    }
    return static_cast<cmsUInt32Number>(data[index]);
}

// Function to safely convert fuzz input to a cmsFloat64Number
cmsFloat64Number safe_convert_to_cmsFloat64Number(const uint8_t* data, size_t size, size_t index) {
    if (index + sizeof(cmsFloat64Number) > size) {
        return 0.0; // Default value if out of bounds
    }
    cmsFloat64Number value;
    memcpy(&value, data + index, sizeof(cmsFloat64Number));
    return value;
}

// Function to safely convert fuzz input to a wchar_t string
std::unique_ptr<wchar_t[]> safe_convert_to_wchar_t(const uint8_t* data, size_t size, size_t index, size_t length) {
    if (index + length * sizeof(wchar_t) > size) {
        return nullptr; // Return nullptr if out of bounds
    }
    std::unique_ptr<wchar_t[]> str(new wchar_t[length + 1]);
    memcpy(str.get(), data + index, length * sizeof(wchar_t));
    str[length] = L'\0'; // Null-terminate the string
    return str;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < sizeof(cmsUInt32Number) * 3 + sizeof(cmsFloat64Number) + sizeof(wchar_t) * 10) {
        return 0; // Insufficient data
    }

    // Initialize variables
    cmsUInt32Number intent = safe_convert_to_cmsUInt32Number(data, size, 0);
    cmsUInt32Number usedDirection = safe_convert_to_cmsUInt32Number(data, size, sizeof(cmsUInt32Number));
    cmsFloat64Number lambda = safe_convert_to_cmsFloat64Number(data, size, sizeof(cmsUInt32Number) * 2);
    cmsUInt32Number dictEntryIndex = safe_convert_to_cmsUInt32Number(data, size, sizeof(cmsUInt32Number) * 2 + sizeof(cmsFloat64Number));

    // Create a profile handle
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) {
        return 0; // Failed to create profile
    }

    // Call cmsIsIntentSupported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, intent, usedDirection);

    // Call cmsIsCLUT
    cmsBool isCLUT = cmsIsCLUT(hProfile, intent, usedDirection);

    // Create a tone curve
    cmsToneCurve* toneCurve = cmsBuildGamma(NULL, 2.2);
    if (!toneCurve) {
        cmsCloseProfile(hProfile);
        return 0; // Failed to create tone curve
    }

    // Call cmsSmoothToneCurve
    cmsBool isSmooth = cmsSmoothToneCurve(toneCurve, lambda);

    // Call cmsEstimateGamma
    cmsFloat64Number gamma = cmsEstimateGamma(toneCurve, 0.001);

    // Create a dictionary
    cmsHANDLE hDict = cmsDictAlloc(NULL);
    if (!hDict) {
        cmsFreeToneCurve(toneCurve);
        cmsCloseProfile(hProfile);
        return 0; // Failed to create dictionary
    }

    // Prepare dictionary entry data
    std::unique_ptr<wchar_t[]> name = safe_convert_to_wchar_t(data, size, sizeof(cmsUInt32Number) * 3 + sizeof(cmsFloat64Number) + sizeof(wchar_t) * 0, 5);
    std::unique_ptr<wchar_t[]> value = safe_convert_to_wchar_t(data, size, sizeof(cmsUInt32Number) * 3 + sizeof(cmsFloat64Number) + sizeof(wchar_t) * 5, 5);

    if (!name || !value) {
        cmsDictFree(hDict);
        cmsFreeToneCurve(toneCurve);
        cmsCloseProfile(hProfile);
        return 0; // Failed to convert fuzz input to wchar_t
    }

    // Call cmsDictAddEntry
    cmsBool isEntryAdded = cmsDictAddEntry(hDict, name.get(), value.get(), NULL, NULL);

    // Clean up resources
    cmsDictFree(hDict);
    cmsFreeToneCurve(toneCurve);
    cmsCloseProfile(hProfile);

    return 0; // Return 0 to indicate success
}
