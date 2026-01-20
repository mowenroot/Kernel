#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely convert uint8_t array to uint32_t
uint32_t safe_convert_to_uint32(const uint8_t* data, size_t size, size_t offset) {
    if (offset + sizeof(uint32_t) > size) {
        return 0; // Return a default value if out of bounds
    }
    return *reinterpret_cast<const uint32_t*>(data + offset);
}

// Function to safely convert uint8_t array to wchar_t array
void safe_convert_to_wchar(const uint8_t* data, size_t size, size_t offset, wchar_t* buffer, size_t buffer_size) {
    if (offset + buffer_size * sizeof(wchar_t) > size) {
        buffer[0] = L'\0'; // Null-terminate if out of bounds
        return;
    }
    memcpy(buffer, data + offset, buffer_size * sizeof(wchar_t));
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 16) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(0);
    if (!hProfile) return 0;

    std::unique_ptr<cmsToneCurve, void(*)(cmsToneCurve*)> toneCurve(
        cmsBuildTabulatedToneCurve16(0, 256, nullptr),
        [](cmsToneCurve* tc) { cmsFreeToneCurve(tc); }
    );
    if (!toneCurve) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Extract inputs from fuzz data
    uint32_t intent = safe_convert_to_uint32(data, size, 0);
    uint32_t usedDirection = safe_convert_to_uint32(data, size, 4);
    cmsFloat64Number lambda = *reinterpret_cast<const cmsFloat64Number*>(data + 8);
    char languageCode[3] = {0}; // Changed from wchar_t to char
    char countryCode[3] = {0};  // Changed from wchar_t to char
    memcpy(languageCode, data + 16, 2); // Copy 2 bytes for language code
    memcpy(countryCode, data + 20, 2);  // Copy 2 bytes for country code
    wchar_t buffer[256] = {0};

    // Call APIs with error handling
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, intent, usedDirection);
    if (isIntentSupported) {
        // Handle supported intent
    }

    cmsBool isDescending = cmsIsToneCurveDescending(toneCurve.get());
    if (isDescending) {
        // Handle descending tone curve
    }

    cmsBool isMonotonic = cmsIsToneCurveMonotonic(toneCurve.get());
    if (isMonotonic) {
        // Handle monotonic tone curve
    }

    cmsBool isSmoothed = cmsSmoothToneCurve(toneCurve.get(), lambda);
    if (isSmoothed) {
        // Handle smoothed tone curve
    }

    cmsUInt32Number infoLength = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, buffer, sizeof(buffer) / sizeof(buffer[0]));
    if (infoLength > 0) {
        // Handle profile info
    }

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}
