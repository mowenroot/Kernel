#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely convert fuzzer input to cmsUInt32Number
cmsUInt32Number safe_convert_to_cmsUInt32Number(const uint8_t* data, size_t size, size_t index) {
    if (index >= size) return 0;
    return static_cast<cmsUInt32Number>(data[index]);
}

// Function to safely convert fuzzer input to cmsFloat64Number
cmsFloat64Number safe_convert_to_cmsFloat64Number(const uint8_t* data, size_t size, size_t index) {
    if (index + sizeof(cmsFloat64Number) > size) return 0.0;
    cmsFloat64Number value;
    memcpy(&value, data + index, sizeof(cmsFloat64Number));
    return value;
}

// Function to safely convert fuzzer input to wchar_t buffer
void safe_convert_to_wchar_t_buffer(const uint8_t* data, size_t size, size_t index, wchar_t* buffer, size_t buffer_size) {
    if (index + buffer_size * sizeof(wchar_t) > size) return;
    memcpy(buffer, data + index, buffer_size * sizeof(wchar_t));
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 16) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(0);
    if (!hProfile) return 0;

    std::unique_ptr<cmsToneCurve, void(*)(cmsToneCurve*)> toneCurve(nullptr, [](cmsToneCurve* t) { if (t) cmsFreeToneCurve(t); });
    toneCurve.reset(cmsBuildTabulatedToneCurve16(0, 256, nullptr));
    if (!toneCurve) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Extract inputs from fuzzer data
    cmsUInt32Number intent = safe_convert_to_cmsUInt32Number(data, size, 0);
    cmsUInt32Number direction = safe_convert_to_cmsUInt32Number(data, size, 4);
    cmsFloat64Number lambda = safe_convert_to_cmsFloat64Number(data, size, 8);
    wchar_t buffer[256] = {0};
    safe_convert_to_wchar_t_buffer(data, size, 16, buffer, 256);

    // Call cmsIsCLUT
    cmsBool isCLUT = cmsIsCLUT(hProfile, intent, direction);
    if (isCLUT) {
        // Handle success
    } else {
        // Handle failure
    }

    // Call cmsIsToneCurveDescending
    cmsBool isDescending = cmsIsToneCurveDescending(toneCurve.get());
    if (isDescending) {
        // Handle success
    } else {
        // Handle failure
    }

    // Call cmsSmoothToneCurve
    cmsBool isSmoothed = cmsSmoothToneCurve(toneCurve.get(), lambda);
    if (isSmoothed) {
        // Handle success
    } else {
        // Handle failure
    }

    // Call cmsIsToneCurveMonotonic
    cmsBool isMonotonic = cmsIsToneCurveMonotonic(toneCurve.get());
    if (isMonotonic) {
        // Handle success
    } else {
        // Handle failure
    }

    // Call cmsGetProfileInfo
    cmsUInt32Number infoLength = cmsGetProfileInfo(hProfile, cmsInfoDescription, "en", "US", buffer, 256);
    if (infoLength > 0) {
        // Handle success
    } else {
        // Handle failure
    }

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}
