#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>
#include <algorithm> // Include for std::min

// Function to safely copy a string from fuzz input
void safe_strncpy(char* dest, const uint8_t* src, size_t size, size_t max_len) {
    size_t len = std::min(size, max_len - 1); // Use std::min from <algorithm>
    memcpy(dest, src, len);
    dest[len] = '\0';
}

// Function to safely copy a wide string from fuzz input
void safe_wcsncpy(wchar_t* dest, const uint8_t* src, size_t size, size_t max_len) {
    size_t len = std::min(size, max_len - 1); // Use std::min from <algorithm>
    for (size_t i = 0; i < len; ++i) {
        dest[i] = static_cast<wchar_t>(src[i]);
    }
    dest[len] = L'\0';
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = nullptr;
    cmsPipeline* lut = nullptr;
    cmsStage* mpe = nullptr;
    cmsUInt32Number intent = data[0];
    cmsUInt32Number usedDirection = data[1];
    char languageCode[3] = {0};
    char countryCode[3] = {0};
    wchar_t buffer[256] = {0};
    cmsUInt16Number in[3] = {0};
    cmsUInt16Number out[3] = {0};

    // Extract language and country codes
    safe_strncpy(languageCode, data + 2, 2, sizeof(languageCode));
    safe_strncpy(countryCode, data + 4, 2, sizeof(countryCode));

    // Extract input values for cmsPipelineEval16
    in[0] = static_cast<cmsUInt16Number>(data[6]) << 8 | data[7];
    in[1] = static_cast<cmsUInt16Number>(data[8]) << 8 | data[9];
    in[2] = static_cast<cmsUInt16Number>(data[10]) << 8 | data[11];

    // Create a profile
    hProfile = cmsCreateProfilePlaceholder(0);
    if (!hProfile) return 0;

    // Check if intent is supported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, intent, usedDirection);

    // Get profile information
    cmsUInt32Number infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, buffer, sizeof(buffer) / sizeof(buffer[0]));

    // Create a pipeline
    lut = cmsPipelineAlloc(0, 3, 3);
    if (!lut) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Create a stage
    mpe = cmsStageAllocCLut16bit(0, 3, 3, 3, nullptr); // Corrected to match the function signature
    if (!mpe) {
        cmsPipelineFree(lut);
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Sample the CLUT
    cmsBool sampleResult = cmsStageSampleCLutFloat(mpe, nullptr, nullptr, 0);

    // Evaluate the pipeline
    cmsPipelineEval16(in, out, lut);

    // Cleanup
    cmsStageFree(mpe);
    cmsPipelineFree(lut);
    cmsCloseProfile(hProfile);

    return 0;
}
