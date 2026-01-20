#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
void safe_strncpy(char* dest, const uint8_t* src, size_t size, size_t max_len) {
    size_t len = size < max_len ? size : max_len - 1;
    memcpy(dest, src, len);
    dest[len] = '\0';
}

// Function to safely copy a wide string from fuzz input
void safe_wcsncpy(wchar_t* dest, const uint8_t* src, size_t size, size_t max_len) {
    size_t len = size / sizeof(wchar_t) < max_len ? size / sizeof(wchar_t) : max_len - 1;
    memcpy(dest, src, len * sizeof(wchar_t));
    dest[len] = L'\0';
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(0);
    if (!hProfile) return 0;

    // Corrected function call to cmsPipelineAlloc with 3 input and 3 output channels
    cmsPipeline* lut = cmsPipelineAlloc(0, 3, 3);
    if (!lut) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Extract inputs from fuzz data
    cmsUInt32Number Intent = data[0];
    cmsUInt32Number UsedDirection = data[1];
    cmsStageLoc loc = static_cast<cmsStageLoc>(data[2] % 2); // cmsAT_BEGIN or cmsAT_END
    
    // Corrected function call to cmsStageAllocIdentity with 3 channels
    cmsStage* mpe = cmsStageAllocIdentity(0, 3);
    if (!mpe) {
        cmsPipelineFree(lut);
        cmsCloseProfile(hProfile);
        return 0;
    }

    char LanguageCode[3];
    char CountryCode[3];
    wchar_t Buffer[256];

    // Copy language and country codes safely
    safe_strncpy(LanguageCode, data + 3, 2, 3);
    safe_strncpy(CountryCode, data + 5, 2, 3);

    // Call cmsIsIntentSupported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, Intent, UsedDirection);

    // Call cmsPipelineStageCount
    cmsUInt32Number stageCount = cmsPipelineStageCount(lut);

    // Call cmsPipelineInsertStage
    int insertResult = cmsPipelineInsertStage(lut, loc, mpe);
    if (insertResult == FALSE) {
        cmsStageFree(mpe);
        cmsPipelineFree(lut);
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Call cmsPipelineUnlinkStage
    cmsStage* unlinkedStage = nullptr;
    cmsPipelineUnlinkStage(lut, loc, &unlinkedStage);
    if (unlinkedStage) {
        cmsStageFree(unlinkedStage);
    }

    // Call cmsGetProfileInfo
    cmsUInt32Number infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, LanguageCode, CountryCode, Buffer, sizeof(Buffer) / sizeof(wchar_t));
    if (infoSize == 0) {
        cmsPipelineFree(lut);
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Clean up
    cmsPipelineFree(lut);
    cmsCloseProfile(hProfile);

    return 0;
}
