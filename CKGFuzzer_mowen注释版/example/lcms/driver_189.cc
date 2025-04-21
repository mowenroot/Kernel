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

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 16) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) return 0;

    cmsUInt32Number Intent = data[0];
    cmsUInt32Number UsedDirection = data[1];

    // Call cmsIsCLUT
    cmsBool isCLUT = cmsIsCLUT(hProfile, Intent, UsedDirection);

    // Call cmsIsMatrixShaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);

    // Prepare for cmsxyY2XYZ
    cmsCIExyY xyY;
    cmsCIEXYZ XYZ;
    if (size >= 24) {
        memcpy(&xyY, data + 2, sizeof(xyY));
        cmsxyY2XYZ(&XYZ, &xyY);
    }

    // Prepare for cmsPipelineEval16
    cmsUInt16Number In[3] = {0, 0, 0};
    cmsUInt16Number Out[3] = {0, 0, 0};
    cmsPipeline* lut = cmsPipelineAlloc(NULL, 3, 3);
    if (lut) {
        if (size >= 30) {
            memcpy(In, data + 22, sizeof(In));
            cmsPipelineEval16(In, Out, lut);
        }
        cmsPipelineFree(lut);
    }

    // Prepare for cmsGetProfileInfo
    char LanguageCode[3] = {0};
    char CountryCode[3] = {0};
    wchar_t Buffer[256] = {0};
    if (size >= 38) {
        safe_strncpy(LanguageCode, data + 30, 2, sizeof(LanguageCode));
        safe_strncpy(CountryCode, data + 32, 2, sizeof(CountryCode));
        cmsGetProfileInfo(hProfile, cmsInfoDescription, LanguageCode, CountryCode, Buffer, sizeof(Buffer));
    }

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}
