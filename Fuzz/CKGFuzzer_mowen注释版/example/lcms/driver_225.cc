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
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) return 0;

    cmsUInt32Number Intent = data[0];
    cmsUInt32Number UsedDirection = data[1];
    cmsUInt32Number dwFlags = data[2];
    cmsInfoType Info = static_cast<cmsInfoType>(data[3]);

    // Extract language and country codes
    char LanguageCode[3] = {0};
    char CountryCode[3] = {0};
    safe_strncpy(LanguageCode, data + 4, 2, 3);
    safe_strncpy(CountryCode, data + 6, 2, 3);

    // Extract buffer sizes
    cmsUInt32Number BufferSize = (data[8] << 8) | data[9];
    cmsUInt32Number dwBufferLen = (data[10] << 8) | data[11];

    // Allocate buffers
    wchar_t* Buffer = (wchar_t*)malloc(BufferSize * sizeof(wchar_t));
    void* CRDBuffer = malloc(dwBufferLen);
    if (!Buffer || !CRDBuffer) {
        cmsCloseProfile(hProfile);
        free(Buffer);
        free(CRDBuffer);
        return 0;
    }

    // Initialize buffers
    memset(Buffer, 0, BufferSize * sizeof(wchar_t));
    memset(CRDBuffer, 0, dwBufferLen);

    // Call APIs
    cmsIsCLUT(hProfile, Intent, UsedDirection);
    cmsIsMatrixShaper(hProfile);
    cmsGetPostScriptCRD(NULL, hProfile, Intent, dwFlags, CRDBuffer, dwBufferLen);

    // Prepare input for cmsPipelineEval16
    cmsUInt16Number In[3] = {data[12], data[13], data[14]};
    cmsUInt16Number Out[3] = {0};
    cmsPipeline* lut = cmsPipelineAlloc(NULL, 3, 3);
    if (lut) {
        cmsPipelineEval16(In, Out, lut);
        cmsPipelineFree(lut);
    }

    // Call cmsGetProfileInfo
    cmsGetProfileInfo(hProfile, Info, LanguageCode, CountryCode, Buffer, BufferSize);

    // Clean up
    cmsCloseProfile(hProfile);
    free(Buffer);
    free(CRDBuffer);

    return 0;
}
