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

// Function to safely allocate memory and copy data from fuzz input
void* safe_alloc_and_copy(const uint8_t* data, size_t size) {
    void* ptr = malloc(size);
    if (ptr) {
        memcpy(ptr, data, size);
    }
    return ptr;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 16) return 0;

    // Create a profile handle
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) return 0;

    // Initialize variables
    cmsInt32Number tagCount = 0;
    cmsUInt32Number infoSize = 0;
    wchar_t* infoBuffer = nullptr;
    cmsTagSignature tagSig = (cmsTagSignature)0; // Corrected initialization
    cmsUInt64Number headerAttributes = 0;
    void* readTagData = nullptr;
    void* writeTagData = nullptr;

    // Get tag count
    tagCount = cmsGetTagCount(hProfile);
    if (tagCount < 0) goto cleanup;

    // Get profile info
    infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, "en", "US", nullptr, 0);
    if (infoSize == 0) goto cleanup;

    infoBuffer = (wchar_t*)malloc(infoSize * sizeof(wchar_t));
    if (!infoBuffer) goto cleanup;

    infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, "en", "US", infoBuffer, infoSize);
    if (infoSize == 0) goto cleanup;

    // Get tag signature
    tagSig = cmsGetTagSignature(hProfile, 0);
    if (tagSig == 0) goto cleanup;

    // Get header attributes
    cmsGetHeaderAttributes(hProfile, &headerAttributes);

    // Read tag
    readTagData = cmsReadTag(hProfile, tagSig);
    if (!readTagData) goto cleanup;

    // Write tag
    writeTagData = safe_alloc_and_copy(data, size);
    if (!writeTagData) goto cleanup;

    if (!cmsWriteTag(hProfile, tagSig, writeTagData)) goto cleanup;

cleanup:
    // Free allocated resources
    free(infoBuffer);
    free(writeTagData);
    cmsCloseProfile(hProfile);

    return 0;
}
