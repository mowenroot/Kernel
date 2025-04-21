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
    std::unique_ptr<uint8_t[]> profileBuffer;
    cmsUInt32Number profileSize = 0;
    cmsTagSignature tagSig = static_cast<cmsTagSignature>(data[0]);
    const uint8_t* tagData = data + 1;
    size_t tagDataSize = size - 1;

    // Open profile from memory
    hProfile = cmsOpenProfileFromMem(data, size);
    if (!hProfile) return 0;

    // Read a tag from the profile
    void* readTag = cmsReadTag(hProfile, tagSig);
    if (readTag) {
        // Write the read tag back to the profile
        if (!cmsWriteTag(hProfile, tagSig, readTag)) {
            cmsCloseProfile(hProfile);
            return 0;
        }
    }

    // Get profile information
    char languageCode[3] = {0};
    char countryCode[3] = {0};
    wchar_t infoBuffer[256] = {0};
    safe_strncpy(languageCode, data + 1, 2, sizeof(languageCode));
    safe_strncpy(countryCode, data + 3, 2, sizeof(countryCode));
    cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, infoBuffer, sizeof(infoBuffer) / sizeof(wchar_t));

    // Save profile to memory
    if (!cmsSaveProfileToMem(hProfile, nullptr, &profileSize)) {
        cmsCloseProfile(hProfile);
        return 0;
    }
    profileBuffer.reset(new uint8_t[profileSize]);
    if (!cmsSaveProfileToMem(hProfile, profileBuffer.get(), &profileSize)) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}
