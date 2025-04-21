#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>
#include <algorithm> // Include for std::min

// Function to safely copy a string from fuzz input to a buffer
void safe_strncpy(char* dest, const uint8_t* src, size_t src_size, size_t dest_size) {
    size_t copy_size = std::min(src_size, dest_size - 1); // Use std::min from <algorithm>
    memcpy(dest, src, copy_size);
    dest[copy_size] = '\0';
}

// Function to safely copy a wide string from fuzz input to a buffer
void safe_wcsncpy(wchar_t* dest, const uint8_t* src, size_t src_size, size_t dest_size) {
    size_t copy_size = std::min(src_size / sizeof(wchar_t), dest_size - 1); // Use std::min from <algorithm>
    memcpy(dest, src, copy_size * sizeof(wchar_t));
    dest[copy_size] = L'\0';
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 10) return 0;

    // Create a placeholder profile
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) return 0;

    // Allocate buffers for profile info retrieval
    const size_t bufferSize = 256;
    std::unique_ptr<wchar_t[]> buffer(new wchar_t[bufferSize]);
    char languageCode[3] = {0};
    char countryCode[3] = {0};

    // Extract language and country codes from fuzz input
    safe_strncpy(languageCode, data, 2, sizeof(languageCode));
    safe_strncpy(countryCode, data + 2, 2, sizeof(countryCode));

    // Retrieve profile info
    cmsUInt32Number infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, buffer.get(), bufferSize);
    if (infoSize == 0) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Create a named color list
    cmsNAMEDCOLORLIST* namedColorList = cmsAllocNamedColorList(NULL, 1, 3, "Prefix", "Suffix");
    if (!namedColorList) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Add a named color to the list using cmsAppendNamedColor
    cmsAppendNamedColor(namedColorList, "ColorName", 0, 0); // Corrected to 4 arguments

    // Retrieve named color count
    cmsUInt32Number colorCount = cmsNamedColorCount(namedColorList);
    if (colorCount == 0) {
        cmsFreeNamedColorList(namedColorList);
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Retrieve named color info
    char colorName[256] = {0};
    char prefix[256] = {0};
    char suffix[256] = {0};
    cmsUInt16Number pcs[3] = {0};
    cmsUInt16Number colorant[3] = {0};

    if (!cmsNamedColorInfo(namedColorList, 0, colorName, prefix, suffix, pcs, colorant)) {
        cmsFreeNamedColorList(namedColorList);
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Find named color index
    const char* searchName = reinterpret_cast<const char*>(data + 4);
    cmsInt32Number colorIndex = cmsNamedColorIndex(namedColorList, searchName);
    if (colorIndex < 0) {
        cmsFreeNamedColorList(namedColorList);
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Free the named color list
    cmsFreeNamedColorList(namedColorList);

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}
