#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>
#include <algorithm> // Include this header for std::min

// Function to safely copy a string from fuzz input
void safe_strncpy(char* dest, const uint8_t* src, size_t src_size, size_t max_len) {
    size_t len = std::min(src_size, max_len - 1);
    memcpy(dest, src, len);
    dest[len] = '\0';
}

// Function to safely copy a wide string from fuzz input
void safe_wcsncpy(wchar_t* dest, const uint8_t* src, size_t src_size, size_t max_len) {
    size_t len = std::min(src_size / sizeof(wchar_t), max_len - 1);
    memcpy(dest, src, len * sizeof(wchar_t));
    dest[len] = L'\0';
}

// Function to safely copy a uint16_t array from fuzz input
void safe_memcpy_uint16(cmsUInt16Number* dest, const uint8_t* src, size_t src_size, size_t max_len) {
    size_t len = std::min(src_size / sizeof(cmsUInt16Number), max_len);
    memcpy(dest, src, len * sizeof(cmsUInt16Number));
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 32) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(0);
    if (!hProfile) return 0;

    std::unique_ptr<cmsNAMEDCOLORLIST, void(*)(cmsNAMEDCOLORLIST*)> namedColorList(
        cmsAllocNamedColorList(0, 10, 10, "Prefix", "Suffix"),
        cmsFreeNamedColorList
    );
    if (!namedColorList) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Extract data for API calls
    char languageCode[3] = {0};
    char countryCode[3] = {0};
    wchar_t profileInfoBuffer[256] = {0};
    char colorName[cmsMAX_PATH] = {0};
    cmsUInt16Number pcs[3] = {0};
    cmsUInt16Number colorant[cmsMAXCHANNELS] = {0};

    safe_strncpy(languageCode, data, 2, sizeof(languageCode));
    safe_strncpy(countryCode, data + 2, 2, sizeof(countryCode));
    safe_wcsncpy(profileInfoBuffer, data + 4, size - 4, sizeof(profileInfoBuffer) / sizeof(wchar_t));
    safe_strncpy(colorName, data + 4 + sizeof(profileInfoBuffer), size - 4 - sizeof(profileInfoBuffer), sizeof(colorName));
    safe_memcpy_uint16(pcs, data + 4 + sizeof(profileInfoBuffer) + sizeof(colorName), size - 4 - sizeof(profileInfoBuffer) - sizeof(colorName), 3);
    safe_memcpy_uint16(colorant, data + 4 + sizeof(profileInfoBuffer) + sizeof(colorName) + 6, size - 4 - sizeof(profileInfoBuffer) - sizeof(colorName) - 6, cmsMAXCHANNELS);

    // Call cmsGetProfileInfo
    cmsUInt32Number profileInfoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, profileInfoBuffer, sizeof(profileInfoBuffer) / sizeof(wchar_t));
    if (profileInfoSize == 0) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Call cmsAppendNamedColor
    if (!cmsAppendNamedColor(namedColorList.get(), colorName, pcs, colorant)) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Call cmsNamedColorIndex
    cmsInt32Number colorIndex = cmsNamedColorIndex(namedColorList.get(), colorName);
    if (colorIndex < 0) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Call cmsNamedColorInfo
    char retrievedColorName[cmsMAX_PATH] = {0};
    char prefix[cmsMAX_PATH] = {0};
    char suffix[cmsMAX_PATH] = {0};
    cmsUInt16Number retrievedPcs[3] = {0};
    cmsUInt16Number retrievedColorant[cmsMAXCHANNELS] = {0};

    if (!cmsNamedColorInfo(namedColorList.get(), colorIndex, retrievedColorName, prefix, suffix, retrievedPcs, retrievedColorant)) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Call cmsNamedColorCount
    cmsUInt32Number colorCount = cmsNamedColorCount(namedColorList.get());
    if (colorCount == 0) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Clean up
    cmsCloseProfile(hProfile);
    return 0;
}
