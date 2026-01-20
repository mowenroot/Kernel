#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <wchar.h>  // Include wchar.h for wide character support

// Function to safely copy a string with bounds checking
void safe_strncpy(char* dest, const char* src, size_t dest_size) {
    if (dest == nullptr || src == nullptr || dest_size == 0) return;
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

// Function to safely copy a wide string with bounds checking
void safe_wcsncpy(wchar_t* dest, const wchar_t* src, size_t dest_size) {
    if (dest == nullptr || src == nullptr || dest_size == 0) return;
    size_t len = wcslen(src);  // Use wcslen to get the length of the wide string
    if (len >= dest_size) len = dest_size - 1;
    wmemcpy(dest, src, len);  // Use wmemcpy to copy the wide string
    dest[len] = L'\0';  // Null-terminate the destination wide string
}

// Function to convert a 3-character string to a 16-bit integer
cmsUInt16Number strTo16(const char str[3]) {
    return (cmsUInt16Number)((str[0] << 8) | str[1]);
}

// Function to convert a 16-bit integer to a 3-character string
void strFrom16(char str[3], cmsUInt16Number val) {
    str[0] = (char)(val >> 8);
    str[1] = (char)(val & 0xFF);
    str[2] = '\0';
}

// Function to calculate the length of a wide string
size_t mywcslen(const wchar_t* str) {
    const wchar_t* s;
    for (s = str; *s; ++s);
    return (s - str);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < 12) return 0;

    // Initialize variables
    cmsMLU* mlu = cmsMLUalloc(NULL, 1);
    if (!mlu) return 0;

    cmsHPROFILE profile = cmsCreateProfilePlaceholder(NULL);
    if (!profile) {
        cmsMLUfree(mlu);
        return 0;
    }

    // Extract language and country codes from input data
    char LanguageCode[3] = {0};
    char CountryCode[3] = {0};
    safe_strncpy(LanguageCode, (const char*)data, 3);
    safe_strncpy(CountryCode, (const char*)(data + 3), 3);

    // Extract ASCII string from input data
    const char* ASCIIString = (const char*)(data + 6);
    size_t ASCIIStringLen = size - 6;

    // Set ASCII string in MLU
    if (!cmsMLUsetASCII(mlu, LanguageCode, CountryCode, ASCIIString)) {
        cmsCloseProfile(profile);
        cmsMLUfree(mlu);
        return 0;
    }

    // Get translation from MLU
    char ObtainedLanguage[3] = {0};
    char ObtainedCountry[3] = {0};
    if (!cmsMLUgetTranslation(mlu, LanguageCode, CountryCode, ObtainedLanguage, ObtainedCountry)) {
        cmsCloseProfile(profile);
        cmsMLUfree(mlu);
        return 0;
    }

    // Check if profile is a matrix shaper
    if (cmsIsMatrixShaper(profile)) {
        // Do something if the profile is a matrix shaper
    }

    // Set wide string in MLU
    wchar_t WideString[128] = {0};
    size_t wideStringLen = mywcslen(WideString);
    if (wideStringLen > 0) {
        if (!cmsMLUsetWide(mlu, LanguageCode, CountryCode, WideString)) {
            cmsCloseProfile(profile);
            cmsMLUfree(mlu);
            return 0;
        }
    }

    // Get profile info
    wchar_t ProfileInfoBuffer[256] = {0};
    cmsUInt32Number infoLen = cmsGetProfileInfo(profile, cmsInfoDescription, LanguageCode, CountryCode, ProfileInfoBuffer, 256);
    if (infoLen == 0) {
        cmsCloseProfile(profile);
        cmsMLUfree(mlu);
        return 0;
    }

    // Clean up
    cmsCloseProfile(profile);
    cmsMLUfree(mlu);

    return 0;
}
