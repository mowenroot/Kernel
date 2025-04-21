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
    size_t len = size < max_len ? size : max_len - 1;
    for (size_t i = 0; i < len; ++i) {
        dest[i] = static_cast<wchar_t>(src[i]);
    }
    dest[len] = L'\0';
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 12) return 0;

    // Initialize variables
    cmsMLU* mlu = cmsMLUalloc(NULL, 1);
    if (!mlu) return 0;

    char LanguageCode[3] = {0};
    char CountryCode[3] = {0};
    char ASCIIString[256] = {0};
    wchar_t WideBuffer[256] = {0};
    char ASCIIBuffer[256] = {0};

    // Extract language and country codes from fuzz input
    safe_strncpy(LanguageCode, data, 3, 3);
    safe_strncpy(CountryCode, data + 3, 3, 3);

    // Extract ASCII string from fuzz input
    safe_strncpy(ASCIIString, data + 6, size - 6, sizeof(ASCIIString) - 1);

    // Set ASCII string in MLU
    if (!cmsMLUsetASCII(mlu, LanguageCode, CountryCode, ASCIIString)) {
        cmsMLUfree(mlu);
        return 0;
    }

    // Get translations count
    cmsUInt32Number translationsCount = cmsMLUtranslationsCount(mlu);
    if (translationsCount == 0) {
        cmsMLUfree(mlu);
        return 0;
    }

    // Get translations codes
    char LanguageCodeFromMLU[3] = {0};
    char CountryCodeFromMLU[3] = {0};
    if (!cmsMLUtranslationsCodes(mlu, 0, LanguageCodeFromMLU, CountryCodeFromMLU)) {
        cmsMLUfree(mlu);
        return 0;
    }

    // Get wide string from MLU
    cmsUInt32Number wideLen = cmsMLUgetWide(mlu, LanguageCodeFromMLU, CountryCodeFromMLU, WideBuffer, sizeof(WideBuffer));
    if (wideLen == 0) {
        cmsMLUfree(mlu);
        return 0;
    }

    // Get ASCII string from MLU
    cmsUInt32Number asciiLen = cmsMLUgetASCII(mlu, LanguageCodeFromMLU, CountryCodeFromMLU, ASCIIBuffer, sizeof(ASCIIBuffer));
    if (asciiLen == 0) {
        cmsMLUfree(mlu);
        return 0;
    }

    // Free the MLU structure
    cmsMLUfree(mlu);

    return 0;
}
