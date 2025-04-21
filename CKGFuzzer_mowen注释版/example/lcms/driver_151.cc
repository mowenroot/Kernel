#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to convert a 3-character string to a 16-bit integer
cmsUInt16Number strTo16(const char str[3]) {
    return (cmsUInt16Number)((str[0] << 8) | str[1]);
}

// Function to convert a 16-bit integer to a 3-character string
void strFrom16(char str[3], cmsUInt16Number val) {
    str[0] = (char)((val >> 8) & 0xFF);
    str[1] = (char)(val & 0xFF);
    str[2] = '\0';
}

// Function to calculate the length of a wide string
size_t mywcslen(const wchar_t* str) {
    const wchar_t* s;
    for (s = str; *s; ++s);
    return (s - str);
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < 12) return 0;

    // Allocate and initialize the cmsMLU structure
    cmsMLU* mlu = cmsMLUalloc(NULL, 1);
    if (!mlu) return 0;

    // Extract language and country codes from the input data
    char language[3] = { (char)data[0], (char)data[1], '\0' };
    char country[3] = { (char)data[2], (char)data[3], '\0' };

    // Extract the wide string from the input data
    size_t wideStrLen = (size - 4) / sizeof(wchar_t);
    wchar_t* wideStr = (wchar_t*)malloc(wideStrLen * sizeof(wchar_t));
    if (!wideStr) {
        cmsMLUfree(mlu);
        return 0;
    }
    memcpy(wideStr, data + 4, wideStrLen * sizeof(wchar_t));

    // Set the wide string in the cmsMLU structure
    if (!cmsMLUsetWide(mlu, language, country, wideStr)) {
        free(wideStr);
        cmsMLUfree(mlu);
        return 0;
    }

    // Retrieve the wide string from the cmsMLU structure
    wchar_t retrievedWideStr[256];
    cmsUInt32Number retrievedWideStrLen = cmsMLUgetWide(mlu, language, country, retrievedWideStr, sizeof(retrievedWideStr));
    if (retrievedWideStrLen == 0) {
        free(wideStr);
        cmsMLUfree(mlu);
        return 0;
    }

    // Retrieve the ASCII string from the cmsMLU structure
    char retrievedASCIIStr[256];
    cmsUInt32Number retrievedASCIIStrLen = cmsMLUgetASCII(mlu, language, country, retrievedASCIIStr, sizeof(retrievedASCIIStr));
    if (retrievedASCIIStrLen == 0) {
        free(wideStr);
        cmsMLUfree(mlu);
        return 0;
    }

    // Set the ASCII string in the cmsMLU structure
    char asciiStr[256];
    memcpy(asciiStr, retrievedASCIIStr, retrievedASCIIStrLen);
    if (!cmsMLUsetASCII(mlu, language, country, asciiStr)) {
        free(wideStr);
        cmsMLUfree(mlu);
        return 0;
    }

    // Retrieve the translation from the cmsMLU structure
    char obtainedLanguage[3];
    char obtainedCountry[3];
    if (!cmsMLUgetTranslation(mlu, language, country, obtainedLanguage, obtainedCountry)) {
        free(wideStr);
        cmsMLUfree(mlu);
        return 0;
    }

    // Free allocated resources
    free(wideStr);
    cmsMLUfree(mlu);

    return 0;
}
