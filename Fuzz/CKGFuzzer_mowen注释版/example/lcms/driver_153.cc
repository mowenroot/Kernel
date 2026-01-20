#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert a uint8_t array to a wide string
wchar_t* SafeConvertToWideString(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;

    // Allocate memory for the wide string
    wchar_t* wideString = (wchar_t*)malloc((size + 1) * sizeof(wchar_t));
    if (!wideString) return nullptr;

    // Convert each byte to a wchar_t
    for (size_t i = 0; i < size; ++i) {
        wideString[i] = (wchar_t)data[i];
    }
    wideString[size] = L'\0'; // Null-terminate the wide string

    return wideString;
}

// Function to safely convert a uint8_t array to an ASCII string
char* SafeConvertToASCIIString(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;

    // Allocate memory for the ASCII string
    char* asciiString = (char*)malloc((size + 1) * sizeof(char));
    if (!asciiString) return nullptr;

    // Copy the data to the ASCII string
    memcpy(asciiString, data, size);
    asciiString[size] = '\0'; // Null-terminate the ASCII string

    return asciiString;
}

// Function to safely copy a uint8_t array to a 3-byte array
void SafeCopyTo3ByteArray(const uint8_t* data, char* dest) {
    if (data == nullptr || dest == nullptr) return;

    // Copy up to 3 bytes
    for (int i = 0; i < 3 && i < (int)strlen((const char*)data); ++i) {
        dest[i] = (char)data[i];
    }
    dest[3] = '\0'; // Null-terminate the string
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < 10) return 0;

    // Initialize variables
    cmsMLU* mlu = cmsMLUalloc(NULL, 1);
    if (!mlu) return 0;

    // Extract language and country codes from the input data
    char language[4] = {0};
    char country[4] = {0};
    SafeCopyTo3ByteArray(data, language);
    SafeCopyTo3ByteArray(data + 3, country);

    // Convert the remaining data to a wide string
    wchar_t* wideString = SafeConvertToWideString(data + 6, size - 6);
    if (!wideString) {
        cmsMLUfree(mlu);
        return 0;
    }

    // Set the wide string in the MLU
    if (!cmsMLUsetWide(mlu, language, country, wideString)) {
        free(wideString);
        cmsMLUfree(mlu);
        return 0;
    }

    // Convert the remaining data to an ASCII string
    char* asciiString = SafeConvertToASCIIString(data + 6, size - 6);
    if (!asciiString) {
        free(wideString);
        cmsMLUfree(mlu);
        return 0;
    }

    // Set the ASCII string in the MLU
    if (!cmsMLUsetASCII(mlu, language, country, asciiString)) {
        free(wideString);
        free(asciiString);
        cmsMLUfree(mlu);
        return 0;
    }

    // Get the number of translations
    cmsUInt32Number translationCount = cmsMLUtranslationsCount(mlu);
    if (translationCount == 0) {
        free(wideString);
        free(asciiString);
        cmsMLUfree(mlu);
        return 0;
    }

    // Retrieve the translation codes
    char obtainedLanguage[4] = {0};
    char obtainedCountry[4] = {0};
    if (!cmsMLUtranslationsCodes(mlu, 0, obtainedLanguage, obtainedCountry)) {
        free(wideString);
        free(asciiString);
        cmsMLUfree(mlu);
        return 0;
    }

    // Get the translation
    char finalLanguage[4] = {0};
    char finalCountry[4] = {0};
    if (!cmsMLUgetTranslation(mlu, obtainedLanguage, obtainedCountry, finalLanguage, finalCountry)) {
        free(wideString);
        free(asciiString);
        cmsMLUfree(mlu);
        return 0;
    }

    // Clean up
    free(wideString);
    free(asciiString);
    cmsMLUfree(mlu);

    return 0;
}
