#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to convert fuzzer input to a wide character string
wchar_t* FuzzInputToWChar(const uint8_t* data, size_t size, size_t* outSize) {
    if (size == 0) return NULL;
    size_t wcharSize = size / sizeof(wchar_t);
    wchar_t* wstr = (wchar_t*)malloc((wcharSize + 1) * sizeof(wchar_t));
    if (!wstr) return NULL;
    memcpy(wstr, data, size);
    wstr[wcharSize] = L'\0';
    *outSize = wcharSize;
    return wstr;
}

// Function to create a cmsMLU structure from fuzzer input
cmsMLU* CreateMLUFromFuzzInput(const uint8_t* data, size_t size) {
    cmsMLU* mlu = cmsMLUalloc(NULL, 1);
    if (!mlu) return NULL;
    if (!cmsMLUsetWide(mlu, "en", "US", (wchar_t*)data)) {
        cmsMLUfree(mlu);
        return NULL;
    }
    return mlu;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for basic operations
    if (size < sizeof(wchar_t) * 2) return 0;

    // Initialize variables
    cmsHANDLE hDict = NULL;
    cmsMLU* displayName = NULL;
    cmsMLU* displayValue = NULL;
    wchar_t* name = NULL;
    wchar_t* value = NULL;
    size_t nameSize, valueSize;
    cmsHANDLE hDictDup = NULL; // Initialize hDictDup to NULL
    const cmsDICTentry* entry = NULL; // Initialize entry to NULL

    // Allocate a new dictionary
    hDict = cmsDictAlloc(NULL);
    if (!hDict) goto cleanup;

    // Convert fuzzer input to wide character strings
    name = FuzzInputToWChar(data, size / 2, &nameSize);
    value = FuzzInputToWChar(data + size / 2, size - size / 2, &valueSize);
    if (!name || !value) goto cleanup;

    // Create cmsMLU structures from fuzzer input
    displayName = CreateMLUFromFuzzInput(data, size / 2);
    displayValue = CreateMLUFromFuzzInput(data + size / 2, size - size / 2);
    if (!displayName || !displayValue) goto cleanup;

    // Add an entry to the dictionary
    if (!cmsDictAddEntry(hDict, name, value, displayName, displayValue)) goto cleanup;

    // Duplicate the dictionary
    hDictDup = cmsDictDup(hDict);
    if (!hDictDup) goto cleanup;

    // Get the entry list and iterate through it
    entry = cmsDictGetEntryList(hDict);
    while (entry) {
        entry = cmsDictNextEntry(entry);
    }

    // Free the duplicated dictionary
    cmsDictFree(hDictDup);

cleanup:
    // Free allocated resources
    if (displayName) cmsMLUfree(displayName);
    if (displayValue) cmsMLUfree(displayValue);
    if (name) free(name);
    if (value) free(value);
    if (hDict) cmsDictFree(hDict);

    return 0;
}
