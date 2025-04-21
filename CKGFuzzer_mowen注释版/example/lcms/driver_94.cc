#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to convert fuzz input to a wide string
wchar_t* FuzzInputToWChar(const uint8_t* data, size_t size, size_t* out_len) {
    if (size == 0) return nullptr;

    // Ensure the input size is even for wide characters
    size_t wchar_size = size / sizeof(wchar_t);
    if (size % sizeof(wchar_t) != 0) return nullptr;

    wchar_t* wstr = (wchar_t*)malloc((wchar_size + 1) * sizeof(wchar_t));
    if (!wstr) return nullptr;

    memcpy(wstr, data, size);
    wstr[wchar_size] = L'\0'; // Null-terminate the string
    *out_len = wchar_size;

    return wstr;
}

// Function to create a dummy cmsMLU structure
cmsMLU* CreateDummyMLU() {
    cmsMLU* mlu = cmsMLUalloc(NULL, 1);
    if (!mlu) return nullptr;

    // Dummy initialization
    if (!cmsMLUsetWide(mlu, "en", "US", L"Dummy")) {
        cmsMLUfree(mlu);
        return nullptr;
    }

    return mlu;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsHANDLE hDict = nullptr;
    cmsHANDLE hDictDup = nullptr;
    cmsMLU* dummyMLU = nullptr;
    wchar_t* name = nullptr;
    wchar_t* value = nullptr;
    size_t name_len = 0, value_len = 0;
    const cmsDICTentry* entry = nullptr; // Initialize entry to nullptr

    // Allocate a new dictionary
    hDict = cmsDictAlloc(NULL);
    if (!hDict) goto cleanup;

    // Create a dummy cmsMLU structure
    dummyMLU = CreateDummyMLU();
    if (!dummyMLU) goto cleanup;

    // Convert fuzz input to wide strings for name and value
    name = FuzzInputToWChar(data, size / 2, &name_len);
    value = FuzzInputToWChar(data + (size / 2), size / 2, &value_len);
    if (!name || !value) goto cleanup;

    // Add an entry to the dictionary
    if (!cmsDictAddEntry(hDict, name, value, dummyMLU, dummyMLU)) goto cleanup;

    // Get the entry list and iterate through it
    entry = cmsDictGetEntryList(hDict);
    while (entry) {
        entry = cmsDictNextEntry(entry);
    }

    // Duplicate the dictionary
    hDictDup = cmsDictDup(hDict);
    if (!hDictDup) goto cleanup;

    // Free the duplicated dictionary
    cmsDictFree(hDictDup);

cleanup:
    // Free allocated resources
    if (hDict) cmsDictFree(hDict);
    if (dummyMLU) cmsMLUfree(dummyMLU);
    if (name) free(name);
    if (value) free(value);

    return 0;
}
