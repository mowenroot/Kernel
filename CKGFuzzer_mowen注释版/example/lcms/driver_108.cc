#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely copy a string from fuzz input
char* SafeStrndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely create a cmsHANDLE from fuzz input
cmsHANDLE CreateIT8Handle(const uint8_t* data, size_t size) {
    if (size < sizeof(cmsHANDLE)) return nullptr;
    cmsHANDLE hIT8 = (cmsHANDLE)malloc(sizeof(cmsHANDLE));
    if (!hIT8) return nullptr;
    memcpy(hIT8, data, sizeof(cmsHANDLE));
    return hIT8;
}

// Function to safely create a cmsHPROFILE from fuzz input
cmsHPROFILE CreateProfileHandle(const uint8_t* data, size_t size) {
    if (size < sizeof(cmsHPROFILE)) return nullptr;
    cmsHPROFILE hProfile = (cmsHPROFILE)malloc(sizeof(cmsHPROFILE));
    if (!hProfile) return nullptr;
    memcpy(hProfile, data, sizeof(cmsHPROFILE));
    return hProfile;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for all operations
    if (size < (sizeof(cmsHANDLE) + sizeof(cmsHPROFILE) + 3 * sizeof(char*))) return 0;

    // Create handles from fuzz input
    cmsHANDLE hIT8 = CreateIT8Handle(data, sizeof(cmsHANDLE));
    cmsHPROFILE hProfile = CreateProfileHandle(data + sizeof(cmsHANDLE), sizeof(cmsHPROFILE));

    // Create strings from fuzz input
    char* cPatch = SafeStrndup(data + sizeof(cmsHANDLE) + sizeof(cmsHPROFILE), size / 3);
    char* cSample = SafeStrndup(data + sizeof(cmsHANDLE) + sizeof(cmsHPROFILE) + size / 3, size / 3);
    char* Val = SafeStrndup(data + sizeof(cmsHANDLE) + sizeof(cmsHPROFILE) + 2 * (size / 3), size / 3);

    // Ensure all allocations were successful
    if (!hIT8 || !hProfile || !cPatch || !cSample || !Val) {
        free(hIT8);
        free(hProfile);
        free(cPatch);
        free(cSample);
        free(Val);
        return 0;
    }

    // Call cmsIT8SetData
    if (!cmsIT8SetData(hIT8, cPatch, cSample, Val)) {
        // Handle error
    }

    // Call cmsIsCLUT
    cmsBool isCLUT = cmsIsCLUT(hProfile, 0, LCMS_USED_AS_INPUT);
    if (!isCLUT) {
        // Handle error
    }

    // Call cmsGetHeaderCreationDateTime
    struct tm creationDateTime;
    if (!cmsGetHeaderCreationDateTime(hProfile, &creationDateTime)) {
        // Handle error
    }

    // Call cmsDetectTAC
    cmsFloat64Number tac = cmsDetectTAC(hProfile);
    if (tac < 0) {
        // Handle error
    }

    // Call cmsGetHeaderModel
    cmsUInt32Number model = cmsGetHeaderModel(hProfile);

    // Clean up
    free(hIT8);
    free(hProfile);
    free(cPatch);
    free(cSample);
    free(Val);

    return 0;
}
