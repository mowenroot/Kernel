#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy data into a buffer
void safe_copy(void* dest, const void* src, size_t size) {
    if (dest && src && size > 0) {
        memcpy(dest, src, size);
    }
}

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    if (size == 0) return nullptr;
    return malloc(size);
}

// Function to safely free memory
void safe_free(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 24) return 0;

    // Create a profile handle
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(nullptr);
    if (!hProfile) return 0;

    // Variables for API inputs
    cmsUInt32Number Intent = data[0];
    cmsUInt32Number UsedDirection = data[1];
    cmsUInt8Number ProfileID[16];
    cmsUInt32Number Flags = *(cmsUInt32Number*)(data + 2);
    char LanguageCode[3] = { static_cast<char>(data[6]), static_cast<char>(data[7]), static_cast<char>(data[8]) }; // Cast uint8_t to char
    char CountryCode[3] = { static_cast<char>(data[9]), static_cast<char>(data[10]), static_cast<char>(data[11]) }; // Cast uint8_t to char
    wchar_t* Buffer = (wchar_t*)safe_malloc(sizeof(wchar_t) * (size - 12));
    cmsUInt32Number BufferSize = size - 12;

    // Copy ProfileID from fuzz input
    safe_copy(ProfileID, data + 12, 16);

    // Call cmsSetHeaderProfileID
    cmsSetHeaderProfileID(hProfile, ProfileID);

    // Call cmsSetHeaderFlags
    cmsSetHeaderFlags(hProfile, Flags);

    // Call cmsIsCLUT
    cmsBool isCLUT = cmsIsCLUT(hProfile, Intent, UsedDirection);

    // Call cmsDetectTAC
    cmsFloat64Number TAC = cmsDetectTAC(hProfile);

    // Call cmsGetProfileInfo
    cmsUInt32Number infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, LanguageCode, CountryCode, Buffer, BufferSize);

    // Clean up
    safe_free(Buffer);
    cmsCloseProfile(hProfile);

    return 0;
}
