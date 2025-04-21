#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely extract an integer from the fuzzer input
int32_t ExtractInt32(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(int32_t) > size) {
        return 0; // Return a default value if not enough data
    }
    int32_t value = *reinterpret_cast<const int32_t*>(data + offset);
    offset += sizeof(int32_t);
    return value;
}

// Function to safely extract a string from the fuzzer input
void ExtractString(const uint8_t* data, size_t& offset, size_t size, char* buffer, size_t bufferSize) {
    if (offset + bufferSize > size) {
        buffer[0] = '\0'; // Null-terminate if not enough data
        return;
    }
    memcpy(buffer, data + offset, bufferSize);
    offset += bufferSize;
    buffer[bufferSize - 1] = '\0'; // Ensure null-termination
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(0); // Placeholder profile
    if (!hProfile) return 0; // Handle profile creation failure

    // Extract inputs from fuzzer data
    int32_t intent = ExtractInt32(data, offset, size);
    int32_t usedDirection = ExtractInt32(data, offset, size);
    char languageCode[3] = {0};
    char countryCode[3] = {0};
    ExtractString(data, offset, size, languageCode, sizeof(languageCode));
    ExtractString(data, offset, size, countryCode, sizeof(countryCode));

    // Check if the intent is supported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, intent, usedDirection);
    if (isIntentSupported) {
        // Further operations can be performed here if needed
    }

    // Check if the profile is a CLUT
    cmsBool isCLUT = cmsIsCLUT(hProfile, intent, usedDirection);
    if (isCLUT) {
        // Further operations can be performed here if needed
    }

    // Check if the profile is a matrix shaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);
    if (isMatrixShaper) {
        // Further operations can be performed here if needed
    }

    // Convert float XYZ to encoded XYZ
    cmsCIEXYZ fXYZ;
    cmsUInt16Number XYZ[3];
    fXYZ.X = *reinterpret_cast<const float*>(data + offset);
    fXYZ.Y = *reinterpret_cast<const float*>(data + offset + sizeof(float));
    fXYZ.Z = *reinterpret_cast<const float*>(data + offset + 2 * sizeof(float));
    offset += 3 * sizeof(float);
    cmsFloat2XYZEncoded(XYZ, &fXYZ);

    // Get profile information
    wchar_t profileInfoBuffer[256];
    cmsUInt32Number profileInfoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, profileInfoBuffer, sizeof(profileInfoBuffer) / sizeof(wchar_t));
    if (profileInfoSize > 0) {
        // Further operations can be performed here if needed
    }

    // Clean up resources
    cmsCloseProfile(hProfile);

    return 0; // Non-zero return values are reserved for future use.
}
