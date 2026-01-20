#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>
#include <algorithm> // Include for std::min

// Function to safely extract an integer from the fuzz input
int32_t ExtractInt(const uint8_t*& data, size_t& size, size_t max_bytes = sizeof(int32_t)) {
    if (size < max_bytes) {
        return 0; // Return a default value if not enough data
    }
    int32_t value = 0;
    memcpy(&value, data, max_bytes);
    data += max_bytes;
    size -= max_bytes;
    return value;
}

// Function to safely extract a string from the fuzz input
void ExtractString(const uint8_t*& data, size_t& size, char* buffer, size_t buffer_size) {
    size_t len = std::min(size, buffer_size - 1); // Use std::min from <algorithm>
    memcpy(buffer, data, len);
    buffer[len] = '\0';
    data += len;
    size -= len;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) {
        return 0; // Handle error
    }

    // Extract inputs from fuzz data
    int32_t intent = ExtractInt(data, size);
    int32_t usedDirection = ExtractInt(data, size);
    char languageCode[3] = {0};
    char countryCode[3] = {0};
    ExtractString(data, size, languageCode, sizeof(languageCode));
    ExtractString(data, size, countryCode, sizeof(countryCode));

    // Call cmsIsIntentSupported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, intent, usedDirection);

    // Call cmsIsCLUT
    cmsBool isCLUT = cmsIsCLUT(hProfile, intent, usedDirection);

    // Call cmsIsMatrixShaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);

    // Prepare for cmsFloat2XYZEncoded
    cmsCIEXYZ fXYZ;
    if (size >= 3 * sizeof(float)) {
        fXYZ.X = *reinterpret_cast<const float*>(data);
        fXYZ.Y = *reinterpret_cast<const float*>(data + sizeof(float));
        fXYZ.Z = *reinterpret_cast<const float*>(data + 2 * sizeof(float));
        data += 3 * sizeof(float);
        size -= 3 * sizeof(float);
    } else {
        // Handle insufficient data
        cmsCloseProfile(hProfile);
        return 0;
    }

    cmsUInt16Number XYZ[3];
    cmsFloat2XYZEncoded(XYZ, &fXYZ);

    // Prepare for cmsGetProfileInfo
    const size_t bufferSize = 256;
    std::unique_ptr<wchar_t[]> buffer(new wchar_t[bufferSize]);
    cmsUInt32Number infoLength = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, buffer.get(), bufferSize);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}
