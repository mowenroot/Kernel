#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract an integer from the fuzz input
int32_t ExtractInt32(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(int32_t) > size) {
        return 0; // Return a default value if not enough data
    }
    int32_t value = *reinterpret_cast<const int32_t*>(data + offset);
    offset += sizeof(int32_t);
    return value;
}

// Function to safely extract a cmsHPROFILE from the fuzz input
cmsHPROFILE ExtractProfile(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(cmsHPROFILE) > size) {
        return nullptr; // Return nullptr if not enough data
    }
    cmsHPROFILE profile = *reinterpret_cast<const cmsHPROFILE*>(data + offset);
    offset += sizeof(cmsHPROFILE);
    return profile;
}

// Function to safely extract a cmsToneCurve from the fuzz input
cmsToneCurve* ExtractToneCurve(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(cmsToneCurve*) > size) {
        return nullptr; // Return nullptr if not enough data
    }
    const void* ptr = data + offset; // Use a temporary void pointer to avoid casting away qualifiers
    offset += sizeof(cmsToneCurve*);
    return const_cast<cmsToneCurve*>(*reinterpret_cast<const cmsToneCurve* const*>(ptr)); // Cast to const pointer to const pointer and then remove const
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    size_t offset = 0;

    // Extract inputs from fuzz data
    cmsHPROFILE profile = ExtractProfile(data, offset, size);
    int32_t intent = ExtractInt32(data, offset, size);
    int32_t usedDirection = ExtractInt32(data, offset, size);
    cmsToneCurve* toneCurve = ExtractToneCurve(data, offset, size);

    // Ensure profile and tone curve are valid
    if (!profile || !toneCurve) {
        return 0; // Exit early if invalid profile or tone curve
    }

    // Call cmsIsIntentSupported and handle errors
    cmsBool isIntentSupported = cmsIsIntentSupported(profile, intent, usedDirection);
    if (isIntentSupported == FALSE) {
        // Handle error (e.g., log or ignore)
    }

    // Call cmsIsCLUT and handle errors
    cmsBool isCLUT = cmsIsCLUT(profile, intent, usedDirection);
    if (isCLUT == FALSE) {
        // Handle error (e.g., log or ignore)
    }

    // Call cmsIsMatrixShaper and handle errors
    cmsBool isMatrixShaper = cmsIsMatrixShaper(profile);
    if (isMatrixShaper == FALSE) {
        // Handle error (e.g., log or ignore)
    }

    // Call cmsIsToneCurveMultisegment and handle errors
    cmsBool isToneCurveMultisegment = cmsIsToneCurveMultisegment(toneCurve);
    if (isToneCurveMultisegment == FALSE) {
        // Handle error (e.g., log or ignore)
    }

    // Call cmsIsToneCurveMonotonic and handle errors
    cmsBool isToneCurveMonotonic = cmsIsToneCurveMonotonic(toneCurve);
    if (isToneCurveMonotonic == FALSE) {
        // Handle error (e.g., log or ignore)
    }

    // Clean up any allocated resources if necessary
    // (Note: cmsHPROFILE and cmsToneCurve are opaque pointers, so no explicit cleanup is needed here)

    return 0; // Return 0 to indicate success
}
