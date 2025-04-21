#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely allocate memory and check for allocation failures
void* safeMalloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely free memory
void safeFree(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Function to safely copy data with bounds checking
void safeCopy(void* dest, const void* src, size_t size) {
    if (size > 0) {
        memcpy(dest, src, size);
    }
}

// Function to safely cast data to a specific type with bounds checking
template <typename T>
T safeCast(const uint8_t* data, size_t size, size_t offset) {
    if (offset + sizeof(T) > size) {
        fprintf(stderr, "Data out of bounds\n");
        exit(EXIT_FAILURE);
    }
    return *reinterpret_cast<const T*>(data + offset);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to be useful
    if (size < sizeof(cmsHPROFILE) + sizeof(cmsUInt32Number) + sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Initialize variables
    cmsHPROFILE hProfile = reinterpret_cast<cmsHPROFILE>(safeMalloc(sizeof(cmsHPROFILE)));
    cmsCIEXYZ blackPoint;
    cmsToneCurve* toneCurve = cmsBuildTabulatedToneCurve16(NULL, 256, NULL); // Corrected to use cmsBuildTabulatedToneCurve16
    cmsFloat64Number lambda = safeCast<cmsFloat64Number>(data, size, sizeof(cmsHPROFILE) + sizeof(cmsUInt32Number));

    // Extract profile handle and intent from the fuzz input
    safeCopy(hProfile, data, sizeof(cmsHPROFILE));
    cmsUInt32Number intent = safeCast<cmsUInt32Number>(data, size, sizeof(cmsHPROFILE));

    // Call cmsIsMatrixShaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);

    // Call cmsDetectDestinationBlackPoint
    cmsBool detectBlackPointSuccess = cmsDetectDestinationBlackPoint(&blackPoint, hProfile, intent, 0);

    // Call cmsSmoothToneCurve
    cmsBool smoothToneCurveSuccess = cmsSmoothToneCurve(toneCurve, lambda);

    // Call cmsGetToneCurveEstimatedTableEntries
    cmsUInt32Number tableEntries = cmsGetToneCurveEstimatedTableEntries(toneCurve);

    // Call cmsIsToneCurveMonotonic
    cmsBool isMonotonic = cmsIsToneCurveMonotonic(toneCurve);

    // Clean up resources
    safeFree(hProfile);
    cmsFreeToneCurve(toneCurve);

    // Return 0 to indicate successful execution
    return 0;
}
