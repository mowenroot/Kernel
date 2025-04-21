#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely allocate memory and handle errors
template <typename T>
T* safe_malloc(size_t size) {
    T* ptr = static_cast<T*>(malloc(size));
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely free allocated memory
template <typename T>
void safe_free(T* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Function to safely copy data and handle errors
void safe_copy(void* dest, const void* src, size_t size) {
    if (memcpy(dest, src, size) != dest) {
        fprintf(stderr, "Memory copy failed\n");
        exit(EXIT_FAILURE);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure input size is sufficient for processing
    if (size < sizeof(cmsUInt32Number) * 4 + sizeof(cmsFloat64Number) + sizeof(cmsCIELab)) {
        return 0;
    }

    // Initialize variables
    cmsHPROFILE hProfile = nullptr;
    cmsUInt32Number Intent = 0;
    cmsUInt32Number UsedDirection = 0;
    cmsUInt32Number nMax = 0;
    cmsUInt32Number* Codes = nullptr;
    char** Descriptions = nullptr;
    cmsFloat64Number AdaptationState = 0.0;
    cmsCIELab Lab = {0.0, 0.0, 0.0};
    double amax = 0.0, amin = 0.0, bmax = 0.0, bmin = 0.0;

    // Extract data from fuzz input
    Intent = *reinterpret_cast<const cmsUInt32Number*>(data);
    UsedDirection = *reinterpret_cast<const cmsUInt32Number*>(data + sizeof(cmsUInt32Number));
    nMax = *reinterpret_cast<const cmsUInt32Number*>(data + 2 * sizeof(cmsUInt32Number));
    AdaptationState = *reinterpret_cast<const cmsFloat64Number*>(data + 3 * sizeof(cmsUInt32Number));
    safe_copy(&Lab, data + 3 * sizeof(cmsUInt32Number) + sizeof(cmsFloat64Number), sizeof(cmsCIELab));
    amax = *reinterpret_cast<const double*>(data + 3 * sizeof(cmsUInt32Number) + sizeof(cmsFloat64Number) + sizeof(cmsCIELab));
    amin = *reinterpret_cast<const double*>(data + 3 * sizeof(cmsUInt32Number) + sizeof(cmsFloat64Number) + sizeof(cmsCIELab) + sizeof(double));
    bmax = *reinterpret_cast<const double*>(data + 3 * sizeof(cmsUInt32Number) + sizeof(cmsFloat64Number) + sizeof(cmsCIELab) + 2 * sizeof(double));
    bmin = *reinterpret_cast<const double*>(data + 3 * sizeof(cmsUInt32Number) + sizeof(cmsFloat64Number) + sizeof(cmsCIELab) + 3 * sizeof(double));

    // Allocate memory for Codes and Descriptions
    Codes = safe_malloc<cmsUInt32Number>(nMax * sizeof(cmsUInt32Number));
    Descriptions = safe_malloc<char*>(nMax * sizeof(char*));

    // Call cmsIsIntentSupported
    cmsBool isSupported = cmsIsIntentSupported(hProfile, Intent, UsedDirection);
    if (isSupported) {
        // Handle supported intent
    }

    // Call cmsGetSupportedIntentsTHR
    cmsUInt32Number nIntents = cmsGetSupportedIntentsTHR(nullptr, nMax, Codes, Descriptions);
    if (nIntents > nMax) {
        fprintf(stderr, "More intents supported than expected\n");
    }

    // Call cmsSetAdaptationStateTHR
    cmsFloat64Number prevAdaptationState = cmsSetAdaptationStateTHR(nullptr, AdaptationState);
    if (prevAdaptationState < 0.0) {
        fprintf(stderr, "Previous adaptation state was invalid\n");
    }

    // Call cmsDesaturateLab
    cmsBool desaturated = cmsDesaturateLab(&Lab, amax, amin, bmax, bmin);
    if (!desaturated) {
        fprintf(stderr, "Desaturation failed\n");
    }

    // Call cmsGetSupportedIntents
    cmsUInt32Number nIntents2 = cmsGetSupportedIntents(nMax, Codes, Descriptions);
    if (nIntents2 > nMax) {
        fprintf(stderr, "More intents supported than expected\n");
    }

    // Free allocated memory
    safe_free(Codes);
    safe_free(Descriptions);

    return 0;
}
