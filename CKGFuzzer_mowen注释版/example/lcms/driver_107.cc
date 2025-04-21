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
        exit(1);
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
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (memcpy(dest, src, n) == nullptr) {
        fprintf(stderr, "Memory copy failed\n");
        exit(1);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < sizeof(cmsUInt32Number) * 5) {
        return 0;
    }

    // Initialize variables
    cmsContext context = cmsCreateContext(nullptr, nullptr);
    if (!context) {
        return 0;
    }

    // Extract inputs from fuzz data
    cmsUInt32Number nMax = *reinterpret_cast<const cmsUInt32Number*>(data);
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);

    cmsUInt32Number* codes = safe_malloc<cmsUInt32Number>(nMax * sizeof(cmsUInt32Number));
    char** descriptions = safe_malloc<char*>(nMax * sizeof(char*));

    // Call cmsGetSupportedIntentsTHR
    cmsUInt32Number intentsCount = cmsGetSupportedIntentsTHR(context, nMax, codes, descriptions);
    if (intentsCount == 0) {
        safe_free(codes);
        safe_free(descriptions);
        cmsDeleteContext(context);
        return 0;
    }

    // Call cmsGetHeaderAttributes
    cmsHPROFILE profile = cmsCreateProfilePlaceholder(context);
    if (!profile) {
        safe_free(codes);
        safe_free(descriptions);
        cmsDeleteContext(context);
        return 0;
    }

    cmsUInt64Number flags;
    cmsGetHeaderAttributes(profile, &flags);

    // Call cmsIsMatrixShaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(profile);

    // Call cmsDesaturateLab
    cmsCIELab lab;
    lab.L = *reinterpret_cast<const double*>(data);
    data += sizeof(double);
    size -= sizeof(double);
    lab.a = *reinterpret_cast<const double*>(data);
    data += sizeof(double);
    size -= sizeof(double);
    lab.b = *reinterpret_cast<const double*>(data);
    data += sizeof(double);
    size -= sizeof(double);

    double amax = *reinterpret_cast<const double*>(data);
    data += sizeof(double);
    size -= sizeof(double);
    double amin = *reinterpret_cast<const double*>(data);
    data += sizeof(double);
    size -= sizeof(double);
    double bmax = *reinterpret_cast<const double*>(data);
    data += sizeof(double);
    size -= sizeof(double);
    double bmin = *reinterpret_cast<const double*>(data);
    data += sizeof(double);
    size -= sizeof(double);

    cmsBool desaturated = cmsDesaturateLab(&lab, amax, amin, bmax, bmin);

    // Call cmsDetectTAC
    cmsFloat64Number tac = cmsDetectTAC(profile);

    // Clean up
    safe_free(codes);
    safe_free(descriptions);
    cmsCloseProfile(profile);
    cmsDeleteContext(context);

    return 0;
}
