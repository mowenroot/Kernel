#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely copy data from fuzz input to a buffer
void safe_copy(void* dest, const uint8_t* src, size_t size) {
    if (size > 0) {
        memcpy(dest, src, size);
    }
}

// Function to safely allocate and copy data from fuzz input to a buffer
template <typename T>
T* safe_alloc_and_copy(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    T* buffer = static_cast<T*>(malloc(size));
    if (buffer) {
        safe_copy(buffer, data, size);
    }
    return buffer;
}

// Function to safely free allocated memory
template <typename T>
void safe_free(T* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Function to safely create a tone curve from fuzz input
cmsToneCurve* create_tone_curve(cmsContext ContextID, const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    cmsToneCurve* curve = cmsBuildTabulatedToneCurve16(ContextID, size / sizeof(cmsUInt16Number), reinterpret_cast<const cmsUInt16Number*>(data));
    return curve;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cmsContext ContextID = cmsCreateContext(nullptr, nullptr);
    if (!ContextID) return 0;

    // Ensure size is sufficient for all operations
    if (size < 1024) return 0;

    // Create a tone curve from the fuzz input
    cmsToneCurve* tone_curves[3] = {
        create_tone_curve(ContextID, data, size / 3),
        create_tone_curve(ContextID, data + (size / 3), size / 3),
        create_tone_curve(ContextID, data + (2 * size / 3), size / 3)
    };

    // Create a linearization device link profile
    cmsHPROFILE linearization_profile = cmsCreateLinearizationDeviceLinkTHR(ContextID, cmsSigRgbData, tone_curves);
    if (!linearization_profile) {
        for (auto& curve : tone_curves) {
            if (curve) cmsFreeToneCurve(curve);
        }
        cmsDeleteContext(ContextID);
        return 0;
    }

    // Create an ink limiting device link profile
    cmsHPROFILE ink_limiting_profile = cmsCreateInkLimitingDeviceLinkTHR(ContextID, cmsSigCmykData, *reinterpret_cast<const cmsFloat64Number*>(data));
    if (!ink_limiting_profile) {
        cmsCloseProfile(linearization_profile);
        for (auto& curve : tone_curves) {
            if (curve) cmsFreeToneCurve(curve);
        }
        cmsDeleteContext(ContextID);
        return 0;
    }

    // Create a Lab 4 profile
    cmsHPROFILE lab_profile = cmsCreateLab4ProfileTHR(ContextID, nullptr);
    if (!lab_profile) {
        cmsCloseProfile(linearization_profile);
        cmsCloseProfile(ink_limiting_profile);
        for (auto& curve : tone_curves) {
            if (curve) cmsFreeToneCurve(curve);
        }
        cmsDeleteContext(ContextID);
        return 0;
    }

    // Create a multi-profile transform
    cmsHPROFILE profiles[] = {linearization_profile, ink_limiting_profile, lab_profile};
    cmsHTRANSFORM transform = cmsCreateMultiprofileTransformTHR(ContextID, profiles, 3, TYPE_RGB_8, TYPE_CMYK_8, INTENT_PERCEPTUAL, 0);
    if (!transform) {
        cmsCloseProfile(linearization_profile);
        cmsCloseProfile(ink_limiting_profile);
        cmsCloseProfile(lab_profile);
        for (auto& curve : tone_curves) {
            if (curve) cmsFreeToneCurve(curve);
        }
        cmsDeleteContext(ContextID);
        return 0;
    }

    // Get profile info
    wchar_t info_buffer[256];
    cmsGetProfileInfo(linearization_profile, cmsInfoDescription, "en", "US", info_buffer, sizeof(info_buffer) / sizeof(wchar_t));

    // Clean up
    cmsDeleteTransform(transform);
    cmsCloseProfile(linearization_profile);
    cmsCloseProfile(ink_limiting_profile);
    cmsCloseProfile(lab_profile);
    for (auto& curve : tone_curves) {
        if (curve) cmsFreeToneCurve(curve);
    }
    cmsDeleteContext(ContextID);

    return 0;
}
