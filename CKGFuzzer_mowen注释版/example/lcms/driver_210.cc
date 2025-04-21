#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely allocate memory and initialize it
template <typename T>
T* safe_malloc(size_t size) {
    T* ptr = (T*)malloc(size);
    if (ptr) {
        memset(ptr, 0, size);
    }
    return ptr;
}

// Function to safely free memory
template <typename T>
void safe_free(T*& ptr) {
    if (ptr) {
        free(ptr);
        ptr = nullptr;
    }
}

// Function to safely copy data from fuzz input
void safe_copy(void* dest, const uint8_t* src, size_t size) {
    if (dest && src && size > 0) {
        memcpy(dest, src, size);
    }
}

// Function to safely create a profile
cmsHPROFILE safe_create_profile(const uint8_t* data, size_t size) {
    if (size < sizeof(cmsCIExyY)) {
        return nullptr;
    }
    cmsCIExyY whitePoint;
    safe_copy(&whitePoint, data, sizeof(cmsCIExyY));
    return cmsCreateRGBProfile(&whitePoint, nullptr, nullptr);
}

// Function to safely create a transform
cmsHTRANSFORM safe_create_transform(cmsHPROFILE inputProfile, cmsHPROFILE outputProfile, const uint8_t* data, size_t size) {
    if (size < sizeof(cmsUInt32Number)) {
        return nullptr;
    }
    cmsUInt32Number intent = *((cmsUInt32Number*)data);
    return cmsCreateTransform(inputProfile, TYPE_RGB_8, outputProfile, TYPE_RGB_8, intent, 0);
}

// Function to safely read a tag
void* safe_read_tag(cmsHPROFILE profile, cmsTagSignature tag, const uint8_t* data, size_t size) {
    if (size < sizeof(cmsTagSignature)) {
        return nullptr;
    }
    return cmsReadTag(profile, tag);
}

// Function to safely write a tag
bool safe_write_tag(cmsHPROFILE profile, cmsTagSignature tag, const uint8_t* data, size_t size) {
    if (size < sizeof(cmsTagSignature)) {
        return false;
    }
    return cmsWriteTag(profile, tag, (void*)data);
}

// Function to safely close a profile
bool safe_close_profile(cmsHPROFILE profile) {
    return cmsCloseProfile(profile);
}

// Function to safely delete a transform
void safe_delete_transform(cmsHTRANSFORM transform) {
    cmsDeleteTransform(transform);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(cmsCIExyY) + sizeof(cmsUInt32Number) + sizeof(cmsTagSignature)) {
        return 0;
    }

    // Create input and output profiles
    cmsHPROFILE inputProfile = safe_create_profile(data, sizeof(cmsCIExyY));
    cmsHPROFILE outputProfile = safe_create_profile(data + sizeof(cmsCIExyY), sizeof(cmsCIExyY));
    if (!inputProfile || !outputProfile) {
        safe_close_profile(inputProfile);
        safe_close_profile(outputProfile);
        return 0;
    }

    // Create a transform
    cmsHTRANSFORM transform = safe_create_transform(inputProfile, outputProfile, data + 2 * sizeof(cmsCIExyY), sizeof(cmsUInt32Number));
    if (!transform) {
        safe_close_profile(inputProfile);
        safe_close_profile(outputProfile);
        return 0;
    }

    // Read a tag from the input profile
    cmsTagSignature tag = *((cmsTagSignature*)(data + 2 * sizeof(cmsCIExyY) + sizeof(cmsUInt32Number)));
    void* tagData = safe_read_tag(inputProfile, tag, data, size);
    if (tagData) {
        // Write the tag to the output profile
        safe_write_tag(outputProfile, tag, (const uint8_t*)tagData, size);
    }

    // Apply the transform
    uint8_t* inputBuffer = safe_malloc<uint8_t>(size);
    uint8_t* outputBuffer = safe_malloc<uint8_t>(size);
    if (inputBuffer && outputBuffer) {
        safe_copy(inputBuffer, data, size);
        cmsDoTransform(transform, inputBuffer, outputBuffer, size);
    }

    // Clean up
    safe_free(inputBuffer);
    safe_free(outputBuffer);
    safe_delete_transform(transform);
    safe_close_profile(inputProfile);
    safe_close_profile(outputProfile);

    return 0;
}
