#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to create a memory IO handler from the fuzzer input
cmsIOHANDLER* createIOHandlerFromFuzzInput(const uint8_t* data, size_t size) {
    cmsIOHANDLER* io = cmsOpenIOhandlerFromMem(NULL, (void*)data, size, "r");
    if (io == NULL) {
        return nullptr;
    }
    return io;
}

// Function to safely allocate memory for a buffer
void* safeMalloc(size_t size) {
    if (size == 0) return nullptr;
    void* ptr = malloc(size);
    if (ptr == nullptr) {
        // Handle memory allocation failure
        abort();
    }
    return ptr;
}

// Function to safely free allocated memory
void safeFree(void* ptr) {
    if (ptr != nullptr) {
        free(ptr);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(cmsTagSignature) + sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Create a memory IO handler from the fuzzer input
    cmsIOHANDLER* io = createIOHandlerFromFuzzInput(data, size);
    if (io == nullptr) {
        return 0;
    }

    // Open the profile from the IO handler
    cmsHPROFILE hProfile = cmsOpenProfileFromIOhandlerTHR(NULL, io);
    if (hProfile == nullptr) {
        cmsCloseIOhandler(io);
        return 0;
    }

    // Extract tag signature and buffer size from the input data
    cmsTagSignature tagSig = *(cmsTagSignature*)(data + size - sizeof(cmsTagSignature));
    cmsUInt32Number bufferSize = *(cmsUInt32Number*)(data + size - sizeof(cmsTagSignature) - sizeof(cmsUInt32Number));

    // Ensure buffer size is within a reasonable limit
    if (bufferSize > size / 2) {
        bufferSize = size / 2;
    }

    // Allocate memory for the buffer
    void* buffer = safeMalloc(bufferSize);
    if (buffer == nullptr) {
        cmsCloseProfile(hProfile);
        cmsCloseIOhandler(io);
        return 0;
    }

    // Read raw tag data
    cmsUInt32Number readSize = cmsReadRawTag(hProfile, tagSig, buffer, bufferSize);
    if (readSize == 0) {
        safeFree(buffer);
        cmsCloseProfile(hProfile);
        cmsCloseIOhandler(io);
        return 0;
    }

    // Check if the profile supports a specific rendering intent
    cmsBool isCLUTSupported = cmsIsCLUT(hProfile, INTENT_PERCEPTUAL, LCMS_USED_AS_INPUT);

    // Write raw tag data back to the profile
    cmsBool writeSuccess = cmsWriteRawTag(hProfile, tagSig, buffer, readSize);

    // Retrieve profile information
    wchar_t profileInfoBuffer[256];
    cmsUInt32Number infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, "en", "US", profileInfoBuffer, sizeof(profileInfoBuffer) / sizeof(wchar_t));

    // Clean up resources
    safeFree(buffer);
    cmsCloseProfile(hProfile);
    cmsCloseIOhandler(io);

    return 0;
}
