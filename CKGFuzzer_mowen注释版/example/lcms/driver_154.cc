#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely allocate memory
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

// Function to safely copy data
void safeMemcpy(void* dest, const void* src, size_t n) {
    if (dest && src && n > 0) {
        memcpy(dest, src, n);
    }
}

// Function to safely set memory
void safeMemset(void* s, int c, size_t n) {
    if (s && n > 0) {
        memset(s, c, n);
    }
}

// Function to safely cast data
template <typename T>
T safeCast(const uint8_t* data, size_t size, size_t offset) {
    if (offset + sizeof(T) > size) {
        return 0; // Return a default value if out of bounds
    }
    return *reinterpret_cast<const T*>(data + offset);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure data and size are valid
    if (!data || size == 0) {
        return 0;
    }

    // Initialize variables
    cmsHPROFILE hProfile = nullptr;
    cmsIOHANDLER* ioHandler = nullptr;
    void* memPtr = nullptr;
    cmsUInt32Number bytesNeeded = 0;
    cmsUInt32Number profileSize = 0;
    cmsContext contextID = cmsGetProfileContextID(nullptr);

    // Step 1: Open a profile from memory
    profileSize = safeCast<cmsUInt32Number>(data, size, 0);
    if (profileSize > size - sizeof(cmsUInt32Number)) {
        profileSize = size - sizeof(cmsUInt32Number);
    }
    hProfile = cmsOpenProfileFromMem(data + sizeof(cmsUInt32Number), profileSize);
    if (!hProfile) {
        return 0;
    }

    // Step 2: Save the profile to memory
    if (!cmsSaveProfileToMem(hProfile, nullptr, &bytesNeeded)) {
        cmsCloseProfile(hProfile);
        return 0;
    }
    memPtr = safeMalloc(bytesNeeded);
    if (!cmsSaveProfileToMem(hProfile, memPtr, &bytesNeeded)) {
        safeFree(memPtr);
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Step 3: Open the profile from the saved memory
    cmsHPROFILE hProfileFromMem = cmsOpenProfileFromMemTHR(contextID, memPtr, bytesNeeded);
    if (!hProfileFromMem) {
        safeFree(memPtr);
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Step 4: Save the profile to an IO handler
    ioHandler = cmsOpenIOhandlerFromMem(contextID, memPtr, bytesNeeded, "w");
    if (!ioHandler) {
        safeFree(memPtr);
        cmsCloseProfile(hProfile);
        cmsCloseProfile(hProfileFromMem);
        return 0;
    }
    if (!cmsSaveProfileToIOhandler(hProfile, ioHandler)) {
        cmsCloseIOhandler(ioHandler);
        safeFree(memPtr);
        cmsCloseProfile(hProfile);
        cmsCloseProfile(hProfileFromMem);
        return 0;
    }

    // Step 5: Open the profile from the IO handler
    cmsHPROFILE hProfileFromIOhandler = cmsOpenProfileFromIOhandlerTHR(contextID, ioHandler);
    if (!hProfileFromIOhandler) {
        cmsCloseIOhandler(ioHandler);
        safeFree(memPtr);
        cmsCloseProfile(hProfile);
        cmsCloseProfile(hProfileFromMem);
        return 0;
    }

    // Step 6: Open the profile from the IO handler in write mode
    cmsHPROFILE hProfileFromIOhandler2 = cmsOpenProfileFromIOhandler2THR(contextID, ioHandler, true);
    if (!hProfileFromIOhandler2) {
        cmsCloseIOhandler(ioHandler);
        safeFree(memPtr);
        cmsCloseProfile(hProfile);
        cmsCloseProfile(hProfileFromMem);
        cmsCloseProfile(hProfileFromIOhandler);
        return 0;
    }

    // Clean up
    cmsCloseIOhandler(ioHandler);
    safeFree(memPtr);
    cmsCloseProfile(hProfile);
    cmsCloseProfile(hProfileFromMem);
    cmsCloseProfile(hProfileFromIOhandler);
    cmsCloseProfile(hProfileFromIOhandler2);

    return 0;
}
