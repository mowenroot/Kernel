#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <iostream>

// Function to create a dummy ICC profile handle for fuzzing purposes
cmsHPROFILE CreateDummyProfile(const uint8_t* data, size_t size) {
    // Allocate memory for the dummy profile
    cmsHPROFILE dummyProfile = (cmsHPROFILE)malloc(sizeof(cmsHPROFILE));
    if (!dummyProfile) {
        return nullptr;
    }

    // Initialize the dummy profile with data from the fuzzer input
    // Ensure we do not overflow the buffer
    size_t copySize = size < sizeof(cmsHPROFILE) ? size : sizeof(cmsHPROFILE);
    memcpy(dummyProfile, data, copySize);

    // Return the dummy profile handle
    return dummyProfile;
}

// Function to free the dummy profile handle
void FreeDummyProfile(cmsHPROFILE hProfile) {
    if (hProfile) {
        free(hProfile);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create a dummy ICC profile handle
    cmsHPROFILE hProfile = CreateDummyProfile(data, size);
    if (!hProfile) {
        return 0; // Early exit if profile creation fails
    }

    // Variables to store API results
    cmsUInt32Number model, flags, manufacturer;
    cmsFloat64Number version;
    struct tm creationDateTime;
    cmsUInt64Number attributes;

    // Call each API function and handle errors
    model = cmsGetHeaderModel(hProfile);
    if (model == 0) {
        std::cerr << "cmsGetHeaderModel failed" << std::endl;
    }

    flags = cmsGetHeaderFlags(hProfile);
    if (flags == 0) {
        std::cerr << "cmsGetHeaderFlags failed" << std::endl;
    }

    if (!cmsGetHeaderCreationDateTime(hProfile, &creationDateTime)) {
        std::cerr << "cmsGetHeaderCreationDateTime failed" << std::endl;
    }

    cmsGetHeaderAttributes(hProfile, &attributes);
    // No error handling needed for cmsGetHeaderAttributes as it does not return a value

    version = cmsGetProfileVersion(hProfile);
    if (version == 0.0) {
        std::cerr << "cmsGetProfileVersion failed" << std::endl;
    }

    manufacturer = cmsGetHeaderManufacturer(hProfile);
    if (manufacturer == 0) {
        std::cerr << "cmsGetHeaderManufacturer failed" << std::endl;
    }

    // Free the dummy profile handle
    FreeDummyProfile(hProfile);

    return 0; // Return 0 to indicate success
}
