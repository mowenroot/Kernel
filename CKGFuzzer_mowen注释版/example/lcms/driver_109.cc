#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <iostream>

// Function to create a dummy ICC profile handle for fuzzing purposes
cmsHPROFILE CreateDummyProfile(const uint8_t* data, size_t size) {
    // Ensure the size is at least the size of a cmsHPROFILE structure
    if (size < sizeof(cmsHPROFILE)) {
        return nullptr;
    }

    // Allocate memory for the dummy profile
    cmsHPROFILE dummyProfile = (cmsHPROFILE)malloc(sizeof(cmsHPROFILE));
    if (!dummyProfile) {
        return nullptr;
    }

    // Initialize the dummy profile with the provided data
    memcpy(dummyProfile, data, sizeof(cmsHPROFILE));

    // Return the dummy profile handle
    return dummyProfile;
}

// Function to free the dummy profile handle
void FreeDummyProfile(cmsHPROFILE hProfile) {
    if (hProfile) {
        free(hProfile);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create a dummy ICC profile handle
    cmsHPROFILE hProfile = CreateDummyProfile(data, size);
    if (!hProfile) {
        return 0; // Return early if profile creation fails
    }

    // Variables to store API results
    cmsUInt32Number model;
    cmsUInt32Number flags;
    struct tm creationDateTime;
    cmsUInt64Number attributes;
    cmsUInt32Number manufacturer;
    cmsUInt8Number profileID[16];

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
    if (attributes == 0) {
        std::cerr << "cmsGetHeaderAttributes failed" << std::endl;
    }

    manufacturer = cmsGetHeaderManufacturer(hProfile);
    if (manufacturer == 0) {
        std::cerr << "cmsGetHeaderManufacturer failed" << std::endl;
    }

    cmsGetHeaderProfileID(hProfile, profileID);
    for (int i = 0; i < 16; ++i) {
        if (profileID[i] != 0) {
            break;
        }
        if (i == 15) {
            std::cerr << "cmsGetHeaderProfileID failed" << std::endl;
        }
    }

    // Free the dummy profile handle
    FreeDummyProfile(hProfile);

    return 0; // Non-zero return values are reserved for future use.
}
