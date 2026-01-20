#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Define the cmsIOHANDLER structure
typedef struct _cms_io_handler {
    uint8_t* data;
    size_t size;
    size_t pos;

    // Function pointers for IO handler methods
    cmsBool (*Seek)(struct _cms_io_handler* io, cmsUInt32Number offset);
    cmsUInt32Number (*Read)(struct _cms_io_handler* io, void* buffer, cmsUInt32Number size, cmsUInt32Number count);
    cmsUInt32Number (*Write)(struct _cms_io_handler* io, const void* buffer, cmsUInt32Number size, cmsUInt32Number count);
    cmsBool (*Close)(struct _cms_io_handler* io);
} cmsIOHANDLER;

// Function to create a cmsIOHANDLER from the fuzzer input data
cmsIOHANDLER* createIOHandlerFromData(const uint8_t* data, size_t size) {
    cmsIOHANDLER* io = (cmsIOHANDLER*)malloc(sizeof(cmsIOHANDLER));
    if (!io) return nullptr;

    // Initialize the IO handler with the fuzzer input data
    io->data = (uint8_t*)malloc(size);
    if (!io->data) {
        free(io);
        return nullptr;
    }
    memcpy(io->data, data, size);
    io->size = size;
    io->pos = 0;

    // Mock implementation of IO handler methods
    io->Seek = [](cmsIOHANDLER* io, cmsUInt32Number offset) -> cmsBool {
        if (offset >= io->size) return FALSE;
        io->pos = offset;
        return TRUE;
    };

    io->Read = [](cmsIOHANDLER* io, void* buffer, cmsUInt32Number size, cmsUInt32Number count) -> cmsUInt32Number {
        if (io->pos + size * count > io->size) return 0;
        memcpy(buffer, io->data + io->pos, size * count);
        io->pos += size * count;
        return count;
    };

    io->Write = [](cmsIOHANDLER* io, const void* buffer, cmsUInt32Number size, cmsUInt32Number count) -> cmsUInt32Number {
        if (io->pos + size * count > io->size) return 0;
        memcpy(io->data + io->pos, buffer, size * count);
        io->pos += size * count;
        return count;
    };

    io->Close = [](cmsIOHANDLER* io) -> cmsBool {
        free(io->data);
        free(io);
        return TRUE;
    };

    return io;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024 * 1024) return 0;

    // Create an IO handler from the fuzzer input data
    cmsIOHANDLER* io = createIOHandlerFromData(data, size);
    if (!io) return 0;

    // Initialize a context for thread-safe operations
    cmsContext contextID = cmsCreateContext(nullptr, nullptr);
    if (!contextID) {
        io->Close(io);
        return 0;
    }

    // Open a profile from the IO handler
    cmsHPROFILE hProfile = cmsOpenProfileFromIOhandlerTHR(contextID, io);
    if (!hProfile) {
        io->Close(io);
        cmsDeleteContext(contextID);
        return 0;
    }

    // Save the profile to the IO handler
    cmsUInt32Number usedSpace = cmsSaveProfileToIOhandler(hProfile, io);
    if (usedSpace == 0) {
        cmsCloseProfile(hProfile);
        io->Close(io);
        cmsDeleteContext(contextID);
        return 0;
    }

    // Read a tag from the profile
    cmsTagSignature tagSig = (cmsTagSignature)0x58595A20; // Example tag signature
    void* tagData = cmsReadTag(hProfile, tagSig);
    if (!tagData) {
        cmsCloseProfile(hProfile);
        io->Close(io);
        cmsDeleteContext(contextID);
        return 0;
    }

    // Write a tag to the profile
    cmsBool writeResult = cmsWriteTag(hProfile, tagSig, tagData);
    if (!writeResult) {
        cmsCloseProfile(hProfile);
        io->Close(io);
        cmsDeleteContext(contextID);
        return 0;
    }

    // Close the profile and IO handler
    cmsCloseProfile(hProfile);
    io->Close(io);
    cmsDeleteContext(contextID);

    return 0;
}
