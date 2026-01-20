#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely copy a string from fuzz input
const char* SafeStringCopy(const uint8_t* data, size_t size, size_t& offset, size_t max_len) {
    if (offset + max_len > size) {
        return nullptr;
    }
    char* str = (char*)malloc(max_len + 1);
    if (!str) {
        return nullptr;
    }
    memcpy(str, data + offset, max_len);
    str[max_len] = '\0';
    offset += max_len;
    return str;
}

// Function to safely get an integer from fuzz input
int SafeGetInt(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(int) > size) {
        return 0;
    }
    int value = *(int*)(data + offset);
    offset += sizeof(int);
    return value;
}

// Function to safely get a double from fuzz input
double SafeGetDouble(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(double) > size) {
        return 0.0;
    }
    double value = *(double*)(data + offset);
    offset += sizeof(double);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsContext context = cmsCreateContext(nullptr, nullptr);
    if (!context) {
        return 0;
    }

    // Load IT8 data from memory
    cmsHANDLE hIT8 = cmsIT8LoadFromMem(context, data, size);
    if (!hIT8) {
        cmsDeleteContext(context);
        return 0;
    }

    // Set data format
    const char* sampleFormat = SafeStringCopy(data, size, offset, 64); // Assuming max format length is 64
    if (sampleFormat) {
        int index = SafeGetInt(data, size, offset);
        cmsIT8SetDataFormat(hIT8, index, sampleFormat);
        free((void*)sampleFormat);
    }

    // Create and smooth a tone curve
    cmsToneCurve* toneCurve = cmsBuildTabulatedToneCurve16(context, 256, nullptr);
    if (toneCurve) {
        double lambda = SafeGetDouble(data, size, offset);
        cmsSmoothToneCurve(toneCurve, lambda);
        cmsIsToneCurveMonotonic(toneCurve);
        cmsFreeToneCurve(toneCurve);
    }

    // Save IT8 data to memory
    cmsUInt32Number bytesNeeded = 0;
    cmsIT8SaveToMem(hIT8, nullptr, &bytesNeeded);
    if (bytesNeeded > 0) {
        std::unique_ptr<uint8_t[]> buffer(new uint8_t[bytesNeeded]);
        cmsIT8SaveToMem(hIT8, buffer.get(), &bytesNeeded);
    }

    // Clean up
    cmsIT8Free(hIT8);
    cmsDeleteContext(context);

    return 0;
}
