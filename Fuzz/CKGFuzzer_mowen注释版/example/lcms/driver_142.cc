#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to check if the input size is sufficient for the required operations
bool isInputSizeValid(size_t size, size_t requiredSize) {
    return size >= requiredSize;
}

// Function to safely copy data from the fuzz input to a buffer
void safeCopy(void* dest, const uint8_t* src, size_t size) {
    if (dest && src && size > 0) {
        memcpy(dest, src, size);
    }
}

// Function to safely convert a uint8_t array to a cmsUInt16Number array
void convertToUInt16Array(cmsUInt16Number* dest, const uint8_t* src, size_t size) {
    if (dest && src && size >= 6) {
        for (size_t i = 0; i < 3; ++i) {
            dest[i] = (src[i * 2] << 8) | src[i * 2 + 1];
        }
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for the operations
    if (!isInputSizeValid(size, 6)) {
        return 0;
    }

    // Allocate memory for the required structures
    cmsCIELab* lab = (cmsCIELab*)malloc(sizeof(cmsCIELab));
    cmsCIELab* lab2 = (cmsCIELab*)malloc(sizeof(cmsCIELab));
    cmsCIELCh* lch = (cmsCIELCh*)malloc(sizeof(cmsCIELCh));
    cmsCIEXYZ* xyz = (cmsCIEXYZ*)malloc(sizeof(cmsCIEXYZ));
    cmsUInt16Number* wLab = (cmsUInt16Number*)malloc(3 * sizeof(cmsUInt16Number));

    // Initialize the structures to avoid undefined behavior
    memset(lab, 0, sizeof(cmsCIELab));
    memset(lab2, 0, sizeof(cmsCIELab));
    memset(lch, 0, sizeof(cmsCIELCh));
    memset(xyz, 0, sizeof(cmsCIEXYZ));
    memset(wLab, 0, 3 * sizeof(cmsUInt16Number));

    // Convert the fuzz input to a cmsUInt16Number array
    convertToUInt16Array(wLab, data, size);

    // Call the API functions
    cmsLabEncoded2FloatV2(lab, wLab);
    cmsLab2XYZ(cmsD50_XYZ(), xyz, lab);
    cmsLab2LCh(lch, lab);
    cmsLCh2Lab(lab2, lch);
    cmsLabEncoded2Float(lab, wLab);
    cmsFloat2LabEncoded(wLab, lab);

    // Free allocated memory
    free(lab);
    free(lab2);
    free(lch);
    free(xyz);
    free(wLab);

    return 0;
}
