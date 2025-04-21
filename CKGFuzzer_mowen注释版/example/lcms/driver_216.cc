#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy data from the fuzz input to a buffer
void safe_copy(void* dest, const uint8_t* src, size_t size) {
    if (size > 0) {
        memcpy(dest, src, size);
    }
}

// Function to safely convert fuzz input to a 16-bit integer
cmsUInt16Number safe_convert_to_uint16(const uint8_t* data, size_t index) {
    if (index + 1 < sizeof(data)) {
        return (data[index] << 8) | data[index + 1];
    }
    return 0;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for the operations
    if (size < 18) {
        return 0;
    }

    // Allocate memory for the structures
    cmsCIELab* lab = (cmsCIELab*)malloc(sizeof(cmsCIELab));
    cmsCIEXYZ* xyz = (cmsCIEXYZ*)malloc(sizeof(cmsCIEXYZ));
    cmsUInt16Number wLab[3];
    cmsUInt16Number wXYZ[3];

    // Initialize the structures
    memset(lab, 0, sizeof(cmsCIELab));
    memset(xyz, 0, sizeof(cmsCIEXYZ));
    memset(wLab, 0, sizeof(wLab));
    memset(wXYZ, 0, sizeof(wXYZ));

    // Extract data from fuzz input
    safe_copy(wLab, data, 6);
    safe_copy(wXYZ, data + 6, 6);

    // Convert encoded Lab values to floating-point format
    cmsLabEncoded2FloatV2(lab, wLab);

    // Convert encoded XYZ values to floating-point format
    cmsXYZEncoded2Float(xyz, wXYZ);

    // Convert floating-point XYZ to encoded format
    cmsFloat2XYZEncoded(wXYZ, xyz);

    // Convert floating-point Lab to encoded format
    cmsFloat2LabEncoded(wLab, lab);

    // Convert encoded Lab values to floating-point format
    cmsLabEncoded2Float(lab, wLab);

    // Convert floating-point Lab to encoded format using V2
    cmsFloat2LabEncodedV2(wLab, lab);

    // Free allocated memory
    free(lab);
    free(xyz);

    return 0;
}
