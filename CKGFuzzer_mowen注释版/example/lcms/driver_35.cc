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

// Function to safely convert fuzz input to a cmsTagSignature
cmsTagSignature safe_tag_signature(const uint8_t* data, size_t size) {
    cmsTagSignature sig = cmsTagSignature(0); // Corrected initialization
    if (size >= sizeof(cmsTagSignature)) {
        memcpy(&sig, data, sizeof(cmsTagSignature));
    }
    return sig;
}

// Function to safely convert fuzz input to a cmsUInt32Number
cmsUInt32Number safe_uint32(const uint8_t* data, size_t size) {
    cmsUInt32Number value = 0;
    if (size >= sizeof(cmsUInt32Number)) {
        memcpy(&value, data, sizeof(cmsUInt32Number));
    }
    return value;
}

// Function to safely convert fuzz input to a cmsCIELab
void safe_cielab(cmsCIELab* lab, const uint8_t* data, size_t size) {
    if (size >= 3 * sizeof(cmsUInt16Number)) {
        cmsUInt16Number wLab[3];
        memcpy(wLab, data, 3 * sizeof(cmsUInt16Number));
        cmsLabEncoded2FloatV2(lab, wLab);
    }
}

// Function to safely convert fuzz input to a cmsCIEXYZ
void safe_ciexyz(cmsCIEXYZ* xyz, const uint8_t* data, size_t size) {
    if (size >= 3 * sizeof(cmsFloat64Number)) {
        memcpy(xyz, data, 3 * sizeof(cmsFloat64Number));
    }
}

// Function to safely convert fuzz input to a cmsInfoType
cmsInfoType safe_info_type(const uint8_t* data, size_t size) {
    cmsInfoType info = cmsInfoDescription;
    if (size >= sizeof(cmsInfoType)) {
        memcpy(&info, data, sizeof(cmsInfoType));
    }
    return info;
}

// Function to safely convert fuzz input to a language and country code
void safe_lang_country(char* lang, char* country, const uint8_t* data, size_t size) {
    if (size >= 6) {
        memcpy(lang, data, 3);
        memcpy(country, data + 3, 3);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 100) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) return 0;

    std::unique_ptr<cmsCIELab> lab(new cmsCIELab);
    std::unique_ptr<cmsCIEXYZ> blackPoint(new cmsCIEXYZ);
    std::unique_ptr<wchar_t[]> buffer(new wchar_t[128]);
    char lang[4] = {0};
    char country[4] = {0};

    // Extract data from fuzz input
    cmsTagSignature tagSig = safe_tag_signature(data, size);
    cmsUInt32Number intent = safe_uint32(data + 4, size - 4);
    cmsUInt32Number flags = safe_uint32(data + 8, size - 8);
    safe_cielab(lab.get(), data + 12, size - 12);
    safe_ciexyz(blackPoint.get(), data + 24, size - 24);
    cmsInfoType infoType = safe_info_type(data + 48, size - 48);
    safe_lang_country(lang, country, data + 52, size - 52);

    // Call cmsWriteTag
    if (!cmsWriteTag(hProfile, tagSig, lab.get())) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Call cmsIsMatrixShaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);

    // Call cmsDetectBlackPoint
    if (!cmsDetectBlackPoint(blackPoint.get(), hProfile, intent, flags)) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Call cmsGetProfileInfo
    cmsUInt32Number infoSize = cmsGetProfileInfo(hProfile, infoType, lang, country, buffer.get(), 128);
    if (infoSize == 0) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Clean up
    cmsCloseProfile(hProfile);
    return 0;
}
