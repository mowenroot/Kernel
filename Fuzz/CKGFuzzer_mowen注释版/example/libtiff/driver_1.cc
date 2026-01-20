#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a TIFF stream in memory
TIFF* createTIFFStream(const uint8_t* data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    // Create a TIFF stream in memory
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Function to initialize TIFFCIELabToRGB structure
int initializeCIELabToRGB(TIFFCIELabToRGB* cielab, const TIFFDisplay* display, float* refWhite) {
    if (TIFFCIELabToRGBInit(cielab, display, refWhite) != 0) {
        return -1;
    }
    return 0;
}

// Function to read raw tile data from TIFF
int readRawTileData(TIFF* tif, uint32 tile, void* buf, tmsize_t size) {
    tmsize_t bytesRead = TIFFReadRawTile(tif, tile, buf, size);
    if (bytesRead == (tmsize_t)(-1)) {
        return -1;
    }
    return 0;
}

// Function to convert CIE L*a*b* to XYZ
void convertCIELabToXYZ(TIFFCIELabToRGB* cielab, uint32 l, int32 a, int32 b, float* X, float* Y, float* Z) {
    TIFFCIELabToXYZ(cielab, l, a, b, X, Y, Z);
}

// Function to access TIFF tag methods
TIFFTagMethods* accessTagMethods(TIFF* tif) {
    return TIFFAccessTagMethods(tif);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(TIFFDisplay) + 3 * sizeof(float) + sizeof(uint32) + sizeof(int32) + sizeof(int32)) {
        return 0;
    }

    // Create a TIFF stream in memory from the fuzz input
    TIFF* tif = createTIFFStream(data, size);
    if (!tif) {
        return 0;
    }

    // Initialize TIFFCIELabToRGB structure
    TIFFCIELabToRGB cielab;
    TIFFDisplay display;
    float refWhite[3];

    // Extract necessary data from fuzz input
    memcpy(&display, data + sizeof(TIFFDisplay), sizeof(TIFFDisplay));
    memcpy(refWhite, data + sizeof(TIFFDisplay) + sizeof(TIFFDisplay), 3 * sizeof(float));

    if (initializeCIELabToRGB(&cielab, &display, refWhite) != 0) {
        TIFFClose(tif);
        return 0;
    }

    // Read raw tile data
    uint32 tile = *(uint32*)(data + sizeof(TIFFDisplay) + sizeof(TIFFDisplay) + 3 * sizeof(float));
    int32 a = *(int32*)(data + sizeof(TIFFDisplay) + sizeof(TIFFDisplay) + 3 * sizeof(float) + sizeof(uint32));
    int32 b = *(int32*)(data + sizeof(TIFFDisplay) + sizeof(TIFFDisplay) + 3 * sizeof(float) + sizeof(uint32) + sizeof(int32));

    void* buf = malloc(size);
    if (!buf) {
        TIFFClose(tif);
        return 0;
    }

    if (readRawTileData(tif, tile, buf, size) != 0) {
        free(buf);
        TIFFClose(tif);
        return 0;
    }

    // Convert CIE L*a*b* to XYZ
    float X, Y, Z;
    convertCIELabToXYZ(&cielab, tile, a, b, &X, &Y, &Z);

    // Access TIFF tag methods
    TIFFTagMethods* tagMethods = accessTagMethods(tif);
    if (!tagMethods) {
        free(buf);
        TIFFClose(tif);
        return 0;
    }

    // Flush data to ensure consistency
    if (TIFFFlushData(tif) != 1) {
        free(buf);
        TIFFClose(tif);
        return 0;
    }

    // Clean up
    free(buf);
    TIFFClose(tif);

    return 0;
}
