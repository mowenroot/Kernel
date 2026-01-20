#include <zlib.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert fuzz input to an integer
int safe_int_from_data(const uint8_t *data, size_t size, size_t index) {
    if (index >= size) return 0;
    return static_cast<int>(data[index]);
}

// Function to safely convert fuzz input to a z_off_t
z_off_t safe_z_off_t_from_data(const uint8_t *data, size_t size, size_t index) {
    if (index >= size) return 0;
    return static_cast<z_off_t>(data[index]);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 10) return 0;

    // Open a gzFile for writing
    gzFile file = gzopen("output_file", "wb");
    if (!file) return 0;

    // Initialize variables
    int level = safe_int_from_data(data, size, 0);
    int strategy = safe_int_from_data(data, size, 1);
    z_off_t offset = safe_z_off_t_from_data(data, size, 2);
    int whence = safe_int_from_data(data, size, 3);

    // Call gzsetparams
    int setparams_result = gzsetparams(file, level, strategy);
    if (setparams_result != Z_OK) {
        gzclose(file);
        return 0;
    }

    // Call gzseek
    z_off_t seek_result = gzseek(file, offset, whence);
    if (seek_result == -1) {
        gzclose(file);
        return 0;
    }

    // Call gztell
    z_off_t tell_result = gztell(file);
    if (tell_result == -1) {
        gzclose(file);
        return 0;
    }

    // Call gzoffset
    z_off_t offset_result = gzoffset(file);
    if (offset_result == -1) {
        gzclose(file);
        return 0;
    }

    // Close the file before rewinding
    gzclose(file);

    // Open the file for reading
    file = gzopen("output_file", "rb");
    if (!file) return 0;

    // Call gzrewind
    int rewind_result = gzrewind(file);
    if (rewind_result != 0) {
        gzclose(file);
        return 0;
    }

    // Call gzerror
    int errnum = 0;
    const char *error_msg = gzerror(file, &errnum);
    if (errnum != Z_OK) {
        gzclose(file);
        return 0;
    }

    // Close the file
    gzclose(file);

    return 0;
}
