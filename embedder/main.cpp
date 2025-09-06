#include "main.h"
#include <iostream>
#include <vector>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <input_image.png> <file_to_hide>\n";
        return 1;
    }

    std::string inputImage = argv[1];
    std::string exeToHide = argv[2];
    std::string outputImage = "encoded.png";

    std::vector<unsigned char> image;
    unsigned width, height;

    // Decode PNG
    unsigned error = lodepng::decode(image, width, height, inputImage);
    if (error) {
        std::cerr << "PNG decode error " << error << ": " << lodepng_error_text(error) << "\n";
        return 1;
    }

    auto dataBits = fileToBits(exeToHide);
    try {
        embedBits(image, dataBits);
    }
    catch (const std::exception& e) {
        std::cerr << "Embed error: " << e.what() << "\n";
        return 1;
    }

    // Encode new image
    error = lodepng::encode(outputImage, image, width, height);
    if (error) {
        std::cerr << "PNG encode error " << error << ": " << lodepng_error_text(error) << "\n";
        return 1;
    }

    std::cout << "File successfully encoded into " << outputImage << "\n";
    return 0;
}
