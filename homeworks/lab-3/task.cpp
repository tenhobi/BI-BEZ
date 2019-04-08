#include <openssl/evp.h>
#include <iostream>
#include <fstream>

#define KEY_VALUE "Muj klic"
#define IV_VALUE "inicial. vektor"

enum class TASK {
    ENCRYPT,
    DECRYPT,
    NONE
};

enum class MODE {
    ECB,
    CBC,
    NONE
};

enum class METHOD {
    ENCRYPT,
    DECRYPT
};

std::string outputFileName;

std::string removeExtension(const std::string &fileName);

std::string getModeName(MODE mode);

bool isFileBMP(char a, char b);

int process(std::fstream &inputFile, std::fstream &outputFile, MODE mode, METHOD method);

int main(int argc, char *argv[]) {
    // Check number of parameters.
    if (argc != 4) {
        std::cout << "Wrong number of arguments." << std::endl;
        return 1;
    }

    OpenSSL_add_all_ciphers();

    std::string taskData = argv[1];
    std::string modeData = argv[2];
    std::string sourceFile = argv[3];

    TASK task = TASK::NONE;
    MODE mode = MODE::NONE;

    if (taskData == "-e") {
        task = TASK::ENCRYPT;
    } else if (taskData == "-d") {
        task = TASK::DECRYPT;
    }

    if (modeData == getModeName(MODE::ECB)) {
        mode = MODE::ECB;
    } else if (modeData == getModeName(MODE::CBC)) {
        mode = MODE::CBC;
    }

    // Check content of parameters.
    if (task == TASK::NONE || mode == MODE::NONE) {
        std::cout << "Wrong parameters." << std::endl;
        return 2;
    }

    // Read the input file.
    std::fstream inputFile;
    inputFile.open(sourceFile, std::ifstream::in | std::ifstream::binary);
    if (!inputFile.is_open()) {
        std::cout << "Couldn't open the inputFile." << std::endl;
        return 3;
    }

    std::fstream outputFile;

    // process
    if (task == TASK::ENCRYPT) {
        outputFileName = removeExtension(sourceFile) + "_" + getModeName(mode) + ".bmp";
        outputFile.open(outputFileName,
                        std::ifstream::out | std::ifstream::binary);
        if (!outputFile.is_open()) {
            std::cout << "Couldn't open the output inputFile." << std::endl;
            inputFile.close();
            std::remove(outputFileName.c_str());
            return 4;
        }

        if (process(inputFile, outputFile, mode, METHOD::ENCRYPT) < 0) {
            std::cout << "Error while encrypting." << std::endl;
            inputFile.close();
            outputFile.close();
            std::remove(outputFileName.c_str());
            return 5;
        }
    } // decrypt
    else {
        std::fstream outputFile;
        outputFileName = removeExtension(sourceFile) + "_dec.bmp";
        outputFile.open(outputFileName, std::ifstream::out | std::ifstream::binary);
        if (!outputFile.is_open()) {
            std::cout << "Couldn't open the output inputFile." << std::endl;
            inputFile.close();
            std::remove(outputFileName.c_str());
            return 4;
        }

        if (process(inputFile, outputFile, mode, METHOD::DECRYPT) < 0) {
            std::cout << "Error while decrypting." << std::endl;
            inputFile.close();
            outputFile.close();
            std::remove(outputFileName.c_str());
            return 5;
        }
    }

    outputFile.close();
    inputFile.close();
}

std::string removeExtension(const std::string &fileName) {
    auto match = fileName.find(".bmp");
    return fileName.substr(0, match);
}

std::string getModeName(const MODE mode) {
    if (mode == MODE::CBC) {
        return "cbc";
    } else if (mode == MODE::ECB) {
        return "ecb";
    }

    return "error";
}

bool isFileBMP(char a, char b) {
    if (a != 'B' && b != 'M') {
        std::cout << "File is not a BMP." << std::endl;
        return false;
    }

    return true;
}

int process(std::fstream &inputFile, std::fstream &outputFile, MODE mode, METHOD method) {
    int res;

    unsigned char key[EVP_MAX_KEY_LENGTH] = KEY_VALUE;
    unsigned char iv[EVP_MAX_IV_LENGTH] = IV_VALUE;

    // Init cipher.
    const EVP_CIPHER *cipher = mode == MODE::CBC ? EVP_des_cbc() : EVP_des_ecb();
    if (!cipher) {
        std::cout << "Cipher " << getModeName(mode) << " does not exist." << std::endl;
        std::remove(outputFileName.c_str());
        return 1;
    }

    // Init context.
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        std::remove(outputFileName.c_str());
        return 2;
    }
    res = EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv);
    if (res != 1) {
        std::remove(outputFileName.c_str());
        return 3;
    }

    char headerSizeData[4];
    inputFile.seekg(10, std::fstream::beg);
    inputFile.read(headerSizeData, 4);

    long headerLength = 0;
    for (int x = 0; x < 4; x++) {
        headerLength += (unsigned long) headerSizeData[x] << (unsigned long) (8 * x);
    }

    inputFile.seekg(0, std::fstream::end);
    long dataLength = inputFile.tellg() - headerLength;

    // Contains data.
    if (dataLength <= 0) {
        std::cout << "Wrong data." << std::endl;
        std::remove(outputFileName.c_str());
        return 4;
    }

    char *headerData = new char[headerLength];

    inputFile.seekg(0, std::fstream::beg);
    inputFile.read(headerData, headerLength);

    if (!isFileBMP(headerData[0], headerData[1])) {
        std::cout << "Wrong BMP file." << std::endl;
        std::remove(outputFileName.c_str());
        return 4;
    }

    // Write header.
    outputFile.write(headerData, headerLength);

    // Store data.
    inputFile.seekg(headerLength, std::fstream::beg);
    char *data = new char[dataLength];
    inputFile.read(data, dataLength);

    // Prepare output data storage.
    char *outputData = new char[((dataLength + 7) / 8) * 8];
    long outputDataLength = 0;

    int tmpLength = 0;

    res = EVP_CipherInit_ex(ctx, cipher, nullptr, key, iv, method == METHOD::ENCRYPT ? 1 : 0);
    if (res != 1) {
        std::cout << "Error in encryption." << std::endl;
        std::remove(outputFileName.c_str());
        return 5;
    }
    res = EVP_CipherUpdate(ctx, reinterpret_cast<unsigned char *>(outputData), &tmpLength,
                            reinterpret_cast<const unsigned char *>(data), dataLength);
    if (res != 1) {
        std::cout << "Error in encryption." << std::endl;
        std::remove(outputFileName.c_str());
        return 6;
    }
    outputDataLength += tmpLength;
    res = EVP_CipherFinal_ex(ctx, reinterpret_cast<unsigned char *>(outputData + outputDataLength), &tmpLength);
    if (res != 1) {
        std::cout << "Error in encryption." << std::endl;
        std::remove(outputFileName.c_str());
        return 7;
    }
    outputDataLength += tmpLength;

    // Write data.
    outputFile.write(outputData, outputDataLength);

    // Clean up.
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
