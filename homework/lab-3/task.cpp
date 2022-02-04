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

int process(std::fstream &inputFile, std::string &outputFileName, MODE mode, METHOD method);

std::string removeExtension(const std::string &fileName);

std::string getModeName(MODE mode);

bool isFileBMP(char a, char b);

int main(int argc, char *argv[]) {
    // Check number of parameters.
    if (argc != 4) {
        std::cout << "Error: Wrong number of arguments." << std::endl;
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
        std::cout << "Error: Wrong parameters." << std::endl;
        return 2;
    }

    // Read the input file.
    std::fstream inputFile;
    inputFile.open(sourceFile, std::ifstream::in | std::ifstream::binary);

    if (!inputFile.is_open()) {
        std::cout << "Error: Couldn't open the input file." << std::endl;
        return 3;
    }

    int returnCode = 0;

    // process
    if (task == TASK::ENCRYPT) {
        std::string outputFileName = removeExtension(sourceFile) + "_" + getModeName(mode) + ".bmp";

        if ((returnCode = process(inputFile, outputFileName, mode, METHOD::ENCRYPT)) != 0) {
            std::cout << "Error: Error while encrypting." << std::endl;
            inputFile.close();
            return returnCode;
        }
    } // decrypt
    else {
        std::string outputFileName = removeExtension(sourceFile) + "_dec.bmp";

        if ((returnCode = process(inputFile, outputFileName, mode, METHOD::DECRYPT)) != 0) {
            std::cout << "Error while decrypting." << std::endl;
            inputFile.close();
            return returnCode;
        }
    }

    inputFile.close();
    std::cout << "Success." << std::endl;
}

int process(std::fstream &inputFile, std::string &outputFileName, MODE mode, METHOD method) {
    int res;

    unsigned char key[EVP_MAX_KEY_LENGTH] = KEY_VALUE;
    unsigned char iv[EVP_MAX_IV_LENGTH] = IV_VALUE;

    // Init cipher.
    const EVP_CIPHER *cipher = mode == MODE::CBC ? EVP_des_cbc() : EVP_des_ecb();
    if (!cipher) {
        std::cout << "Error: Cipher " << getModeName(mode) << " does not exist." << std::endl;
        return 4;
    }

    // Init context.
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        return 5;
    }
    res = EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv);
    if (res != 1) {
        return 6;
    }

    // Load file size data.
    long fileSizeDataLength = 4;
    char *fileSizeData = new char[fileSizeDataLength];
    inputFile.seekg(2, std::fstream::beg);
    inputFile.read(fileSizeData, fileSizeDataLength);
    long fileLength = 0;
    for (int x = 0; x < fileSizeDataLength; x++) {
        fileLength += (unsigned long) fileSizeData[x] << (unsigned long) (8 * x);
    }

    // Load header size data.
    char headerSizeData[4];
    inputFile.seekg(10, std::fstream::beg);
    inputFile.read(headerSizeData, 4);
    long headerLength = 0;
    for (int x = 0; x < 4; x++) {
        headerLength += (unsigned long) headerSizeData[x] << (unsigned long) (8 * x);
    }

    // Compute data length.
    inputFile.seekg(0, std::fstream::end);
    long dataLength = inputFile.tellg() - headerLength;

    // Check if data exists.
    if (dataLength <= 0) {
        std::cout << "Error: wrong data length." << std::endl;
        return 7;
    }

    // Check if the data length is ok.
    if (dataLength + headerLength != fileLength) {
        std::cout << "Error: wrong file length" << std::endl;
        return 8;
    }

    // Check for BMP file format.
    char *headerData = new char[headerLength];
    inputFile.seekg(0, std::fstream::beg);
    inputFile.read(headerData, headerLength);
    if (!isFileBMP(headerData[0], headerData[1])) {
        std::cout << "Error: wrong BMP file format." << std::endl;
        return 9;
    }

    // Store input data.
    inputFile.seekg(headerLength, std::fstream::beg);
    char *data = new char[dataLength];
    inputFile.read(data, dataLength);

    // Everything is OK, open outputFile.
    std::fstream outputFile;
    outputFile.open(outputFileName, std::ifstream::in | std::ifstream::out | std::ifstream::binary);

    if (!outputFile.is_open()) {
        std::cout << "Error: Couldn't open the output file." << std::endl;
        return 10;
    }

    // Write header data.
    outputFile.write(headerData, headerLength);

    // Init cipher.
    res = EVP_CipherInit_ex(ctx, cipher, nullptr, key, iv, method == METHOD::ENCRYPT ? 1 : 0);
    if (res != 1) {
        std::cout << "Error in encryption – init." << std::endl;
        return 11;
    }

    // Prepare output data storage.
    int inputBufferLength = 1024;
    int outputBufferLength = inputBufferLength + 4 * EVP_MAX_BLOCK_LENGTH;
    char *inputBufferData = new char[inputBufferLength];
    char *outputBufferData = new char[outputBufferLength];
    long outputDataLength = 0;
    int tmpLength = 0;

    inputFile.seekg(headerLength, std::fstream::beg);

    // Process data.
    while (true) {
        if (inputFile.eof()) {
            break;
        }

        inputFile.read(inputBufferData, inputBufferLength);

        res = EVP_CipherUpdate(ctx, reinterpret_cast<unsigned char *>(outputBufferData), &tmpLength,
                               reinterpret_cast<const unsigned char *>(inputBufferData), inputFile.gcount());
        if (res != 1) {
            std::cout << "Error in encryption – update." << std::endl;
            return 12;
        }

        outputDataLength += tmpLength;
        outputFile.write(outputBufferData, tmpLength);
    }

    res = EVP_CipherFinal_ex(ctx, reinterpret_cast<unsigned char *>(outputBufferData), &tmpLength);
    if (res != 1) {
        std::cout << "Error in encryption – final." << std::endl;
        return 13;
    }
    outputDataLength += tmpLength;
    outputFile.write(outputBufferData, tmpLength);

    // Update header data with file length.
    fileSizeData[0] = outputDataLength + headerLength;
    outputFile.seekg(2);
    outputFile.write(fileSizeData, fileSizeDataLength);

    // Clean up.
    EVP_CIPHER_CTX_free(ctx);
    return 0;
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
