#include <openssl/evp.h>
#include <iostream>

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

std::string removeExtension(const std::string &fileName);

std::string getModeName(MODE mode);

int main(int argc, char *argv[]) {
    // Check number of parameters.
    if (argc != 4) {
        std::cout << "Wrong number of arguments." << std::endl;
        return 1;
    }

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

    if (modeData == "ecb") {
        mode = MODE::ECB;
    } else if (modeData == "cbc") {
        mode = MODE::CBC;
    }

    // Check content of parameters.
    if (task == TASK::NONE || mode == MODE::NONE) {
        std::cout << "Wrong parameters." << std::endl;
        return 2;
    }

    // Read the file. r = read, b = binary
    FILE *file = fopen(sourceFile.c_str(), "rb");
    if (!file) {
        std::cout << "Couldn't open the file." << std::endl;
        return 3;
    }

    // encrypt
    if (task == TASK::ENCRYPT) {
        FILE *outputFile = fopen((removeExtension(sourceFile) + "_" + getModeName(mode) + ".bmp").c_str(), "wb");
        if (!outputFile) {
            std::cout << "Couldn't open the output file." << std::endl;
            fclose(file);
            return 4;
        }

        // TODO

        fclose(outputFile);
    } // decrypt
    else {
        FILE *outputFile = fopen((removeExtension(sourceFile) + "_" + getModeName(mode) + ".bmp").c_str(), "wb");
        if (!outputFile) {
            std::cout << "Couldn't open the output file." << std::endl;
            fclose(file);
            return 4;
        }

        // TODO

        fclose(outputFile);
    }

    fclose(file);
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

void x() {


    int res;
    unsigned char ot[1024] = "Text pro rc4.";  // open text
    unsigned char st[1024];  // sifrovany text
    unsigned char key[EVP_MAX_KEY_LENGTH] = "Muj klic";  // klic pro sifrovani
    unsigned char iv[EVP_MAX_IV_LENGTH] = "inicial. vektor";  // inicializacni vektor
    const char cipherName[] = "RC4";
    const EVP_CIPHER *cipher;

    OpenSSL_add_all_ciphers();
    /* sifry i hashe by se nahraly pomoci OpenSSL_add_all_algorithms() */
    cipher = EVP_get_cipherbyname(cipherName);
    if (!cipher) {
        printf("Sifra %s neexistuje.\n", cipherName);
        exit(1);
    }

    int otLength = strlen((const char *) ot);
    int stLength = 0;
    int tmpLength = 0;

    EVP_CIPHER_CTX *ctx; // context structure
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) exit(2);

    printf("OT: %s\n", ot);

    /* Sifrovani */
    res = EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);  // context init - set cipher, key, init vector
    if (res != 1) exit(3);
    res = EVP_EncryptUpdate(ctx, st, &tmpLength, ot, otLength);  // encryption of pt
    if (res != 1) exit(4);
    stLength += tmpLength;
    res = EVP_EncryptFinal_ex(ctx, st + stLength, &tmpLength);  // get the remaining ct
    if (res != 1) exit(5);
    stLength += tmpLength;

    printf("Zasifrovano %d znaku.\n", stLength);

    /* Desifrovani */
    res = EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);  // nastaveni kontextu pro desifrovani
    if (res != 1) exit(6);
    res = EVP_DecryptUpdate(ctx, ot, &tmpLength, st, stLength);  // desifrovani st
    if (res != 1) exit(7);
    otLength += tmpLength;
    res = EVP_DecryptFinal_ex(ctx, ot + otLength, &tmpLength);  // dokonceni (ziskani zbytku z kontextu)
    if (res != 1) exit(8);
    otLength += tmpLength;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    /* Vypsani zasifrovaneho a rozsifrovaneho textu. */
    printf("ST: %s\nDT: %s\n", st, ot);

    exit(0);
}