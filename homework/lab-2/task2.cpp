#include <openssl/evp.h>
#include <iostream>
#include <cstring>
#include <iomanip>

#define PRINT true
#define DO_NOT_PRINT false
#define DATA_LENGTH 1024

void encrypt();

void decrypt();

int getSize(const unsigned char *data);

void printText(const unsigned char *data);

void printHex(const unsigned char *data, int length);

void encryptAndPrint(const unsigned char *ot,
                     unsigned char *st,
                     const unsigned char *key,
                     const unsigned char *iv,
                     const EVP_CIPHER *cipher,
                     int index,
                     bool printOt = DO_NOT_PRINT);

void readInput(unsigned char *data);

void stringToHex(unsigned char *data, unsigned char *result, int &length);

int main(int argc, char *argv[]) {
    // encrypt
    if (argc == 2 && (!strncmp(argv[1], "-e", 3))) {
        encrypt();
    } // decrypt
    else if (argc == 2 && (!strncmp(argv[1], "-d", 3))) {
        decrypt();
    } // invalid
    else {
        printf("Invalid input.");
        exit(1);
    }

    exit(0);
}

void encrypt() {
    unsigned char ot1[DATA_LENGTH] = "Toto je tajna testovaci zprava";
    unsigned char ot2[DATA_LENGTH] = "abcdefghijklmnopqrstuvwxyz0123";
    unsigned char st1[DATA_LENGTH] = {0};
    unsigned char st2[DATA_LENGTH] = {0};

    unsigned char key[EVP_MAX_KEY_LENGTH] = "Nejtajnejsi klic";
    unsigned char iv[EVP_MAX_IV_LENGTH] = "inicial. vektor";

    const char cipherName[] = "RC4";
    const EVP_CIPHER *cipher;

    OpenSSL_add_all_ciphers();
    cipher = EVP_get_cipherbyname(cipherName);

    if (!cipher) {
        printf("Cipher %s does not exist.", cipherName);
        exit(2);
    }

    encryptAndPrint(ot1, st1, key, iv, cipher, 1, PRINT);
    encryptAndPrint(ot2, st2, key, iv, cipher, 2);
}

void decrypt() {
    unsigned char ot1[DATA_LENGTH] = {0}; // known
    unsigned char st1[DATA_LENGTH] = {0}; // known
    unsigned char st2[DATA_LENGTH] = {0}; // known
    unsigned char tmp[DATA_LENGTH] = {0};
    unsigned char tmp2[DATA_LENGTH] = {0};
    int st1Length = 0;
    int st2Length = 0;

    // load the known data
    readInput(ot1);
    readInput(tmp);
    stringToHex(tmp, st1, st1Length);
    readInput(tmp2);
    stringToHex(tmp2, st2, st2Length);

    int limit = std::min(st1Length, st2Length);
    std::cout << "delka: " << limit << std::endl;

    // results
    std::cout << "OT1: ";
    printText(ot1);
    std::cout << std::endl << "ST1: ";
    printHex(st1, st1Length);
    std::cout << std::endl << "ST2: ";
    printHex(st2, st2Length);
    std::cout << std::endl << "=> OT2: ";

    // compute ST2
    for (int i = 0; i < limit; i++) {
        std::cout << (char) (st1[i] ^ st2[i] ^ ot1[i]);
    }

    std::cout << std::endl;
}

int getSize(const unsigned char *data) {
    return (int) strlen((const char *) data);
}

void printText(const unsigned char *data) {
    for (int j = 0; j < getSize(data); j++) {
        std::cout << data[j];
    }
}

void printHex(const unsigned char *data, int length) {
    for (int j = 0; j < length; j++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) data[j];
    }
}

void encryptAndPrint(const unsigned char *ot,
                     unsigned char *st,
                     const unsigned char *key,
                     const unsigned char *iv,
                     const EVP_CIPHER *cipher,
                     int index,
                     bool printOt) {
    int res;
    int tmpLength = 0;
    int otLength = getSize(ot);
    int stLength = 0;

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) exit(3);

    // encryption
    res = EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv);
    if (res != 1) exit(4);
    res = EVP_EncryptUpdate(ctx, st, &tmpLength, ot, otLength);
    if (res != 1) exit(5);
    stLength += tmpLength;
    res = EVP_EncryptFinal_ex(ctx, st + stLength, &tmpLength);
    if (res != 1) exit(6);
    stLength += tmpLength;
    EVP_CIPHER_CTX_free(ctx);

    if (printOt == PRINT) {
        printf("OT%d (%d): %s\n", index, otLength, ot);
    }

    printf("ST%d (%d): ", index, stLength);
    printHex(st, stLength);
    printf("\n");
}

void readInput(unsigned char *data) {
    int counter = 0;
    char c;
    while ((c = static_cast<char>(getchar())) != '\n' && c != EOF) {
        if (counter >= DATA_LENGTH) {
            std::cout << "Limit exceeded" << std::endl;
            exit(8);
        }

        data[counter++] = c;
    }

    if (counter == 0) {
        std::cout << "Input data is missing." << std::endl;
        exit(9);
    }
}

void stringToHex(unsigned char *data, unsigned char *result, int &length) {
    unsigned int resultLength = 0;
    int stringLength = getSize(data);

    // odd length
    if (stringLength % 2 == 1) {
        for (int i = getSize(data) + 1; i > 0; i--) {
            data[i] = data[i - 1];
        }
        data[0] = '0';
        stringLength = getSize(data);
    }

    if (getSize(data) % 2 == 1) {
        std::cout << "Error: odd length!" << std::endl;
        exit(10);
    }

    for (int i = 0; i < stringLength; i++) {
        unsigned char value;

        if (data[i] >= '0' && data[i] <= '9') {
            value = data[i] - '0';
        } else if (data[i] >= 'a' && data[i] <= 'z') {
            value = (char) (data[i] - 'a' + 10);
        } else if (data[i] >= 'A' && data[i] <= 'Z') {
            value = (char) (data[i] - 'A' + 10);
        } else {
            std::cout << "Error while loading" << (int) data[i] << std::endl;
            exit(7);
        }

        (result)[resultLength / 2] = (result)[resultLength / 2] | (value << (4 * (!(resultLength % 2))));
        resultLength++;
    }

    length = resultLength / 2;
}

/*
Toto je tajna testovaci zprava
8854ad32ee8653d78484de5cbddc465bace2cc13892548bf0e65a0253c40
bd59ba39ab8a519f998fdf5eb1925d4eaee4d0119d3056e70d6fe2757812

abcdefghijklmnopqrstuvwxyz0123
06fb7405eba8d9e94fb1f28f0dd21fdec55fd54750ee84d95ecccf2b1b48
33f6630eaea4dba152baf38d019c04cbc759c94544fb9a815dc68d7b5f1a

# urizle

abcdefghijklmnopqrstuvwxyz0123
b6f22f7101bf3a10ee9cba5e94eb39deb4b5b1579105c712c1a95ddadb40
b6f22f7101bf3a10ee9cba5e94eb39deb4b5b1579105c712c1a95dda

abcdefghijklmnopqrstuvwxyz0123
b6f22f7101bf3a10ee9cba5e94eb39deb4b5b1579105c712c1a95ddadb40
9af16c6105b33319a78ca14098f337cf
*/
