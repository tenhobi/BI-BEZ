#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define PRINT 0
#define DO_NOT_PRINT 1

void vypis(const unsigned char *data) {
    for (int j = 0; j < strlen((const char *) data); j++) {
        printf("%02x", data[j]);
    }
}

void myEncrypt(const unsigned char *ot,
               unsigned char *st,
               const unsigned char *key,
               const unsigned char *iv,
               const EVP_CIPHER *cipher,
               int index,
               int printOt) {
    int res;
    int tmpLength = 0;
    int otLength = strlen((const char *) ot);
    int stLength = 0;

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) exit(2);

    // encryption
    res = EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
    if (res != 1) exit(3);
    res = EVP_EncryptUpdate(ctx, st, &tmpLength, ot, otLength);
    if (res != 1) exit(4);
    stLength += tmpLength;
    res = EVP_EncryptFinal_ex(ctx, st + stLength, &tmpLength);
    if (res != 1) exit(5);
    stLength += tmpLength;
    EVP_CIPHER_CTX_free(ctx);

    if (printOt == PRINT) {
        printf("OT%d (%d): %s\n", index, otLength, ot);
    }

    printf("ST%d (%d): ", index, stLength);
    vypis(st);
    printf("\n");
}

int main(int argc, char *argv[]) {
    // encrypt
    if (argc == 2 && (!strncmp(argv[1], "-e", 3))) {
        unsigned char ot1[1024] = "Toto je tajna testovaci zprava";
        unsigned char ot2[1024] = "abcdefghijklmnopqrstuvwxyz0123";
        unsigned char st1[1024] = "";
        unsigned char st2[1024] = "";

        unsigned char key[EVP_MAX_KEY_LENGTH] = "Nejtajnejsi klic";
        unsigned char iv[EVP_MAX_IV_LENGTH] = "inicial. vektor";

        const char cipherName[] = "RC4";
        const EVP_CIPHER *cipher;

        OpenSSL_add_all_ciphers();
        cipher = EVP_get_cipherbyname(cipherName);
        if (!cipher) {
            printf("Cipher %s does not exist.", cipherName);
            exit(1);
        }

        myEncrypt(ot1, st1, key, iv, cipher, 1, PRINT);
        myEncrypt(ot2, st2, key, iv, cipher, 2, DO_NOT_PRINT);
    }
        // decrypt
    else if (argc == 2 && (!strncmp(argv[1], "-d", 3))) {
        unsigned char ot1[1024];
        unsigned char ot2[1024];
        unsigned char st1[1024];
        unsigned char st2[1024];
    }
        // invalid
    else {
        printf("Invalid input.");
        exit(1);
    }

    exit(0);
}