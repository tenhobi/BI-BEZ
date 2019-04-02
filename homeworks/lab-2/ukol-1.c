#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define MESSAGE_LENGTH 42

void textGenerator(unsigned char *message);

void findHashMessage(EVP_MD_CTX *ctx, const EVP_MD *type, unsigned char *hash, int *length);

int main(int argc, char *argv[]) {
    // initialization
    char hashFunction[] = "sha256";
    EVP_MD_CTX *ctx;
    const EVP_MD *type;
    unsigned char hash[EVP_MAX_MD_SIZE];
    int length;

    srand(time(NULL));
    OpenSSL_add_all_digests();
    type = EVP_get_digestbyname(hashFunction);

    if (!type) {
        printf("Hash %s neexistuje.\n", hashFunction);
        exit(1);
    }

    // create context
    ctx = EVP_MD_CTX_create();
    if (ctx == NULL) exit(2);

    // find message
    findHashMessage(ctx, type, hash, &length);

    // destroy context
    EVP_MD_CTX_destroy(ctx);
}

void findHashMessage(EVP_MD_CTX *ctx, const EVP_MD *type, unsigned char *hash, int *length) {
    unsigned char message[MESSAGE_LENGTH + 1] = {0};

    // find the right hash
    while ((hash[0] != 0xAA) || (hash[1] != 0xBB)) {
        int res;

        // generate message
        textGenerator(message);

        res = EVP_DigestInit_ex(ctx, type, NULL);
        if (res != 1) exit(3);
        res = EVP_DigestUpdate(ctx, message, MESSAGE_LENGTH);
        if (res != 1) exit(4);
        res = EVP_DigestFinal_ex(ctx, hash, (unsigned int *) length);
        if (res != 1) exit(5);
    }

    printf("message: '%s'"
           "\nhash: ", message);

    for (int i = 0; i < (*length); i++) {
        printf("%02x ", hash[i]);
    }
    printf("\n");
}

void textGenerator(unsigned char *message) {
    char chars[] = "123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    for (int i = 0; i < MESSAGE_LENGTH; i++) {
        // randomly select one char from chars
        int position = rand() % (sizeof(chars) - 1);
        message[i] = chars[position];
    }
}
