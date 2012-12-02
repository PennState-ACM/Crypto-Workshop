#include <stdio.h>
#include <string.h>

#include "aes.h"

#define BUFFER         2048
#define KEY_LENGTH     256
#define MSG_FILENAME   "enc.bin"
#define KEY_FILENAME   "key.bin"
#define IV_FILENAME    "iv.bin"

int main() {
    EVP_CIPHER_CTX context;
    unsigned char key[KEY_LENGTH/8]; // AES key
    unsigned char iv[KEY_LENGTH/8];  // IV
    unsigned char *enc_msg;          // Encrypted message
    char *dec_msg;                   // Decrypted message

    // Init the decyption context
    EVP_CIPHER_CTX_init(&context);

    // Read the encrypted message, key, and IV
    printf("Reading encrypted message and attempting decryption...\n");
    
    enc_msg = malloc(BUFFER);
    
    // Read the encrypted message
    FILE *fd = fopen(MSG_FILENAME, "r");

    // Determine size of the encrypted message file
    fseek(fd, 0L, SEEK_END);
    size_t enc_msg_len = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    size_t enc_len = fread(enc_msg, 1, enc_msg_len, fd);
    fclose(fd);

    // Read the key
    fd = fopen(KEY_FILENAME, "r");
    fread(key, 1, KEY_LENGTH/8, fd);
    fclose(fd);

    // Read the IV
    fd = fopen(IV_FILENAME, "r");
    fread(iv, 1, KEY_LENGTH/8, fd);
    fclose(fd);


    // Decrypt it
    aes_decrypt(&context, key, iv, enc_msg, enc_len, &dec_msg);
    printf("Decrypted message: %s\n", dec_msg);


    // Clean up...
    EVP_CIPHER_CTX_cleanup(&context);

    free(enc_msg);
    free(dec_msg);
    enc_msg = NULL;
    dec_msg = NULL;
    return 0;
}