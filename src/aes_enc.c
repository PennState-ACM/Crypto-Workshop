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
    char msg[BUFFER];                // Message to encrypt
    unsigned char *enc_msg;          // Encrypted message

    // Init encryption context
    EVP_CIPHER_CTX_init(&context);

    // Generate key
    printf("Generating AES (%d bits) key...\n", KEY_LENGTH);
    aes_gen_key(&(*key), &(*iv));


    // Get the message to encrypt
    printf("Message to encrypt: ");
    fgets((char*)msg, BUFFER-1, stdin);
    msg[strlen((char*)msg)-1] = '\0';


    // Encrypt the message
    size_t enc_len = aes_encrypt(&context, key, iv, (unsigned char*)msg, strlen(msg), &enc_msg);


    // Write the encrypted message to a file
    FILE *fd = fopen(MSG_FILENAME, "w");
    fwrite(enc_msg, 1, enc_len, fd);
    fclose(fd);

    // Write the key
    fd = fopen(KEY_FILENAME, "w");
    fwrite(key, 1, KEY_LENGTH/8, fd);
    fclose(fd);

    // Write the IV
    fd = fopen(IV_FILENAME, "w");
    fwrite(iv, 1, KEY_LENGTH/8, fd);
    fclose(fd);
    
    printf("Encrypted message written to file.\n");


    // Clean up...
    free(enc_msg);
    enc_msg = NULL;
    EVP_CIPHER_CTX_cleanup(&context);

    return 0;
}