#include "aes.h"

int aes_gen_key(unsigned char *key, unsigned char *iv) {
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), (unsigned char*)SALT, (unsigned char*)AES_KEY_PASS, strlen(AES_KEY_PASS), KEY_GEN_COUNT, key, iv);
    return 0;
}


int aes_encrypt(EVP_CIPHER_CTX* context, const unsigned char *key, const unsigned char *iv, const unsigned char *msg, size_t msg_len, unsigned char **enc_msg) {
    size_t block_len   = 0;
    size_t enc_msg_len = 0;

    *enc_msg = (unsigned char*)malloc(msg_len + AES_BLOCK_SIZE);

    EVP_EncryptInit(context, EVP_aes_256_cbc(), key, iv);
    
    EVP_EncryptUpdate(context, *enc_msg, (int*)&block_len, (unsigned char*)msg, msg_len);
    enc_msg_len += block_len;

    EVP_EncryptFinal_ex(context, *enc_msg + enc_msg_len, (int*)&block_len);

    return enc_msg_len + block_len;
}


int aes_decrypt(EVP_CIPHER_CTX* context, const unsigned char *key, const unsigned char *iv, unsigned char *enc_msg, size_t enc_msg_len, char **dec_msg) {
    size_t block_len   = 0;
    size_t dec_msg_len = 0;

    *dec_msg = (char*)malloc(enc_msg_len);

    EVP_DecryptInit(context, EVP_aes_256_cbc(), key, iv);

    EVP_DecryptUpdate(context, (unsigned char*)*dec_msg, (int*)&block_len, enc_msg, (int)enc_msg_len);
    dec_msg_len += block_len;

    EVP_DecryptFinal_ex(context, (unsigned char*)*dec_msg + dec_msg_len, (int*)&block_len);
    dec_msg_len += block_len;

    (*dec_msg)[dec_msg_len] = '\0';

    return enc_msg_len;
}