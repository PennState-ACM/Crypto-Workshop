#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <string.h>

#define KEY_GEN_COUNT 5
#define AES_KEY_PASS  "Penn State ACM"
#define SALT          "Penn State ACM"

int aes_gen_key(unsigned char *key, unsigned char *iv);
int aes_encrypt(EVP_CIPHER_CTX* context, const unsigned char *key, const unsigned char *iv, const unsigned char *msg, size_t msgLen, unsigned char **encMsg);
int aes_decrypt(EVP_CIPHER_CTX* context, const unsigned char *key, const unsigned char *iv, unsigned char *enc_msg, size_t enc_msg_len, char **dec_msg);