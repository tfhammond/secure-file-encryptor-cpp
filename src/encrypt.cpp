#include "encrypt.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fstream>
#include <vector>
#include <iostream>

// AES-GCM 
static constexpr int KEY_LEN = 32;   // 256 bits
static constexpr int IV_LEN  = 12;   // recommended for GCM
static constexpr int TAG_LEN = 16;   // 128-bit tag

bool encrypt_file(const std::string& in_path, const std::string& out_path, const std::string& key_path) {

    // Read the entire plaintext into memory
    std::ifstream in(in_path, std::ios::binary);

    if (!in) { // If file failed to open.
        std::cerr << "Error: CANNOT OPEN INPUT FILE '" << in_path << std::endl;
        return false;
    }

    std::istreambuf_iterator<char> it(in);
    std::istreambuf_iterator<char> end;
    std::vector<uint8_t> plaintext(it, end);
    //std::vector<uint8_t> plaintext(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    in.close();

    //create key
    std::vector<uint8_t> key(KEY_LEN);
    std::vector<uint8_t> iv(IV_LEN);

    if (!RAND_bytes(key.data(), KEY_LEN) || !RAND_bytes(iv.data(), IV_LEN)) { //test RAND_bytes

        std::cerr << "Error: RAND_bytes failed" << std::endl;
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new(); //allocation check

    if (!ctx) { //test EVP_CIPHER_CTX_new
        std::cerr << "Error: EVP_CIPHER_CTX_new has failed" << std::endl;
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) { //Initializes for AES-256 in GCM mode
        std::cerr << "Error: EVP_EncryptInit_ex has failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) != 1) { //Set length of initialization vector (IV)
        std::cerr << "Error: EVP_CIPHER_CTX_ctrl has failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        std::cerr << "Error: EVP_EncryptInit_ex has failed (set key/iv)" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }


    // Encrypting plaintext

    std::vector<uint8_t> ciphertext(plaintext.size());
    int out_len1 = 0; //bytes written by EVP_EncryptUpdate
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len1, plaintext.data(), plaintext.size()) != 1) {
        std::cerr << "Error: EVP_EncryptUpdate has failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int out_len2 = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len1, &out_len2) != 1) {
        std::cerr << "Error: EVP_EncryptFinal_ex has failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    //auth tag
    std::vector<uint8_t> tag(TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag.data()) != 1) {
        std::cerr << "Error: EVP_CIPHER_CTX_ctrl get tag failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    EVP_CIPHER_CTX_free(ctx);

    // Writing the key and IV to the key file

    std::ofstream kf(key_path, std::ios::binary); // output file stream
    if (!kf){
        std::cerr << "Error: cannot open key file '" << key_path << std::endl;
        return false;
    }
    //writes
    kf.write(reinterpret_cast<const char*>(key.data()), KEY_LEN); // gotta convert from uint8_t* to const char* for .write(). not sure if this is the correct way to do it?
    kf.write(reinterpret_cast<const char*>(iv.data()), IV_LEN);
    kf.close();

    // Writing the ciphertext and tag to the output file
    std::ofstream of(out_path, std::ios::binary);
    if (!of) {
        std::cerr << "Error: cannot open output file" << std::endl;
        return false;
    }
    of.write(reinterpret_cast<const char*>(ciphertext.data()), out_len1 + out_len2);
    of.write(reinterpret_cast<const char*>(tag.data()), TAG_LEN);

    std::cout << "ENCRYPTED '" << in_path << "' to " << out_path << std::endl;
    return true;

}
