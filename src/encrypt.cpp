#include "encrypt.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <iostream>

// AES-GCM 
static constexpr int KEY_LEN = 32;   // 256 bits
static constexpr int IV_LEN  = 12;   // recommended for GCM
static constexpr int TAG_LEN = 16;   // 128-bit tag
static constexpr size_t CHUNK_SIZE = 64 * 1024;

bool encrypt_file(const std::string& in_path, const std::string& out_path, const std::string& key_path) {

    std::ifstream in(in_path, std::ios::binary);

    if (!in) { // If file failed to open.
        std::cerr << "Error: CANNOT OPEN INPUT FILE '" << in_path << std::endl;
        return false;
    }

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

    std::filesystem::path temp_path = std::filesystem::path(out_path).concat(".tmp");
    std::ofstream of(temp_path, std::ios::binary);
    if (!of) {
        std::cerr << "Error: cannot open output file" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    auto cleanup_temp = [&temp_path, &of]() {
        of.close();
        std::error_code ec;
        std::filesystem::remove(temp_path, ec);
    };

    std::vector<uint8_t> in_buf(CHUNK_SIZE);
    std::vector<uint8_t> out_buf(CHUNK_SIZE + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    while (in) {
        in.read(reinterpret_cast<char*>(in_buf.data()), static_cast<std::streamsize>(in_buf.size()));
        std::streamsize read_len = in.gcount();
        if (read_len <= 0) {
            break;
        }
        int out_len = 0; //bytes written by EVP_EncryptUpdate
        if (EVP_EncryptUpdate(ctx, out_buf.data(), &out_len, in_buf.data(), static_cast<int>(read_len)) != 1) {
            std::cerr << "Error: EVP_EncryptUpdate has failed" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            cleanup_temp();
            return false;
        }
        of.write(reinterpret_cast<const char*>(out_buf.data()), out_len);
        if (!of) {
            std::cerr << "Error: cannot write output file" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            cleanup_temp();
            return false;
        }
    }
    if (in.bad()) {
        std::cerr << "Error: cannot read input file '" << in_path << "'" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        cleanup_temp();
        return false;
    }

    int out_len_final = 0;
    if (EVP_EncryptFinal_ex(ctx, out_buf.data(), &out_len_final) != 1) {
        std::cerr << "Error: EVP_EncryptFinal_ex has failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        cleanup_temp();
        return false;
    }
    if (out_len_final > 0) {
        of.write(reinterpret_cast<const char*>(out_buf.data()), out_len_final);
        if (!of) {
            std::cerr << "Error: cannot write output file" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            cleanup_temp();
            return false;
        }
    }

    //auth tag
    std::vector<uint8_t> tag(TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag.data()) != 1) {
        std::cerr << "Error: EVP_CIPHER_CTX_ctrl get tag failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        cleanup_temp();
        return false;
    }
    EVP_CIPHER_CTX_free(ctx);

    of.write(reinterpret_cast<const char*>(tag.data()), TAG_LEN);
    if (!of) {
        std::cerr << "Error: cannot write output file" << std::endl;
        cleanup_temp();
        return false;
    }
    of.close();

    // Writing the key and IV to the key file

    std::ofstream kf(key_path, std::ios::binary); // output file stream
    if (!kf){
        std::cerr << "Error: cannot open key file '" << key_path << std::endl;
        cleanup_temp();
        return false;
    }
    //writes
    kf.write(reinterpret_cast<const char*>(key.data()), KEY_LEN); // gotta convert from uint8_t* to const char* for .write(). not sure if this is the correct way to do it?
    kf.write(reinterpret_cast<const char*>(iv.data()), IV_LEN);
    if (!kf) {
        std::cerr << "Error: cannot write key file '" << key_path << std::endl;
        cleanup_temp();
        return false;
    }
    kf.close();

    std::error_code ec;
    std::filesystem::remove(out_path, ec);
    ec.clear();
    std::filesystem::rename(temp_path, out_path, ec);
    if (ec) {
        std::cerr << "Error: cannot finalize output file '" << out_path << "'" << std::endl;
        cleanup_temp();
        return false;
    }

    std::cout << "ENCRYPTED '" << in_path << "' to " << out_path << std::endl;
    return true;

}
