#include "decrypt.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <vector>
#include <iostream>

// AES-GCM 
static constexpr int KEY_LEN = 32;   // 256 bits
static constexpr int IV_LEN  = 12;   // recommended for GCM
static constexpr int TAG_LEN = 16;   // 128-bit tag
static constexpr size_t CHUNK_SIZE = 64 * 1024;

bool decrypt_file(const std::string& in_path, const std::string& out_path, const std::string& key_path) {

    //Load key and IV from the key file
    std::ifstream kf(key_path, std::ios::binary);
    if (!kf) {
        std::cerr << "Error: cannot open key file '" << key_path << "'" << std::endl;
        return false;
    }
    std::istreambuf_iterator<char> kit(kf);//Iterate all bytes from key file
    std::istreambuf_iterator<char> kend;
    std::vector<uint8_t> key_iv(kit, kend); //buffer
    kf.close();


    if (key_iv.size() != KEY_LEN + IV_LEN) { //Check the size before decrypting
        std::cerr << "Error: key file size is incorrect. Expected Bytes: " << (KEY_LEN + IV_LEN) << std::endl;
        return false;
    }

    //Break up into key and IV 
    std::vector<uint8_t> key(key_iv.begin(), key_iv.begin() + KEY_LEN);
    std::vector<uint8_t> iv(key_iv.begin() + KEY_LEN, key_iv.end());

    std::error_code size_ec;
    std::uintmax_t file_size = std::filesystem::file_size(in_path, size_ec);
    if (size_ec) {
        std::cerr << "Error: cannot stat input file '" << in_path << "'" << std::endl;
        return false;
    }
    if (file_size < TAG_LEN) {
        std::cerr << "Error: input file too small to contain tag" << std::endl;
        return false;
    }
    std::uintmax_t cipher_len = file_size - TAG_LEN;

    //Load ciphertext and tag from input file
    std::ifstream inpf(in_path, std::ios::binary);
    if (!inpf) {
        std::cerr << "Error: cannot open inpuyt file '" << in_path << "'" << std::endl;
        return false;
    }

    std::filesystem::path temp_path = std::filesystem::path(out_path).concat(".tmp");
    std::ofstream of(temp_path, std::ios::binary);
    if (!of) {
        std::cerr << "Error: cannot open output file '" << out_path << "'" << std::endl;
        return false;
    }
    auto cleanup_temp = [&temp_path, &of]() {
        of.close();
        std::error_code ec;
        std::filesystem::remove(temp_path, ec);
    };


    //Initialize evp context for the decryption
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error: EVP_CIPHER_CTX_new has failed" << std::endl;
        cleanup_temp();
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) { //Initializes for AES 256 in GCM mode
        std::cerr << "Error: EVP_DecryptInit_ex has failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        cleanup_temp();
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) != 1) { //set IV length
        std::cerr << "Error: EVP_CIPHER_CTX_ctrl (set IV Length) has failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        cleanup_temp();
        return false;
    }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) { // set key and iv for
        std::cerr << "Error: EVP_DecryptInit_ex (set key/iv) has failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        cleanup_temp();
        return false;
    }

    // decrypt

    std::vector<uint8_t> in_buf(CHUNK_SIZE);
    std::vector<uint8_t> out_buf(CHUNK_SIZE + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    std::uintmax_t remaining = cipher_len;
    while (remaining > 0) {
        size_t to_read = static_cast<size_t>(std::min<std::uintmax_t>(remaining, CHUNK_SIZE));
        inpf.read(reinterpret_cast<char*>(in_buf.data()), static_cast<std::streamsize>(to_read));
        if (inpf.gcount() != static_cast<std::streamsize>(to_read)) {
            std::cerr << "Error: cannot read input file '" << in_path << "'" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            cleanup_temp();
            return false;
        }
        int out_len = 0;
        if (EVP_DecryptUpdate(ctx, out_buf.data(), &out_len, in_buf.data(), static_cast<int>(to_read)) != 1) {
            std::cerr << "Error: EVP_DecryptUpdate has failed" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            cleanup_temp();
            return false;
        }
        of.write(reinterpret_cast<const char*>(out_buf.data()), out_len);
        if (!of) {
            std::cerr << "Error: cannot write output file '" << out_path << "'" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            cleanup_temp();
            return false;
        }
        remaining -= to_read;
    }

    std::vector<uint8_t> tag(TAG_LEN);
    inpf.read(reinterpret_cast<char*>(tag.data()), TAG_LEN);
    if (inpf.gcount() != TAG_LEN) {
        std::cerr << "Error: input file too small to contain tag" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        cleanup_temp();
        return false;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag.data()) != 1){ //set auth tag
        std::cerr << "Error: EVP_CIPHER_CTX_ctrl (set tag) has failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        cleanup_temp();
        return false;
    }
    int out_len2 = 0;
    int ret = EVP_DecryptFinal_ex(ctx, out_buf.data(), &out_len2);

    EVP_CIPHER_CTX_free(ctx);
    if (ret <= 0) { // could be wrong key or iv or tag
        std::cerr << "Error: decryption failed (AUTHENTICATION ERROR)" << std::endl;
        cleanup_temp();
        return false;
    }
    if (out_len2 > 0) {
        of.write(reinterpret_cast<const char*>(out_buf.data()), out_len2);
        if (!of) {
            std::cerr << "Error: cannot write output file '" << out_path << "'" << std::endl;
            cleanup_temp();
            return false;
        }
    }
    of.close();

    std::error_code ec;
    std::filesystem::remove(out_path, ec);
    ec.clear();
    std::filesystem::rename(temp_path, out_path, ec);
    if (ec) {
        std::cerr << "Error: cannot finalize output file '" << out_path << "'" << std::endl;
        cleanup_temp();
        return false;
    }

    std::cout << "DECRYPTED '" << in_path << "' to " << out_path << std::endl;
    return true;

}
