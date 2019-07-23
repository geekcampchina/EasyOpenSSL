// Copyright (c) 2016, Fifi Lyu. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include <easyopenssl/enc.h>
#include <easyopenssl/base64.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

const char* EasyOpenSSLEnc::error_ = "";

EasyOpenSSLEnc::EasyOpenSSLEnc() {
}

EasyOpenSSLEnc::~EasyOpenSSLEnc() {
}

BIO *EasyOpenSSLEnc::DecryptBioBuf(const std::string &txt) {
  char* _txt = const_cast<char*>(txt.c_str());
  return BIO_new_mem_buf(reinterpret_cast<void*>(_txt), -1);
}

void EasyOpenSSLEnc::Base64Bio(BIO *bio, BIO *bio_buf) {
  BIO *bio_base64 = BIO_new(BIO_f_base64());

  // 不添加换行符
  // 如果不设置此选项，所有输入的 Base64 字符串，每65个字符之后就必须有一个换行符，
  // 才能正常解密。
  BIO_set_flags(bio_base64, BIO_FLAGS_BASE64_NO_NL);

  BIO_push(bio_base64, bio_buf);  // bio_base64 <-> bio_buf
  BIO_push(bio, bio_base64);  // bio <-> bio_base64 <-> bio_buf
}

void EasyOpenSSLEnc::CleanAll(BIO *bio) {
  // free BIO_new
  BIO_free_all(bio);
  CRYPTO_cleanup_all_ex_data();

  // for OpenSSL_add_all_ciphers(), removes all ciphers
  EVP_cleanup();
}

BIO *EasyOpenSSLEnc::InitBio(const EncodingAction enc,
                             const std::string &cipher_name,
                             const std::string &key, const std::string &iv) {
  OpenSSL_add_all_ciphers();
  const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name.c_str());

  if (!cipher) {
    error_ = "Invalid cipher algorithm.";
    return nullptr;
  }

  BIO *bio = BIO_new(BIO_f_cipher());

  BIO_set_cipher(bio, cipher, (const unsigned char *) (key.c_str()),
                 (const unsigned char *) (iv.c_str()), enc);

  return bio;
}

bool EasyOpenSSLEnc::EncryptBioWrite(BIO *bio, const std::string &txt,
                                       std::string *buffer) {
  BIO_write(bio, txt.c_str(), txt.size());

  if (BIO_flush(bio) <= 0) {
    error_ = "Failed to call BIO_flush().";
    return false;
  }

  BUF_MEM *buf_mem = nullptr;
  BIO_get_mem_ptr(bio, &buf_mem);
  *buffer = move(std::string(buf_mem->data, buf_mem->length));

  return true;
}

void EasyOpenSSLEnc::DecryptBioRead(BIO *bio, std::string *buffer) {
  char read_buf[256];
  int read_len = 0;

  while ((read_len = BIO_read(bio, read_buf, 256)) > 0)
    *buffer += move(std::string(read_buf, read_len));
}

bool EasyOpenSSLEnc::Encrypt(const std::string &cipher_name,
                             const std::string &plaintext,
                             const std::string &key, const std::string &iv,
                             std::string *buffer) {
  BIO *bio_buf = BIO_new(BIO_s_mem());
  BIO *bio = InitBio(kENCRYPT, cipher_name, key, iv);

  if (bio == nullptr)
    return false;

  Base64Bio(bio, bio_buf);

  bool ret_val = true;

  if (!EncryptBioWrite(bio, plaintext, buffer)) {
    ret_val = false;
  }

  CleanAll(bio);

  return ret_val;
}

bool EasyOpenSSLEnc::Decrypt(const std::string &cipher_name,
                             const std::string &ciphertext,
                             const std::string &key, const std::string &iv,
                             std::string *buffer) {
  bool ret_val = false;
  BIO *bio_buf = DecryptBioBuf(ciphertext);
  BIO *bio = InitBio(kDECRYPT, cipher_name, key, iv);

  if (bio == nullptr) {
    ret_val = false;
  } else {
    Base64Bio(bio, bio_buf);
    DecryptBioRead(bio, buffer);
    ret_val = true;
  }

  CleanAll(bio);

  return ret_val;
}

std::string EasyOpenSSLEnc::GetLastError() {
  return error_;
}
