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

#include <easyopenssl/digest.h>
#include <openssl/bio.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <assert.h>
#include <map>
#include <cstring>

const int kBuffSize = 1024 * 8;

using std::map;

#ifdef _DEBUG
#define EASYOPENSSL_ASSERT(expression) assert(expression);
#else
#define EASYOPENSSL_ASSERT(expression) {\
  if ((expression) == 0) {\
    fprintf(stderr, "[Error] Fatal error,force quit.\n");\
    exit(EXIT_FAILURE);\
  }\
}
#endif

EasyOpenSSLDigest::EasyOpenSSLDigest() {
}

EasyOpenSSLDigest::~EasyOpenSSLDigest() {
}

std::string EasyOpenSSLDigest::Calculate(const EVP_MD *md, const int msg_type,
                                         const std::string &msg) {
  EASYOPENSSL_ASSERT(msg_type == 0 || msg_type == 1);

  // 必须是 unsigned char*，否则 BIO_gets 得到的结果不正确。
  // signed char取值范围是 -128 ~ 127。
  // unsigned char 取值范围是 0 ~ 255，刚好是 Extended ASCII(EASCII)
  // 编码的表示范围。
  // 加密后的数据是由EASCII字符组成，所以必须用 unsigned char。
  unsigned char *buffer = new unsigned char[kBuffSize];
  std::fill_n(buffer, kBuffSize, 0);

  BIO *bio_err = BIO_new(BIO_s_file());
  EASYOPENSSL_ASSERT(bio_err != nullptr);
  BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

  BIO *bio_md = BIO_new(BIO_f_md());
  BIO_set_md(bio_md, md);

  BIO *bio = nullptr;

  if (msg_type == 0) {
    BIO *in_file = BIO_new(BIO_s_file());
    bio = BIO_push(bio_md, in_file);
    if (BIO_read_filename(in_file, msg.c_str()) <= 0) {
      BIO_printf(bio_err, "Read Error in %s\n", msg.c_str());
      ERR_print_errors(bio_err);
      return "";
    }

    while (true) {
      const int i = BIO_read(bio, reinterpret_cast<char*>(buffer), kBuffSize);

      if (i < 0) {
        BIO_printf(bio_err, "Read Error in %s\n", msg.c_str());
        ERR_print_errors(bio_err);
        return "";
      }

      if (i == 0)
        break;
    }
  } else {
    BIO *bio_s_null = BIO_new(BIO_s_null());
    // 构造BIO 链, bio_md 在顶部
    bio = BIO_push(bio_md, bio_s_null);
    BIO_write(bio, msg.c_str(), msg.size());
  }

  // BIO_gets 仅仅是获取数据，不会修改数据
  // BIO_read 会修改数据，然后返回
  const int len = BIO_gets(bio, reinterpret_cast<char*>(buffer), kBuffSize);

  if (len < 0) {
    ERR_print_errors(bio_err);
    return "";
  }

  BIO_free_all(bio);
  CRYPTO_cleanup_all_ex_data();

  const size_t array_len = len * 2 + 1;
  char *hash = new char[array_len];
  std::fill_n(hash, array_len, 0);

  // +1 原因：
  // The  functions  snprintf() and vsnprintf() write at most size bytes
  // (including the terminating null byte ('\0')) to str.
  const size_t hex_num_len = sizeof(char) * 2 + 1;

  for (int i = 0; i < len; i++)
    snprintf(&hash[i * 2], hex_num_len, "%02x",
             static_cast<unsigned int>(buffer[i]));

  const std::string ret_val(hash, len * 2);
  delete[] hash;
  delete[] buffer;

  return ret_val;
}

std::string EasyOpenSSLDigest::CalculateHmac(const EVP_MD *md,
                                             const std::string &key,
                                             const std::string &msg) {
  unsigned char* buffer = HMAC(md, key.c_str(),
                               key.size(),
                               (unsigned char*) msg.c_str(),
                               msg.size(),
                               nullptr,
                               nullptr);

  if (buffer == nullptr)
    return "";

  const size_t len = strlen(reinterpret_cast<char*>(buffer));
  const size_t array_len = len * 2 + 1;
  char *hash = new char[array_len];
  std::fill_n(hash, array_len, 0);

  // +1 原因：
  // The  functions  snprintf() and vsnprintf() write at most size bytes
  // (including the terminating null byte ('\0')) to str.
  const size_t hex_num_len = sizeof(char) * 2 + 1;

  for (size_t i = 0; i < len; i++)
    snprintf(&hash[i * 2], hex_num_len, "%02x",
             static_cast<unsigned int>(buffer[i]));

  const std::string ret_val(hash, len * 2);
  delete[] hash;

  return ret_val;
}

std::string EasyOpenSSLDigest::Md5(const std::string &msg) {
  return Calculate(EVP_md5(), 1, msg);
}

std::string EasyOpenSSLDigest::Md5Sum(const std::string &file) {
  return Calculate(EVP_md5(), 0, file);
}

std::string EasyOpenSSLDigest::HmacMd5(const std::string &key,
                                       const std::string &msg) {
  return CalculateHmac(EVP_md5(), key, msg);
}

std::string EasyOpenSSLDigest::Sha1(const std::string &msg) {
  return Calculate(EVP_sha1(), 1, msg);
}

std::string EasyOpenSSLDigest::Sha1Sum(const std::string &file) {
  return Calculate(EVP_sha1(), 0, file);
}

std::string EasyOpenSSLDigest::HmacSha1(const std::string &key,
                                        const std::string &msg) {
  return CalculateHmac(EVP_sha1(), key, msg);
}

std::string EasyOpenSSLDigest::Sha224(const std::string &msg) {
  return Calculate(EVP_sha224(), 1, msg);
}

std::string EasyOpenSSLDigest::Sha224Sum(const std::string &file) {
  return Calculate(EVP_sha224(), 0, file);
}

std::string EasyOpenSSLDigest::HmacSha224(const std::string &key,
                                          const std::string &msg) {
  return CalculateHmac(EVP_sha224(), key, msg);
}

std::string EasyOpenSSLDigest::Sha256(const std::string &msg) {
  return Calculate(EVP_sha256(), 1, msg);
}

std::string EasyOpenSSLDigest::Sha256Sum(const std::string &file) {
  return Calculate(EVP_sha256(), 0, file);
}

std::string EasyOpenSSLDigest::HmacSha256(const std::string &key,
                                          const std::string &msg) {
  return CalculateHmac(EVP_sha256(), key, msg);
}

std::string EasyOpenSSLDigest::Sha384(const std::string &msg) {
  return Calculate(EVP_sha384(), 1, msg);
}

std::string EasyOpenSSLDigest::Sha384Sum(const std::string &file) {
  return Calculate(EVP_sha384(), 0, file);
}

std::string EasyOpenSSLDigest::HmacSha384(const std::string &key,
                                          const std::string &msg) {
  return CalculateHmac(EVP_sha384(), key, msg);
}

std::string EasyOpenSSLDigest::Sha512(const std::string &msg) {
  return Calculate(EVP_sha512(), 1, msg);
}

std::string EasyOpenSSLDigest::Sha512Sum(const std::string &file) {
  return Calculate(EVP_sha512(), 0, file);
}

std::string EasyOpenSSLDigest::HmacSha512(const std::string &key,
                                          const std::string &msg) {
  return CalculateHmac(EVP_sha512(), key, msg);
}
