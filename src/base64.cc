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

#include <easyopenssl/base64.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <algorithm>

EasyOpenSSLBase64::EasyOpenSSLBase64() {
}

EasyOpenSSLBase64::~EasyOpenSSLBase64() {
}

size_t EasyOpenSSLBase64::ComputeSize(const std::string &base64) {
  const size_t size = base64.size();
  size_t padding = 0;

  if (base64[size - 1] == '=' && base64[size - 2] == '=')
    padding = 2;
  else if (base64[size - 1] == '=')
    padding = 1;
  else
    padding = 0;

  return (size * 3) / 4 - padding;
}

std::string EasyOpenSSLBase64::Encode(const std::string &plaintext) {
  BIO *bio = nullptr;
  BIO *bio_base64 = nullptr;
  BUF_MEM *buf_mem = nullptr;

  bio_base64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(bio_base64, bio);

  // Ignore newlines - write everything in one line
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(bio, plaintext.c_str(), plaintext.size());

  if (BIO_flush(bio) <= 0)
    return "";

  BIO_get_mem_ptr(bio, &buf_mem);

  const std::string tmp(buf_mem->data, buf_mem->length);

  BIO_free_all(bio);
  // 仅仅使用 BIO_free_all 无法释放所有内存
  CRYPTO_cleanup_all_ex_data();

  return tmp;
}

std::string EasyOpenSSLBase64::Decode(const std::string &cipher) {
  BIO *bio = nullptr;
  BIO *bio_base64 = nullptr;

  const size_t size = ComputeSize(cipher.c_str());
  char *buffer = new char[size + 1];
  std::fill_n(buffer, size + 1, 0);

  char *_cipher = const_cast<char*>(cipher.c_str());
  bio = BIO_new_mem_buf(reinterpret_cast<void*>(_cipher), -1);
  bio_base64 = BIO_new(BIO_f_base64());
  bio = BIO_push(bio_base64, bio);

  // Do not use newlines to flush buffer
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  const size_t read_size_ = BIO_read(bio, buffer, size);

  BIO_free_all(bio);
  // 仅仅使用 BIO_free_all 无法释放所有内存
  CRYPTO_cleanup_all_ex_data();

  const std::string ret_val(
      read_size_ == size ? std::string(buffer, size) : "");
  delete[] buffer;

  return ret_val;
}
