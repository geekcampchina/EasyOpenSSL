// -*- C++ -*-
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

// Encoding with Ciphers

#ifndef INCLUDE_EASYOPENSSL_ENC_H_
#define INCLUDE_EASYOPENSSL_ENC_H_

#include <easyopenssl/type.h>
#include <openssl/bio.h>
#include <string>

//! openssl enc 命令行工具的库版本
class EasyOpenSSLEnc {
 private:
  static const char* error_;

 private:
  typedef enum {
    kDECRYPT,
    kENCRYPT,
  } EncodingAction;

 private:
  static BIO *DecryptBioBuf(const std::string &txt);

  static void Base64Bio(BIO *bio, BIO *bio_buf);

  static void CleanAll(BIO *bio);

  static BIO *InitBio(const EncodingAction enc, const std::string &cipher_name,
                      const std::string &key, const std::string &iv);

  static bool EncryptBioWrite(BIO *bio, const std::string &txt,
                              std::string *buffer);

  static void DecryptBioRead(BIO *bio, std::string *buffer);

 private:
  EasyOpenSSLEnc();

 public:
  ~EasyOpenSSLEnc();

  //! 按照指定算法加密文本，密文使用 BASE64(带换行符) 表示
  /*!
   使用命令 openssl list-cipher-algorithms 查看所有支持的加密算法
   */
  /*!
   * @param[in] cipher_name 加密算法
   * @param[in] plaintext 明文
   * @param[in] key 密钥
   * @param[in] iv 向量
   * @param[out] buffer 密文，密文使用 BASE64(带换行符) 表示
   * @return 布尔
   */
  static bool Encrypt(const std::string &cipher_name,
                      const std::string &plaintext, const std::string &key,
                      const std::string &iv, std::string *buffer);

  //! 按照指定算法解密文本，密文使用 BASE64(带换行符) 表示
  /*!
   使用命令 openssl list-cipher-algorithms 查看所有支持的加密算法
   */
  /*!
   * @param[in] cipher_name 加密算法
   * @param[in] ciphertext 密文，密文使用 BASE64(带换行符) 表示
   * @param[in] key 密钥
   * @param[in] iv 向量
   * @param[out] buffer 明文
   * @return 布尔
   */
  static bool Decrypt(const std::string &cipher_name,
                      const std::string &ciphertext, const std::string &key,
                      const std::string &iv, std::string *buffer);

  //! 获取错误信息
  /*!
   调用其它函数失败，会将错误信息保存到类成员变量 error_ 中。所以，需要使用
   get_last_error() 函数获取错误信息。
   */
  /*!
   * @return 字符串
   */
  static std::string GetLastError();
};

#endif  // INCLUDE_EASYOPENSSL_ENC_H_
