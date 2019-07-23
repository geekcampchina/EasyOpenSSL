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

#ifndef INCLUDE_EASYOPENSSL_DIGEST_H_
#define INCLUDE_EASYOPENSSL_DIGEST_H_

#include <openssl/evp.h>
#include <string>

//! 摘要算法类
class EasyOpenSSLDigest {
 private:
  EasyOpenSSLDigest();

  //! 计算摘要
  /*!
   * @param[in] md 摘要算法
   * @param[in] type 消息来源类型，0表示文件，1表示字符串
   * @param[in] msg 消息
   * @return 摘要
   */
  static std::string Calculate(const EVP_MD *md, const int msg_type,
                               const std::string &msg);

  //! 计算密钥散列消息认证码
  /*!
   * @param[in] md 密钥散列算法
   * @param[in] key 密钥
   * @param[in] msg 消息
   * @return 消息认证码
   */
  static std::string CalculateHmac(const EVP_MD *md, const std::string &key,
                                   const std::string &msg);

 public:
  ~EasyOpenSSLDigest();

  //! 计算字符串的 MD5 摘要
  /*!
   * @param[in] msg 消息
   * @return 摘要
   */
  static std::string Md5(const std::string &msg);

  //! 计算文件的 MD5 校验值
  /*!
   * @param[in] file 文件
   * @return 校验值
   */
  static std::string Md5Sum(const std::string &file);

  //! 基于 MD5 摘要算法计算密钥散列消息认证码
  /*!
   * @param[in] key 密钥
   * @param[in] msg 消息
   * @return 消息认证码
   */
  static std::string HmacMd5(const std::string &key, const std::string &msg);

  //! 计算字符串的 SHA-1 摘要
  /*!
   * @param[in] msg 消息
   * @return 摘要
   */
  static std::string Sha1(const std::string &msg);

  //! 计算文件的 SHA-1 校验值
  /*!
   * @param[in] file 文件
   * @return 校验值
   */
  static std::string Sha1Sum(const std::string &file);

  //! 基于 SHA-1 摘要算法计算密钥散列消息认证码
  /*!
   * @param[in] key 密钥
   * @param[in] msg 消息
   * @return 消息认证码
   */
  static std::string HmacSha1(const std::string &key, const std::string &msg);

  //! 计算字符串的 SHA-224 摘要
  /*!
   * @param[in] msg 消息
   * @return 摘要
   */
  static std::string Sha224(const std::string &msg);

  //! 计算文件的 SHA-224 校验值
  /*!
   * @param[in] file 文件
   * @return 校验值
   */
  static std::string Sha224Sum(const std::string &file);

  //! 基于 SHA-224 摘要算法计算密钥散列消息认证码
  /*!
   * @param[in] key 密钥
   * @param[in] msg 消息
   * @return 消息认证码
   */
  static std::string HmacSha224(const std::string &key,
                                const std::string &msg);

  //! 计算字符串的 SHA-256 摘要
  /*!
   * @param[in] msg 消息
   * @return 摘要
   */
  static std::string Sha256(const std::string &msg);

  //! 计算文件的 SHA-256 校验值
  /*!
   * @param[in] file 文件
   * @return 校验值
   */
  static std::string Sha256Sum(const std::string &file);

  //! 基于 SHA-256 摘要算法计算密钥散列消息认证码
  /*!
   * @param[in] key 密钥
   * @param[in] msg 消息
   * @return 消息认证码
   */
  static std::string HmacSha256(const std::string &key,
                                const std::string &msg);

  //! 计算字符串的 SHA-384 摘要
  /*!
   * @param[in] msg 消息
   * @return 摘要
   */
  static std::string Sha384(const std::string &msg);

  //! 计算文件的 SHA-384 校验值
  /*!
   * @param[in] file 文件
   * @return 校验值
   */
  static std::string Sha384Sum(const std::string &file);

  //! 基于 SHA-384 摘要算法计算密钥散列消息认证码
  /*!
   * @param[in] key 密钥
   * @param[in] msg 消息
   * @return 消息认证码
   */
  static std::string HmacSha384(const std::string &key,
                                const std::string &msg);

  //! 计算字符串的 SHA-512 摘要
  /*!
   * @param[in] msg 消息
   * @return 摘要
   */
  static std::string Sha512(const std::string &msg);

  //! 计算文件的 SHA-512 校验值
  /*!
   * @param[in] file 文件
   * @return 校验值
   */
  static std::string Sha512Sum(const std::string &file);

  //! 基于 SHA-512 摘要算法计算密钥散列消息认证码
  /*!
   * @param[in] key 密钥
   * @param[in] msg 消息
   * @return 消息认证码
   */
  static std::string HmacSha512(const std::string &key,
                                const std::string &msg);
};

#endif  // INCLUDE_EASYOPENSSL_DIGEST_H_
