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

/** @file */

#ifndef INCLUDE_EASYOPENSSL_BASE64_H_
#define INCLUDE_EASYOPENSSL_BASE64_H_

#include <string>

//! Base64 解码/编码
class EasyOpenSSLBase64 {
 private:
  EasyOpenSSLBase64();

 public:
  ~EasyOpenSSLBase64();

  //! 计算 Base64 字符串解码后的字符串长度
  /*!
   Base64：http://zh.wikipedia.org/zh/Base64
   将 3 byte 的数据，放入一个24bit的缓冲区中。
   数据不足 3 byte 的话，缓冲区剩下的bit用0补足(Base64中的等号)。
   然后，每次取出 6 个 bit。不断进行，直到全部输入数据转换完成。

   补0说明：
   1. 如果要编码的字节数不能被3整除，最后会多出1个或2个字节， 那么可以使用下面的方法进行处理：
   先使用0字节值在末尾补足，使其能够被3整除，然后再进行base64的编码。
   在编码后的base64文本后加上一个或两个'='号，代表补足的字节数。也就是说，
   2. 如果最后剩余一个八位字节（1个byte）时，最后一个6位的base64字节块有四位是0值，最后附加
   上2个等号；
   3. 如果最后剩余两个八位字节（2个byte）时，最后一个6位的base字节块有两位是0值，最后附加1个
   等号。

   也就是
   1 byte = 8 bit
   1 base64 = 6 bit(可能含末尾补足的0)

   明文长度 = (密文长度 * 6) / 8 - 等号数量
   明文长度 = (密文长度 * 3) / 4 - 等号数量
   */
  static size_t ComputeSize(const std::string &base64);

  //! Base64 字符串编码
  /*!
   * @param[in] plaintext 明文
   * @return 编码的 Base64 字符串
   */
  static std::string Encode(const std::string &plaintext);

  //! Base64 字符串解码
  /*!
   * @param[in] 编码的 Base64 字符串
   * @return 明文字符串
   */
  static std::string Decode(const std::string &base64);
};

#endif  // INCLUDE_EASYOPENSSL_BASE64_H_
