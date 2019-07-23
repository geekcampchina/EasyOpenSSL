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

#include <gtest/gtest.h>
#include <easyopenssl/enc.h>

const char *kPlainText = "Hello, World!";
const char *kCiphertext = "kMVCdzL/f+smepEw7NyESQ==";

const char *kKey = "0123456789:;<=>?@ABCDEFGHIJKLMNO";
const char *kIv = "0123456789:;<=>?";
const char *CIPHER_NAME = "AES-256-CBC";

TEST(ENC_TEST, EasyOpenSSLEnc_Encrypt) {
  std::string buffer("");
  const bool ret_val = EasyOpenSSLEnc::Encrypt(CIPHER_NAME, kPlainText, kKey,
                                               kIv, &buffer);

  ASSERT_TRUE(ret_val);
  ASSERT_EQ(kCiphertext, buffer);
}

TEST(ENC_TEST, EasyOpenSSLEnc_Decrypt) {
  std::string buffer("");
  const bool ret_val = EasyOpenSSLEnc::Decrypt(CIPHER_NAME, kCiphertext,
                                               kKey, kIv, &buffer);

  ASSERT_TRUE(ret_val);
  ASSERT_EQ(kPlainText, buffer);
}

TEST(ENC_TEST, EasyOpenSSLEnc_GetLastError) {
  std::string buffer("");
  const bool ret_val = EasyOpenSSLEnc::Encrypt("AES-test123-CBC",
                                               kCiphertext, kKey, kIv,
                                               &buffer);

  ASSERT_FALSE(ret_val);
  ASSERT_EQ("", buffer);
  ASSERT_EQ("Invalid cipher algorithm.", EasyOpenSSLEnc::GetLastError());
}
