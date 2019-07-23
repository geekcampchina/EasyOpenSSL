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
#include <easyopenssl/digest.h>
#include <openssl/bio.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <boost/filesystem.hpp>
#include <map>
#include <fstream>

namespace bfs = boost::filesystem;

const char *kKey = "123456";
const char *kPlainText = "Hello, World!";

std::string g_test_file("");

TEST(DIGEST_TEST, Init) {
  bfs::path test_file_path(bfs::temp_directory_path());
  test_file_path.append(bfs::unique_path("%%%%%%%%%%%%%%%%").string());
  g_test_file = test_file_path.make_preferred().string();

  std::ofstream ofs(g_test_file, std::ofstream::out);
  ofs << "test";
  ofs.close();

  ASSERT_TRUE(bfs::exists(test_file_path));
}

TEST(DIGEST_TEST, Md5) {
  ASSERT_EQ("65a8e27d8879283831b664bd8b7f0ad4",
            EasyOpenSSLDigest::Md5(kPlainText));
}

TEST(DIGEST_TEST, Md5Sum) {
  ASSERT_EQ("098f6bcd4621d373cade4e832627b4f6",
            EasyOpenSSLDigest::Md5Sum(g_test_file));
}

TEST(DIGEST_TEST, HmacMd5) {
  ASSERT_EQ("999a53e606cb7d95681e2004db63ef77",
            EasyOpenSSLDigest::HmacMd5(kKey, kPlainText));
}

TEST(DIGEST_TEST, Sha1) {
  ASSERT_EQ("0a0a9f2a6772942557ab5355d76af442f8f65e01",
            EasyOpenSSLDigest::Sha1(kPlainText));
}

TEST(DIGEST_TEST, Sha1Sum) {
  ASSERT_EQ("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
            EasyOpenSSLDigest::Sha1Sum(g_test_file));
}

TEST(DIGEST_TEST, HmacSha1) {
  ASSERT_EQ("b3d4fc5cf50489b5f9967277ca6dbc50d3969190",
            EasyOpenSSLDigest::HmacSha1(kKey, kPlainText));
}

TEST(DIGEST_TEST, Sha224) {
  ASSERT_EQ("72a23dfa411ba6fde01dbfabf3b00a709c93ebf2"
            "73dc29e2d8b261ff",
            EasyOpenSSLDigest::Sha224(kPlainText));
}

TEST(DIGEST_TEST, Sha224Sum) {
  ASSERT_EQ("90a3ed9e32b2aaf4c61c410eb925426119e1a9dc5"
            "3d4286ade99a809",
            EasyOpenSSLDigest::Sha224Sum(g_test_file));
}

TEST(DIGEST_TEST, HmacSha224) {
  ASSERT_EQ("bf25a8ba23b97a8da673ffab63a3e428ada55231"
            "78a9832d946cfa15",
            EasyOpenSSLDigest::HmacSha224(kKey, kPlainText));
}

TEST(DIGEST_TEST, Sha256) {
  ASSERT_EQ("dffd6021bb2bd5b0af676290809ec3a53191dd81"
            "c7f70a4b28688a362182986f",
            EasyOpenSSLDigest::Sha256(kPlainText));
}

TEST(DIGEST_TEST, Sha256Sum) {
  ASSERT_EQ("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2"
            "b0b822cd15d6c15b0f00a08",
            EasyOpenSSLDigest::Sha256Sum(g_test_file));
}

TEST(DIGEST_TEST, HmacSha256) {
  ASSERT_EQ("fe2cf3347d7855c9d6ecb8f6aeea8eeb24fa1bef"
            "21aea4c36a05ed423259bb8a",
            EasyOpenSSLDigest::HmacSha256(kKey, kPlainText));
}

TEST(DIGEST_TEST, Sha384) {
  ASSERT_EQ("5485cc9b3365b4305dfb4e8337e0a598a574f824"
            "2bf17289e0dd6c20a3cd44a089de16ab4ab308f6"
            "3e44b1170eb5f515",
            EasyOpenSSLDigest::Sha384(kPlainText));
}

TEST(DIGEST_TEST, Sha384Sum) {
  ASSERT_EQ("768412320f7b0aa5812fce428dc4706b3cae50e02"
            "a64caa16a782249bfe8efc4b7ef1ccb126255d196"
            "047dfedf17a0a9",
            EasyOpenSSLDigest::Sha384Sum(g_test_file));
}

TEST(DIGEST_TEST, HmacSha384) {
  ASSERT_EQ("a53930e5c7a138ac301544843401e1cfe88930d1"
            "54ab1ab170dca95cb6a1cbec1b7e8d49a6b78a3a"
            "e9f132f5534328a7",
            EasyOpenSSLDigest::HmacSha384(kKey, kPlainText));
}

TEST(DIGEST_TEST, Sha512) {
  ASSERT_EQ("374d794a95cdcfd8b35993185fef9ba368f160d8"
            "daf432d08ba9f1ed1e5abe6cc69291e0fa2fe000"
            "6a52570ef18c19def4e617c33ce52ef0a6e5fbe3"
            "18cb0387",
            EasyOpenSSLDigest::Sha512(kPlainText));
}

TEST(DIGEST_TEST, Sha512Sum) {
  ASSERT_EQ("ee26b0dd4af7e749aa1a8ee3c10ae9923f6189807"
            "72e473f8819a5d4940e0db27ac185f8a0e1d5f84f"
            "88bc887fd67b143732c304cc5fa9ad8e6f57f5002"
            "8a8ff",
            EasyOpenSSLDigest::Sha512Sum(g_test_file));
}

TEST(DIGEST_TEST, HmacSha512) {
  ASSERT_EQ("8140e9625edd4efabbd44dcfc0a46b24c8678a53"
            "a8a04d63df5f0c8004c204896b1bedda26461003"
            "3f8762e11f65cb04064156e867942c223fb314ed"
            "c6637103",
            EasyOpenSSLDigest::HmacSha512(kKey, kPlainText));
}

TEST(DIGEST_TEST, Clean) {
  bfs::remove(g_test_file);
}
