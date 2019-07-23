FUNCTION(ADD_UNITTEST unittest_name src_files)
  ADD_EXECUTABLE(${unittest_name} ${src_files})
  TARGET_LINK_LIBRARIES(${unittest_name}
                        easyopenssl
                        ${Boost_LIBRARIES}
                        ${GTEST_BOTH_LIBRARIES}
                        ${OPENSSL_CRYPTO_LIBRARY})

  ADD_TEST(NAME ${unittest_name} COMMAND ${unittest_name})
ENDFUNCTION(ADD_UNITTEST)

ADD_UNITTEST(base64_test base64_test.cc)
ADD_UNITTEST(digest_test digest_test.cc)
ADD_UNITTEST(enc_test enc_test.cc)