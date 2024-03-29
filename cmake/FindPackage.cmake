LIST(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules/")

IF(MSVC)
  # 解决 GTest 编译报错：“std::tuple”: 模板 参数太多
  ADD_DEFINITIONS("-D_VARIADIC_MAX=10")
ENDIF()

FIND_PACKAGE(GTest REQUIRED)
INCLUDE_DIRECTORIES(${GTEST_INCLUDE_DIRS})

IF(MSVC)
  SET(Boost_USE_STATIC_LIBS ON)
  SET(Boost_USE_STATIC_RUNTIME ON)
  SET(Boost_USE_MULTITHREADED ON)
  SET(Boost_USE_DEBUG_RUNTIME ON)
ENDIF()

FIND_PACKAGE(Boost 1.60.0 REQUIRED COMPONENTS filesystem system)
INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIRS})

FIND_PACKAGE(OpenSSL REQUIRED)
INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})