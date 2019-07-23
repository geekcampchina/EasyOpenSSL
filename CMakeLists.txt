CMAKE_MINIMUM_REQUIRED(VERSION 3.5)

PROJECT(EasyOpenSSL)

IF(MSVC)
  SET(BUILD_MODE STATIC)
ELSE()
  SET(BUILD_MODE SHARED)
ENDIF()

# 设置默认 CMAKE_BUILD_TYPE 为 release
IF(NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE Release
      CACHE STRING
      "Choose the type of build, options are: Debug Release \
          RelWithDebInfo MinSizeRel."
      FORCE)
ENDIF(NOT CMAKE_BUILD_TYPE)

INCLUDE(cmake/CompilerChecks.cmake)
INCLUDE(cmake/CompilerFlags.cmake)
INCLUDE(cmake/FindPackage.cmake)
INCLUDE(cmake/OutputDir.cmake)

INCLUDE_DIRECTORIES("include")

ENABLE_TESTING()

# CMAKE_INSTALL_PREFIX 只能在主 CMake 配置中生效，不能在包含的其它目录设置
# 设置安装路径
# 在 64 位系统上，32 位程序会安装到 C:/Program Files (x86)
# 在 64 位系统上，64 位程序会安装到 C:/Program Files
# 在 32 位系统上，程序会安装到 C:/Program Files
IF(MSVC)
  string(REPLACE
      "EasyOpenSSL"
      "Geek Camp China"
      NEW_INSTALL_PREFIX
      ${CMAKE_INSTALL_PREFIX})
  SET(CMAKE_INSTALL_PREFIX ${NEW_INSTALL_PREFIX})
ENDIF()

ADD_SUBDIRECTORY(src)
ADD_SUBDIRECTORY(test)
