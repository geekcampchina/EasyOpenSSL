IF(MSVC)
  #省略默认库，生成的库文件中不包含libcmt.lib这样的默认库
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /Zl")
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Zl")
ENDIF()

ADD_LIBRARY(easyopenssl ${BUILD_MODE} 
            base64.cc digest.cc enc.cc)

INSTALL(TARGETS easyopenssl DESTINATION lib)