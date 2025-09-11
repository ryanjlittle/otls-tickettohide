cmake_minimum_required (VERSION 3.0 VERSION 4.0)
project (otls)
set(NAME "otls")

IF(ENABLE_WASM)
  set(CMAKE_FOLDER ${CMAKE_INSTALL_PREFIX})
  include(${CMAKE_FOLDER}/cmake/emp-base.cmake)

  find_package(OpenSSL REQUIRED)
  include_directories(${OPENSSL_INCLUDE_DIR})

  set(EMP-TOOL_INCLUDE_DIRS ${CMAKE_INSTALL_PREFIX}/include)
  set(EMP-TOOL_LIBRARIES ${CMAKE_INSTALL_PREFIX}/lib/libemp-tool.a ${OPENSSL_LIBRARIES})
  include_directories(${EMP-TOOL_INCLUDE_DIRS})

  set(EMP-OT_INCLUDE_DIRS ${CMAKE_INSTALL_PREFIX}/include)
  set(EMP-OT_LIBRARIES "")
  include_directories(${EMP-OT_INCLUDE_DIRS})

  set(EMP-ZK_INCLUDE_DIRS ${CMAKE_INSTALL_PREFIX}/include)
  set(EMP-ZK_LIBRARIES ${CMAKE_INSTALL_PREFIX}/lib/libemp-zk.a)
  include_directories(${EMP-ZK_INCLUDE_DIRS})
ELSE()
  find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
  include(${CMAKE_FOLDER}/cmake/emp-base.cmake)

  find_package(emp-ot REQUIRED)
  include_directories(${EMP-OT_INCLUDE_DIRS})

  find_package(emp-zk REQUIRED)
  include_directories(${EMP-ZK_INCLUDE_DIRS})
ENDIF()

set(OTLS_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(TTH_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tickettohide)

include_directories(${OTLS_SOURCE_DIR})
set(sources
  src/backend/switch.cpp
  src/cipher/utils.cpp
)
option(LOAD_CIRCUIT_FROM_MEM "" OFF)
IF(LOAD_CIRCUIT_FROM_MEM)
  add_definitions(-DLOAD_CIRCUIT_FROM_MEM=1)
  list(APPEND sources
    src/cipher/circuit_files/aes128_ks_data.cpp
    src/cipher/circuit_files/aes128_with_ks_data.cpp
  )
ENDIF()
option(USE_PRIMUS_EMP "use primus emp" OFF)
IF(USE_PRIMUS_EMP)
  add_definitions(-DUSE_PRIMUS_EMP=1)
ENDIF()
add_compile_options(-fPIC)
IF(USE_PRIMUS_EMP)
add_library(otls ${sources})
ELSE()
add_library(otls SHARED ${sources})
ENDIF()
target_link_libraries(otls ${EMP-TOOL_LIBRARIES} ${EMP-ZK_LIBRARIES} dl)

install(FILES cmake/otls-config.cmake DESTINATION cmake/)
install(TARGETS otls DESTINATION lib)

install(DIRECTORY src/backend src/cipher src/protocol DESTINATION include)

option(ENABLE_OTLS_TEST "otls test" ON)
IF(ENABLE_OTLS_TEST)
  ENABLE_TESTING()
  ADD_SUBDIRECTORY(src/test)
ENDIF()

option(ENABLE_TTH "ticket to hide" ON)
IF(ENABLE_TTH)
  add_executable(tickettohide
    tickettohide/tickettohide.cpp
  )
  target_link_libraries(tickettohide PRIVATE otls)
  add_executable(tickettohide_test
    tickettohide/tickettohide_test.cpp
  )
  target_link_libraries(tickettohide_test PRIVATE otls)
  add_executable(hmac_test
    tickettohide/hmac_test.cpp
  )
  target_link_libraries(hmac_test PRIVATE otls)
ENDIF()