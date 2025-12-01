set(sources
        backend/switch.cpp
        cipher/utils.cpp
)
option(LOAD_CIRCUIT_FROM_MEM "" OFF)
IF(LOAD_CIRCUIT_FROM_MEM)
    add_definitions(-DLOAD_CIRCUIT_FROM_MEM=1)
    list(APPEND sources
            cipher/circuit_files/aes128_ks_data.cpp
            cipher/circuit_files/aes128_with_ks_data.cpp
    )
ENDIF()
option(USE_PRIMUS_EMP "use primus emp" ON)
IF(USE_PRIMUS_EMP)
    add_definitions(-DUSE_PRIMUS_EMP=1)
ENDIF()

add_compile_options(-fPIC)
IF(USE_PRIMUS_EMP)
    add_library(otls ${sources})
ELSE()
    add_library(otls SHARED ${sources})
ENDIF()

target_include_directories(otls PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(otls ${EMP-TOOL_LIBRARIES} ${EMP-ZK_LIBRARIES} dl)

install(TARGETS otls DESTINATION lib)
install(DIRECTORY backend cipher protocol DESTINATION include)

option(ENABLE_OTLS_TEST "otls test" OFF)
IF(ENABLE_OTLS_TEST)
    ENABLE_TESTING()
    ADD_SUBDIRECTORY(test)
ENDIF()