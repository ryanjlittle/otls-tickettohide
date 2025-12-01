add_executable(tickettohide
    tickettohide.cpp
)
target_link_libraries(tickettohide PRIVATE otls)
option(ENABLE_TTH_TEST "tth test" OFF)
IF(ENABLE_TTH_TEST)
    ENABLE_TESTING()
    ADD_SUBDIRECTORY(test)
ENDIF()