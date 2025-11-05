cmake_minimum_required(VERSION 3.16)

# Find Qt Test module
find_package(Qt6 REQUIRED COMPONENTS Test)

# Helper function to add tests
function(add_keycard_test TEST_NAME)
    add_executable(${TEST_NAME} ${TEST_NAME}.cpp)
    
    target_link_libraries(${TEST_NAME}
        PRIVATE
            status-keycard-qt
            Qt6::Test
            Qt6::Core
    )
    
    target_include_directories(${TEST_NAME}
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../src
            ${KEYCARD_QT_DIR}/include  # Access keycard-qt headers for testing
    )
    
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endfunction()

# Add test executables
add_keycard_test(test_rpc_service)
add_keycard_test(test_session_manager)
add_keycard_test(test_signal_manager)
add_keycard_test(test_c_api)
add_keycard_test(test_pairing_storage)
add_keycard_test(test_integration)

# Coverage target (optional, requires gcov/lcov)
if(CMAKE_BUILD_TYPE MATCHES "Debug")
    option(ENABLE_COVERAGE "Enable code coverage" OFF)
    if(ENABLE_COVERAGE)
        target_compile_options(status-keycard-qt PRIVATE --coverage)
        target_link_options(status-keycard-qt PRIVATE --coverage)
    endif()
endif()
