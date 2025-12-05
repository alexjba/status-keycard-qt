cmake_minimum_required(VERSION 3.16)

# Find Qt Test module
find_package(Qt6 REQUIRED COMPONENTS Test)

# Helper function to add tests
function(add_keycard_test TEST_NAME)
    # Check if there are additional source files
    if(${ARGC} GREATER 1)
        set(EXTRA_SOURCES ${ARGN})
        add_executable(${TEST_NAME} ${TEST_NAME}.cpp ${EXTRA_SOURCES})
    else()
        add_executable(${TEST_NAME} ${TEST_NAME}.cpp)
    endif()
    
    target_link_libraries(${TEST_NAME}
        PRIVATE
            status-keycard-qt
            Qt6::Test
            Qt6::Core
            Qt6::Concurrent
    )
    
    target_include_directories(${TEST_NAME}
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../src
            ${CMAKE_CURRENT_SOURCE_DIR}  # For test headers/mocks
            ${KEYCARD_QT_DIR}/include  # Access keycard-qt headers for testing
    )
    
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endfunction()

# Add test executables
add_keycard_test(test_rpc_service)
add_keycard_test(test_session_manager mocks/mock_keycard_backend.cpp)
add_keycard_test(test_signal_manager)

# Flow API tests (pure logic - NO hardware, runs instantly)
add_keycard_test(test_flow_logic_only)

# Flow API tests (mock APDU responses)
add_keycard_test(test_flow_with_mock_backend mocks/mock_keycard_backend.cpp)

# Flow signal routing test (proves signals reach SignalManager)
add_keycard_test(test_flow_signal_routing mocks/mock_keycard_backend.cpp)

# Flow API tests (require hardware - disabled by default)
# State machine test is pure logic - NO hardware needed, always enabled!
add_keycard_test(test_flow_state_machine)

# SignFlow TLV parsing and ECDSA recovery tests (pure logic - NO hardware)
add_executable(test_sign_flow_tlv_parsing test_sign_flow_tlv_parsing.cpp)
target_link_libraries(test_sign_flow_tlv_parsing
    PRIVATE
        status-keycard-qt
        Qt6::Test
        Qt6::Core
        Qt6::Concurrent
        OpenSSL::Crypto  # Required for ECDSA operations
)
target_include_directories(test_sign_flow_tlv_parsing
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${KEYCARD_QT_DIR}/include
)
add_test(NAME test_sign_flow_tlv_parsing COMMAND test_sign_flow_tlv_parsing)

# Flow signals constants test (pure logic - NO hardware needed)
add_keycard_test(test_flow_signals)

# Coverage target (optional, requires gcov/lcov)
if(CMAKE_BUILD_TYPE MATCHES "Debug")
    option(ENABLE_COVERAGE "Enable code coverage" OFF)
    if(ENABLE_COVERAGE)
        target_compile_options(status-keycard-qt PRIVATE --coverage)
        target_link_options(status-keycard-qt PRIVATE --coverage)
    endif()
endif()
