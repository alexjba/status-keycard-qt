cmake_minimum_required(VERSION 3.16)
project(status-keycard-qt VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Options - Save user preferences before adding keycard-qt
option(BUILD_TESTING "Build unit tests" ON)
option(BUILD_EXAMPLES "Build example applications" OFF)
set(STATUS_KEYCARD_BUILD_TESTING ${BUILD_TESTING})  # Save status-keycard-qt test preference
set(STATUS_KEYCARD_BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS})  # Save status-keycard-qt library type preference

# Find dependencies
find_package(Qt6 REQUIRED COMPONENTS Core Nfc Concurrent)

# OpenSSL is REQUIRED for key derivation (secp256k1 public key derivation)
# For Android and iOS, we use manually provided paths instead of find_package
if((ANDROID OR IOS) AND OPENSSL_CRYPTO_LIBRARY)
    if(NOT OPENSSL_BUILD_INCLUDE_DIR OR NOT OPENSSL_SOURCE_INCLUDE_DIR)
        message(FATAL_ERROR "OPENSSL_BUILD_INCLUDE_DIR and OPENSSL_SOURCE_INCLUDE_DIR are required for mobile builds")
    endif()
    set(OpenSSL_FOUND TRUE)
    if(ANDROID)
        message(STATUS "Using manually provided OpenSSL for Android (status-keycard-qt)")
    else()
        message(STATUS "Using manually provided OpenSSL for iOS (status-keycard-qt)")
    endif()
    message(STATUS "  Build include dir: ${OPENSSL_BUILD_INCLUDE_DIR}")
    message(STATUS "  Source include dir: ${OPENSSL_SOURCE_INCLUDE_DIR}")
else()
    find_package(OpenSSL REQUIRED)
    message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
endif()

# Fetch keycard-qt dependency using CMake FetchContent
include(FetchContent)

# ============================================================================
# Keycard-Qt Configuration Options
# ============================================================================

# Disable keycard-qt tests, examples
set(BUILD_TESTING OFF CACHE BOOL "Disable keycard-qt tests" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "Disable keycard-qt examples" FORCE)

# Force keycard-qt to build as a static library
# This will be linked into status-keycard-qt, so only one library is needed
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build keycard-qt as static library" FORCE)

# Android NFC Backend Configuration
if(ANDROID)
    # Option 1: USE_ANDROID_NFC_BACKEND (default: ON)
    # - ON:  Use direct Android NFC JNI backend (recommended, includes JAR)
    # - OFF: Use Qt NFC backend (requires ENABLE_QT_NFC_ANDROID_WORKAROUNDS)
    option(USE_ANDROID_NFC_BACKEND "Use direct Android NFC backend instead of Qt NFC" ON)
    
    # Option 2: ENABLE_QT_NFC_ANDROID_WORKAROUNDS (default: OFF if using Android backend)
    # - Only needed if USE_ANDROID_NFC_BACKEND=OFF
    # - Works around Qt 6.9.x NFC bugs on Android
    if(USE_ANDROID_NFC_BACKEND)
        option(ENABLE_QT_NFC_ANDROID_WORKAROUNDS "Enable Qt 6.9.x NFC workarounds" OFF)
    else()
        option(ENABLE_QT_NFC_ANDROID_WORKAROUNDS "Enable Qt 6.9.x NFC workarounds" ON)
    endif()
    
    message(STATUS "=== Android NFC Configuration ===")
    message(STATUS "  USE_ANDROID_NFC_BACKEND: ${USE_ANDROID_NFC_BACKEND}")
    message(STATUS "  ENABLE_QT_NFC_ANDROID_WORKAROUNDS: ${ENABLE_QT_NFC_ANDROID_WORKAROUNDS}")
    message(STATUS "=================================")
endif()

# Fetch keycard-qt with configuration
# Allow using local keycard-qt for development/testing
if(DEFINED KEYCARD_QT_SOURCE_DIR AND EXISTS "${KEYCARD_QT_SOURCE_DIR}/CMakeLists.txt")
    message(STATUS "Using local keycard-qt from: ${KEYCARD_QT_SOURCE_DIR}")
    FetchContent_Declare(
      keycard-qt
      SOURCE_DIR ${KEYCARD_QT_SOURCE_DIR}
    )
else()
    message(STATUS "Fetching keycard-qt from Git repository...")
    FetchContent_Declare(
      keycard-qt
      GIT_REPOSITORY https://github.com/alexjba/keycard-qt
      GIT_TAG master  # TODO: Update to specific tag/commit when available
    )
endif()

FetchContent_MakeAvailable(keycard-qt)

# Restore status-keycard-qt preferences
set(BUILD_TESTING ${STATUS_KEYCARD_BUILD_TESTING} CACHE BOOL "Build status-keycard-qt tests" FORCE)
set(BUILD_SHARED_LIBS ${STATUS_KEYCARD_BUILD_SHARED_LIBS} CACHE BOOL "Build status-keycard-qt as shared/static" FORCE)

# Set KEYCARD_QT_DIR for compatibility
set(KEYCARD_QT_DIR "${keycard-qt_SOURCE_DIR}")

# Library sources
set(SOURCES
    src/c_api.cpp
    src/session/session_manager.cpp
    src/storage/pairing_storage.cpp
    src/storage/file_pairing_storage.cpp
    src/signal_manager.cpp
    src/rpc/rpc_service.cpp
    # Flow API
    src/flow/flow_signals.cpp
    src/flow/flow_state_machine.cpp
    src/flow/flow_manager.cpp
    src/flow/flows/flow_base.cpp
    # Flow implementations
    src/flow/flows/login_flow.cpp
    src/flow/flows/get_app_info_flow.cpp
    src/flow/flows/recover_account_flow.cpp
    src/flow/flows/load_account_flow.cpp
    src/flow/flows/sign_flow.cpp
    src/flow/flows/change_pin_flow.cpp
    src/flow/flows/change_puk_flow.cpp
    src/flow/flows/change_pairing_flow.cpp
    src/flow/flows/export_public_flow.cpp
    src/flow/flows/get_metadata_flow.cpp
    src/flow/flows/store_metadata_flow.cpp
)

if(ANDROID)
    list(APPEND SOURCES 
        src/android_nfc_bridge.cpp
    )
endif()

# Create library (shared or static based on BUILD_SHARED_LIBS)
add_library(status-keycard-qt ${SOURCES})

# CRITICAL: For Android builds, ensure the NFC JAR is built and published BEFORE
# this library is built, so the Android app can resolve the Maven dependency
if(ANDROID AND TARGET android-nfc-jar)
    add_dependencies(status-keycard-qt android-nfc-jar)
    message(STATUS "Added dependency: status-keycard-qt -> android-nfc-jar")
    message(STATUS "  JAR will be published to Maven Local before library build")
endif()

target_include_directories(status-keycard-qt
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(status-keycard-qt
    PUBLIC
        Qt6::Core
        Qt6::Nfc
        Qt6::Concurrent
    PRIVATE
        keycard-qt  # Linked privately so it's absorbed into libstatus-keycard-qt
)

# When building as a static library, bundle keycard-qt into status-keycard-qt
# This ensures consumers only need to link against status-keycard-qt
if(NOT BUILD_SHARED_LIBS)
    message(STATUS "Building status-keycard-qt as STATIC library - bundling keycard-qt")
    
    # Use a custom command to combine the static libraries after build
    # This is platform-specific:
    # - On Unix/macOS: Use ar or libtool
    # - On Windows: Use lib.exe
    
    if(APPLE)
        # On macOS and iOS, use libtool to combine static libraries
        add_custom_command(TARGET status-keycard-qt POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E echo "Bundling keycard-qt into status-keycard-qt..."
            COMMAND libtool -static -o 
                $<TARGET_FILE:status-keycard-qt>.tmp
                $<TARGET_FILE:status-keycard-qt>
                $<TARGET_FILE:keycard-qt>
            COMMAND ${CMAKE_COMMAND} -E rename
                $<TARGET_FILE:status-keycard-qt>.tmp
                $<TARGET_FILE:status-keycard-qt>
            COMMENT "Combining static libraries using libtool (macOS/iOS)"
            VERBATIM
        )
    elseif(MSVC)
        # On Windows with MSVC, use lib.exe
        add_custom_command(TARGET status-keycard-qt POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E echo "Bundling keycard-qt into status-keycard-qt..."
            COMMAND lib.exe /OUT:$<TARGET_FILE:status-keycard-qt>.tmp
                $<TARGET_FILE:status-keycard-qt>
                $<TARGET_FILE:keycard-qt>
            COMMAND ${CMAKE_COMMAND} -E rename
                $<TARGET_FILE:status-keycard-qt>.tmp
                $<TARGET_FILE:status-keycard-qt>
            COMMENT "Combining static libraries using lib.exe (MSVC)"
            VERBATIM
        )
    else()
        # On Linux, Android, Windows MinGW, and other Unix-like systems, use ar with MRI script
        # This covers: Linux, Android NDK, MinGW/MSYS2, Cygwin, etc.
        add_custom_command(TARGET status-keycard-qt POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E echo "Bundling keycard-qt into status-keycard-qt..."
            COMMAND ${CMAKE_COMMAND} -E echo "CREATE $<TARGET_FILE:status-keycard-qt>.tmp" > ${CMAKE_CURRENT_BINARY_DIR}/combine.mri
            COMMAND ${CMAKE_COMMAND} -E echo "ADDLIB $<TARGET_FILE:status-keycard-qt>" >> ${CMAKE_CURRENT_BINARY_DIR}/combine.mri
            COMMAND ${CMAKE_COMMAND} -E echo "ADDLIB $<TARGET_FILE:keycard-qt>" >> ${CMAKE_CURRENT_BINARY_DIR}/combine.mri
            COMMAND ${CMAKE_COMMAND} -E echo "SAVE" >> ${CMAKE_CURRENT_BINARY_DIR}/combine.mri
            COMMAND ${CMAKE_COMMAND} -E echo "END" >> ${CMAKE_CURRENT_BINARY_DIR}/combine.mri
            COMMAND ${CMAKE_AR} -M < ${CMAKE_CURRENT_BINARY_DIR}/combine.mri
            COMMAND ${CMAKE_COMMAND} -E rename
                $<TARGET_FILE:status-keycard-qt>.tmp
                $<TARGET_FILE:status-keycard-qt>
            COMMENT "Combining static libraries using ar (Linux/Android/MinGW)"
            VERBATIM
        )
    endif()
    
    # Ensure keycard-qt is built before we try to bundle it
    add_dependencies(status-keycard-qt keycard-qt)
endif()

# Link PC/SC framework on Apple platforms (desktop only, not iOS)
# This is needed because keycard-qt uses PC/SC on desktop and links it privately
if(APPLE AND NOT IOS)
    find_library(PCSC_LIBRARY PCSC)
    if(PCSC_LIBRARY)
        target_link_libraries(status-keycard-qt PRIVATE ${PCSC_LIBRARY})
        message(STATUS "Found PCSC framework for status-keycard-qt: ${PCSC_LIBRARY}")
    else()
        message(WARNING "PCSC framework not found")
    endif()
endif()

# Link PC/SC library on Linux (not Android)
if(UNIX AND NOT APPLE AND NOT ANDROID)
    # Use pkg-config to get PC/SC include paths and libraries
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(PCSC libpcsclite)
        if(PCSC_FOUND)
            target_link_libraries(status-keycard-qt PRIVATE ${PCSC_LIBRARIES})
            message(STATUS "Found PC/SC via pkg-config for status-keycard-qt: ${PCSC_VERSION}")
        else()
            message(WARNING "PC/SC not found via pkg-config")
        endif()
    else()
        # Fallback to find_library if pkg-config not available
        find_library(PCSCLITE_LIBRARY pcsclite)
        if(PCSCLITE_LIBRARY)
            target_link_libraries(status-keycard-qt PRIVATE ${PCSCLITE_LIBRARY})
            message(STATUS "Found PC/SC library for status-keycard-qt: ${PCSCLITE_LIBRARY}")
        else()
            message(WARNING "PC/SC library not found")
        endif()
    endif()
endif()

# OpenSSL support (for key derivation)
# For Android and iOS with manually provided paths, link directly and add include directories
if((ANDROID OR IOS) AND OPENSSL_CRYPTO_LIBRARY)
    message(STATUS "Linking status-keycard-qt against OpenSSL crypto library: ${OPENSSL_CRYPTO_LIBRARY}")
    target_link_libraries(status-keycard-qt PUBLIC ${OPENSSL_CRYPTO_LIBRARY})
    
    # Check if OpenSSL headers are available
    set(OPENSSL_INCLUDES_AVAILABLE FALSE)
    
    # Add include directories
    # For OpenSSL 3.x on Android/iOS, we can use source headers directly
    set(OPENSSL_INCLUDES_AVAILABLE FALSE)
    
    # Check if source headers exist (these are the main API headers)
    if(EXISTS "${OPENSSL_SOURCE_INCLUDE_DIR}")
        message(STATUS "Adding OpenSSL source include dir: ${OPENSSL_SOURCE_INCLUDE_DIR}")
        target_include_directories(status-keycard-qt PRIVATE ${OPENSSL_SOURCE_INCLUDE_DIR})
        set(OPENSSL_INCLUDES_AVAILABLE TRUE)
        
        # Also add build dir if it exists (has generated configuration.h)
        if(EXISTS "${OPENSSL_BUILD_INCLUDE_DIR}")
            message(STATUS "Adding OpenSSL build include dir: ${OPENSSL_BUILD_INCLUDE_DIR}")
            target_include_directories(status-keycard-qt PRIVATE ${OPENSSL_BUILD_INCLUDE_DIR})
        else()
            message(STATUS "OpenSSL build includes not found (using source headers only)")
        endif()
    else()
        message(WARNING "OpenSSL source include dir not found: ${OPENSSL_SOURCE_INCLUDE_DIR}")
        message(WARNING "OpenSSL headers not available. Building WITHOUT OpenSSL support.")
    endif()
    
    # Define KEYCARD_QT_HAS_OPENSSL if we have headers AND library
    if(OPENSSL_INCLUDES_AVAILABLE AND EXISTS "${OPENSSL_CRYPTO_LIBRARY}")
        target_compile_definitions(status-keycard-qt PRIVATE KEYCARD_QT_HAS_OPENSSL)
        message(STATUS "OpenSSL support: ENABLED (library + headers available)")
    else()
        message(STATUS "OpenSSL support: DISABLED (missing library or headers)")
    endif()
else()
    # For other platforms, use the imported target
    target_link_libraries(status-keycard-qt PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(status-keycard-qt PRIVATE KEYCARD_QT_HAS_OPENSSL)
    message(STATUS "OpenSSL support enabled for status-keycard-qt")
endif()

# Set library properties
set_target_properties(status-keycard-qt PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    OUTPUT_NAME "status-keycard-qt"
)

# Installation
install(TARGETS status-keycard-qt
    EXPORT status-keycard-qt-targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/
    DESTINATION include
)

# Tests
if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

# Examples
if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Summary
message(STATUS "=== status-keycard-qt configuration ===")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Build testing: ${BUILD_TESTING}")
message(STATUS "Build examples: ${BUILD_EXAMPLES}")
if(BUILD_SHARED_LIBS)
    message(STATUS "Library type: SHARED")
    message(STATUS "keycard-qt bundling: N/A (shared library)")
else()
    message(STATUS "Library type: STATIC")
    message(STATUS "keycard-qt bundling: ENABLED (combined into single archive)")
endif()
message(STATUS "Qt6 version: ${Qt6_VERSION}")
message(STATUS "keycard-qt location: ${KEYCARD_QT_DIR}")
