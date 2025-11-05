#ifndef STATUS_KEYCARD_H
#define STATUS_KEYCARD_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file status_keycard.h
 * @brief C API for Status Keycard - Compatible with nim-keycard-go
 * 
 * This library provides the EXACT same C API as status-keycard-go
 * so that nim-keycard-go can link to it without any changes.
 */

// Opaque context type
typedef struct StatusKeycardContextImpl* StatusKeycardContext;

// Signal callback type
typedef void (*SignalCallback)(const char* signal_json);

// ============================================================================
// Core RPC Functions (MUST match nim-keycard-go)
// ============================================================================

/**
 * @brief Initialize the RPC service
 * @return JSON response with error field (must be freed with Free())
 * Response format: {"error":""} on success, {"error":"message"} on failure
 */
char* KeycardInitializeRPC(void);

/**
 * @brief Call an RPC method (compatibility wrapper - uses global context)
 * @param payload_json JSON-RPC request string
 * @return JSON-RPC response string (must be freed with Free())
 */
char* KeycardCallRPC(const char* payload_json);

/**
 * @brief Set signal event callback (compatibility wrapper - uses global context)
 * @param callback Function pointer to receive signal events
 */
void KeycardSetSignalEventCallback(SignalCallback callback);

/**
 * @brief Free memory allocated by library
 * @param param Pointer to memory to free
 */
void Free(void* param);

/**
 * @brief Reset API state (compatibility wrapper - uses global context)
 */
void ResetAPI(void);

// ============================================================================
// Context-Based API (For testing and advanced usage)
// ============================================================================

/**
 * @brief Create a new keycard context (for multi-context scenarios)
 * @return StatusKeycardContext handle or NULL on failure
 */
StatusKeycardContext KeycardCreateContext(void);

/**
 * @brief Call an RPC method with specific context
 * @param ctx Context handle
 * @param payload_json JSON-RPC request string
 * @return JSON-RPC response string (must be freed with Free())
 */
char* KeycardCallRPCWithContext(StatusKeycardContext ctx, const char* payload_json);

/**
 * @brief Set signal event callback for specific context
 * @param ctx Context handle
 * @param callback Function pointer to receive signal events
 */
void KeycardSetSignalEventCallbackWithContext(StatusKeycardContext ctx, SignalCallback callback);

/**
 * @brief Reset API state for specific context
 * @param ctx Context handle
 */
void ResetAPIWithContext(StatusKeycardContext ctx);

/**
 * @brief Destroy a keycard context and free resources
 * @param ctx Context handle
 */
void KeycardDestroyContext(StatusKeycardContext ctx);

// ============================================================================
// Flow API (Deprecated, for compatibility) - Uses global context
// ============================================================================

char* KeycardInitFlow(const char* storageDir);
char* KeycardStartFlow(int flowType, const char* jsonParams);
char* KeycardResumeFlow(const char* jsonParams);
char* KeycardCancelFlow(void);

// ============================================================================
// Mocked Functions (For testing) - Uses global context
// ============================================================================

char* MockedLibRegisterKeycard(int cardIndex, int readerState, 
                                int keycardState, const char* mockedKeycard, 
                                const char* mockedKeycardHelper);
char* MockedLibReaderPluggedIn(void);
char* MockedLibReaderUnplugged(void);
char* MockedLibKeycardInserted(int cardIndex);
char* MockedLibKeycardRemoved(void);

// ============================================================================
// Android JNI Support (not part of original API)
// ============================================================================

// NOTE: KeycardSetAndroidTag is now OBSOLETE after Qt NFC fix
//
// The JNI registration fix in keycard-qt properly registers QtNative.onNewIntent(),
// enabling Qt NFC to work automatically without Activity modifications.
// Manual tag forwarding is no longer needed.
//
// See: keycard-qt/src/channel/android_jni_register.cpp

#if 0  // DISABLED - Qt NFC works automatically now
#ifdef __ANDROID__
#include <jni.h>

/**
 * @brief Set Android IsoDep tag for keycard communication
 * @param env JNI environment
 * @param tag Android Tag object (jobject)
 * @return 1 if successful, 0 if failed
 * 
 * This function is called from Java when an NFC tag is detected.
 * It extracts the IsoDep interface and passes it to the KeycardChannel.
 */
int KeycardSetAndroidTag(JNIEnv* env, jobject tag);

#endif // __ANDROID__
#endif // DISABLED

#ifdef __cplusplus
}
#endif

#endif // STATUS_KEYCARD_H
