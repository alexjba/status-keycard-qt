#include "status-keycard-qt/status_keycard.h"
#include "rpc/rpc_service.h"
#include "session/session_manager.h"
#include "signal_manager.h"
#include "flow/flow_manager.h"
#include "storage/file_pairing_storage.h"
#include <QString>
#include <QObject>
#include <QThread>
#include <QJsonDocument>
#include <QJsonObject>
#include <memory>
#include <cstring>

// Context structure
struct StatusKeycardContextImpl {
    std::unique_ptr<StatusKeycard::RpcService> rpcService;
    StatusKeycard::SignalManager* signalManager;
    SignalCallback signalCallback;
    std::shared_ptr<Keycard::CommandSet> sharedCommandSet;  // Shared between FlowManager and SessionManager
    std::shared_ptr<Keycard::KeycardChannel> channel;  // Global channel instance
    std::shared_ptr<Keycard::IPairingStorage> pairingStorage;
    
    StatusKeycardContextImpl()
        : signalCallback(nullptr)
        , sharedCommandSet(nullptr)
    {
        qDebug() << "StatusKeycardContextImpl: Constructor called";
        // Initialize Qt if needed
        int argc = 0;
        char* argv[] = {nullptr};
        
        channel = std::make_shared<Keycard::KeycardChannel>();
        
// #if defined(Q_OS_ANDROID) || defined(Q_OS_IOS)
//         pairingStorage = std::make_shared<StatusKeycard::SecurePairingStorage>();
//         qDebug() << "C API: Using SecurePairingStorage";
// #else
        pairingStorage = std::make_shared<StatusKeycard::FilePairingStorage>();
//         qDebug() << "C API: Using FilePairingStorage";
// #endif

        // Get CommandSet from FlowManager
        sharedCommandSet = std::make_shared<Keycard::CommandSet>(channel, pairingStorage, [](const QString& cardUID) { return "KeycardDefaultPairing"; });
        
        // Create RPC service
        rpcService = std::make_unique<StatusKeycard::RpcService>();
        rpcService->setSharedCommandSet(sharedCommandSet);
        
        // Get signal manager instance
        signalManager = StatusKeycard::SignalManager::instance();
        
        // Connect SessionManager signals to SignalManager
        QObject::connect(rpcService->sessionManager(), &StatusKeycard::SessionManager::stateChanged,
                        [this](StatusKeycard::SessionState, StatusKeycard::SessionState) {
            // Emit status-changed signal
            auto status = rpcService->sessionManager()->getStatus();
            signalManager->emitStatusChanged(status);
        });
        
        // Connect FlowManager signals to SignalManager
        QObject::connect(StatusKeycard::FlowManager::instance(), &StatusKeycard::FlowManager::flowSignal,
                        [this](const QString& type, const QJsonObject& event) {
            // Build signal JSON
            QJsonObject signal;
            signal["type"] = type;
            signal["event"] = event;
            
            QJsonDocument doc(signal);
            QString jsonString = QString::fromUtf8(doc.toJson(QJsonDocument::Compact));
            
            signalManager->emitSignal(jsonString);
        });
        
        // Connect channel state changes to SignalManager
        QObject::connect(channel.get(), &Keycard::KeycardChannel::channelStateChanged, signalManager,
                        [this](Keycard::ChannelOperationalState state) {
            // Convert enum to string
            qDebug() << "StatusKeycardContextImpl: Channel state changed:" << static_cast<int>(state);
            QString stateStr;
            switch (state) {
                case Keycard::ChannelOperationalState::Idle:
                    stateStr = "idle";
                    break;
                case Keycard::ChannelOperationalState::WaitingForKeycard:
                    stateStr = "waiting-for-keycard";
                    break;
                case Keycard::ChannelOperationalState::Reading:
                    stateStr = "reading";
                    break;
                case Keycard::ChannelOperationalState::Error:
                    stateStr = "error";
                    break;
            }
            qDebug() << "StatusKeycardContextImpl: Emitting channel state changed signal:" << stateStr;
            signalManager->emitChannelStateChanged(stateStr);
        });

    }
    
    ~StatusKeycardContextImpl() {
        qDebug() << "StatusKeycardContextImpl: Destructor called";
    }
};

extern "C" {

// ============================================================================
// Core RPC Functions (MUST match nim-keycard-go)
// ============================================================================

// Global context for compatibility with old API
static StatusKeycardContext g_global_context = nullptr;

// Internal function that returns context (not exposed in header)
static StatusKeycardContext KeycardInitializeRPCInternal(void) {
    try {
        StatusKeycardContextImpl* ctx = new StatusKeycardContextImpl();
        qDebug() << "C API: Context created successfully";
        return reinterpret_cast<StatusKeycardContext>(ctx);
    } catch (...) {
        qCritical() << "C API: Failed to create context!";
        return nullptr;
    }
}

// Initialize global context if needed
static void ensure_global_context() {
    if (!g_global_context) {
        g_global_context = KeycardInitializeRPCInternal();
    }
}

// Public function that returns JSON string (matching nim-keycard-go expectation)
char* KeycardInitializeRPC(void) {
    // Create global context if needed
    ensure_global_context();
    
    // Return success response in Go format: {"error":""}
    const char* response = R"({"error":""})";
    return strdup(response);
}

// Context-based API for testing and advanced usage
StatusKeycardContext KeycardCreateContext(void) {
    return KeycardInitializeRPCInternal();
}

void KeycardDestroyContext(StatusKeycardContext ctx) {
    if (ctx) {
        StatusKeycardContextImpl* impl = reinterpret_cast<StatusKeycardContextImpl*>(ctx);
        delete impl;
    }
}

char* KeycardCallRPCWithContext(StatusKeycardContext ctx, const char* payload_json) {
    qDebug() << "C API: KeycardCallRPCWithContext() called";
    qDebug() << "C API: Payload:" << (payload_json ? payload_json : "NULL");
    
    if (!ctx || !payload_json) {
        qCritical() << "C API: Invalid context or payload!";
        // Return error response
        const char* error = R"({"jsonrpc":"2.0","id":"","result":null,"error":{"code":-32603,"message":"Invalid context or payload"}})";
        return strdup(error);
    }
    
    StatusKeycardContextImpl* impl = reinterpret_cast<StatusKeycardContextImpl*>(ctx);
    
    // Process the JSON-RPC request
    QString request = QString::fromUtf8(payload_json);
    qDebug() << "C API: Processing RPC request:" << request;
    QString response = impl->rpcService->processRequest(request);
    qDebug() << "C API: RPC response:" << response;
    
    // Return response (caller must free with Free())
    return strdup(response.toUtf8().constData());
}

void KeycardSetSignalEventCallbackWithContext(StatusKeycardContext ctx, SignalCallback callback) {
    if (!ctx) {
        return;
    }
    
    StatusKeycardContextImpl* impl = reinterpret_cast<StatusKeycardContextImpl*>(ctx);
    impl->signalCallback = callback;
    impl->signalManager->setCallback(callback);
}

void Free(void* param) {
    if (param) {
        free(param);
    }
}

void ResetAPIWithContext(StatusKeycardContext ctx) {
    if (!ctx) {
        return;
    }
    
    StatusKeycardContextImpl* impl = reinterpret_cast<StatusKeycardContextImpl*>(ctx);
    
    // Stop the session
    if (impl->rpcService && impl->rpcService->sessionManager()) {
        impl->rpcService->sessionManager()->stop();
    }
    
    // Reset RPC service
    impl->rpcService.reset();
    impl->rpcService = std::make_unique<StatusKeycard::RpcService>();
    
    // Reconnect signals
    QObject::connect(impl->rpcService->sessionManager(), &StatusKeycard::SessionManager::stateChanged,
                    [impl](StatusKeycard::SessionState, StatusKeycard::SessionState) {
        auto status = impl->rpcService->sessionManager()->getStatus();
        impl->signalManager->emitStatusChanged(status);
    });
}

// ============================================================================
// Flow API (Deprecated but kept for compatibility)
// ============================================================================

char* KeycardInitFlowWithContext(StatusKeycardContext ctx, const char* storageDir) {
    if (!ctx || !storageDir) {
        const char* error = R"({"success": false, "error": "Invalid parameters"})";
        return strdup(error);
    }
    
    StatusKeycardContextImpl* impl = reinterpret_cast<StatusKeycardContextImpl*>(ctx);
    
    // Initialize FlowManager with storage directory
    if (auto fileStorage = std::dynamic_pointer_cast<StatusKeycard::FilePairingStorage>(impl->pairingStorage)) {
        fileStorage->setPath(QString::fromUtf8(storageDir));
    }
    bool success = StatusKeycard::FlowManager::instance()->init(impl->sharedCommandSet);
    
    if (!success) {
        const char* error = R"({"success": false, "error": "Failed to initialize FlowManager"})";
        return strdup(error);
    }
    
    
    const char* response = R"({"success": true})";
    return strdup(response);
}

char* KeycardStartFlowWithContext(StatusKeycardContext ctx, int flowType, const char* jsonParams) {
    if (!ctx) {
        const char* error = R"({"success": false, "error": "Invalid context"})";
        return strdup(error);
    }
    
    // Parse JSON parameters
    QJsonObject params;
    if (jsonParams && strlen(jsonParams) > 0) {
        QJsonDocument doc = QJsonDocument::fromJson(QByteArray(jsonParams));
        if (doc.isObject()) {
            params = doc.object();
        }
    }
    
    // IMPORTANT: Marshal to Qt main thread!
    // This function is called from Nim threads, but startFlow() creates Qt objects
    // and manipulates state that must be on the Qt main thread.
    bool success = false;
    
    // Check if we're already on the Qt main thread
    auto flowManager = StatusKeycard::FlowManager::instance();
    if (QThread::currentThread() == flowManager->thread()) {
        // Already on Qt thread - call directly to avoid deadlock
        success = flowManager->startFlow(flowType, params);
    } else {
        // Different thread - marshal to Qt thread
        QMetaObject::invokeMethod(flowManager,
                                 [flowType, params, &success]() {
            success = StatusKeycard::FlowManager::instance()->startFlow(flowType, params);
        }, Qt::BlockingQueuedConnection);
    }
    
    if (success) {
        const char* response = R"({"success": true})";
        return strdup(response);
    } else {
        QString error = StatusKeycard::FlowManager::instance()->lastError();
        QJsonObject errorObj;
        errorObj["success"] = false;
        errorObj["error"] = error;
        QByteArray json = QJsonDocument(errorObj).toJson(QJsonDocument::Compact);
        return strdup(json.constData());
    }
}

char* KeycardResumeFlowWithContext(StatusKeycardContext ctx, const char* jsonParams) {
    if (!ctx) {
        const char* error = R"({"success": false, "error": "Invalid context"})";
        return strdup(error);
    }
    
    // Parse JSON parameters
    QJsonObject params;
    if (jsonParams && strlen(jsonParams) > 0) {
        QJsonDocument doc = QJsonDocument::fromJson(QByteArray(jsonParams));
        if (doc.isObject()) {
            params = doc.object();
        }
    }
    
    // IMPORTANT: Marshal to Qt main thread (same reason as startFlow)
    bool success = false;
    
    // Check if we're already on the Qt main thread
    auto flowManager = StatusKeycard::FlowManager::instance();
    if (QThread::currentThread() == flowManager->thread()) {
        // Already on Qt thread - call directly to avoid deadlock
        success = flowManager->resumeFlow(params);
    } else {
        // Different thread - marshal to Qt thread
        QMetaObject::invokeMethod(flowManager,
                                 [params, &success]() {
            success = StatusKeycard::FlowManager::instance()->resumeFlow(params);
        }, Qt::BlockingQueuedConnection);
    }
    
    if (success) {
        const char* response = R"({"success": true})";
        return strdup(response);
    } else {
        QString error = StatusKeycard::FlowManager::instance()->lastError();
        QJsonObject errorObj;
        errorObj["success"] = false;
        errorObj["error"] = error;
        QByteArray json = QJsonDocument(errorObj).toJson(QJsonDocument::Compact);
        return strdup(json.constData());
    }
}

char* KeycardCancelFlowWithContext(StatusKeycardContext ctx) {
    if (!ctx) {
        const char* error = R"({"success": false, "error": "Invalid context"})";
        return strdup(error);
    }
    
    // IMPORTANT: Marshal to Qt main thread (same reason as startFlow)
    bool success = false;
    
    // Check if we're already on the Qt main thread
    auto flowManager = StatusKeycard::FlowManager::instance();
    if (QThread::currentThread() == flowManager->thread()) {
        // Already on Qt thread - call directly to avoid deadlock
        success = flowManager->cancelFlow();
    } else {
        // Different thread - marshal to Qt thread
        QMetaObject::invokeMethod(flowManager,
                                 [&success]() {
            success = StatusKeycard::FlowManager::instance()->cancelFlow();
        }, Qt::BlockingQueuedConnection);
    }
    
    if (success) {
        const char* response = R"({"success": true})";
        return strdup(response);
    } else {
        const char* error = R"({"success": false, "error": "Failed to cancel flow"})";
        return strdup(error);
    }
}

// ============================================================================
// Mocked Functions (For testing)
// ============================================================================

char* MockedLibRegisterKeycardWithContext(StatusKeycardContext ctx, int cardIndex, int readerState, 
                                int keycardState, const char* mockedKeycard, 
                                const char* mockedKeycardHelper) {
    (void)ctx;
    (void)cardIndex;
    (void)readerState;
    (void)keycardState;
    (void)mockedKeycard;
    (void)mockedKeycardHelper;
    const char* response = R"({"success": true, "message": "Mocked functions not implemented in Qt version"})";
    return strdup(response);
}

char* MockedLibReaderPluggedInWithContext(StatusKeycardContext ctx) {
    (void)ctx;
    const char* response = R"({"success": true})";
    return strdup(response);
}

char* MockedLibReaderUnpluggedWithContext(StatusKeycardContext ctx) {
    (void)ctx;
    const char* response = R"({"success": true})";
    return strdup(response);
}

char* MockedLibKeycardInsertedWithContext(StatusKeycardContext ctx, int cardIndex) {
    (void)ctx;
    (void)cardIndex;
    const char* response = R"({"success": true})";
    return strdup(response);
}

char* MockedLibKeycardRemovedWithContext(StatusKeycardContext ctx) {
    (void)ctx;
    const char* response = R"({"success": true})";
    return strdup(response);
}

// ============================================================================
// Compatibility Wrappers (No context parameter - for Nim compatibility)
// ============================================================================

// NOTE: g_global_context and ensure_global_context() are already defined above
// near KeycardInitializeRPC() to avoid forward declaration issues

// Wrapper: setSignalEventCallback (Nim expects this signature)
void KeycardSetSignalEventCallback(SignalCallback callback) {
    qDebug() << "========================================";
    qDebug() << "C API: KeycardSetSignalEventCallback() called!";
    qDebug() << "C API: Callback pointer:" << (void*)callback;
    qDebug() << "========================================";
    ensure_global_context();
    KeycardSetSignalEventCallbackWithContext(g_global_context, callback);
    qDebug() << "C API: Signal callback registered successfully";
}

// Wrapper: resetAPI (Nim expects this signature)
void ResetAPI() {
    if (g_global_context) {
        ResetAPIWithContext(g_global_context);
    }
}

// Wrapper: keycardInitFlow (Nim expects this signature)
char* KeycardInitFlow(const char* storageDir) {
    ensure_global_context();
    return KeycardInitFlowWithContext(g_global_context, storageDir);
}

// Wrapper: keycardStartFlow (Nim expects this signature)
char* KeycardStartFlow(int flowType, const char* jsonParams) {
    ensure_global_context();
    return KeycardStartFlowWithContext(g_global_context, flowType, jsonParams);
}

// Wrapper: keycardResumeFlow (Nim expects this signature)
char* KeycardResumeFlow(const char* jsonParams) {
    ensure_global_context();
    return KeycardResumeFlowWithContext(g_global_context, jsonParams);
}

// Wrapper: keycardCancelFlow (Nim expects this signature)
char* KeycardCancelFlow() {
    ensure_global_context();
    return KeycardCancelFlowWithContext(g_global_context);
}

// NOTE: keycardInitializeRPC is removed - Nim uses KeycardInitializeRPC directly

// Wrapper: keycardCallRPC (Nim expects this signature)
char* KeycardCallRPC(const char* params) {
    ensure_global_context();
    return KeycardCallRPCWithContext(g_global_context, params);
}

// Wrapper: Mocked functions without context
char* MockedLibRegisterKeycard(int cardIndex, int readerState, int keycardState, 
                               const char* mockedKeycard, const char* mockedKeycardHelper) {
    ensure_global_context();
    return MockedLibRegisterKeycardWithContext(g_global_context, cardIndex, readerState, keycardState, 
                                   mockedKeycard, mockedKeycardHelper);
}

char* MockedLibReaderPluggedIn() {
    ensure_global_context();
    return MockedLibReaderPluggedInWithContext(g_global_context);
}

char* MockedLibReaderUnplugged() {
    ensure_global_context();
    return MockedLibReaderUnpluggedWithContext(g_global_context);
}

char* MockedLibKeycardInserted(int cardIndex) {
    ensure_global_context();
    return MockedLibKeycardInsertedWithContext(g_global_context, cardIndex);
}

char* MockedLibKeycardRemoved() {
    ensure_global_context();
    return MockedLibKeycardRemovedWithContext(g_global_context);
}

// // ============================================================================
// // Android JNI Support
// // ============================================================================

// // NOTE: This section is now OBSOLETE after Qt NFC fix in keycard-qt
// //
// // The JNI registration fix in keycard-qt/src/channel/android_jni_register.cpp
// // properly registers QtNative.onNewIntent(), enabling Qt NFC to work automatically
// // without any Activity modifications or manual tag forwarding.
// //
// // This code is kept for reference but is no longer used or needed.
// // Qt NFC now handles everything automatically!
// //
// // See: keycard-qt/src/channel/android_jni_register.cpp

// #if 0  // DISABLED - Qt NFC works automatically now
// #ifdef Q_OS_ANDROID
// #include <keycard-qt/keycard_channel.h>

// int KeycardSetAndroidTag(JNIEnv* env, jobject tag) {
//     qWarning() << "========================================";
//     qWarning() << "🎯 KeycardSetAndroidTag: Called from Java!";
//     qWarning() << "🎯 JNI env:" << (void*)env;
//     qWarning() << "🎯 Tag object:" << (void*)tag;
    
//     // Ensure global context exists
//     ensure_global_context();
    
//     if (!g_global_context || !g_global_context->rpcService) {
//         qCritical() << "❌ KeycardSetAndroidTag: No RpcService available!";
//         return 0;
//     }
    
//     // Get the SessionManager from the RpcService
//     auto* sessionManager = g_global_context->rpcService->sessionManager();
//     if (!sessionManager) {
//         qCritical() << "❌ KeycardSetAndroidTag: No SessionManager available!";
//         return 0;
//     }
    
//     // Get the KeycardChannel from the SessionManager
//     auto* channel = sessionManager->getChannel();
//     if (!channel) {
//         qCritical() << "❌ KeycardSetAndroidTag: No KeycardChannel available!";
//         qCritical() << "❌ Make sure SessionManager::start() was called first!";
//         return 0;
//     }
    
//     qWarning() << "🎯 Found KeycardChannel at:" << (void*)channel;
//     qWarning() << "🎯 Calling setAndroidTag()...";
    
//     // Call setAndroidTag on the KeycardChannel
//     bool success = channel->setAndroidTag(tag);
    
//     if (success) {
//         qWarning() << "✅ KeycardSetAndroidTag: SUCCESS! Tag set and connected";
//         qWarning() << "========================================";
//         return 1;
//     } else {
//         qCritical() << "❌ KeycardSetAndroidTag: FAILED to set tag";
//         qWarning() << "========================================";
//         return 0;
//     }
// }

// // JNI wrapper function that Java can call
// extern "C" JNIEXPORT jint JNICALL
// Java_app_status_mobile_StatusQtActivity_nativeKeycardSetAndroidTag(JNIEnv* env, jobject thiz, jobject tag) {
//     qWarning() << "🔔 JNI: Java_app_status_mobile_StatusQtActivity_nativeKeycardSetAndroidTag called";
//     return KeycardSetAndroidTag(env, tag);
// }

// #endif // Q_OS_ANDROID
// #endif // DISABLED

} // extern "C"
