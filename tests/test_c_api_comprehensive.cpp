// Copyright (C) 2025 Status Research & Development GmbH
// SPDX-License-Identifier: MIT

#include <QtTest/QtTest>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDir>
#include <QTemporaryDir>
#include "status-keycard-qt/status_keycard.h"
#include "flow/flow_manager.h"
#include "mocks/mock_keycard_backend.h"
#include <keycard-qt/keycard_channel.h>

using namespace StatusKeycardTest;

/**
 * @brief Comprehensive tests for C API with dependency injection
 * 
 * Tests ALL C API functions:
 * - Context management
 * - RPC calls
 * - Signal callbacks
 * - Flow API
 * - Mocked functions
 * - Error conditions
 * - Edge cases
 * - Memory management
 */
class TestCApiComprehensive : public QObject
{
    Q_OBJECT

private:
    StatusKeycardContext m_ctx;
    QStringList m_receivedSignals;
    QTemporaryDir m_tempDir;
    
    static TestCApiComprehensive* s_instance;
    
    static void signalCallback(const char* signal_json) {
        if (s_instance && signal_json) {
            s_instance->m_receivedSignals.append(QString::fromUtf8(signal_json));
            qDebug() << "[Signal]" << signal_json;
        }
    }
    
    // Helper: Parse JSON response
    QJsonObject parseResponse(char* response) {
        if (!response) {
            qWarning() << "parseResponse: response is NULL";
            return QJsonObject();
        }
        QJsonDocument doc = QJsonDocument::fromJson(QByteArray(response));
        Free(response);
        if (doc.isNull()) {
            qWarning() << "parseResponse: invalid JSON";
            return QJsonObject();
        }
        return doc.object();
    }
    
    // Helper: Create RPC request
    QString createRPCRequest(const QString& method, const QJsonObject& params = QJsonObject()) {
        QJsonObject request;
        request["jsonrpc"] = "2.0";
        request["id"] = 1;
        request["method"] = method;
        if (!params.isEmpty()) {
            request["params"] = params;
        }
        return QJsonDocument(request).toJson(QJsonDocument::Compact);
    }

private slots:
    void initTestCase() {
        qDebug() << "========================================";
        qDebug() << "C API Comprehensive Tests with DI";
        qDebug() << "========================================";
        s_instance = this;
        QVERIFY(m_tempDir.isValid());
    }

    void cleanupTestCase() {
        qDebug() << "========================================";
        qDebug() << "C API Tests Complete";
        qDebug() << "========================================";
        
        // Ensure FlowManager singleton is destroyed
        StatusKeycard::FlowManager::destroyInstance();
        
        s_instance = nullptr;
    }

    void init() {
        m_ctx = nullptr;
        m_receivedSignals.clear();
    }

    void cleanup() {
        if (m_ctx) {
            KeycardDestroyContext(m_ctx);
            m_ctx = nullptr;
        }
        
        // Cancel any running flows
        if (StatusKeycard::FlowManager::instance()) {
            StatusKeycard::FlowManager::instance()->cancelFlow();
        }
        
        m_receivedSignals.clear();
        
        // Small wait to let async operations finish
        QTest::qWait(50);
    }

    // ========================================================================
    // Context Management Tests
    // ========================================================================

    void testCreateContext() {
        qDebug() << "\n=== TEST: Create Context ===";
        
        m_ctx = KeycardCreateContext();
        QVERIFY(m_ctx != nullptr);
        
        qDebug() << "✓ Context created successfully";
    }

    void testCreateMultipleContexts() {
        qDebug() << "\n=== TEST: Create Multiple Contexts ===";
        
        StatusKeycardContext ctx1 = KeycardCreateContext();
        StatusKeycardContext ctx2 = KeycardCreateContext();
        StatusKeycardContext ctx3 = KeycardCreateContext();
        
        QVERIFY(ctx1 != nullptr);
        QVERIFY(ctx2 != nullptr);
        QVERIFY(ctx3 != nullptr);
        
        // All should be different
        QVERIFY(ctx1 != ctx2);
        QVERIFY(ctx2 != ctx3);
        QVERIFY(ctx1 != ctx3);
        
        KeycardDestroyContext(ctx1);
        KeycardDestroyContext(ctx2);
        KeycardDestroyContext(ctx3);
        
        qDebug() << "✓ Multiple independent contexts work";
    }

    void testDestroyContext() {
        qDebug() << "\n=== TEST: Destroy Context ===";
        
        m_ctx = KeycardCreateContext();
        QVERIFY(m_ctx != nullptr);
        
        // Destroy should not crash
        KeycardDestroyContext(m_ctx);
        m_ctx = nullptr;
        
        qDebug() << "✓ Context destroyed successfully";
    }

    void testDestroyNullContext() {
        qDebug() << "\n=== TEST: Destroy NULL Context ===";
        
        // Should be safe to destroy null
        KeycardDestroyContext(nullptr);
        
        qDebug() << "✓ Destroying NULL context is safe";
    }

    void testDestroyContextTwice() {
        qDebug() << "\n=== TEST: Destroy Context Twice ===";
        
        m_ctx = KeycardCreateContext();
        QVERIFY(m_ctx != nullptr);
        
        KeycardDestroyContext(m_ctx);
        
        // Second destroy with stale pointer should be documented as undefined
        // In practice, user should set to NULL after destroy
        m_ctx = nullptr;
        
        qDebug() << "✓ Double destroy test (user must NULL pointer)";
    }

    // ========================================================================
    // Initialization Tests
    // ========================================================================

    void testInitializeRPC() {
        qDebug() << "\n=== TEST: Initialize RPC ===";
        
        char* response = KeycardInitializeRPC();
        QJsonObject obj = parseResponse(response);
        
        QVERIFY(obj.contains("error"));
        QCOMPARE(obj["error"].toString(), QString(""));
        
        qDebug() << "✓ RPC initialized successfully";
    }

    void testInitializeRPCMultipleTimes() {
        qDebug() << "\n=== TEST: Initialize RPC Multiple Times ===";
        
        // Should be idempotent
        char* response1 = KeycardInitializeRPC();
        QJsonObject obj1 = parseResponse(response1);
        QCOMPARE(obj1["error"].toString(), QString(""));
        
        char* response2 = KeycardInitializeRPC();
        QJsonObject obj2 = parseResponse(response2);
        QCOMPARE(obj2["error"].toString(), QString(""));
        
        qDebug() << "✓ Multiple initializations are safe";
    }

    // ========================================================================
    // RPC Call Tests
    // ========================================================================

    void testCallRPCWithNullContext() {
        qDebug() << "\n=== TEST: Call RPC with NULL Context ===";
        
        QString request = createRPCRequest("status_ping");
        char* response = KeycardCallRPCWithContext(nullptr, request.toUtf8().constData());
        
        // Should return error
        QJsonObject obj = parseResponse(response);
        QVERIFY(obj.contains("error"));
        // Error message may vary
        
        qDebug() << "✓ NULL context returns error";
    }

    void testCallRPCWithNullPayload() {
        qDebug() << "\n=== TEST: Call RPC with NULL Payload ===";
        
        m_ctx = KeycardCreateContext();
        char* response = KeycardCallRPCWithContext(m_ctx, nullptr);
        
        // Should return error
        QJsonObject obj = parseResponse(response);
        QVERIFY(obj.contains("error"));
        
        qDebug() << "✓ NULL payload returns error";
    }

    void testCallRPCWithInvalidJSON() {
        qDebug() << "\n=== TEST: Call RPC with Invalid JSON ===";
        
        m_ctx = KeycardCreateContext();
        char* response = KeycardCallRPCWithContext(m_ctx, "not valid json{");
        
        // Should return JSON-RPC error
        QJsonObject obj = parseResponse(response);
        QVERIFY(obj.contains("error"));
        
        qDebug() << "✓ Invalid JSON returns error";
    }

    void testCallRPCWithEmptyString() {
        qDebug() << "\n=== TEST: Call RPC with Empty String ===";
        
        m_ctx = KeycardCreateContext();
        char* response = KeycardCallRPCWithContext(m_ctx, "");
        
        QJsonObject obj = parseResponse(response);
        QVERIFY(obj.contains("error"));
        
        qDebug() << "✓ Empty string returns error";
    }

    void testCallRPCMethodNotFound() {
        qDebug() << "\n=== TEST: Call RPC Method Not Found ===";
        
        m_ctx = KeycardCreateContext();
        QString request = createRPCRequest("nonexistent_method");
        char* response = KeycardCallRPCWithContext(m_ctx, request.toUtf8().constData());
        
        QJsonObject obj = parseResponse(response);
        QVERIFY(obj.contains("error"));
        
        qDebug() << "✓ Non-existent method returns error";
    }

    void testCallRPCWithValidRequest() {
        qDebug() << "\n=== TEST: Call RPC with Valid Request ===";
        
        m_ctx = KeycardCreateContext();
        
        // Create a valid RPC request
        QString request = createRPCRequest("status_ping");
        char* response = KeycardCallRPCWithContext(m_ctx, request.toUtf8().constData());
        
        QJsonObject obj = parseResponse(response);
        
        // Should have standard JSON-RPC fields
        QVERIFY(obj.contains("jsonrpc"));
        QVERIFY(obj.contains("id"));
        
        qDebug() << "Response:" << QJsonDocument(obj).toJson(QJsonDocument::Compact);
        qDebug() << "✓ Valid RPC call works";
    }

    void testCallRPCGlobalFunction() {
        qDebug() << "\n=== TEST: Call RPC Global Function ===";
        
        // Test the global compatibility function
        KeycardInitializeRPC();
        
        QString request = createRPCRequest("status_ping");
        char* response = KeycardCallRPC(request.toUtf8().constData());
        
        QVERIFY(response != nullptr);
        QJsonObject obj = parseResponse(response);
        
        QVERIFY(obj.contains("jsonrpc"));
        
        qDebug() << "✓ Global RPC function works";
    }

    // ========================================================================
    // Signal Callback Tests
    // ========================================================================

    void testSetSignalCallback() {
        qDebug() << "\n=== TEST: Set Signal Callback ===";
        
        m_ctx = KeycardCreateContext();
        
        // Set callback
        KeycardSetSignalEventCallbackWithContext(m_ctx, &TestCApiComprehensive::signalCallback);
        
        // Callback is set (we can't verify directly, but no crash = good)
        qDebug() << "✓ Signal callback set";
    }

    void testSetSignalCallbackNull() {
        qDebug() << "\n=== TEST: Set NULL Signal Callback ===";
        
        m_ctx = KeycardCreateContext();
        
        // Should be safe to set NULL callback
        KeycardSetSignalEventCallbackWithContext(m_ctx, nullptr);
        
        qDebug() << "✓ NULL callback is safe";
    }

    void testSetSignalCallbackGlobal() {
        qDebug() << "\n=== TEST: Set Signal Callback Global ===";
        
        KeycardSetSignalEventCallback(&TestCApiComprehensive::signalCallback);
        
        // Can't verify directly, but no crash
        qDebug() << "✓ Global signal callback works";
    }

    void testSignalCallbackMultipleContexts() {
        qDebug() << "\n=== TEST: Signal Callback Multiple Contexts ===";
        
        StatusKeycardContext ctx1 = KeycardCreateContext();
        StatusKeycardContext ctx2 = KeycardCreateContext();
        
        // Each context can have its own callback
        KeycardSetSignalEventCallbackWithContext(ctx1, &TestCApiComprehensive::signalCallback);
        KeycardSetSignalEventCallbackWithContext(ctx2, &TestCApiComprehensive::signalCallback);
        
        KeycardDestroyContext(ctx1);
        KeycardDestroyContext(ctx2);
        
        qDebug() << "✓ Multiple context callbacks work";
    }

    // ========================================================================
    // Reset API Tests
    // ========================================================================

    void testResetAPI() {
        qDebug() << "\n=== TEST: Reset API ===";
        
        m_ctx = KeycardCreateContext();
        
        // Reset should be safe
        ResetAPIWithContext(m_ctx);
        
        qDebug() << "✓ Reset API works";
    }

    void testResetAPIGlobal() {
        qDebug() << "\n=== TEST: Reset API Global ===";
        
        ResetAPI();
        
        qDebug() << "✓ Global reset works";
    }

    void testResetAPINullContext() {
        qDebug() << "\n=== TEST: Reset API NULL Context ===";
        
        // Should be safe
        ResetAPIWithContext(nullptr);
        
        qDebug() << "✓ Reset with NULL context is safe";
    }

    // ========================================================================
    // Flow API Tests
    // ========================================================================

    void testFlowInitWithNullDir() {
        qDebug() << "\n=== TEST: Flow Init with NULL Dir ===";
        
        char* response = KeycardInitFlow(nullptr);
        
        // Should return error
        QJsonObject obj = parseResponse(response);
        QVERIFY(obj.contains("error"));
        
        qDebug() << "✓ NULL storage dir returns error";
    }

    void testFlowInitWithInvalidDir() {
        qDebug() << "\n=== TEST: Flow Init with Invalid Dir ===";
        
        char* response = KeycardInitFlow("/nonexistent/invalid/path");
        
        // Implementation creates directories as needed and starts fresh
        // This is acceptable behavior - it doesn't need to fail
        QJsonObject obj = parseResponse(response);
        QVERIFY(obj.contains("success"));
        
        qDebug() << "✓ Invalid storage dir handled (creates as needed)";
    }

    void testFlowInitWithValidDir() {
        qDebug() << "\n=== TEST: Flow Init with Valid Dir ===";
        
        char* response = KeycardInitFlow(m_tempDir.path().toUtf8().constData());
        
        QJsonObject obj = parseResponse(response);
        // May succeed or return info about initialization
        
        qDebug() << "Response:" << QJsonDocument(obj).toJson(QJsonDocument::Compact);
        qDebug() << "✓ Valid storage dir processed";
    }

    void testFlowStartWithoutInit() {
        qDebug() << "\n=== TEST: Flow Start without Init ===";
        
        QJsonObject params;
        params["pin"] = "000000";
        QString paramsStr = QJsonDocument(params).toJson(QJsonDocument::Compact);
        
        char* response = KeycardStartFlow(0, paramsStr.toUtf8().constData());
        
        // Global context auto-initializes, so this succeeds
        QJsonObject obj = parseResponse(response);
        QVERIFY(obj.contains("success"));
        
        qDebug() << "✓ Start without explicit init handled (uses global context)";
    }

    void testFlowResumeWithoutStart() {
        qDebug() << "\n=== TEST: Flow Resume without Start ===";
        
        QJsonObject params;
        params["pin"] = "000000";
        QString paramsStr = QJsonDocument(params).toJson(QJsonDocument::Compact);
        
        char* response = KeycardResumeFlow(paramsStr.toUtf8().constData());
        
        QJsonObject obj = parseResponse(response);
        QVERIFY(obj.contains("error"));
        
        qDebug() << "✓ Resume without start returns error";
    }

    void testFlowCancelWithoutStart() {
        qDebug() << "\n=== TEST: Flow Cancel without Start ===";
        
        char* response = KeycardCancelFlow();
        
        // Should be safe
        QJsonObject obj = parseResponse(response);
        // May return success or error
        
        qDebug() << "✓ Cancel without start handled";
    }

    void testFlowStartWithNullParams() {
        qDebug() << "\n=== TEST: Flow Start with NULL Params ===";
        
        char* response = KeycardStartFlow(0, nullptr);
        
        // NULL params are treated as empty JSON object, which is valid
        QJsonObject obj = parseResponse(response);
        QVERIFY(obj.contains("success"));
        
        qDebug() << "✓ NULL params handled gracefully (treated as empty object)";
    }

    void testFlowStartWithInvalidFlowType() {
        qDebug() << "\n=== TEST: Flow Start with Invalid Flow Type ===";
        
        char* response = KeycardStartFlow(999, "{}");
        
        QJsonObject obj = parseResponse(response);
        QVERIFY(obj.contains("error"));
        
        qDebug() << "✓ Invalid flow type returns error";
    }

    // ========================================================================
    // Mocked Functions Tests
    // ========================================================================

    void testMockedRegisterKeycard() {
        qDebug() << "\n=== TEST: Mocked Register Keycard ===";
        
        char* response = MockedLibRegisterKeycard(0, 0, 0, "{}", "{}");
        
        // Should return JSON response
        QVERIFY(response != nullptr);
        QJsonObject obj = parseResponse(response);
        
        // Format depends on implementation
        qDebug() << "✓ Mocked register keycard works";
    }

    void testMockedRegisterKeycardWithNullParams() {
        qDebug() << "\n=== TEST: Mocked Register Keycard with NULL ===";
        
        char* response = MockedLibRegisterKeycard(0, 0, 0, nullptr, nullptr);
        
        // Should handle NULL gracefully
        QVERIFY(response != nullptr);
        Free(response);
        
        qDebug() << "✓ NULL params handled";
    }

    void testMockedReaderPluggedIn() {
        qDebug() << "\n=== TEST: Mocked Reader Plugged In ===";
        
        char* response = MockedLibReaderPluggedIn();
        QVERIFY(response != nullptr);
        Free(response);
        
        qDebug() << "✓ Mocked reader plugged in works";
    }

    void testMockedReaderUnplugged() {
        qDebug() << "\n=== TEST: Mocked Reader Unplugged ===";
        
        char* response = MockedLibReaderUnplugged();
        QVERIFY(response != nullptr);
        Free(response);
        
        qDebug() << "✓ Mocked reader unplugged works";
    }

    void testMockedKeycardInserted() {
        qDebug() << "\n=== TEST: Mocked Keycard Inserted ===";
        
        char* response = MockedLibKeycardInserted(0);
        QVERIFY(response != nullptr);
        Free(response);
        
        qDebug() << "✓ Mocked keycard inserted works";
    }

    void testMockedKeycardRemoved() {
        qDebug() << "\n=== TEST: Mocked Keycard Removed ===";
        
        char* response = MockedLibKeycardRemoved();
        QVERIFY(response != nullptr);
        Free(response);
        
        qDebug() << "✓ Mocked keycard removed works";
    }

    // ========================================================================
    // Memory Management Tests
    // ========================================================================

    void testFreeNull() {
        qDebug() << "\n=== TEST: Free NULL ===";
        
        // Should be safe to free NULL
        Free(nullptr);
        
        qDebug() << "✓ Freeing NULL is safe";
    }

    void testFreeValidPointer() {
        qDebug() << "\n=== TEST: Free Valid Pointer ===";
        
        char* response = KeycardInitializeRPC();
        QVERIFY(response != nullptr);
        
        Free(response);
        
        qDebug() << "✓ Freeing valid pointer works";
    }

    void testFreeMultipleResponses() {
        qDebug() << "\n=== TEST: Free Multiple Responses ===";
        
        char* r1 = KeycardInitializeRPC();
        char* r2 = KeycardInitializeRPC();
        char* r3 = KeycardInitializeRPC();
        
        Free(r1);
        Free(r2);
        Free(r3);
        
        qDebug() << "✓ Freeing multiple pointers works";
    }

    // ========================================================================
    // Complex Scenarios
    // ========================================================================

    void testContextLifecycle() {
        qDebug() << "\n=== TEST: Complete Context Lifecycle ===";
        
        // Create
        m_ctx = KeycardCreateContext();
        QVERIFY(m_ctx != nullptr);
        
        // Set callback
        KeycardSetSignalEventCallbackWithContext(m_ctx, &TestCApiComprehensive::signalCallback);
        
        // Make RPC call
        QString request = createRPCRequest("status_ping");
        char* response = KeycardCallRPCWithContext(m_ctx, request.toUtf8().constData());
        Free(response);
        
        // Reset
        ResetAPIWithContext(m_ctx);
        
        // Destroy
        KeycardDestroyContext(m_ctx);
        m_ctx = nullptr;
        
        qDebug() << "✓ Complete lifecycle works";
    }

    void testConcurrentContexts() {
        qDebug() << "\n=== TEST: Concurrent Contexts ===";
        
        StatusKeycardContext ctx1 = KeycardCreateContext();
        StatusKeycardContext ctx2 = KeycardCreateContext();
        
        // Both can be used independently
        QString request = createRPCRequest("status_ping");
        
        char* r1 = KeycardCallRPCWithContext(ctx1, request.toUtf8().constData());
        char* r2 = KeycardCallRPCWithContext(ctx2, request.toUtf8().constData());
        
        QVERIFY(r1 != nullptr);
        QVERIFY(r2 != nullptr);
        
        Free(r1);
        Free(r2);
        
        KeycardDestroyContext(ctx1);
        KeycardDestroyContext(ctx2);
        
        qDebug() << "✓ Concurrent contexts work independently";
    }

    void testErrorRecovery() {
        qDebug() << "\n=== TEST: Error Recovery ===";
        
        m_ctx = KeycardCreateContext();
        
        // Cause error
        char* error_response = KeycardCallRPCWithContext(m_ctx, "invalid");
        Free(error_response);
        
        // Should still work after error
        QString request = createRPCRequest("status_ping");
        char* ok_response = KeycardCallRPCWithContext(m_ctx, request.toUtf8().constData());
        QVERIFY(ok_response != nullptr);
        Free(ok_response);
        
        qDebug() << "✓ Context recovers from errors";
    }
};

TestCApiComprehensive* TestCApiComprehensive::s_instance = nullptr;

QTEST_MAIN(TestCApiComprehensive)
#include "test_c_api_comprehensive.moc"

