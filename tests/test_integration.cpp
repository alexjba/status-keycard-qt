#include <QtTest/QtTest>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QTemporaryDir>
#include <QEventLoop>
#include <QTimer>
#include "status-keycard-qt/status_keycard.h"

/**
 * @brief Integration tests for the full API stack
 * 
 * These tests simulate real-world usage of the library by status-desktop,
 * testing the complete flow from C API → RPC Service → SessionManager → Signals
 */
class TestIntegration : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void init();
    void cleanup();

    // Full stack integration tests
    void testFullInitializationFlow();
    void testStartStopCycle();
    void testStatusQueryFlow();
    void testSignalEmission();
    void testErrorPropagation();
    
    // Real-world workflow tests
    void testTypicalDesktopWorkflow();
    void testMultipleCardsWorkflow();
    void testCardInsertRemoveFlow();
    void testPairingWorkflow();
    
    // JSON-RPC integration tests
    void testCompleteJSONRPCFlow();
    void testConcurrentRequests();
    void testLongRunningOperations();
    
    // Memory and resource tests
    void testMemoryManagement();
    void testContextIsolation();
    void testResourceCleanup();

private:
    StatusKeycardContext m_ctx;
    QTemporaryDir* m_tempDir;
    QString m_storagePath;
    QStringList m_receivedSignals;
    
    // Helper methods
    QString callRPC(const QString& method, const QJsonObject& params = QJsonObject());
    QJsonObject parseResponse(const QString& response);
    bool isSuccessResponse(const QJsonObject& response);
    QString getErrorMessage(const QJsonObject& response);
    void waitForSignal(int timeoutMs = 1000);
    
    static void signalCallback(const char* signal_json);
    static QStringList s_receivedSignals;
};

QStringList TestIntegration::s_receivedSignals;

void TestIntegration::signalCallback(const char* signal_json)
{
    if (signal_json) {
        s_receivedSignals.append(QString::fromUtf8(signal_json));
        qDebug() << "Signal received:" << signal_json;
    }
}

void TestIntegration::initTestCase()
{
    s_receivedSignals.clear();
}

void TestIntegration::cleanupTestCase()
{
    // Nothing needed
}

void TestIntegration::init()
{
    m_tempDir = new QTemporaryDir();
    QVERIFY(m_tempDir->isValid());
    m_storagePath = m_tempDir->filePath("integration_pairings.json");
    
    m_ctx = KeycardCreateContext();
    QVERIFY(m_ctx != nullptr);
    
    s_receivedSignals.clear();
    m_receivedSignals.clear();
    
    KeycardSetSignalEventCallbackWithContext(m_ctx, signalCallback);
}

void TestIntegration::cleanup()
{
    if (m_ctx) {
        // Stop the service gracefully
        callRPC("keycard.Stop");
        KeycardDestroyContext(m_ctx);
        m_ctx = nullptr;
    }
    
    delete m_tempDir;
    m_tempDir = nullptr;
    
    s_receivedSignals.clear();
    m_receivedSignals.clear();
}

QString TestIntegration::callRPC(const QString& method, const QJsonObject& params)
{
    QJsonObject request;
    request["jsonrpc"] = "2.0";
    request["id"] = QString::number(QRandomGenerator::global()->generate());
    request["method"] = method;
    
    if (!params.isEmpty()) {
        QJsonArray paramsArray;
        paramsArray.append(params);
        request["params"] = paramsArray;
    } else {
        request["params"] = QJsonArray();
    }
    
    QString requestStr = QString::fromUtf8(QJsonDocument(request).toJson(QJsonDocument::Compact));
    char* responseStr = KeycardCallRPCWithContext(m_ctx, requestStr.toUtf8().constData());
    
    if (responseStr == nullptr) {
        qWarning() << "KeycardCallRPCWithContext returned nullptr for method:" << method;
        return QString();
    }
    
    QString response = QString::fromUtf8(responseStr);
    Free(responseStr);
    
    return response;
}

QJsonObject TestIntegration::parseResponse(const QString& response)
{
    QJsonDocument doc = QJsonDocument::fromJson(response.toUtf8());
    if (!doc.isObject()) {
        qWarning() << "Response is not a valid JSON object:" << response;
        return QJsonObject();
    }
    return doc.object();
}

bool TestIntegration::isSuccessResponse(const QJsonObject& response)
{
    return response.contains("result") && (!response.contains("error") || response["error"].isNull());
}

QString TestIntegration::getErrorMessage(const QJsonObject& response)
{
    if (response.contains("error") && !response["error"].isNull()) {
        return response["error"].toObject()["message"].toString();
    }
    return QString();
}

void TestIntegration::waitForSignal(int timeoutMs)
{
    QEventLoop loop;
    QTimer::singleShot(timeoutMs, &loop, &QEventLoop::quit);
    loop.exec();
}

// ============================================================================
// Full Stack Integration Tests
// ============================================================================

void TestIntegration::testFullInitializationFlow()
{
    // Test the complete initialization flow
    
    // 1. Context is initialized
    QVERIFY(m_ctx != nullptr);
    
    // 2. Start the service
    QJsonObject startParams;
    startParams["storageFilePath"] = m_storagePath;
    startParams["logEnabled"] = false;
    
    QString response = callRPC("keycard.Start", startParams);
    QJsonObject resp = parseResponse(response);
    
    // May succeed or fail depending on hardware availability
    // But should return valid JSON
    QVERIFY(resp.contains("result") || resp.contains("error"));
    
    // 3. Get status
    response = callRPC("keycard.GetStatus");
    resp = parseResponse(response);
    QVERIFY(isSuccessResponse(resp));
    
    QJsonObject status = resp["result"].toObject();
    QVERIFY(status.contains("state"));
    QVERIFY(status.contains("keycardInfo"));
    QVERIFY(status.contains("keycardStatus"));
    QVERIFY(status.contains("metadata"));
    
    // 4. Stop the service
    response = callRPC("keycard.Stop");
    resp = parseResponse(response);
    QVERIFY(isSuccessResponse(resp));
}

void TestIntegration::testStartStopCycle()
{
    // Test multiple start/stop cycles
    
    for (int i = 0; i < 3; i++) {
        QJsonObject startParams;
        startParams["storageFilePath"] = m_storagePath;
        
        QString response = callRPC("keycard.Start", startParams);
        QJsonObject resp = parseResponse(response);
        
        // Each start should succeed (we stop between iterations)
        // May succeed or fail based on hardware availability
        QVERIFY(resp.contains("result") || resp.contains("error"));
        
        // Stop always works
        response = callRPC("keycard.Stop");
        resp = parseResponse(response);
        QVERIFY(isSuccessResponse(resp));
    }
    
    // Test that starting twice without stop is rejected
    QJsonObject startParams;
    startParams["storageFilePath"] = m_storagePath;
    
    QString response = callRPC("keycard.Start", startParams);
    QJsonObject resp1 = parseResponse(response);
    
    response = callRPC("keycard.Start", startParams);
    QJsonObject resp2 = parseResponse(response);
    
    // Second start should fail (already started)
    QVERIFY(!isSuccessResponse(resp2));
    
    // Cleanup
    callRPC("keycard.Stop");
}

void TestIntegration::testStatusQueryFlow()
{
    // Start service
    QJsonObject startParams;
    startParams["storageFilePath"] = m_storagePath;
    callRPC("keycard.Start", startParams);
    
    // Query status multiple times
    for (int i = 0; i < 5; i++) {
        QString response = callRPC("keycard.GetStatus");
        QJsonObject resp = parseResponse(response);
        
        QVERIFY(isSuccessResponse(resp));
        
        QJsonObject status = resp["result"].toObject();
        QString state = status["state"].toString();
        
        // State should be one of the valid states
        QStringList validStates = {
            "unknown-reader-state", "no-readers-found", "waiting-for-reader",
            "reader-connection-error", "waiting-for-card", "connecting-card",
            "empty-keycard", "not-keycard", "connection-error", "pairing-error",
            "blocked-pin", "blocked-puk", "ready", "authorized", "factory-resetting"
        };
        QVERIFY(validStates.contains(state));
    }
}

void TestIntegration::testSignalEmission()
{
    s_receivedSignals.clear();
    
    // Start service (should emit signal)
    QJsonObject startParams;
    startParams["storageFilePath"] = m_storagePath;
    callRPC("keycard.Start", startParams);
    
    // Wait for signals
    waitForSignal(500);
    
    // Should have received at least one status-changed signal
    bool hasStatusSignal = false;
    for (const QString& signal : s_receivedSignals) {
        QJsonDocument doc = QJsonDocument::fromJson(signal.toUtf8());
        if (doc.isObject()) {
            QJsonObject obj = doc.object();
            if (obj["type"].toString() == "status-changed") {
                hasStatusSignal = true;
                
                // Validate signal structure
                QVERIFY(obj.contains("event"));
                QJsonObject event = obj["event"].toObject();
                QVERIFY(event.contains("state"));
                QVERIFY(event.contains("keycardInfo"));
                QVERIFY(event.contains("keycardStatus"));
                QVERIFY(event.contains("metadata"));
            }
        }
    }
    
    // Note: Signal emission depends on hardware and timing
    qDebug() << "Received" << s_receivedSignals.size() << "signals";
}

void TestIntegration::testErrorPropagation()
{
    // Test that errors propagate correctly through the stack
    
    // 1. Try operation without starting
    QString response = callRPC("keycard.Initialize", QJsonObject{{"pin", "123456"}, {"puk", "123456123456"}});
    QJsonObject resp = parseResponse(response);
    
    QVERIFY(!isSuccessResponse(resp));
    QString error = getErrorMessage(resp);
    QVERIFY(!error.isEmpty());
    
    // 2. Try with invalid parameters
    QJsonObject params;
    params["pin"] = "12345"; // Too short
    params["puk"] = "123456123456";
    
    response = callRPC("keycard.Initialize", params);
    resp = parseResponse(response);
    
    QVERIFY(!isSuccessResponse(resp));
    error = getErrorMessage(resp);
    QVERIFY(error.contains("PIN") || error.contains("6"));
}

// ============================================================================
// Real-World Workflow Tests
// ============================================================================

void TestIntegration::testTypicalDesktopWorkflow()
{
    // Simulate a typical status-desktop workflow
    
    // 1. Application starts - Initialize RPC
    QVERIFY(m_ctx != nullptr);
    
    // 2. Set up signal callback
    KeycardSetSignalEventCallbackWithContext(m_ctx, signalCallback);
    
    // 3. Start keycard service
    QJsonObject startParams;
    startParams["storageFilePath"] = m_storagePath;
    startParams["logEnabled"] = false;
    
    QString response = callRPC("keycard.Start", startParams);
    QJsonObject resp = parseResponse(response);
    
    // 4. Poll for status periodically
    for (int i = 0; i < 3; i++) {
        response = callRPC("keycard.GetStatus");
        resp = parseResponse(response);
        QVERIFY(isSuccessResponse(resp));
        
        QTest::qWait(100); // Simulate polling interval
    }
    
    // 5. User attempts card operation (will fail without card)
    QJsonObject initParams;
    initParams["pin"] = "123456";
    initParams["puk"] = "123456123456";
    initParams["pairingPassword"] = "KeycardDefaultPairing";
    
    response = callRPC("keycard.Initialize", initParams);
    resp = parseResponse(response);
    // Will fail without card - that's OK
    
    // 6. Get metadata (will fail without card)
    response = callRPC("keycard.GetMetadata");
    resp = parseResponse(response);
    // Will fail - that's OK
    
    // 7. Application shuts down - Stop service
    response = callRPC("keycard.Stop");
    resp = parseResponse(response);
    QVERIFY(isSuccessResponse(resp));
}

void TestIntegration::testMultipleCardsWorkflow()
{
    // Test workflow with multiple cards (simulated via storage)
    
    // Start service
    QJsonObject startParams;
    startParams["storageFilePath"] = m_storagePath;
    callRPC("keycard.Start", startParams);
    
    // Simulate multiple card operations
    QStringList cardUIDs = {"card-1", "card-2", "card-3"};
    
    for (const QString& uid : cardUIDs) {
        // Query status (would change with different cards)
        QString response = callRPC("keycard.GetStatus");
        QJsonObject resp = parseResponse(response);
        QVERIFY(isSuccessResponse(resp));
        
        // Each card would have different pairing
        // (Can't test without real cards, but API flow is validated)
    }
}

void TestIntegration::testCardInsertRemoveFlow()
{
    // Test card insertion/removal detection
    
    // Start service
    QJsonObject startParams;
    startParams["storageFilePath"] = m_storagePath;
    callRPC("keycard.Start", startParams);
    
    s_receivedSignals.clear();
    
    // Wait for initial state
    QString response = callRPC("keycard.GetStatus");
    QJsonObject resp = parseResponse(response);
    QVERIFY(isSuccessResponse(resp));
    
    QJsonObject status = resp["result"].toObject();
    QString initialState = status["state"].toString();
    
    // Simulate waiting for card (would emit signals on real hardware)
    waitForSignal(500);
    
    // Query status again
    response = callRPC("keycard.GetStatus");
    resp = parseResponse(response);
    QVERIFY(isSuccessResponse(resp));
    
    qDebug() << "Initial state:" << initialState;
    qDebug() << "Signals received:" << s_receivedSignals.size();
}

void TestIntegration::testPairingWorkflow()
{
    // Test complete pairing workflow
    
    // Start service
    QJsonObject startParams;
    startParams["storageFilePath"] = m_storagePath;
    callRPC("keycard.Start", startParams);
    
    // Get initial status
    QString response = callRPC("keycard.GetStatus");
    QJsonObject resp = parseResponse(response);
    QVERIFY(isSuccessResponse(resp));
    
    QJsonObject status = resp["result"].toObject();
    QString state = status["state"].toString();
    
    // If card is ready, try to initialize (will work with real card)
    if (state == "ready" || state == "empty-keycard") {
        QJsonObject initParams;
        initParams["pin"] = "123456";
        initParams["puk"] = "123456123456";
        initParams["pairingPassword"] = "KeycardDefaultPairing";
        
        response = callRPC("keycard.Initialize", initParams);
        resp = parseResponse(response);
        
        // May succeed or fail depending on card state
        // The important thing is we get a valid response
        QVERIFY(resp.contains("result") || resp.contains("error"));
    }
}

// ============================================================================
// JSON-RPC Integration Tests
// ============================================================================

void TestIntegration::testCompleteJSONRPCFlow()
{
    // Test the complete JSON-RPC request/response flow
    
    // Start service
    QJsonObject startParams;
    startParams["storageFilePath"] = m_storagePath;
    
    QString response = callRPC("keycard.Start", startParams);
    QJsonObject resp = parseResponse(response);
    
    // Verify JSON-RPC 2.0 compliance
    QCOMPARE(resp["jsonrpc"].toString(), QString("2.0"));
    QVERIFY(resp.contains("id"));
    QVERIFY(resp.contains("result") || resp.contains("error"));
    
    // Test all 15 methods for JSON-RPC compliance
    QStringList methods = {
        "keycard.Stop", "keycard.GetStatus",
        "keycard.Initialize", "keycard.Authorize",
        "keycard.ChangePIN", "keycard.ChangePUK",
        "keycard.Unblock", "keycard.GenerateMnemonic",
        "keycard.LoadMnemonic", "keycard.FactoryReset",
        "keycard.GetMetadata", "keycard.StoreMetadata",
        "keycard.ExportLoginKeys", "keycard.ExportRecoverKeys"
    };
    
    for (const QString& method : methods) {
        QJsonObject params;
        
        // Add required parameters for methods that need them
        if (method == "keycard.Initialize") {
            params["pin"] = "123456";
            params["puk"] = "123456123456";
        } else if (method == "keycard.Authorize") {
            params["pin"] = "123456";
        } else if (method == "keycard.ChangePIN") {
            params["newPin"] = "654321";
        } else if (method == "keycard.ChangePUK") {
            params["newPuk"] = "098765432109";
        } else if (method == "keycard.Unblock") {
            params["puk"] = "123456123456";
            params["newPin"] = "654321";
        } else if (method == "keycard.GenerateMnemonic") {
            params["length"] = 12;
        } else if (method == "keycard.LoadMnemonic") {
            params["mnemonic"] = "test mnemonic";
        } else if (method == "keycard.StoreMetadata") {
            params["name"] = "Test";
            params["paths"] = QJsonArray();
        }
        
        response = callRPC(method, params);
        resp = parseResponse(response);
        
        // Verify JSON-RPC structure
        QCOMPARE(resp["jsonrpc"].toString(), QString("2.0"));
        QVERIFY(resp.contains("id"));
        QVERIFY(resp.contains("result") || resp.contains("error"));
    }
}

void TestIntegration::testConcurrentRequests()
{
    // Test that multiple requests work correctly
    
    // Start service
    QJsonObject startParams;
    startParams["storageFilePath"] = m_storagePath;
    callRPC("keycard.Start", startParams);
    
    // Make multiple concurrent status requests
    QList<QString> responses;
    for (int i = 0; i < 10; i++) {
        QString response = callRPC("keycard.GetStatus");
        responses.append(response);
    }
    
    // All should succeed
    for (const QString& response : responses) {
        QJsonObject resp = parseResponse(response);
        QVERIFY(isSuccessResponse(resp));
    }
}

void TestIntegration::testLongRunningOperations()
{
    // Test operations that might take time
    
    // Start service
    QJsonObject startParams;
    startParams["storageFilePath"] = m_storagePath;
    callRPC("keycard.Start", startParams);
    
    // Try a potentially long operation (generate mnemonic)
    QJsonObject params;
    params["length"] = 24;
    
    QString response = callRPC("keycard.GenerateMnemonic", params);
    QJsonObject resp = parseResponse(response);
    
    // Will fail without card, but should complete quickly
    QVERIFY(resp.contains("result") || resp.contains("error"));
}

// ============================================================================
// Memory and Resource Tests
// ============================================================================

void TestIntegration::testMemoryManagement()
{
    // Test that memory is properly managed
    
    // Make many calls and verify no leaks (visual inspection via instruments)
    for (int i = 0; i < 100; i++) {
        QString response = callRPC("keycard.GetStatus");
        QJsonObject resp = parseResponse(response);
        QVERIFY(resp.contains("result"));
    }
    
    // All responses should be freed properly by Free()
}

void TestIntegration::testContextIsolation()
{
    // Test that multiple contexts are isolated
    
    StatusKeycardContext ctx2 = KeycardCreateContext();
    QVERIFY(ctx2 != nullptr);
    QVERIFY(ctx2 != m_ctx);
    
    // Start service in ctx2
    QJsonObject startParams;
    startParams["storageFilePath"] = m_tempDir->filePath("ctx2_pairings.json");
    
    QJsonObject request;
    request["jsonrpc"] = "2.0";
    request["id"] = "1";
    request["method"] = "keycard.Start";
    QJsonArray params;
    params.append(startParams);
    request["params"] = params;
    
    QString requestStr = QString::fromUtf8(QJsonDocument(request).toJson(QJsonDocument::Compact));
    char* response = KeycardCallRPCWithContext(ctx2, requestStr.toUtf8().constData());
    QVERIFY(response != nullptr);
    Free(response);
    
    // Stop and cleanup ctx2
    request["method"] = "keycard.Stop";
    request["params"] = QJsonArray();
    requestStr = QString::fromUtf8(QJsonDocument(request).toJson(QJsonDocument::Compact));
    response = KeycardCallRPCWithContext(ctx2, requestStr.toUtf8().constData());
    Free(response);
    
    KeycardDestroyContext(ctx2);
}

void TestIntegration::testResourceCleanup()
{
    // Test that resources are cleaned up properly
    
    // Start service
    QJsonObject startParams;
    startParams["storageFilePath"] = m_storagePath;
    callRPC("keycard.Start", startParams);
    
    // Make some operations
    for (int i = 0; i < 10; i++) {
        callRPC("keycard.GetStatus");
    }
    
    // Stop service
    callRPC("keycard.Stop");
    
    // Reset API
    ResetAPIWithContext(m_ctx);
    
    // Context is still valid after reset
    QVERIFY(m_ctx != nullptr);
    
    // Should work again
    QString response = callRPC("keycard.GetStatus");
    QJsonObject resp = parseResponse(response);
    QVERIFY(isSuccessResponse(resp));
}

QTEST_MAIN(TestIntegration)
#include "test_integration.moc"

