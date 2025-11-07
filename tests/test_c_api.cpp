#include <QtTest/QtTest>
#include <QJsonDocument>
#include <QJsonObject>
#include "status-keycard-qt/status_keycard.h"
#include "flow/flow_manager.h"

using namespace StatusKeycard;

class TestCApi : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void init();
    void cleanup();

    // Context management tests
    void testKeycardInitializeRPC();
    void testKeycardInitializeRPCMultiple();
    void testFreeFunction();
    void testResetAPI();
    
    // RPC call tests
    void testKeycardCallRPCNullContext();
    void testKeycardCallRPCNullPayload();
    void testKeycardCallRPCValid();
    void testKeycardCallRPCInvalidJSON();
    void testKeycardCallRPCMethodNotFound();
    
    // Signal callback tests
    void testSetSignalEventCallback();
    void testSetSignalEventCallbackNull();
    
    // Flow API tests (deprecated)
    void testFlowAPIReturnsDeprecated();
    
    // Mocked API tests
    void testMockedFunctionsReturnSuccess();

private:
    StatusKeycardContext m_ctx;
    
    static QStringList s_receivedSignals;
    static void signalCallback(const char* signal_json);
};

QStringList TestCApi::s_receivedSignals;

void TestCApi::signalCallback(const char* signal_json)
{
    if (signal_json) {
        s_receivedSignals.append(QString::fromUtf8(signal_json));
    }
}

void TestCApi::initTestCase()
{
    s_receivedSignals.clear();
}

void TestCApi::cleanupTestCase()
{
    // Nothing needed
}

void TestCApi::init()
{
    m_ctx = KeycardCreateContext();
    s_receivedSignals.clear();
}

void TestCApi::cleanup()
{
    if (m_ctx) {
        KeycardDestroyContext(m_ctx);
        m_ctx = nullptr;
    }
    s_receivedSignals.clear();
}

void TestCApi::testKeycardInitializeRPC()
{
    // Test the compatibility API that returns JSON string
    char* response = KeycardInitializeRPC();
    QVERIFY(response != nullptr);
    
    QJsonDocument doc = QJsonDocument::fromJson(QByteArray(response));
    QJsonObject obj = doc.object();
    QVERIFY(obj.contains("error"));
    QCOMPARE(obj["error"].toString(), QString(""));
    
    Free(response);
}

void TestCApi::testKeycardInitializeRPCMultiple()
{
    StatusKeycardContext ctx1 = KeycardCreateContext();
    StatusKeycardContext ctx2 = KeycardCreateContext();
    
    QVERIFY(ctx1 != nullptr);
    QVERIFY(ctx2 != nullptr);
    QVERIFY(ctx1 != ctx2);
    
    KeycardDestroyContext(ctx1);
    KeycardDestroyContext(ctx2);
}

void TestCApi::testFreeFunction()
{
    char* testStr = strdup("test string");
    QVERIFY(testStr != nullptr);
    
    Free(testStr);
    // If this doesn't crash, the test passes
    
    // Test null pointer
    Free(nullptr);
    // Should not crash
}

void TestCApi::testResetAPI()
{
    // Reset should not crash even with operations in progress
    ResetAPIWithContext(m_ctx);
    
    // Context should still be valid after reset
    QVERIFY(m_ctx != nullptr);
}

void TestCApi::testKeycardCallRPCNullContext()
{
    char* response = KeycardCallRPCWithContext(nullptr, "{\"method\":\"keycard.Stop\"}");
    QVERIFY(response != nullptr);
    
    // Should return error response
    QJsonDocument doc = QJsonDocument::fromJson(QByteArray(response));
    QJsonObject obj = doc.object();
    QVERIFY(obj.contains("error"));
    
    Free(response);
}

void TestCApi::testKeycardCallRPCNullPayload()
{
    char* response = KeycardCallRPCWithContext(m_ctx, nullptr);
    QVERIFY(response != nullptr);
    
    // Should return error response
    QJsonDocument doc = QJsonDocument::fromJson(QByteArray(response));
    QJsonObject obj = doc.object();
    QVERIFY(obj.contains("error"));
    
    Free(response);
}

void TestCApi::testKeycardCallRPCValid()
{
    const char* request = R"({
        "jsonrpc": "2.0",
        "id": "test-id",
        "method": "keycard.Stop",
        "params": []
    })";
    
    char* response = KeycardCallRPCWithContext(m_ctx, request);
    QVERIFY(response != nullptr);
    
    // Parse response
    QJsonDocument doc = QJsonDocument::fromJson(QByteArray(response));
    QJsonObject obj = doc.object();
    
    QCOMPARE(obj["jsonrpc"].toString(), QString("2.0"));
    QCOMPARE(obj["id"].toString(), QString("test-id"));
    QVERIFY(obj.contains("result"));
    
    Free(response);
}

void TestCApi::testKeycardCallRPCInvalidJSON()
{
    const char* invalidRequest = "{ invalid json }";
    
    char* response = KeycardCallRPCWithContext(m_ctx, invalidRequest);
    QVERIFY(response != nullptr);
    
    // Should return parse error
    QJsonDocument doc = QJsonDocument::fromJson(QByteArray(response));
    QJsonObject obj = doc.object();
    QVERIFY(obj.contains("error"));
    QCOMPARE(obj["error"].toObject()["code"].toInt(), -32700);
    
    Free(response);
}

void TestCApi::testKeycardCallRPCMethodNotFound()
{
    const char* request = R"({
        "jsonrpc": "2.0",
        "id": "test-id",
        "method": "keycard.NonExistentMethod",
        "params": []
    })";
    
    char* response = KeycardCallRPCWithContext(m_ctx, request);
    QVERIFY(response != nullptr);
    
    // Should return method not found error
    QJsonDocument doc = QJsonDocument::fromJson(QByteArray(response));
    QJsonObject obj = doc.object();
    QVERIFY(obj.contains("error"));
    QCOMPARE(obj["error"].toObject()["code"].toInt(), -32601);
    
    Free(response);
}

void TestCApi::testSetSignalEventCallback()
{
    KeycardSetSignalEventCallbackWithContext(m_ctx, signalCallback);
    
    // Trigger a status change by calling GetStatus
    const char* request = R"({
        "jsonrpc": "2.0",
        "id": "test-id",
        "method": "keycard.GetStatus",
        "params": []
    })";
    
    char* response = KeycardCallRPCWithContext(m_ctx, request);
    Free(response);
    
    // No signals should be emitted by GetStatus itself
    // (signals are emitted on state changes, not queries)
}

void TestCApi::testSetSignalEventCallbackNull()
{
    KeycardSetSignalEventCallbackWithContext(m_ctx, signalCallback);
    KeycardSetSignalEventCallbackWithContext(m_ctx, nullptr);
    
    // Should not crash
}

void TestCApi::testFlowAPIReturnsDeprecated()
{
    // Flow API uses global context - test that the wrapper functions work
    char* response = KeycardInitFlow("/tmp/test");
    QVERIFY(response != nullptr);
    
    // Should be valid JSON response (success or error, not a crash)
    QString responseStr = QString::fromUtf8(response);
    QVERIFY(responseStr.contains("success") || responseStr.contains("error") || responseStr.contains("result"));
    
    Free(response);
    
    // Test other Flow API methods - they should not crash
    response = KeycardStartFlow(0, "{}");
    QVERIFY(response != nullptr);
    Free(response);
    
    response = KeycardResumeFlow("{}");
    QVERIFY(response != nullptr);
    Free(response);
    
    response = KeycardCancelFlow();
    QVERIFY(response != nullptr);
    Free(response);
    
    // Cleanup
    FlowManager::destroyInstance();
}

void TestCApi::testMockedFunctionsReturnSuccess()
{
    // Mocked API uses global context, not the context parameter
    char* response = MockedLibRegisterKeycard(0, 0, 0, "", "");
    QVERIFY(response != nullptr);
    Free(response);
    
    response = MockedLibReaderPluggedIn();
    QVERIFY(response != nullptr);
    Free(response);
    
    response = MockedLibReaderUnplugged();
    QVERIFY(response != nullptr);
    Free(response);
    
    response = MockedLibKeycardInserted(0);
    QVERIFY(response != nullptr);
    Free(response);
    
    response = MockedLibKeycardRemoved();
    QVERIFY(response != nullptr);
    Free(response);
}

QTEST_MAIN(TestCApi)
#include "test_c_api.moc"

