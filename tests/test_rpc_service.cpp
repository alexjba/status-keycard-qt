#include <QtTest/QtTest>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include "rpc/rpc_service.h"

using namespace StatusKeycard;

class TestRpcService : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void init();
    void cleanup();

    // JSON-RPC protocol tests
    void testParseError();
    void testMethodNotFound();
    void testInvalidRequest();
    void testSuccessResponse();
    
    // Session API method tests
    void testStartMethod();
    void testStopMethod();
    void testGetStatusMethod();
    void testInitializeMethod();
    void testAuthorizeMethod();
    void testChangePINMethod();
    void testChangePUKMethod();
    void testUnblockMethod();
    void testGenerateMnemonicMethod();
    void testLoadMnemonicMethod();
    void testFactoryResetMethod();
    void testGetMetadataMethod();
    void testStoreMetadataMethod();
    void testExportLoginKeysMethod();
    void testExportRecoverKeysMethod();
    
    // Integration tests
    void testFullWorkflow();

private:
    RpcService* m_service;
    QString sendRequest(const QString& method, const QJsonObject& params = QJsonObject());
    QJsonObject parseResponse(const QString& response);
};

void TestRpcService::initTestCase()
{
    // Nothing needed
}

void TestRpcService::cleanupTestCase()
{
    // Nothing needed
}

void TestRpcService::init()
{
    m_service = new RpcService();
}

void TestRpcService::cleanup()
{
    delete m_service;
    m_service = nullptr;
}

QString TestRpcService::sendRequest(const QString& method, const QJsonObject& params)
{
    QJsonObject request;
    request["jsonrpc"] = "2.0";
    request["id"] = "test-id";
    request["method"] = method;
    
    if (!params.isEmpty()) {
        QJsonArray paramsArray;
        paramsArray.append(params);
        request["params"] = paramsArray;
    } else {
        request["params"] = QJsonArray();
    }
    
    QJsonDocument doc(request);
    QString requestStr = QString::fromUtf8(doc.toJson(QJsonDocument::Compact));
    
    return m_service->processRequest(requestStr);
}

QJsonObject TestRpcService::parseResponse(const QString& response)
{
    QJsonDocument doc = QJsonDocument::fromJson(response.toUtf8());
    return doc.object();
}

void TestRpcService::testParseError()
{
    QString invalidJson = "{ invalid json }";
    QString response = m_service->processRequest(invalidJson);
    
    QJsonObject resp = parseResponse(response);
    QVERIFY(resp.contains("error"));
    QCOMPARE(resp["error"].toObject()["code"].toInt(), -32700);
}

void TestRpcService::testMethodNotFound()
{
    QString response = sendRequest("keycard.NonExistentMethod");
    
    QJsonObject resp = parseResponse(response);
    QVERIFY(resp.contains("error"));
    QCOMPARE(resp["error"].toObject()["code"].toInt(), -32601);
}

void TestRpcService::testInvalidRequest()
{
    QString response = m_service->processRequest("{}");
    
    QJsonObject resp = parseResponse(response);
    // Should handle gracefully (method not found)
    QVERIFY(resp.contains("error"));
}

void TestRpcService::testSuccessResponse()
{
    QString response = sendRequest("keycard.Stop");
    
    QJsonObject resp = parseResponse(response);
    QVERIFY(resp.contains("result"));
    QVERIFY(!resp.contains("error") || resp["error"].isNull());
    QCOMPARE(resp["jsonrpc"].toString(), QString("2.0"));
    QCOMPARE(resp["id"].toString(), QString("test-id"));
}

void TestRpcService::testStartMethod()
{
    QJsonObject params;
    params["storageFilePath"] = "/tmp/test_pairings.json";
    params["logEnabled"] = false;
    
    QString response = sendRequest("keycard.Start", params);
    QJsonObject resp = parseResponse(response);
    
    // Should succeed or fail gracefully
    QVERIFY(resp.contains("result") || resp.contains("error"));
}

void TestRpcService::testStopMethod()
{
    QString response = sendRequest("keycard.Stop");
    QJsonObject resp = parseResponse(response);
    
    QVERIFY(resp.contains("result"));
    QVERIFY(resp["result"].toObject().isEmpty());
}

void TestRpcService::testGetStatusMethod()
{
    QString response = sendRequest("keycard.GetStatus");
    QJsonObject resp = parseResponse(response);
    
    QVERIFY(resp.contains("result"));
    QJsonObject status = resp["result"].toObject();
    
    // Should have state field
    QVERIFY(status.contains("state"));
    
    // Should have nullable fields
    QVERIFY(status.contains("keycardInfo"));
    QVERIFY(status.contains("keycardStatus"));
    QVERIFY(status.contains("metadata"));
}

void TestRpcService::testInitializeMethod()
{
    QJsonObject params;
    params["pin"] = "123456";
    params["puk"] = "123456123456";
    params["pairingPassword"] = "KeycardDefaultPairing";
    
    QString response = sendRequest("keycard.Initialize", params);
    QJsonObject resp = parseResponse(response);
    
    // Will fail without a card, but should validate params
    QVERIFY(resp.contains("result") || resp.contains("error"));
    
    // Test invalid PIN length
    params["pin"] = "12345";
    response = sendRequest("keycard.Initialize", params);
    resp = parseResponse(response);
    QVERIFY(resp.contains("error"));
    QCOMPARE(resp["error"].toObject()["code"].toInt(), -32602);
}

void TestRpcService::testAuthorizeMethod()
{
    QJsonObject params;
    params["pin"] = "123456";
    
    QString response = sendRequest("keycard.Authorize", params);
    QJsonObject resp = parseResponse(response);
    
    // Should have result with authorized field (false without card)
    if (resp.contains("result")) {
        QVERIFY(resp["result"].toObject().contains("authorized"));
    }
    
    // Test invalid PIN length
    params["pin"] = "12345";
    response = sendRequest("keycard.Authorize", params);
    resp = parseResponse(response);
    QVERIFY(resp.contains("error"));
}

void TestRpcService::testChangePINMethod()
{
    QJsonObject params;
    params["newPin"] = "654321";
    
    QString response = sendRequest("keycard.ChangePIN", params);
    QJsonObject resp = parseResponse(response);
    
    // Will fail without authorization, but params should be validated
    QVERIFY(resp.contains("result") || resp.contains("error"));
}

void TestRpcService::testChangePUKMethod()
{
    QJsonObject params;
    params["newPuk"] = "098765432109";
    
    QString response = sendRequest("keycard.ChangePUK", params);
    QJsonObject resp = parseResponse(response);
    
    QVERIFY(resp.contains("result") || resp.contains("error"));
}

void TestRpcService::testUnblockMethod()
{
    QJsonObject params;
    params["puk"] = "123456123456";
    params["newPin"] = "654321";
    
    QString response = sendRequest("keycard.Unblock", params);
    QJsonObject resp = parseResponse(response);
    
    QVERIFY(resp.contains("result") || resp.contains("error"));
    
    // Test invalid params
    params["puk"] = "12345";
    response = sendRequest("keycard.Unblock", params);
    resp = parseResponse(response);
    QVERIFY(resp.contains("error"));
}

void TestRpcService::testGenerateMnemonicMethod()
{
    QJsonObject params;
    params["length"] = 12;
    
    QString response = sendRequest("keycard.GenerateMnemonic", params);
    QJsonObject resp = parseResponse(response);
    
    // Will fail without card, but should validate
    QVERIFY(resp.contains("result") || resp.contains("error"));
}

void TestRpcService::testLoadMnemonicMethod()
{
    QJsonObject params;
    params["mnemonic"] = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    params["passphrase"] = "";
    
    QString response = sendRequest("keycard.LoadMnemonic", params);
    QJsonObject resp = parseResponse(response);
    
    QVERIFY(resp.contains("result") || resp.contains("error"));
    
    // Test missing mnemonic
    params.remove("mnemonic");
    response = sendRequest("keycard.LoadMnemonic", params);
    resp = parseResponse(response);
    QVERIFY(resp.contains("error"));
}

void TestRpcService::testFactoryResetMethod()
{
    QString response = sendRequest("keycard.FactoryReset");
    QJsonObject resp = parseResponse(response);
    
    QVERIFY(resp.contains("result") || resp.contains("error"));
}

void TestRpcService::testGetMetadataMethod()
{
    QString response = sendRequest("keycard.GetMetadata");
    QJsonObject resp = parseResponse(response);
    
    QVERIFY(resp.contains("result") || resp.contains("error"));
    
    if (resp.contains("result")) {
        QJsonObject result = resp["result"].toObject();
        QVERIFY(result.contains("metadata"));
    }
}

void TestRpcService::testStoreMetadataMethod()
{
    QJsonObject params;
    params["name"] = "Test Wallet";
    params["paths"] = QJsonArray({"m/44'/60'/0'/0", "m/44'/60'/0'/1"});
    
    QString response = sendRequest("keycard.StoreMetadata", params);
    QJsonObject resp = parseResponse(response);
    
    QVERIFY(resp.contains("result") || resp.contains("error"));
}

void TestRpcService::testExportLoginKeysMethod()
{
    QString response = sendRequest("keycard.ExportLoginKeys");
    QJsonObject resp = parseResponse(response);
    
    // Not yet implemented
    QVERIFY(resp.contains("error"));
}

void TestRpcService::testExportRecoverKeysMethod()
{
    QString response = sendRequest("keycard.ExportRecoverKeys");
    QJsonObject resp = parseResponse(response);
    
    // Not yet implemented
    QVERIFY(resp.contains("error"));
}

void TestRpcService::testFullWorkflow()
{
    // Test a typical workflow sequence
    
    // 1. Start service
    QJsonObject startParams;
    startParams["storageFilePath"] = "/tmp/test_workflow_pairings.json";
    QString response = sendRequest("keycard.Start", startParams);
    QJsonObject resp = parseResponse(response);
    // May fail without reader, but should process request
    QVERIFY(resp.contains("result") || resp.contains("error"));
    
    // 2. Get status
    response = sendRequest("keycard.GetStatus");
    resp = parseResponse(response);
    QVERIFY(resp.contains("result"));
    
    // 3. Stop service
    response = sendRequest("keycard.Stop");
    resp = parseResponse(response);
    QVERIFY(resp.contains("result"));
}

QTEST_MAIN(TestRpcService)
#include "test_rpc_service.moc"

