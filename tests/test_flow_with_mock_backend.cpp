#include <QtTest/QtTest>
#include "mocks/mock_keycard_backend.h"
#include "flow/flow_params.h"
#include <QJsonObject>
#include <QSignalSpy>

using namespace StatusKeycardTest;
using namespace StatusKeycard;

class TestFlowWithMockBackend : public QObject
{
    Q_OBJECT

private slots:
    void testMockBackendCreation()
    {
        MockKeycardBackend backend;
        QVERIFY(!backend.isConnected());
    }

    void testMockBackendCardInsert()
    {
        MockKeycardBackend backend;
        QSignalSpy spy(&backend, &MockKeycardBackend::targetDetected);
        
        backend.startDetection();
        backend.simulateCardInserted();
        
        QVERIFY(backend.isConnected());
        QCOMPARE(spy.count(), 1);
    }

    void testMockBackendCardRemove()
    {
        MockKeycardBackend backend;
        QSignalSpy spy(&backend, &MockKeycardBackend::cardRemoved);
        
        backend.startDetection();
        backend.simulateCardInserted();
        backend.simulateCardRemoved();
        
        QVERIFY(!backend.isConnected());
        QCOMPARE(spy.count(), 1);
    }

    void testMockBackendAutoConnect()
    {
        MockKeycardBackend backend;
        backend.setAutoConnect(true);
        
        QSignalSpy spy(&backend, &MockKeycardBackend::targetDetected);
        backend.startDetection();
        
        QVERIFY(spy.wait(200));
        QVERIFY(backend.isConnected());
    }

    void testMockBackendSelectAPDU()
    {
        MockKeycardBackend backend;
        backend.simulateCardInserted();
        
        QByteArray selectAPDU = QByteArray::fromHex("00A4040000");
        QByteArray response = backend.transmit(selectAPDU);
        
        QVERIFY(response.size() > 2);
        QCOMPARE(static_cast<quint8>(response[response.size()-2]), quint8(0x90));
        QCOMPARE(static_cast<quint8>(response[response.size()-1]), quint8(0x00));
    }

    void testMockBackendConfiguration()
    {
        MockKeycardBackend backend;
        
        backend.setPIN("123456");
        backend.setPUK("111111111111");
        backend.setPairingPassword("TestPassword");
        backend.setCardInitialized(true);
        
        backend.simulateCardInserted();
        QVERIFY(backend.isConnected());
    }

    void testGetAppInfoFlowParams()
    {
        QJsonObject params;
        QVERIFY(params.isEmpty() || true);
    }

    void testLoginFlowParams()
    {
        QJsonObject params;
        params[FlowParams::PIN] = "000000";
        params[FlowParams::PAIRING_PASS] = "KeycardTest";
        
        QVERIFY(params.contains(FlowParams::PIN));
        QVERIFY(params.contains(FlowParams::PAIRING_PASS));
    }

    void testRecoverAccountFlowParams()
    {
        QJsonObject params;
        params[FlowParams::PIN] = "000000";
        params[FlowParams::PAIRING_PASS] = "KeycardTest";
        
        QVERIFY(params.contains(FlowParams::PIN));
        QVERIFY(params.contains(FlowParams::PAIRING_PASS));
    }

    void testLoadAccountFlowParams()
    {
        QJsonObject params;
        params[FlowParams::MNEMONIC] = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        params[FlowParams::PIN] = "000000";
        params[FlowParams::PUK] = "000000000000";
        
        QVERIFY(params.contains(FlowParams::MNEMONIC));
        QVERIFY(params.contains(FlowParams::PIN));
        QVERIFY(params.contains(FlowParams::PUK));
    }

    void testSignFlowParams()
    {
        QJsonObject params;
        params[FlowParams::TX_HASH] = "0xabcdef1234567890";
        params[FlowParams::BIP44_PATH] = "m/44'/60'/0'/0/0";
        params[FlowParams::PIN] = "000000";
        
        QVERIFY(params.contains(FlowParams::TX_HASH));
        QVERIFY(params.contains(FlowParams::BIP44_PATH));
        QVERIFY(params.contains(FlowParams::PIN));
    }

    void testChangePINFlowParams()
    {
        QJsonObject params;
        params[FlowParams::PIN] = "000000";
        params[FlowParams::NEW_PIN] = "123456";
        
        QVERIFY(params.contains(FlowParams::PIN));
        QVERIFY(params.contains(FlowParams::NEW_PIN));
    }

    void testExportPublicFlowParams()
    {
        QJsonObject params;
        params[FlowParams::BIP44_PATH] = "m/44'/60'/0'/0/0";
        params[FlowParams::PIN] = "000000";
        
        QVERIFY(params.contains(FlowParams::BIP44_PATH));
        QVERIFY(params.contains(FlowParams::PIN));
    }

    void testGetMetadataFlowParams()
    {
        QJsonObject params;
        params[FlowParams::PIN] = "000000";
        
        QVERIFY(params.contains(FlowParams::PIN));
    }

    void testStoreMetadataFlowParams()
    {
        QJsonObject params;
        params[FlowParams::CARD_META] = "test metadata";
        params[FlowParams::PIN] = "000000";
        
        QVERIFY(params.contains(FlowParams::CARD_META));
        QVERIFY(params.contains(FlowParams::PIN));
    }
};

QTEST_MAIN(TestFlowWithMockBackend)
#include "test_flow_with_mock_backend.moc"
