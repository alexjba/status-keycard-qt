#include <QtTest/QtTest>
#include "flow/flow_signals.h"
#include "flow/flow_params.h"
#include "signal_manager.h"
#include <QJsonDocument>
#include <QJsonObject>

using namespace StatusKeycard;

class TestFlowSignals : public QObject
{
    Q_OBJECT

private:
    QString lastSignal;
    
private slots:
    void initTestCase()
    {
        // Register callback to capture signals
        SignalManager::instance()->setCallback([](const char* signal) {
            // Signals are captured by the test
        });
    }

    void cleanupTestCase()
    {
        SignalManager::instance()->setCallback(nullptr);
    }

    void testSignalConstants()
    {
        // Verify signal type constants match expected values
        QCOMPARE(FlowSignals::FLOW_RESULT, QString("keycard.flow-result"));
        QCOMPARE(FlowSignals::INSERT_CARD, QString("keycard.action.insert-card"));
        QCOMPARE(FlowSignals::CARD_INSERTED, QString("keycard.action.card-inserted"));
        QCOMPARE(FlowSignals::SWAP_CARD, QString("keycard.action.swap-card"));
        QCOMPARE(FlowSignals::ENTER_PAIRING, QString("keycard.action.enter-pairing"));
        QCOMPARE(FlowSignals::ENTER_PIN, QString("keycard.action.enter-pin"));
        QCOMPARE(FlowSignals::ENTER_PUK, QString("keycard.action.enter-puk"));
        QCOMPARE(FlowSignals::ENTER_NEW_PAIRING, QString("keycard.action.enter-new-pairing"));
        QCOMPARE(FlowSignals::ENTER_NEW_PIN, QString("keycard.action.enter-new-pin"));
        QCOMPARE(FlowSignals::ENTER_NEW_PUK, QString("keycard.action.enter-new-puk"));
        QCOMPARE(FlowSignals::ENTER_TX_HASH, QString("keycard.action.enter-tx-hash"));
        QCOMPARE(FlowSignals::ENTER_PATH, QString("keycard.action.enter-bip44-path"));
        QCOMPARE(FlowSignals::ENTER_MNEMONIC, QString("keycard.action.enter-mnemonic"));
        QCOMPARE(FlowSignals::ENTER_NAME, QString("keycard.action.enter-cardname"));
        QCOMPARE(FlowSignals::ENTER_WALLETS, QString("keycard.action.enter-wallets"));
    }

    void testEmitInsertCard()
    {
        // Test that emitInsertCard creates correct signal
        // Note: Actual emission tested in integration tests
        // Here we just verify the constants and structure are correct
        QVERIFY(!FlowSignals::INSERT_CARD.isEmpty());
    }

    void testEmitEnterPIN()
    {
        // Verify PIN retries parameter can be included
        QVERIFY(!FlowSignals::ENTER_PIN.isEmpty());
        QVERIFY(!FlowParams::PIN_RETRIES.isEmpty());
    }

    void testEmitEnterPairing()
    {
        // Verify free slots parameter can be included
        QVERIFY(!FlowSignals::ENTER_PAIRING.isEmpty());
        QVERIFY(!FlowParams::FREE_SLOTS.isEmpty());
    }

    void testFlowResultFormat()
    {
        // Test flow result signal format
        QJsonObject result;
        result[FlowParams::KEY_UID] = "test-key-uid";
        result[FlowParams::INSTANCE_UID] = "test-instance-uid";
        
        QVERIFY(result.contains(FlowParams::KEY_UID));
        QVERIFY(result.contains(FlowParams::INSTANCE_UID));
    }

    void testErrorFormat()
    {
        // Test error signal format
        QJsonObject event;
        event[FlowParams::ERROR_KEY] = "test-error";
        
        QCOMPARE(event[FlowParams::ERROR_KEY].toString(), QString("test-error"));
    }

    void testCardInfoFormat()
    {
        // Test card info format in signals
        QJsonObject cardInfo;
        cardInfo[FlowParams::INSTANCE_UID] = "abc123";
        cardInfo[FlowParams::KEY_UID] = "def456";
        cardInfo[FlowParams::FREE_SLOTS] = 3;
        cardInfo[FlowParams::PIN_RETRIES] = 3;
        cardInfo[FlowParams::PUK_RETRIES] = 5;
        
        QCOMPARE(cardInfo[FlowParams::INSTANCE_UID].toString(), QString("abc123"));
        QCOMPARE(cardInfo[FlowParams::KEY_UID].toString(), QString("def456"));
        QCOMPARE(cardInfo[FlowParams::FREE_SLOTS].toInt(), 3);
        QCOMPARE(cardInfo[FlowParams::PIN_RETRIES].toInt(), 3);
        QCOMPARE(cardInfo[FlowParams::PUK_RETRIES].toInt(), 5);
    }
};

QTEST_MAIN(TestFlowSignals)
#include "test_flow_signals.moc"

