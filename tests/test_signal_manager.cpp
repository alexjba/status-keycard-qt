#include <QtTest/QtTest>
#include <QJsonDocument>
#include <QJsonObject>
#include "signal_manager.h"
#include "session/session_manager.h"

using namespace StatusKeycard;

class TestSignalManager : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void init();
    void cleanup();

    // Signal Manager tests
    void testSingleton();
    void testSetCallback();
    void testEmitStatusChanged();
    void testEmitStatusChangedWithNullFields();
    void testEmitError();
    void testSignalFormat();
    void testMultipleSignals();

private:
    SignalManager* m_signalManager;
    QStringList m_receivedSignals;
    
    static void signalCallback(const char* signal_json);
    static QStringList s_receivedSignals;
};

QStringList TestSignalManager::s_receivedSignals;

void TestSignalManager::signalCallback(const char* signal_json)
{
    s_receivedSignals.append(QString::fromUtf8(signal_json));
}

void TestSignalManager::initTestCase()
{
    s_receivedSignals.clear();
}

void TestSignalManager::cleanupTestCase()
{
    // Nothing needed
}

void TestSignalManager::init()
{
    m_signalManager = SignalManager::instance();
    s_receivedSignals.clear();
    m_signalManager->setCallback(signalCallback);
}

void TestSignalManager::cleanup()
{
    m_signalManager->setCallback(nullptr);
    s_receivedSignals.clear();
}

void TestSignalManager::testSingleton()
{
    SignalManager* instance1 = SignalManager::instance();
    SignalManager* instance2 = SignalManager::instance();
    
    QCOMPARE(instance1, instance2);
    QVERIFY(instance1 != nullptr);
}

void TestSignalManager::testSetCallback()
{
    // Callback already set in init()
    
    // Create a test status
    SessionManager::Status status;
    status.state = "ready";
    
    m_signalManager->emitStatusChanged(status);
    
    QCOMPARE(s_receivedSignals.size(), 1);
    
    // Clear callback
    m_signalManager->setCallback(nullptr);
    s_receivedSignals.clear();
    
    m_signalManager->emitStatusChanged(status);
    
    // No signal should be received
    QCOMPARE(s_receivedSignals.size(), 0);
}

void TestSignalManager::testEmitStatusChanged()
{
    SessionManager::Status status;
    status.state = "ready";
    
    // Create keycardInfo
    status.keycardInfo = new SessionManager::ApplicationInfoV2();
    status.keycardInfo->installed = true;
    status.keycardInfo->initialized = true;
    status.keycardInfo->instanceUID = "abcd1234";
    status.keycardInfo->version = "3.0";
    status.keycardInfo->availableSlots = 3;
    status.keycardInfo->keyUID = "deadbeef";
    
    // Create keycardStatus
    status.keycardStatus = new SessionManager::ApplicationStatus();
    status.keycardStatus->remainingAttemptsPIN = 3;
    status.keycardStatus->remainingAttemptsPUK = 5;
    status.keycardStatus->keyInitialized = true;
    status.keycardStatus->path = "m/44'/60'/0'";
    
    m_signalManager->emitStatusChanged(status);
    
    QCOMPARE(s_receivedSignals.size(), 1);
    
    // Parse the signal
    QJsonDocument doc = QJsonDocument::fromJson(s_receivedSignals[0].toUtf8());
    QJsonObject signal = doc.object();
    
    QCOMPARE(signal["type"].toString(), QString("status-changed"));
    QVERIFY(signal.contains("event"));
    
    QJsonObject event = signal["event"].toObject();
    QCOMPARE(event["state"].toString(), QString("ready"));
    
    // Verify keycardInfo
    QVERIFY(event.contains("keycardInfo"));
    QJsonObject keycardInfo = event["keycardInfo"].toObject();
    QCOMPARE(keycardInfo["installed"].toBool(), true);
    QCOMPARE(keycardInfo["initialized"].toBool(), true);
    QCOMPARE(keycardInfo["instanceUID"].toString(), QString("abcd1234"));
    QCOMPARE(keycardInfo["version"].toString(), QString("3.0"));
    
    // Verify keycardStatus
    QVERIFY(event.contains("keycardStatus"));
    QJsonObject keycardStatus = event["keycardStatus"].toObject();
    QCOMPARE(keycardStatus["remainingAttemptsPIN"].toInt(), 3);
    QCOMPARE(keycardStatus["remainingAttemptsPUK"].toInt(), 5);
    QCOMPARE(keycardStatus["keyInitialized"].toBool(), true);
}

void TestSignalManager::testEmitStatusChangedWithNullFields()
{
    SessionManager::Status status;
    status.state = "waiting-for-card";
    // All pointers are null
    
    m_signalManager->emitStatusChanged(status);
    
    QCOMPARE(s_receivedSignals.size(), 1);
    
    // Parse the signal
    QJsonDocument doc = QJsonDocument::fromJson(s_receivedSignals[0].toUtf8());
    QJsonObject signal = doc.object();
    
    QJsonObject event = signal["event"].toObject();
    QCOMPARE(event["state"].toString(), QString("waiting-for-card"));
    
    // Verify null fields
    QVERIFY(event["keycardInfo"].isNull());
    QVERIFY(event["keycardStatus"].isNull());
    QVERIFY(event["metadata"].isNull());
}

void TestSignalManager::testEmitError()
{
    m_signalManager->emitError("Test error message");
    
    QCOMPARE(s_receivedSignals.size(), 1);
    
    // Parse the signal
    QJsonDocument doc = QJsonDocument::fromJson(s_receivedSignals[0].toUtf8());
    QJsonObject signal = doc.object();
    
    QCOMPARE(signal["type"].toString(), QString("error"));
    QVERIFY(signal.contains("event"));
    
    QJsonObject event = signal["event"].toObject();
    QCOMPARE(event["error"].toString(), QString("Test error message"));
}

void TestSignalManager::testSignalFormat()
{
    SessionManager::Status status;
    status.state = "ready";
    
    m_signalManager->emitStatusChanged(status);
    
    QCOMPARE(s_receivedSignals.size(), 1);
    
    // Verify it's valid JSON
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(s_receivedSignals[0].toUtf8(), &parseError);
    
    QCOMPARE(parseError.error, QJsonParseError::NoError);
    QVERIFY(doc.isObject());
    
    QJsonObject signal = doc.object();
    
    // Verify required fields
    QVERIFY(signal.contains("type"));
    QVERIFY(signal.contains("event"));
}

void TestSignalManager::testMultipleSignals()
{
    // Emit multiple different signals
    SessionManager::Status status1;
    status1.state = "waiting-for-card";
    m_signalManager->emitStatusChanged(status1);
    
    SessionManager::Status status2;
    status2.state = "connecting-card";
    m_signalManager->emitStatusChanged(status2);
    
    m_signalManager->emitError("Test error");
    
    SessionManager::Status status3;
    status3.state = "ready";
    m_signalManager->emitStatusChanged(status3);
    
    QCOMPARE(s_receivedSignals.size(), 4);
    
    // Verify each signal
    for (const QString& signalStr : s_receivedSignals) {
        QJsonDocument doc = QJsonDocument::fromJson(signalStr.toUtf8());
        QVERIFY(doc.isObject());
        
        QJsonObject signal = doc.object();
        QVERIFY(signal.contains("type"));
        QVERIFY(signal.contains("event"));
    }
}

QTEST_MAIN(TestSignalManager)
#include "test_signal_manager.moc"

