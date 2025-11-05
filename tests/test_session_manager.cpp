#include <QtTest/QtTest>
#include <QTemporaryDir>
#include "session/session_manager.h"
#include "session/session_state.h"

using namespace StatusKeycard;

class TestSessionManager : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void init();
    void cleanup();

    // Lifecycle tests
    void testInitialState();
    void testStart();
    void testStartAlreadyStarted();
    void testStartWithInvalidPath();
    void testStop();
    void testStopNotStarted();
    
    // State management tests
    void testStateTransitions();
    void testGetStatus();
    void testStateStrings();
    
    // Error handling tests
    void testLastError();
    void testOperationWithoutStart();
    void testOperationWithoutCard();
    
    // Card operations tests (without physical card)
    void testInitializeWithoutCard();
    void testAuthorizeWithoutCard();
    void testChangePINWithoutCard();
    void testChangePUKWithoutCard();
    void testUnblockPINWithoutCard();
    void testGenerateMnemonicWithoutCard();
    void testLoadMnemonicWithoutCard();
    void testFactoryResetWithoutCard();
    
    // Status structure tests
    void testStatusStructure();
    void testStatusWithNullFields();
    
    // Signal emission tests
    void testStateChangedSignal();

private:
    SessionManager* m_manager;
    QTemporaryDir* m_tempDir;
    QString m_storagePath;
    
    QVector<QPair<SessionState, SessionState>> m_stateChanges;
    
    void onStateChanged(SessionState newState, SessionState oldState);
};

void TestSessionManager::initTestCase()
{
    // Nothing needed
}

void TestSessionManager::cleanupTestCase()
{
    // Nothing needed
}

void TestSessionManager::init()
{
    m_tempDir = new QTemporaryDir();
    QVERIFY(m_tempDir->isValid());
    m_storagePath = m_tempDir->filePath("test_pairings.json");
    
    m_manager = new SessionManager();
    m_stateChanges.clear();
    
    connect(m_manager, &SessionManager::stateChanged,
            this, &TestSessionManager::onStateChanged);
}

void TestSessionManager::cleanup()
{
    delete m_manager;
    m_manager = nullptr;
    
    delete m_tempDir;
    m_tempDir = nullptr;
    
    m_stateChanges.clear();
}

void TestSessionManager::onStateChanged(SessionState newState, SessionState oldState)
{
    m_stateChanges.append(qMakePair(newState, oldState));
}

void TestSessionManager::testInitialState()
{
    QCOMPARE(m_manager->currentState(), SessionState::UnknownReaderState);
    QVERIFY(!m_manager->isStarted());
    QVERIFY(m_manager->lastError().isEmpty());
}

void TestSessionManager::testStart()
{
    bool result = m_manager->start(m_storagePath);
    
    // May succeed or fail depending on whether PC/SC is available
    // But should not crash
    if (result) {
        QVERIFY(m_manager->isStarted());
        QCOMPARE(m_manager->currentState(), SessionState::WaitingForCard);
    } else {
        QVERIFY(!m_manager->lastError().isEmpty());
    }
}

void TestSessionManager::testStartAlreadyStarted()
{
    m_manager->start(m_storagePath);
    
    // Starting again should fail
    bool result = m_manager->start(m_storagePath);
    QVERIFY(!result);
    QVERIFY(!m_manager->lastError().isEmpty());
}

void TestSessionManager::testStartWithInvalidPath()
{
    // Empty path should fail or succeed with empty storage
    // (Implementation detail - may allow empty path)
    bool result = m_manager->start("");
    // Just verify it doesn't crash
    // May succeed or fail depending on implementation
}

void TestSessionManager::testStop()
{
    m_manager->start(m_storagePath);
    
    m_manager->stop();
    
    QVERIFY(!m_manager->isStarted());
    QCOMPARE(m_manager->currentState(), SessionState::UnknownReaderState);
}

void TestSessionManager::testStopNotStarted()
{
    // Stopping when not started should not crash
    m_manager->stop();
    
    QVERIFY(!m_manager->isStarted());
}

void TestSessionManager::testStateTransitions()
{
    m_stateChanges.clear();
    
    bool started = m_manager->start(m_storagePath);
    
    if (started) {
        // Should have at least one state transition
        QVERIFY(m_stateChanges.size() >= 1);
        
        // Last transition should be to WaitingForCard
        QCOMPARE(m_stateChanges.last().first, SessionState::WaitingForCard);
    }
    
    m_manager->stop();
    
    // Should have stop transition
    if (m_stateChanges.size() > 0) {
        QCOMPARE(m_stateChanges.last().first, SessionState::UnknownReaderState);
    }
}

void TestSessionManager::testGetStatus()
{
    SessionManager::Status status = m_manager->getStatus();
    
    // Should have a state string
    QVERIFY(!status.state.isEmpty());
    QCOMPARE(status.state, sessionStateToString(m_manager->currentState()));
    
    // Initially, pointers should be null
    QVERIFY(status.keycardInfo == nullptr);
    QVERIFY(status.keycardStatus == nullptr);
    QVERIFY(status.metadata == nullptr);
}

void TestSessionManager::testStateStrings()
{
    // Test all state strings match expected values
    QCOMPARE(sessionStateToString(SessionState::UnknownReaderState), QString("unknown-reader-state"));
    QCOMPARE(sessionStateToString(SessionState::NoReadersFound), QString("no-readers-found"));
    QCOMPARE(sessionStateToString(SessionState::WaitingForReader), QString("waiting-for-reader"));
    QCOMPARE(sessionStateToString(SessionState::WaitingForCard), QString("waiting-for-card"));
    QCOMPARE(sessionStateToString(SessionState::ConnectingCard), QString("connecting-card"));
    QCOMPARE(sessionStateToString(SessionState::EmptyKeycard), QString("empty-keycard"));
    QCOMPARE(sessionStateToString(SessionState::Ready), QString("ready"));
    QCOMPARE(sessionStateToString(SessionState::Authorized), QString("authorized"));
    QCOMPARE(sessionStateToString(SessionState::BlockedPIN), QString("blocked-pin"));
    QCOMPARE(sessionStateToString(SessionState::BlockedPUK), QString("blocked-puk"));
}

void TestSessionManager::testLastError()
{
    // Initially no error
    QVERIFY(m_manager->lastError().isEmpty());
    
    // Try operation without starting
    bool result = m_manager->authorize("123456");
    QVERIFY(!result);
    
    // Should have error message
    QVERIFY(!m_manager->lastError().isEmpty());
}

void TestSessionManager::testOperationWithoutStart()
{
    // All operations should fail without starting
    
    QVERIFY(!m_manager->initialize("123456", "123456123456", ""));
    QVERIFY(!m_manager->authorize("123456"));
    QVERIFY(!m_manager->changePIN("654321"));
    QVERIFY(!m_manager->changePUK("098765432109"));
    QVERIFY(!m_manager->unblockPIN("123456123456", "654321"));
    QVERIFY(!m_manager->factoryReset());
    
    QVector<int> mnemonic = m_manager->generateMnemonic(12);
    QVERIFY(mnemonic.isEmpty());
    
    QString keyUID = m_manager->loadMnemonic("test mnemonic", "");
    QVERIFY(keyUID.isEmpty());
}

void TestSessionManager::testOperationWithoutCard()
{
    m_manager->start(m_storagePath);
    
    // Operations should fail without card
    QVERIFY(!m_manager->initialize("123456", "123456123456", ""));
    QVERIFY(!m_manager->authorize("123456"));
    QVERIFY(!m_manager->changePIN("654321"));
}

void TestSessionManager::testInitializeWithoutCard()
{
    m_manager->start(m_storagePath);
    
    bool result = m_manager->initialize("123456", "123456123456", "KeycardDefaultPairing");
    QVERIFY(!result);
    QVERIFY(!m_manager->lastError().isEmpty());
}

void TestSessionManager::testAuthorizeWithoutCard()
{
    m_manager->start(m_storagePath);
    
    bool result = m_manager->authorize("123456");
    QVERIFY(!result);
}

void TestSessionManager::testChangePINWithoutCard()
{
    m_manager->start(m_storagePath);
    
    bool result = m_manager->changePIN("654321");
    QVERIFY(!result);
}

void TestSessionManager::testChangePUKWithoutCard()
{
    m_manager->start(m_storagePath);
    
    bool result = m_manager->changePUK("098765432109");
    QVERIFY(!result);
}

void TestSessionManager::testUnblockPINWithoutCard()
{
    m_manager->start(m_storagePath);
    
    bool result = m_manager->unblockPIN("123456123456", "654321");
    QVERIFY(!result);
}

void TestSessionManager::testGenerateMnemonicWithoutCard()
{
    m_manager->start(m_storagePath);
    
    QVector<int> indexes = m_manager->generateMnemonic(12);
    QVERIFY(indexes.isEmpty());
}

void TestSessionManager::testLoadMnemonicWithoutCard()
{
    m_manager->start(m_storagePath);
    
    QString keyUID = m_manager->loadMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "");
    QVERIFY(keyUID.isEmpty());
}

void TestSessionManager::testFactoryResetWithoutCard()
{
    m_manager->start(m_storagePath);
    
    bool result = m_manager->factoryReset();
    QVERIFY(!result);
}

void TestSessionManager::testStatusStructure()
{
    SessionManager::Status status = m_manager->getStatus();
    
    // Test Status destructor handles null pointers
    SessionManager::Status status2;
    status2.state = "test";
    // Destructor should not crash with null pointers
}

void TestSessionManager::testStatusWithNullFields()
{
    SessionManager::Status status = m_manager->getStatus();
    
    // All fields should be null initially
    QVERIFY(status.keycardInfo == nullptr);
    QVERIFY(status.keycardStatus == nullptr);
    QVERIFY(status.metadata == nullptr);
    
    // Test that we can safely delete
    // (destructor test)
}

void TestSessionManager::testStateChangedSignal()
{
    m_stateChanges.clear();
    
    bool started = m_manager->start(m_storagePath);
    
    if (started) {
        // Should have emitted stateChanged signal
        QVERIFY(m_stateChanges.size() >= 1);
        
        // Verify signal parameters
        for (const auto& change : m_stateChanges) {
            // New state and old state should be different
            // (unless it's a no-op, which shouldn't happen)
            QVERIFY(change.first != change.second);
        }
    }
}

QTEST_MAIN(TestSessionManager)
#include "test_session_manager.moc"

