#include <QtTest/QtTest>
#include <QTemporaryDir>
#include "session/session_manager.h"
#include "session/session_state.h"
#include "mocks/mock_keycard_backend.h"
#include <keycard-qt/keycard_channel.h>
#include <keycard-qt/command_set.h>
#include <memory>

using namespace StatusKeycard;
using namespace StatusKeycardTest;
using namespace Keycard;

class TestSessionManager : public QObject
{
    Q_OBJECT

private:
    SessionManager* m_manager;
    QTemporaryDir* m_tempDir;
    QVector<QPair<SessionState, SessionState>> m_stateChanges;
    
    std::shared_ptr<CommandSet> createMockCommandSet()
    {
        auto* mockBackend = new MockKeycardBackend();
        mockBackend->setAutoConnect(true);
        auto channel = std::make_shared<KeycardChannel>(mockBackend);
        auto cmdSet = std::make_shared<CommandSet>(channel, nullptr, nullptr);
        // Use shorter timeout for tests (1 second instead of 60)
        cmdSet->setDefaultWaitTimeout(1000);
        return cmdSet;
    }
    
    void onStateChanged(SessionState newState, SessionState oldState)
    {
        m_stateChanges.append(qMakePair(newState, oldState));
    }

private slots:
    void init()
    {
        m_tempDir = new QTemporaryDir();
        QVERIFY(m_tempDir->isValid());
        
        m_manager = new SessionManager();
        m_stateChanges.clear();
        
        connect(m_manager, &SessionManager::stateChanged,
                this, &TestSessionManager::onStateChanged);
        
        auto cmdSet = createMockCommandSet();
        m_manager->setCommandSet(cmdSet);
    }

    void cleanup()
    {
        if (m_manager) {
            m_manager->stop();
            delete m_manager;
            m_manager = nullptr;
        }
        
        delete m_tempDir;
        m_tempDir = nullptr;
        
        m_stateChanges.clear();
    }

    void testInitialState()
    {
        QCOMPARE(m_manager->currentState(), SessionState::UnknownReaderState);
        QVERIFY(!m_manager->isStarted());
        QVERIFY(m_manager->lastError().isEmpty());
    }

    void testStart()
    {
        bool result = m_manager->start();
        QVERIFY(result);
        QVERIFY(m_manager->isStarted());
        
        QTest::qWait(300);
        
        SessionState state = m_manager->currentState();
        QVERIFY(state == SessionState::WaitingForCard || 
                state == SessionState::WaitingForReader ||
                state == SessionState::ConnectingCard ||
                state == SessionState::Ready ||
                state == SessionState::EmptyKeycard);
    }

    void testStartAlreadyStarted()
    {
        m_manager->start();
        
        bool result = m_manager->start();
        QVERIFY(!result);
        QVERIFY(!m_manager->lastError().isEmpty());
    }

    void testStop()
    {
        m_manager->start();
        QTest::qWait(100);
        
        m_manager->stop();
        
        QTest::qWait(100);
        
        QVERIFY(!m_manager->isStarted());
        QCOMPARE(m_manager->currentState(), SessionState::UnknownReaderState);
    }

    void testStopNotStarted()
    {
        m_manager->stop();
        QVERIFY(!m_manager->isStarted());
    }

    void testStateTransitions()
    {
        m_stateChanges.clear();
        
        m_manager->start();
        QTest::qWait(300);
        
        QVERIFY(m_stateChanges.size() >= 1);
        
        SessionState lastState = m_stateChanges.last().first;
        QVERIFY(lastState == SessionState::WaitingForCard || 
                lastState == SessionState::WaitingForReader ||
                lastState == SessionState::ConnectingCard ||
                lastState == SessionState::Ready ||
                lastState == SessionState::EmptyKeycard);
        
        m_manager->stop();
        QTest::qWait(100);
        
        if (m_stateChanges.size() > 0) {
            QCOMPARE(m_stateChanges.last().first, SessionState::UnknownReaderState);
        }
    }

    void testGetStatus()
    {
        SessionManager::Status status = m_manager->getStatus();
        
        QVERIFY(!status.state.isEmpty());
        QCOMPARE(status.state, sessionStateToString(m_manager->currentState()));
        
        QVERIFY(status.keycardInfo == nullptr);
        QVERIFY(status.keycardStatus == nullptr);
        QVERIFY(status.metadata == nullptr);
    }

    void testStateStrings()
    {
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

    void testLastError()
    {
        QVERIFY(m_manager->lastError().isEmpty());
        
        bool result = m_manager->authorize("123456");
        QVERIFY(!result);
        
        QVERIFY(!m_manager->lastError().isEmpty());
    }

    void testOperationWithoutStart()
    {
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

    void testStateChangedSignal()
    {
        m_stateChanges.clear();
        
        m_manager->start();
        QTest::qWait(200);
        
        QVERIFY(m_stateChanges.size() >= 1);
        
        for (const auto& change : m_stateChanges) {
            QVERIFY(change.first != change.second);
        }
    }
};

QTEST_MAIN(TestSessionManager)
#include "test_session_manager.moc"
