#include <QtTest/QtTest>
#include <QtConcurrent/QtConcurrent>
#include "flow/flow_manager.h"
#include "flow/flow_types.h"
#include "flow/flow_signals.h"
#include "signal_manager.h"
#include <QTemporaryDir>
#include <QJsonObject>
#include <QJsonDocument>
#include <QSignalSpy>

using namespace StatusKeycard;

class TestFlowIntegration : public QObject
{
    Q_OBJECT

private:
    QTemporaryDir* tempDir;
    QStringList capturedSignals;
    
private slots:
    void initTestCase()
    {
        tempDir = new QTemporaryDir();
        QVERIFY(tempDir->isValid());
        
        // Register signal callback to capture all signals
        SignalManager::instance()->setCallback([](const char* signal) {
            qDebug() << "Signal received:" << signal;
            // Note: Callback is static, can't easily capture in test
            // Signals will be tested via QSignalSpy in individual tests
        });
        
        // Initialize FlowManager
        FlowManager::instance()->initFlow(tempDir->path());
    }

    void cleanupTestCase()
    {
        delete tempDir;
        SignalManager::instance()->setCallback(nullptr);
    }

    void init()
    {
        capturedSignals.clear();
        FlowManager::instance()->cancelFlow();
        QTest::qWait(100);
    }

    /**
     * Test GetAppInfo flow - simplest flow that doesn't require a card
     * It will pause waiting for card, which we can test
     */
    void testGetAppInfoFlowStart()
    {
        FlowManager* mgr = FlowManager::instance();
        
        QSignalSpy spy(mgr, &FlowManager::flowSignal);
        
        QJsonObject params;
        bool started = mgr->startFlow(static_cast<int>(FlowType::GetAppInfo), params);
        QVERIFY(started);
        
        // Wait for flow to start and pause (waiting for card)
        QTest::qWait(200);
        
        // Should have emitted at least one signal (likely "insert-card")
        QVERIFY(spy.count() > 0);
        
        // Check first signal
        if (spy.count() > 0) {
            QList<QVariant> arguments = spy.takeFirst();
            QString signalType = arguments.at(0).toString();
            // Should be waiting for card
            QVERIFY(signalType.contains("insert") || signalType.contains("card"));
        }
        
        // State should be Paused (waiting for card)
        QCOMPARE(mgr->state(), FlowState::Paused);
    }

    /**
     * Test flow cancellation
     */
    void testFlowCancellation()
    {
        FlowManager* mgr = FlowManager::instance();
        
        // Start a flow
        QJsonObject params;
        mgr->startFlow(static_cast<int>(FlowType::GetAppInfo), params);
        QTest::qWait(100);
        
        // Cancel it
        bool cancelled = mgr->cancelFlow();
        QVERIFY(cancelled);
        
        // Wait for cancellation
        QTest::qWait(200);
        
        // Should be back to Idle
        QCOMPARE(mgr->state(), FlowState::Idle);
    }

    /**
     * Test that flows emit proper signals when pausing
     */
    void testFlowPauseSignals()
    {
        FlowManager* mgr = FlowManager::instance();
        QSignalSpy spy(mgr, &FlowManager::flowSignal);
        
        // Start Login flow (will pause for card)
        QJsonObject params;
        mgr->startFlow(static_cast<int>(FlowType::Login), params);
        
        // Wait for pause signal
        QTest::qWait(200);
        
        // Should have received signal(s)
        QVERIFY(spy.count() > 0);
        
        // Verify signal format
        for (int i = 0; i < spy.count(); ++i) {
            QList<QVariant> arguments = spy.at(i);
            QString signalType = arguments.at(0).toString();
            QJsonObject event = arguments.at(1).toJsonObject();
            
            qDebug() << "Signal" << i << ":" << signalType;
            
            // Signal type should be valid
            QVERIFY(!signalType.isEmpty());
            QVERIFY(signalType.startsWith("keycard."));
        }
    }

    /**
     * Test multiple flow lifecycle
     */
    void testMultipleFlowLifecycles()
    {
        FlowManager* mgr = FlowManager::instance();
        
        for (int i = 0; i < 3; ++i) {
            // Start flow
            QJsonObject params;
            bool started = mgr->startFlow(static_cast<int>(FlowType::GetAppInfo), params);
            QVERIFY(started);
            
            QTest::qWait(100);
            
            // Cancel flow
            bool cancelled = mgr->cancelFlow();
            QVERIFY(cancelled);
            
            QTest::qWait(100);
            
            // Should be Idle
            QCOMPARE(mgr->state(), FlowState::Idle);
        }
    }

    /**
     * Test flow with parameters
     */
    void testFlowWithParameters()
    {
        FlowManager* mgr = FlowManager::instance();
        
        QJsonObject params;
        params["pin"] = "000000";
        params["pairing-pass"] = "KeycardTest";
        
        bool started = mgr->startFlow(static_cast<int>(FlowType::Login), params);
        QVERIFY(started);
        
        QTest::qWait(100);
        
        // Flow should start (will pause for card but params are stored)
        QVERIFY(mgr->state() != FlowState::Idle);
    }

    /**
     * Test all flow types can start
     */
    void testAllFlowTypesStart()
    {
        FlowManager* mgr = FlowManager::instance();
        
        QList<FlowType> flowTypes = {
            FlowType::GetAppInfo,
            FlowType::Login,
            FlowType::RecoverAccount,
            FlowType::LoadAccount,
            FlowType::Sign,
            FlowType::ChangePIN,
            FlowType::ChangePUK,
            FlowType::ChangePairing,
            FlowType::ExportPublic,
            FlowType::GetMetadata,
            FlowType::StoreMetadata
        };
        
        for (FlowType flowType : flowTypes) {
            // Cancel any running flow
            mgr->cancelFlow();
            QTest::qWait(150);
            
            // Start flow
            QJsonObject params;
            bool started = mgr->startFlow(static_cast<int>(flowType), params);
            
            QVERIFY2(started, 
                QString("Failed to start flow type %1").arg(static_cast<int>(flowType)).toLatin1());
            
            QTest::qWait(100);
            
            // Should not be Idle (flow is running/paused)
            QVERIFY2(mgr->state() != FlowState::Idle || mgr->currentFlowType() == static_cast<int>(flowType),
                QString("Flow type %1 didn't start properly").arg(static_cast<int>(flowType)).toLatin1());
        }
    }

    /**
     * Test resume flow (even though we don't have a real card)
     */
    void testResumeFlow()
    {
        FlowManager* mgr = FlowManager::instance();
        
        // Start flow (will pause for card)
        mgr->startFlow(static_cast<int>(FlowType::GetAppInfo), QJsonObject());
        QTest::qWait(150);
        
        QCOMPARE(mgr->state(), FlowState::Paused);
        
        // Try to resume (will fail without card but tests the API)
        QJsonObject resumeParams;
        bool resumed = mgr->resumeFlow(resumeParams);
        
        // Resume should work (even if flow continues to wait)
        QVERIFY(resumed);
        
        QTest::qWait(100);
    }

    /**
     * Test error handling
     */
    void testErrorHandling()
    {
        FlowManager* mgr = FlowManager::instance();
        
        // Try to start with invalid flow type
        QJsonObject params;
        // FlowType only goes 0-13, try 999
        bool started = mgr->startFlow(999, params);
        
        // Should fail gracefully
        QVERIFY(!started);
        QVERIFY(!mgr->lastError().isEmpty());
    }

    /**
     * Test concurrent operations
     */
    void testConcurrentOperations()
    {
        FlowManager* mgr = FlowManager::instance();
        
        // Start a flow
        mgr->startFlow(static_cast<int>(FlowType::GetAppInfo), QJsonObject());
        QTest::qWait(100);
        
        // Try concurrent cancel and resume
        QFuture<bool> cancelFuture = QtConcurrent::run([mgr]() {
            return mgr->cancelFlow();
        });
        
        QFuture<bool> resumeFuture = QtConcurrent::run([mgr]() {
            QThread::msleep(10);
            return mgr->resumeFlow(QJsonObject());
        });
        
        cancelFuture.waitForFinished();
        resumeFuture.waitForFinished();
        
        // Should handle gracefully (one should succeed)
        QTest::qWait(200);
        
        // Final state should be valid
        FlowState state = mgr->state();
        QVERIFY(state == FlowState::Idle || 
                state == FlowState::Paused ||
                state == FlowState::Running);
    }
};

QTEST_MAIN(TestFlowIntegration)
#include "test_flow_integration.moc"

