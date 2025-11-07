#include <QtTest/QtTest>
#include <QtConcurrent/QtConcurrent>
#include "flow/flow_manager.h"
#include "flow/flow_types.h"
#include <QTemporaryDir>
#include <QJsonObject>

using namespace StatusKeycard;

class TestFlowManager : public QObject
{
    Q_OBJECT

private:
    QTemporaryDir* tempDir;
    
private slots:
    void initTestCase()
    {
        tempDir = new QTemporaryDir();
        QVERIFY(tempDir->isValid());
    }

    void cleanupTestCase()
    {
        delete tempDir;
    }

    void init()
    {
        // Reset before each test
        FlowManager::instance()->cancelFlow();
    }

    void testSingleton()
    {
        FlowManager* mgr1 = FlowManager::instance();
        FlowManager* mgr2 = FlowManager::instance();
        
        QCOMPARE(mgr1, mgr2);
        QVERIFY(mgr1 != nullptr);
    }

    void testInitFlow()
    {
        FlowManager* mgr = FlowManager::instance();
        
        bool success = mgr->initFlow(tempDir->path());
        QVERIFY(success);
        
        // Channel and storage should be initialized
        QVERIFY(mgr->channel() != nullptr);
        QVERIFY(mgr->storage() != nullptr);
    }

    void testInitialState()
    {
        FlowManager* mgr = FlowManager::instance();
        mgr->initFlow(tempDir->path());
        
        QCOMPARE(mgr->state(), FlowState::Idle);
        QCOMPARE(mgr->currentFlowType(), -1);
    }

    void testStartFlowWithoutInit()
    {
        FlowManager* mgr = FlowManager::instance();
        
        // Try to start without init - should work (init is optional)
        QJsonObject params;
        // Note: Will fail because no flows can run without card
        // but we're testing the API works
        int flowType = static_cast<int>(FlowType::GetAppInfo);
        mgr->startFlow(flowType, params);
        
        // Should have tried to start
        QVERIFY(mgr->state() != FlowState::Idle || mgr->currentFlowType() == flowType);
    }

    void testStartValidFlow()
    {
        FlowManager* mgr = FlowManager::instance();
        mgr->initFlow(tempDir->path());
        
        QJsonObject params;
        int flowType = static_cast<int>(FlowType::GetAppInfo);
        
        bool success = mgr->startFlow(flowType, params);
        QVERIFY(success);
        
        // State should change from Idle
        QTest::qWait(50); // Give it time to start
        QVERIFY(mgr->state() != FlowState::Idle || mgr->currentFlowType() == flowType);
    }

    void testStartFlowWhileRunning()
    {
        FlowManager* mgr = FlowManager::instance();
        mgr->initFlow(tempDir->path());
        
        QJsonObject params;
        mgr->startFlow(static_cast<int>(FlowType::GetAppInfo), params);
        QTest::qWait(50);
        
        // Try to start another while running
        bool success = mgr->startFlow(static_cast<int>(FlowType::Login), params);
        QVERIFY(!success); // Should fail
        
        QVERIFY(!mgr->lastError().isEmpty());
    }

    void testCancelFlow()
    {
        FlowManager* mgr = FlowManager::instance();
        mgr->initFlow(tempDir->path());
        
        QJsonObject params;
        mgr->startFlow(static_cast<int>(FlowType::GetAppInfo), params);
        QTest::qWait(50);
        
        bool success = mgr->cancelFlow();
        QVERIFY(success);
        
        // Wait for cancellation to complete
        QTest::qWait(100);
        
        // Should be back to Idle
        QCOMPARE(mgr->state(), FlowState::Idle);
    }

    void testCancelWhenIdle()
    {
        FlowManager* mgr = FlowManager::instance();
        mgr->initFlow(tempDir->path());
        
        // Cancel when no flow running should succeed (no-op)
        bool success = mgr->cancelFlow();
        QVERIFY(success);
    }

    void testAllFlowTypes()
    {
        FlowManager* mgr = FlowManager::instance();
        mgr->initFlow(tempDir->path());
        
        QJsonObject params;
        
        // Test that all flow types can be created
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
            mgr->cancelFlow();
            QTest::qWait(100);
            
            bool success = mgr->startFlow(static_cast<int>(flowType), params);
            QVERIFY2(success, QString("Failed to start flow type %1")
                .arg(static_cast<int>(flowType)).toLatin1());
            
            QTest::qWait(50);
        }
    }

    void testThreadSafety()
    {
        FlowManager* mgr = FlowManager::instance();
        mgr->initFlow(tempDir->path());
        
        // Try concurrent starts (only one should succeed)
        QFuture<bool> f1 = QtConcurrent::run([mgr]() {
            return mgr->startFlow(static_cast<int>(FlowType::GetAppInfo), QJsonObject());
        });
        
        QFuture<bool> f2 = QtConcurrent::run([mgr]() {
            QThread::msleep(10);
            return mgr->startFlow(static_cast<int>(FlowType::Login), QJsonObject());
        });
        
        f1.waitForFinished();
        f2.waitForFinished();
        
        // At least one should have succeeded
        QVERIFY(f1.result() || f2.result());
    }
};

QTEST_MAIN(TestFlowManager)
#include "test_flow_manager.moc"

