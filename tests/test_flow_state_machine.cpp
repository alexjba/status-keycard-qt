#include <QtTest/QtTest>
#include <QtConcurrent/QtConcurrent>
#include "flow/flow_state_machine.h"

using namespace StatusKeycard;

class TestFlowStateMachine : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase()
    {
        // Setup
    }

    void cleanupTestCase()
    {
        // Cleanup
    }

    void testInitialState()
    {
        FlowStateMachine sm;
        QCOMPARE(sm.state(), FlowState::Idle);
    }

    void testValidTransitions()
    {
        FlowStateMachine sm;
        
        // Idle -> Running
        QVERIFY(sm.transition(FlowState::Running));
        QCOMPARE(sm.state(), FlowState::Running);
        
        // Running -> Paused
        QVERIFY(sm.transition(FlowState::Paused));
        QCOMPARE(sm.state(), FlowState::Paused);
        
        // Paused -> Resuming
        QVERIFY(sm.transition(FlowState::Resuming));
        QCOMPARE(sm.state(), FlowState::Resuming);
        
        // Resuming -> Running
        QVERIFY(sm.transition(FlowState::Running));
        QCOMPARE(sm.state(), FlowState::Running);
        
        // Running -> Idle (completion)
        QVERIFY(sm.transition(FlowState::Idle));
        QCOMPARE(sm.state(), FlowState::Idle);
    }

    void testInvalidTransitions()
    {
        FlowStateMachine sm;
        
        // Can't go from Idle to Paused
        QVERIFY(!sm.transition(FlowState::Paused));
        QCOMPARE(sm.state(), FlowState::Idle);
        
        // Can't go from Idle to Resuming
        QVERIFY(!sm.transition(FlowState::Resuming));
        QCOMPARE(sm.state(), FlowState::Idle);
        
        // Start properly
        QVERIFY(sm.transition(FlowState::Running));
        
        // Can't go from Running to Resuming
        QVERIFY(!sm.transition(FlowState::Resuming));
        QCOMPARE(sm.state(), FlowState::Running);
    }

    void testCancellation()
    {
        FlowStateMachine sm;
        
        // Start flow
        QVERIFY(sm.transition(FlowState::Running));
        
        // Cancel from Running
        QVERIFY(sm.transition(FlowState::Cancelling));
        QCOMPARE(sm.state(), FlowState::Cancelling);
        
        // Must go to Idle after cancelling
        QVERIFY(sm.transition(FlowState::Idle));
        QCOMPARE(sm.state(), FlowState::Idle);
    }

    void testCancelFromPaused()
    {
        FlowStateMachine sm;
        
        // Start and pause
        QVERIFY(sm.transition(FlowState::Running));
        QVERIFY(sm.transition(FlowState::Paused));
        
        // Cancel from Paused
        QVERIFY(sm.transition(FlowState::Cancelling));
        QCOMPARE(sm.state(), FlowState::Cancelling);
        
        // Back to Idle
        QVERIFY(sm.transition(FlowState::Idle));
        QCOMPARE(sm.state(), FlowState::Idle);
    }

    void testReset()
    {
        FlowStateMachine sm;
        
        // Go through some states
        sm.transition(FlowState::Running);
        sm.transition(FlowState::Paused);
        
        // Reset should go back to Idle
        sm.reset();
        QCOMPARE(sm.state(), FlowState::Idle);
    }

    void testSameStateTransition()
    {
        FlowStateMachine sm;
        
        // Same state is always allowed
        QVERIFY(sm.transition(FlowState::Idle));
        QCOMPARE(sm.state(), FlowState::Idle);
        
        sm.transition(FlowState::Running);
        QVERIFY(sm.transition(FlowState::Running));
        QCOMPARE(sm.state(), FlowState::Running);
    }

    void testStateChangedSignal()
    {
        FlowStateMachine sm;
        QSignalSpy spy(&sm, &FlowStateMachine::stateChanged);
        
        // Transition should emit signal
        sm.transition(FlowState::Running);
        
        QCOMPARE(spy.count(), 1);
        QList<QVariant> arguments = spy.takeFirst();
        QCOMPARE(arguments.at(0).value<FlowState>(), FlowState::Idle);
        QCOMPARE(arguments.at(1).value<FlowState>(), FlowState::Running);
    }

    void testThreadSafety()
    {
        FlowStateMachine sm;
        
        // Start flow
        sm.transition(FlowState::Running);
        
        // Simulate concurrent access
        QThreadPool pool;
        QFuture<bool> future1 = QtConcurrent::run([&sm]() {
            return sm.transition(FlowState::Paused);
        });
        
        QFuture<bool> future2 = QtConcurrent::run([&sm]() {
            QThread::msleep(10);
            return sm.transition(FlowState::Cancelling);
        });
        
        future1.waitForFinished();
        future2.waitForFinished();
        
        // One should succeed, state should be valid
        FlowState finalState = sm.state();
        QVERIFY(finalState == FlowState::Paused || 
                finalState == FlowState::Cancelling);
    }
};

QTEST_MAIN(TestFlowStateMachine)
#include "test_flow_state_machine.moc"

