#include <QtTest/QtTest>
#include <QtConcurrent/QtConcurrent>
#include "flow/flow_state_machine.h"

using namespace StatusKeycard;

class TestFlowStateMachine : public QObject
{
    Q_OBJECT

private slots:
    void testInitialState()
    {
        FlowStateMachine sm;
        QCOMPARE(sm.state(), FlowState::Idle);
    }

    void testValidTransitions()
    {
        FlowStateMachine sm;
        
        QVERIFY(sm.transition(FlowState::Running));
        QCOMPARE(sm.state(), FlowState::Running);
        
        QVERIFY(sm.transition(FlowState::Paused));
        QCOMPARE(sm.state(), FlowState::Paused);
        
        QVERIFY(sm.transition(FlowState::Resuming));
        QCOMPARE(sm.state(), FlowState::Resuming);
        
        QVERIFY(sm.transition(FlowState::Running));
        QCOMPARE(sm.state(), FlowState::Running);
        
        QVERIFY(sm.transition(FlowState::Idle));
        QCOMPARE(sm.state(), FlowState::Idle);
    }

    void testInvalidTransitions()
    {
        FlowStateMachine sm;
        
        QVERIFY(!sm.transition(FlowState::Paused));
        QCOMPARE(sm.state(), FlowState::Idle);
        
        QVERIFY(!sm.transition(FlowState::Resuming));
        QCOMPARE(sm.state(), FlowState::Idle);
        
        QVERIFY(sm.transition(FlowState::Running));
        
        QVERIFY(!sm.transition(FlowState::Resuming));
        QCOMPARE(sm.state(), FlowState::Running);
    }

    void testCancellation()
    {
        FlowStateMachine sm;
        
        QVERIFY(sm.transition(FlowState::Running));
        
        QVERIFY(sm.transition(FlowState::Cancelling));
        QCOMPARE(sm.state(), FlowState::Cancelling);
        
        QVERIFY(sm.transition(FlowState::Idle));
        QCOMPARE(sm.state(), FlowState::Idle);
    }

    void testCancelFromPaused()
    {
        FlowStateMachine sm;
        
        QVERIFY(sm.transition(FlowState::Running));
        QVERIFY(sm.transition(FlowState::Paused));
        
        QVERIFY(sm.transition(FlowState::Cancelling));
        QCOMPARE(sm.state(), FlowState::Cancelling);
        
        QVERIFY(sm.transition(FlowState::Idle));
        QCOMPARE(sm.state(), FlowState::Idle);
    }

    void testReset()
    {
        FlowStateMachine sm;
        
        sm.transition(FlowState::Running);
        sm.transition(FlowState::Paused);
        
        sm.reset();
        QCOMPARE(sm.state(), FlowState::Idle);
    }

    void testSameStateTransition()
    {
        FlowStateMachine sm;
        
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
        
        sm.transition(FlowState::Running);
        
        QCOMPARE(spy.count(), 1);
        QList<QVariant> arguments = spy.takeFirst();
        QCOMPARE(arguments.at(0).value<FlowState>(), FlowState::Idle);
        QCOMPARE(arguments.at(1).value<FlowState>(), FlowState::Running);
    }

    void testThreadSafety()
    {
        FlowStateMachine sm;
        
        sm.transition(FlowState::Running);
        
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
        
        FlowState finalState = sm.state();
        QVERIFY(finalState == FlowState::Paused || 
                finalState == FlowState::Cancelling);
    }
};

QTEST_MAIN(TestFlowStateMachine)
#include "test_flow_state_machine.moc"
