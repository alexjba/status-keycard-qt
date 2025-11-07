#include "flow_state_machine.h"
#include <QDebug>
#include <QMutexLocker>

namespace StatusKeycard {

FlowStateMachine::FlowStateMachine(QObject* parent)
    : QObject(parent)
    , m_state(FlowState::Idle)
{
}

FlowStateMachine::~FlowStateMachine()
{
}

FlowState FlowStateMachine::state() const
{
    QMutexLocker locker(&m_mutex);
    return m_state;
}

bool FlowStateMachine::canTransition(FlowState newState) const
{
    // NOTE: This method assumes the mutex is already held by the caller!
    // It's called from transition() which already locks the mutex.
    // DO NOT add QMutexLocker here or it will deadlock!
    
    // Same state is always allowed
    if (newState == m_state) {
        return true;
    }
    
    // Valid transitions based on status-keycard-go logic
    switch (m_state) {
        case FlowState::Idle:
            // Can only start running from idle
            return (newState == FlowState::Running);
            
        case FlowState::Running:
            // Can pause, cancel, or complete (back to idle)
            return (newState == FlowState::Paused ||
                    newState == FlowState::Cancelling ||
                    newState == FlowState::Idle);
            
        case FlowState::Paused:
            // Can resume, cancel, or restart (back to running)
            return (newState == FlowState::Resuming ||
                    newState == FlowState::Cancelling ||
                    newState == FlowState::Running);
            
        case FlowState::Resuming:
            // Must go back to running
            return (newState == FlowState::Running);
            
        case FlowState::Cancelling:
            // Must go to idle
            return (newState == FlowState::Idle);
    }
    
    return false;
}

bool FlowStateMachine::transition(FlowState newState)
{
    qDebug() << "FlowStateMachine: transition() called, trying to acquire mutex...";
    QMutexLocker locker(&m_mutex);
    qDebug() << "FlowStateMachine: mutex acquired";
    
    FlowState oldState = m_state;
    qDebug() << "FlowStateMachine: Current state:" << static_cast<int>(oldState)
             << "Target state:" << static_cast<int>(newState);
    
    // Check if transition is valid
    if (!canTransition(newState)) {
        qWarning() << "FlowStateMachine: Invalid transition:"
                   << static_cast<int>(oldState) << "->"
                   << static_cast<int>(newState);
        return false;
    }
    qDebug() << "FlowStateMachine: Transition is valid";
    
    // Same state, nothing to do
    if (oldState == newState) {
        return true;
    }
    
    // Perform transition
    m_state = newState;
    
    qDebug() << "FlowStateMachine: State transition:"
             << static_cast<int>(oldState) << "->"
             << static_cast<int>(newState);
    
    qDebug() << "FlowStateMachine: About to unlock mutex and emit signal...";
    // Emit signal (unlock mutex first to avoid deadlock)
    locker.unlock();
    qDebug() << "FlowStateMachine: Mutex unlocked, emitting signal...";
    emit stateChanged(oldState, newState);
    qDebug() << "FlowStateMachine: Signal emitted, returning true";
    
    return true;
}

void FlowStateMachine::reset()
{
    QMutexLocker locker(&m_mutex);
    
    // Hard reset - force to Idle regardless of transition rules
    if (m_state != FlowState::Idle) {
        FlowState oldState = m_state;
        m_state = FlowState::Idle;
        
        qDebug() << "FlowStateMachine: Hard reset:"
                 << static_cast<int>(oldState) << "-> 0 (Idle)";
        
        // Unlock and emit signal
        locker.unlock();
        emit stateChanged(oldState, FlowState::Idle);
    }
}

} // namespace StatusKeycard

