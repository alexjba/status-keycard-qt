#ifndef FLOW_STATE_MACHINE_H
#define FLOW_STATE_MACHINE_H

#include "flow_types.h"
#include <QObject>
#include <QMutex>

namespace StatusKeycard {

/**
 * @brief Flow state machine
 * 
 * Tracks flow state and validates state transitions.
 * Thread-safe.
 */
class FlowStateMachine : public QObject {
    Q_OBJECT
    
public:
    explicit FlowStateMachine(QObject* parent = nullptr);
    ~FlowStateMachine();
    
    /**
     * @brief Get current state
     */
    FlowState state() const;
    
    /**
     * @brief Check if transition is valid
     * @param newState Target state
     * @return true if transition is allowed
     */
    bool canTransition(FlowState newState) const;
    
    /**
     * @brief Transition to new state
     * @param newState Target state
     * @return true if transition succeeded
     */
    bool transition(FlowState newState);
    
    /**
     * @brief Reset to Idle state
     */
    void reset();
    
signals:
    /**
     * @brief Emitted when state changes
     * @param oldState Previous state
     * @param newState New state
     */
    void stateChanged(FlowState oldState, FlowState newState);
    
private:
    FlowState m_state;
    mutable QMutex m_mutex;
};

} // namespace StatusKeycard

#endif // FLOW_STATE_MACHINE_H

