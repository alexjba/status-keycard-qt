#ifndef FLOW_MANAGER_H
#define FLOW_MANAGER_H

#include "flow_types.h"
#include "flow_state_machine.h"
#include <QObject>
#include <QJsonObject>
#include <QMutex>
#include <QFuture>
#include <memory>

// Forward declarations
namespace Keycard {
    class KeycardChannel;
    class CommandSet;
}

namespace StatusKeycard {

class FlowBase;

/**
 * @brief Flow Manager - Main coordinator for Flow API
 * 
 * Singleton class that:
 * - Manages flow lifecycle
 * - Uses KeycardChannel and shared CommandSet
 * - Handles NFC events (card detected/removed)
 * - Routes signals to/from flows
 * - Integrates with C API
 * 
 * Thread-safe.
 */
class FlowManager : public QObject {
    Q_OBJECT
    
public:
    /**
     * @brief Get singleton instance
     */
    static FlowManager* instance();
    
    /**
     * @brief Destroy singleton instance (for testing only)
     * 
     * Properly cleans up and destroys the singleton instance.
     * Should only be called in test cleanup to reset state between tests.
     */
    static void destroyInstance();
    
    /**
     * @brief Initialize flow system
     * @param commandSet Shared CommandSet for sharing with SessionManager
     * @return true if successful
     */
    bool init(std::shared_ptr<Keycard::CommandSet> commandSet);
    
    /**
     * @brief Start a flow
     * @param flowType Flow type to start
     * @param params Flow parameters
     * @return true if started successfully
     */
    bool startFlow(int flowType, const QJsonObject& params);
    
    /**
     * @brief Resume paused flow
     * @param params New parameters from user
     * @return true if resumed successfully
     */
    bool resumeFlow(const QJsonObject& params);
    
    /**
     * @brief Cancel current flow
     * @return true if cancelled successfully
     */
    bool cancelFlow();
    
    /**
     * @brief Get current flow state
     */
    FlowState state() const;
    
    /**
     * @brief Get current flow type
     * @return Current flow type, or -1 if no flow running
     */
    int currentFlowType() const;
    
    /**
     * @brief Get last error message
     */
    QString lastError() const;
    
    // ============================================================================
    // Resource access (for FlowBase)
    // ============================================================================
    
    /**
     * @brief Get keycard channel
     */
    Keycard::KeycardChannel* channel() const { return m_channel.get(); }

    /**
     * @brief Get command set (shared across all flows)
     * 
     * Returns a persistent CommandSet that maintains the secure channel
     * across multiple flows, matching status-keycard-go's behavior.
     */
    std::shared_ptr<Keycard::CommandSet> commandSet() const { return m_commandSet; }
    
signals:
    /**
     * @brief Flow signal emitted (for C API)
     * @param type Signal type (e.g., "keycard.action.enter-pin")
     * @param event Event data
     */
    void flowSignal(const QString& type, const QJsonObject& event);
    
private slots:
    /**
     * @brief Handle card detected event from NFC
     * @param uid Card UID
     */
    void onCardDetected(const QString& uid);
    
    /**
     * @brief Handle card removed event from NFC
     */
    void onCardRemoved();
    
private:
    /**
     * @brief Build card info JSON from CommandSet's ApplicationInfo
     * @return JSON with instance-uid, key-uid, free-slots (if available)
     */
    QJsonObject buildCardInfoFromCommandSet() const;

    /**
     * @brief Handle flow paused (from FlowBase)
     * @param action Signal type
     * @param event Event data
     */
    void onFlowPaused(const QString& action, const QJsonObject& event);
    
    /**
     * @brief Handle flow completed (from FlowBase)
     * @param result Flow result
     */
    void onFlowCompleted(const QJsonObject& result);
    
    /**
     * @brief Handle flow error (from FlowBase)
     * @param error Error message
     */
    void onFlowError(const QString& error);
    
private:
    // Singleton
    FlowManager(QObject* parent = nullptr);
    ~FlowManager();
    FlowManager(const FlowManager&) = delete;
    FlowManager& operator=(const FlowManager&) = delete;
    
    /**
     * @brief Create flow instance
     * @param flowType Flow type
     * @param params Flow parameters
     * @return Flow instance or nullptr
     */
    FlowBase* createFlow(FlowType flowType, const QJsonObject& params);
    
    /**
     * @brief Run flow in separate thread
     */
    void runFlowAsync();
    
    /**
     * @brief Cleanup current flow
     */
    void cleanupFlow();
    
    // State
    FlowStateMachine* m_stateMachine;
    FlowBase* m_currentFlow;
    FlowType m_currentFlowType;
    QJsonObject m_currentParams;
    QString m_lastError;
    bool m_waitingForCard;
    bool m_continuousDetectionRunning;  // Track if continuous detection is active
    QString m_currentCardUid;  // Track current card to avoid duplicate detections
    QFuture<void> m_flowFuture;  // Track async flow execution to wait for completion
    
    // Resources
    std::shared_ptr<Keycard::KeycardChannel> m_channel;
    std::shared_ptr<Keycard::CommandSet> m_commandSet;  // Shared command set (maintains secure channel)
    
    // Thread safety
    mutable QMutex m_mutex;
    
    // Singleton instance
    static FlowManager* s_instance;
    static QMutex s_instanceMutex;
};

} // namespace StatusKeycard

#endif // FLOW_MANAGER_H

