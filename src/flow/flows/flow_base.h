#ifndef FLOW_BASE_H
#define FLOW_BASE_H

#include "../flow_types.h"
#include "../flow_params.h"
#include <QObject>
#include <QJsonObject>
#include <QWaitCondition>
#include <QMutex>
#include <keycard-qt/command_set.h>
#include <keycard-qt/types.h>

// Forward declarations
namespace Keycard {
    class KeycardChannel;
}

namespace StatusKeycard {

// Forward declarations
class FlowManager;
class PairingStorage;

/**
 * @brief Base class for all flow implementations
 * 
 * Provides common functionality:
 * - Card connection and detection
 * - Pairing management
 * - Secure channel establishment
 * - Pause/resume mechanism
 * - Error handling
 */
class FlowBase : public QObject {
    Q_OBJECT
    
public:
    FlowBase(FlowManager* manager, FlowType type, const QJsonObject& params, QObject* parent = nullptr);
    virtual ~FlowBase();
    
    /**
     * @brief Execute the flow (pure virtual)
     * 
     * Each flow type must implement this.
     * Should call pause functions when user input needed.
     * Should return result when complete.
     * 
     * @return Flow result JSON
     */
    virtual QJsonObject execute() = 0;
    
    /**
     * @brief Resume flow after pause
     * @param newParams New parameters provided by user
     */
    void resume(const QJsonObject& newParams);
    
    /**
     * @brief Cancel flow
     */
    void cancel();
    
    /**
     * @brief Get flow type
     */
    FlowType flowType() const { return m_flowType; }
    
signals:
    /**
     * @brief Flow paused, waiting for user input
     * @param action Signal type (e.g., "keycard.action.enter-pin")
     * @param event Event data
     */
    void flowPaused(const QString& action, const QJsonObject& event);
    
    /**
     * @brief Flow completed successfully
     * @param result Flow result
     */
    void flowCompleted(const QJsonObject& result);
    
    /**
     * @brief Flow failed with error
     * @param error Error message
     */
    void flowError(const QString& error);
    
protected:
    // ============================================================================
    // Access to manager resources
    // ============================================================================
    
    /**
     * @brief Get keycard channel
     */
    Keycard::KeycardChannel* channel();
    
    /**
     * @brief Get pairing storage
     */
    PairingStorage* storage();
    
    /**
     * @brief Get command set
     * @return CommandSet for card operations (shared across all flows)
     */
    Keycard::CommandSet* commandSet() { return m_commandSet; }
    
    /**
     * @brief Get flow parameters
     */
    QJsonObject params() const { return m_params; }
    
    // ============================================================================
    // Pause/Resume mechanism
    // ============================================================================
    
    /**
     * @brief Pause and wait for user input
     * @param action Signal type to emit
     * @param error Error message
     */
    void pauseAndWait(const QString& action, const QString& error);
    
    /**
     * @brief Pause with additional status info
     * @param action Signal type to emit
     * @param error Error message
     * @param status Additional status data
     */
    void pauseAndWaitWithStatus(const QString& action, const QString& error, 
                                const QJsonObject& status);
    
    /**
     * @brief Pause and restart flow from beginning
     * @param action Signal type to emit
     * @param error Error message
     * 
     * Used when wrong card detected, etc.
     */
    void pauseAndRestart(const QString& action, const QString& error);
    
    // ============================================================================
    // Card operations
    // ============================================================================
    
    /**
     * @brief Wait for card detection
     * @return true if card detected, false if cancelled
     */
    bool waitForCard();
    
    /**
     * @brief Connect to card and select applet
     * @return true if successful
     */
    bool selectKeycard();
    
    /**
     * @brief Open secure channel (pair if needed)
     * @param authenticate If true, also verify PIN
     * @return true if successful
     */
    bool openSecureChannelAndAuthenticate(bool authenticate);
    
    /**
     * @brief Verify PIN
     * @return true if successful
     */
    bool verifyPIN();
    
    /**
     * @brief Check if card has keys
     * @return true if card has keys
     */
    bool requireKeys();
    
    /**
     * @brief Check if card has NO keys
     * @return true if card has no keys
     */
    bool requireNoKeys();
    
    // ============================================================================
    // Card information
    // ============================================================================
    
    /**
     * @brief Card information structure
     */
    struct CardInfo {
        QString instanceUID;
        QString keyUID;
        int freeSlots = -1;
        int pinRetries = -1;
        int pukRetries = -1;
        int version = -1;
        bool initialized = false;
        bool keyInitialized = false;
    };
    
    /**
     * @brief Get current card info
     */
    const CardInfo& cardInfo() const { return m_cardInfo; }
    
    /**
     * @brief Update card info from ApplicationInfo
     */
    void updateCardInfo(const Keycard::ApplicationInfo& appInfo);
    
    // ============================================================================
    // Helper utilities
    // ============================================================================
    
public:
    /**
     * @brief Check if flow was cancelled
     */
    bool isCancelled() const { return m_cancelled; }
    
    /**
     * @brief Check if flow should restart
     */
    bool shouldRestart() const { return m_shouldRestart; }
    
    /**
     * @brief Reset restart flag (called before re-execution)
     */
    void resetRestartFlag() { m_shouldRestart = false; }
    
    /**
     * @brief Reset card info for restart (called before re-execution)
     */
    void resetCardInfo();
    
protected:
    
    /**
     * @brief Build card info JSON for signals
     */
    QJsonObject buildCardInfoJson() const;
    
private:
    FlowManager* m_manager;
    FlowType m_flowType;
    QJsonObject m_params;
    CardInfo m_cardInfo;
    
    // Pause/resume synchronization
    QWaitCondition m_resumeCondition;
    QMutex m_resumeMutex;
    bool m_paused;
    bool m_cancelled;
    bool m_shouldRestart;
    
    // CommandSet for card operations (points to FlowManager's persistent instance)
    // NOT owned by this class - managed by FlowManager to maintain secure channel
    Keycard::CommandSet* m_commandSet;
};

} // namespace StatusKeycard

#endif // FLOW_BASE_H

