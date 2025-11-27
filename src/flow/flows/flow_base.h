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


struct FlowResult {
    bool ok;
    QJsonObject result;
};

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
     * @brief Pause and wait for user input
     * @param action Signal type to emit
     * @param error Error message
     */
    void pauseAndWait(const QString& action, const QString& error);

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
    Keycard::KeycardChannel* channel() const;
    
    /**
     * @brief Get pairing storage
     */
    PairingStorage* storage() const;
    
    /**
     * @brief Get command set
     * @return CommandSet for card operations (shared across all flows)
     */
    std::shared_ptr<Keycard::CommandSet> commandSet() const;
    
    /**
     * @brief Get flow parameters
     */
    QJsonObject params() const { return m_params; }
    
    // ============================================================================
    // Pause/Resume mechanism
    // ============================================================================

    
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
     * @brief Connect to card and select applet
     * @return true if successful
     */
    bool selectKeycard();
    
    /**
     * @brief Verify PIN
     * @return true if successful
     */
    bool verifyPIN(bool giveup = false);

    /**
     * @brief Unblock PIN
     * @return true if successful
     */
    bool unblockPIN();
    
    /**
     * @brief Check if card has keys
     * @return true if card has keys
     */
    bool requireKeys();
    
    /**
     * @brief Check if card has NO keys
     * @return true if card has no keys
     */
    FlowResult requireNoKeys();


    /**
     * @brief Load mnemonic onto card
     * @return true if successful
     */
    FlowResult loadMnemonic();
    
    /**
     * @brief Initialize keycard
     * @return FlowResult
     */
    FlowResult initializeKeycard();

    /**
     * @brief Convert mnemonic to seed
     * @param mnemonic Mnemonic
     * @param password Password
     * @return seed
     */
    static QByteArray mnemonicToSeed(const QString& mnemonic, const QString& password);
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
    const FlowBase::CardInfo cardInfo() const;
    
    /**
     * @brief Builds CardInfo from ApplicationInfo
     */
    FlowBase::CardInfo buildCardInfo() const;
    
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
    
protected:
    
    /**
     * @brief Build card info JSON for signals
     */
    QJsonObject buildCardInfoJson() const;


    /**
     * @brief Compute Ethereum address from public key using Qt's QCryptographicHash
     * @param pubKey Public key
     * @return Ethereum address
     */
    static QString publicKeyToAddress(const QByteArray& pubKey);

    /**
     * @brief Parse exported key data from TLV format
     * @param data Raw TLV data from exportKey
     * @param publicKey Output: extracted public key (65 bytes uncompressed)
     * @param privateKey Output: extracted private key (32 bytes, if present)
     * @return true if parsing succeeded
     */
    static bool parseExportedKey(const QByteArray& data, QByteArray& publicKey, QByteArray& privateKey);

private:
    FlowManager* m_manager;
    FlowType m_flowType;
    QJsonObject m_params;
    
    // Pause/resume synchronization
    QWaitCondition m_resumeCondition;
    QMutex m_resumeMutex;
    bool m_paused;
    bool m_cancelled;
    bool m_shouldRestart;
};

} // namespace StatusKeycard

#endif // FLOW_BASE_H

