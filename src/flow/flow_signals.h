#ifndef FLOW_SIGNALS_H
#define FLOW_SIGNALS_H

#include <QString>
#include <QJsonObject>

namespace StatusKeycard {

/**
 * @brief Flow signal emission
 * 
 * Signals MUST match status-keycard-go/pkg/flow/types.go exactly
 * 
 * Signal format:
 * {
 *   "type": "keycard.action.XXX",
 *   "event": {
 *     "error": "error-message",
 *     "instance-uid": "...",
 *     "key-uid": "...",
 *     "pin-retries": 3,
 *     ... other fields
 *   }
 * }
 */
class FlowSignals {
public:
    // Signal type constants (matching status-keycard-go)
    static const QString FLOW_RESULT;          // "keycard.flow-result"
    static const QString INSERT_CARD;          // "keycard.action.insert-card"
    static const QString CARD_INSERTED;        // "keycard.action.card-inserted"
    static const QString SWAP_CARD;            // "keycard.action.swap-card"
    static const QString ENTER_PAIRING;        // "keycard.action.enter-pairing"
    static const QString ENTER_PIN;            // "keycard.action.enter-pin"
    static const QString ENTER_PUK;            // "keycard.action.enter-puk"
    static const QString ENTER_NEW_PAIRING;    // "keycard.action.enter-new-pairing"
    static const QString ENTER_NEW_PIN;        // "keycard.action.enter-new-pin"
    static const QString ENTER_NEW_PUK;        // "keycard.action.enter-new-puk"
    static const QString ENTER_TX_HASH;        // "keycard.action.enter-tx-hash"
    static const QString ENTER_PATH;           // "keycard.action.enter-bip44-path"
    static const QString ENTER_MNEMONIC;       // "keycard.action.enter-mnemonic"
    static const QString ENTER_NAME;           // "keycard.action.enter-cardname"
    static const QString ENTER_WALLETS;        // "keycard.action.enter-wallets"
    
    /**
     * @brief Emit flow result (completion)
     * @param result Flow result data
     */
    static void emitFlowResult(const QJsonObject& result);
    
    /**
     * @brief Emit insert card request
     */
    static void emitInsertCard();
    
    /**
     * @brief Emit card inserted notification
     */
    static void emitCardInserted();
    
    /**
     * @brief Emit swap card request (wrong card detected)
     * @param error Error message
     * @param cardInfo Card information
     */
    static void emitSwapCard(const QString& error, const QJsonObject& cardInfo);
    
    /**
     * @brief Emit enter pairing password request
     * @param retriesLeft Retries remaining (-1 if unknown)
     */
    static void emitEnterPairing(int retriesLeft = -1);
    
    /**
     * @brief Emit enter PIN request
     * @param retriesLeft PIN retries remaining
     */
    static void emitEnterPIN(int retriesLeft);
    
    /**
     * @brief Emit enter PUK request
     * @param retriesLeft PUK retries remaining
     */
    static void emitEnterPUK(int retriesLeft);
    
    /**
     * @brief Emit enter new pairing password request
     */
    static void emitEnterNewPairing();
    
    /**
     * @brief Emit enter new PIN request
     */
    static void emitEnterNewPIN();
    
    /**
     * @brief Emit enter new PUK request
     */
    static void emitEnterNewPUK();
    
    /**
     * @brief Emit enter transaction hash request
     */
    static void emitEnterTxHash();
    
    /**
     * @brief Emit enter BIP44 path request
     */
    static void emitEnterPath();
    
    /**
     * @brief Emit enter mnemonic request
     */
    static void emitEnterMnemonic();
    
    /**
     * @brief Emit enter card name request
     */
    static void emitEnterName();
    
    /**
     * @brief Emit enter wallet paths request
     */
    static void emitEnterWallets();
    
private:
    /**
     * @brief Build signal JSON
     * @param type Signal type
     * @param event Event data
     * @return Complete signal JSON
     */
    static QJsonObject buildSignal(const QString& type, const QJsonObject& event);
    
    /**
     * @brief Emit signal via SignalManager
     * @param signal Signal JSON
     */
    static void emitSignal(const QJsonObject& signal);
};

} // namespace StatusKeycard

#endif // FLOW_SIGNALS_H

