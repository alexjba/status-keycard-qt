#ifndef RECOVER_ACCOUNT_FLOW_H
#define RECOVER_ACCOUNT_FLOW_H

#include "flow_base.h"

namespace StatusKeycard {

/**
 * @brief RecoverAccount Flow - Export all keys for recovery
 * 
 * Exports all 5 keys needed for account recovery:
 * - Encryption key (m/43'/60'/1581'/1'/0) - private + public
 * - Whisper key (m/43'/60'/1581'/0'/0) - private + public  
 * - EIP1581 key (m/43'/60'/1581') - public only
 * - Wallet root key (m/44'/60'/0') - extended public
 * - Wallet key (m/44'/60'/0'/0) - public only
 * - Master key (m) - public only
 * 
 * Similar to Login flow but exports more keys for full recovery.
 */
class RecoverAccountFlow : public FlowBase {
    Q_OBJECT
    
public:
    RecoverAccountFlow(FlowManager* manager, const QJsonObject& params, QObject* parent = nullptr);
    ~RecoverAccountFlow();
    
    /**
     * @brief Execute the recover account flow
     * @return Flow result JSON
     */
    QJsonObject execute() override;
    
private:
    /**
     * @brief Export a key at specified path
     * @param path BIP32/44 derivation path
     * @param includePrivate If true, export private key
     * @return KeyPair JSON or empty on error
     */
    QJsonObject exportKey(const QString& path, bool includePrivate);
    
    // BIP44 paths (matching status-keycard-go)
    static const QString EIP1581_PATH;         // m/43'/60'/1581'
    static const QString WHISPER_PATH;         // m/43'/60'/1581'/0'/0
    static const QString ENCRYPTION_PATH;      // m/43'/60'/1581'/1'/0
    static const QString WALLET_ROOT_PATH;     // m/44'/60'/0'
    static const QString WALLET_PATH;          // m/44'/60'/0'/0
    static const QString MASTER_PATH;          // m
};

} // namespace StatusKeycard

#endif // RECOVER_ACCOUNT_FLOW_H

