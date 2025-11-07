#ifndef LOGIN_FLOW_H
#define LOGIN_FLOW_H

#include "flow_base.h"

namespace StatusKeycard {

/**
 * @brief Login Flow - Export whisper + encryption keys
 * 
 * Exports the two keys needed for Status login:
 * - Encryption key (m/43'/60'/1581'/1'/0)
 * - Whisper key (m/43'/60'/1581'/0'/0)
 * 
 * Both keys are exported with private keys included.
 * 
 * Result format:
 * {
 *   "instance-uid": "...",
 *   "key-uid": "...",
 *   "encryption-key": {
 *     "address": "0x...",
 *     "publicKey": "0x...",
 *     "privateKey": "0x..."
 *   },
 *   "whisper-key": {
 *     "address": "0x...",
 *     "publicKey": "0x...",
 *     "privateKey": "0x..."
 *   }
 * }
 */
class LoginFlow : public FlowBase {
    Q_OBJECT
    
public:
    LoginFlow(FlowManager* manager, const QJsonObject& params, QObject* parent = nullptr);
    ~LoginFlow();
    
    /**
     * @brief Execute the login flow
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
    static const QString EIP1581_PATH;    // m/43'/60'/1581'
    static const QString WHISPER_PATH;    // m/43'/60'/1581'/0'/0
    static const QString ENCRYPTION_PATH; // m/43'/60'/1581'/1'/0
};

} // namespace StatusKeycard

#endif // LOGIN_FLOW_H

