#include "recover_account_flow.h"
#include "../flow_manager.h"
#include "../flow_params.h"
#include <keycard-qt/command_set.h>
#include <keycard-qt/types.h>
#include <QDebug>

namespace StatusKeycard {

// BIP44 paths (matching status-keycard-go exactly)
const QString RecoverAccountFlow::EIP1581_PATH = "m/43'/60'/1581'";
const QString RecoverAccountFlow::WHISPER_PATH = "m/43'/60'/1581'/0'/0";
const QString RecoverAccountFlow::ENCRYPTION_PATH = "m/43'/60'/1581'/1'/0";
const QString RecoverAccountFlow::WALLET_ROOT_PATH = "m/44'/60'/0'";
const QString RecoverAccountFlow::WALLET_PATH = "m/44'/60'/0'/0";
const QString RecoverAccountFlow::MASTER_PATH = "m";

RecoverAccountFlow::RecoverAccountFlow(FlowManager* manager, const QJsonObject& params, QObject* parent)
    : FlowBase(manager, FlowType::RecoverAccount, params, parent)
{
    qDebug() << "RecoverAccountFlow: Created";
}

RecoverAccountFlow::~RecoverAccountFlow()
{
    qDebug() << "RecoverAccountFlow: Destroyed";
}

QJsonObject RecoverAccountFlow::execute()
{
    qDebug() << "RecoverAccountFlow: Starting execution";
    
    // 1. Wait for card
    if (!waitForCard()) {
        qWarning() << "RecoverAccountFlow: Card wait cancelled";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "cancelled";
        return error;
    }
    
    // 2. Select keycard applet
    if (!selectKeycard()) {
        qCritical() << "RecoverAccountFlow: Failed to select keycard";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "select-failed";
        return error;
    }
    
    // 3. Check card has keys
    if (!requireKeys()) {
        qWarning() << "RecoverAccountFlow: Card has no keys";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "no-keys";
        return error;
    }
    
    // 4. Open secure channel and authenticate (verify PIN)
    if (!openSecureChannelAndAuthenticate(true)) {
        qCritical() << "RecoverAccountFlow: Authentication failed";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "auth-failed";
        return error;
    }
    
    // 5. Export encryption key (with private key)
    qDebug() << "RecoverAccountFlow: Exporting encryption key...";
    QJsonObject encKey = exportKey(ENCRYPTION_PATH, true);
    if (encKey.isEmpty()) {
        qCritical() << "RecoverAccountFlow: Failed to export encryption key";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "export-encryption-failed";
        return error;
    }
    
    // 6. Export whisper key (with private key)
    qDebug() << "RecoverAccountFlow: Exporting whisper key...";
    QJsonObject whisperKey = exportKey(WHISPER_PATH, true);
    if (whisperKey.isEmpty()) {
        qCritical() << "RecoverAccountFlow: Failed to export whisper key";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "export-whisper-failed";
        return error;
    }
    
    // 7. Export EIP1581 key (public only)
    qDebug() << "RecoverAccountFlow: Exporting EIP1581 key...";
    QJsonObject eip1581Key = exportKey(EIP1581_PATH, false);
    if (eip1581Key.isEmpty()) {
        qCritical() << "RecoverAccountFlow: Failed to export EIP1581 key";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "export-eip1581-failed";
        return error;
    }
    
    // 8. Export wallet root key (extended public - for now just public)
    qDebug() << "RecoverAccountFlow: Exporting wallet root key...";
    QJsonObject walletRootKey = exportKey(WALLET_ROOT_PATH, false);
    if (walletRootKey.isEmpty()) {
        qCritical() << "RecoverAccountFlow: Failed to export wallet root key";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "export-wallet-root-failed";
        return error;
    }
    
    // 9. Export wallet key (public only)
    qDebug() << "RecoverAccountFlow: Exporting wallet key...";
    QJsonObject walletKey = exportKey(WALLET_PATH, false);
    if (walletKey.isEmpty()) {
        qCritical() << "RecoverAccountFlow: Failed to export wallet key";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "export-wallet-failed";
        return error;
    }
    
    // 10. Export master key (public only)
    qDebug() << "RecoverAccountFlow: Exporting master key...";
    QJsonObject masterKey = exportKey(MASTER_PATH, false);
    if (masterKey.isEmpty()) {
        qCritical() << "RecoverAccountFlow: Failed to export master key";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "export-master-failed";
        return error;
    }
    
    // 11. Build result
    QJsonObject result = buildCardInfoJson();
    result[FlowParams::ENC_KEY] = encKey;
    result[FlowParams::WHISPER_KEY] = whisperKey;
    result[FlowParams::EIP1581_KEY] = eip1581Key;
    result[FlowParams::WALLET_ROOT_KEY] = walletRootKey;
    result[FlowParams::WALLET_KEY] = walletKey;
    result[FlowParams::MASTER_KEY] = masterKey;
    
    qDebug() << "RecoverAccountFlow: Execution completed successfully";
    return result;
}

QJsonObject RecoverAccountFlow::exportKey(const QString& path, bool includePrivate)
{
    qDebug() << "RecoverAccountFlow: Exporting key at path:" << path 
             << "includePrivate:" << includePrivate;
    
    // Check if cancelled
    if (isCancelled()) {
        qWarning() << "RecoverAccountFlow: Export cancelled";
        return QJsonObject();
    }
    
    // Get command set from FlowBase
    auto* cmdSet = commandSet();
    if (!cmdSet) {
        qCritical() << "RecoverAccountFlow: No command set available!";
        return QJsonObject();
    }
    
    // Export key
    bool makeCurrent = (path == MASTER_PATH); // Only for master path
    uint8_t exportType = includePrivate ? 
        Keycard::APDU::P2ExportKeyPrivateAndPublic :
        Keycard::APDU::P2ExportKeyPublicOnly;
    
    QByteArray keyData = cmdSet->exportKey(true, makeCurrent, path, exportType);
    
    if (keyData.isEmpty()) {
        qCritical() << "RecoverAccountFlow: Export key returned empty data!";
        return QJsonObject();
    }
    
    qDebug() << "RecoverAccountFlow: Exported key, data size:" << keyData.size();
    
    // Parse key data
    QJsonObject keyPair;
    
    if (includePrivate && keyData.size() >= 97) {
        // Public key (65 bytes uncompressed)
        QByteArray publicKey = keyData.left(65);
        keyPair["publicKey"] = QString("0x") + publicKey.toHex();
        
        // Private key (32 bytes)
        QByteArray privateKey = keyData.mid(65, 32);
        keyPair["privateKey"] = QString("0x") + privateKey.toHex();
        
        keyPair["address"] = "";
        
    } else if (!includePrivate && keyData.size() >= 65) {
        // Public key only
        QByteArray publicKey = keyData.left(65);
        keyPair["publicKey"] = QString("0x") + publicKey.toHex();
        keyPair["address"] = "";
        
    } else {
        qCritical() << "RecoverAccountFlow: Invalid key data size:" << keyData.size();
        return QJsonObject();
    }
    
    qDebug() << "RecoverAccountFlow: Key exported successfully";
    return keyPair;
}

} // namespace StatusKeycard

