#include "login_flow.h"
#include "../flow_manager.h"
#include "../flow_params.h"
#include <keycard-qt/command_set.h>
#include <keycard-qt/types.h>
#include <QDebug>

namespace StatusKeycard {

// BIP44 paths (matching status-keycard-go exactly)
const QString LoginFlow::EIP1581_PATH = "m/43'/60'/1581'";
const QString LoginFlow::WHISPER_PATH = "m/43'/60'/1581'/0'/0";
const QString LoginFlow::ENCRYPTION_PATH = "m/43'/60'/1581'/1'/0";

LoginFlow::LoginFlow(FlowManager* manager, const QJsonObject& params, QObject* parent)
    : FlowBase(manager, FlowType::Login, params, parent)
{
    qDebug() << "LoginFlow: Created";
}

LoginFlow::~LoginFlow()
{
    qDebug() << "LoginFlow: Destroyed";
}

QJsonObject LoginFlow::execute()
{
    qDebug() << "LoginFlow: Starting execution";
    
    // 1. Wait for card
    if (!waitForCard()) {
        qWarning() << "LoginFlow: Card wait cancelled";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "cancelled";
        return error;
    }
    
    // 2. Select keycard applet
    if (!selectKeycard()) {
        qCritical() << "LoginFlow: Failed to select keycard";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "select-failed";
        return error;
    }
    
    // 3. Check card has keys
    if (!requireKeys()) {
        qWarning() << "LoginFlow: Card has no keys";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "no-keys";
        return error;
    }
    
    // 4. Open secure channel and authenticate (verify PIN)
    if (!openSecureChannelAndAuthenticate(true)) {
        qCritical() << "LoginFlow: Authentication failed";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "auth-failed";
        return error;
    }
    
    // 5. Export encryption key (with private key)
    qDebug() << "LoginFlow: Exporting encryption key...";
    QJsonObject encKey = exportKey(ENCRYPTION_PATH, true);
    if (encKey.isEmpty()) {
        qCritical() << "LoginFlow: Failed to export encryption key";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "export-encryption-failed";
        return error;
    }
    
    // 6. Export whisper key (with private key)
    qDebug() << "LoginFlow: Exporting whisper key...";
    QJsonObject whisperKey = exportKey(WHISPER_PATH, true);
    if (whisperKey.isEmpty()) {
        qCritical() << "LoginFlow: Failed to export whisper key";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "export-whisper-failed";
        return error;
    }
    
    // 7. Build result
    QJsonObject result = buildCardInfoJson();
    result[FlowParams::ENC_KEY] = encKey;
    result[FlowParams::WHISPER_KEY] = whisperKey;
    
    qDebug() << "LoginFlow: Execution completed successfully";
    return result;
}

QJsonObject LoginFlow::exportKey(const QString& path, bool includePrivate)
{
    qDebug() << "LoginFlow: Exporting key at path:" << path 
             << "includePrivate:" << includePrivate;
    
    // Check if cancelled
    if (isCancelled()) {
        qWarning() << "LoginFlow: Export cancelled";
        return QJsonObject();
    }
    
    // Get command set from FlowBase
    auto* cmdSet = commandSet();
    if (!cmdSet) {
        qCritical() << "LoginFlow: No command set available!";
        return QJsonObject();
    }
    
    // Export key
    // derive=true, makeCurrent=(path=="m"), exportType=private or public
    bool makeCurrent = (path == "m"); // Only for master path
    uint8_t exportType = includePrivate ? 
        Keycard::APDU::P2ExportKeyPrivateAndPublic :
        Keycard::APDU::P2ExportKeyPublicOnly;
    
    QByteArray keyData = cmdSet->exportKey(true, makeCurrent, path, exportType);
    
    if (keyData.isEmpty()) {
        qCritical() << "LoginFlow: Export key returned empty data!";
        return QJsonObject();
    }
    
    qDebug() << "LoginFlow: Exported key, data size:" << keyData.size();
    
    // Parse key data
    // Format depends on export type
    // For P2ExportKeyPrivateAndPublic: 65 bytes public + 32 bytes private
    // For P2ExportKeyPublicOnly: 65 bytes public
    
    QJsonObject keyPair;
    
    if (includePrivate && keyData.size() >= 97) {
        // Public key (65 bytes uncompressed)
        QByteArray publicKey = keyData.left(65);
        keyPair["publicKey"] = QString("0x") + publicKey.toHex();
        
        // Private key (32 bytes)
        QByteArray privateKey = keyData.mid(65, 32);
        keyPair["privateKey"] = QString("0x") + privateKey.toHex();
        
        // Derive address from public key (last 20 bytes of keccak256 hash)
        // For now, we'll skip address derivation and just export keys
        // TODO: Implement proper address derivation with keccak256
        keyPair["address"] = "";
        
    } else if (!includePrivate && keyData.size() >= 65) {
        // Public key only
        QByteArray publicKey = keyData.left(65);
        keyPair["publicKey"] = QString("0x") + publicKey.toHex();
        keyPair["address"] = "";
        
    } else {
        qCritical() << "LoginFlow: Invalid key data size:" << keyData.size()
                   << "expected:" << (includePrivate ? 97 : 65);
        return QJsonObject();
    }
    
    qDebug() << "LoginFlow: Key exported successfully";
    qDebug() << "  Public key:" << keyPair["publicKey"].toString().left(20) << "...";
    if (includePrivate) {
        qDebug() << "  Private key:" << keyPair["privateKey"].toString().left(20) << "...";
    }
    
    return keyPair;
}

} // namespace StatusKeycard

