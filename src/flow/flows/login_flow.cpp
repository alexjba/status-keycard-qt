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
}

LoginFlow::~LoginFlow()
{
}

QJsonObject LoginFlow::execute()
{
    qDebug() << "LoginFlow: Starting execution";
    
    // 1. Select keycard applet
    if (!selectKeycard()) {
        qCritical() << "LoginFlow: Failed to select keycard";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "select-failed";
        return error;
    }
    
    // 2. Check card has keys
    if (!requireKeys()) {
        qWarning() << "LoginFlow: Card has no keys";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "no-keys";
        return error;
    }
    
    // 3. Open secure channel and authenticate (verify PIN)
    if (!verifyPIN()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "auth-failed";
        return error;
    }
    
    // 4. Export encryption key (with private key)
    qDebug() << "LoginFlow: Exporting encryption key...";
    QJsonObject encKey = exportKey(ENCRYPTION_PATH, true);
    if (encKey.isEmpty()) {
        qCritical() << "LoginFlow: Failed to export encryption key";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "export-encryption-failed";
        return error;
    }
    
    // 5. Export whisper key (with private key)
    qDebug() << "LoginFlow: Exporting whisper key...";
    QJsonObject whisperKey = exportKey(WHISPER_PATH, true);
    if (whisperKey.isEmpty()) {
        qCritical() << "LoginFlow: Failed to export whisper key";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "export-whisper-failed";
        return error;
    }
    
    // 6. Build result
    QJsonObject result = buildCardInfoJson();
    result[FlowParams::ENC_KEY] = encKey;
    result[FlowParams::WHISPER_KEY] = whisperKey;
    
    qDebug() << "LoginFlow: Execution completed successfully";
    return result;
}

QJsonObject LoginFlow::exportKey(const QString& path, bool includePrivate)
{
    // Check if cancelled
    if (isCancelled()) {
        qWarning() << "LoginFlow: Export cancelled";
        return QJsonObject();
    }
    
    // Get command set from FlowBase
    auto cmdSet = commandSet();
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
    
    // Parse key data
    // Parse TLV-encoded key data
    QByteArray publicKey, privateKey;
    if (!parseExportedKey(keyData, publicKey, privateKey)) {
        qCritical() << "LoginFlow: Failed to parse exported key data";
        return QJsonObject();
    }
    
    QJsonObject keyPair;
    keyPair["publicKey"] = QString("0x") + publicKey.toHex();
    keyPair["address"] = FlowBase::publicKeyToAddress(publicKey);
    
    if (includePrivate && !privateKey.isEmpty()) {
        keyPair["privateKey"] = QString("0x") + privateKey.toHex();
    } else if (includePrivate) {
        qCritical() << "LoginFlow: Private key requested but not found in exported data";
        return QJsonObject();
    }
    
    return keyPair;
}

} // namespace StatusKeycard

