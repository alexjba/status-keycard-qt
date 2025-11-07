#include "load_account_flow.h"
#include "../flow_manager.h"
#include "../flow_params.h"
#include "../flow_signals.h"
#include <keycard-qt/command_set.h>
#include <keycard-qt/types.h>
#include <keycard-qt/keycard_channel.h>
#include <QDebug>
#include <QJsonArray>
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace StatusKeycard {

// Convert BIP39 mnemonic to binary seed using PBKDF2-HMAC-SHA512
// This matches the BIP39 standard and status-keycard-go implementation
static QByteArray mnemonicToSeed(const QString& mnemonic, const QString& password)
{
    // BIP39 standard:
    // - Key: mnemonic (NFKD normalized)
    // - Salt: "mnemonic" + password (NFKD normalized)
    // - Iterations: 2048
    // - Key length: 64 bytes
    // - Hash: SHA-512
    
    // Qt's QString already handles Unicode, we use normalized form for consistency
    QString normalizedMnemonic = mnemonic.normalized(QString::NormalizationForm_D);
    QString normalizedPassword = password.normalized(QString::NormalizationForm_D);
    
    // BIP39 salt is "mnemonic" + password
    QString saltString = QString("mnemonic") + normalizedPassword;
    
    QByteArray mnemonicBytes = normalizedMnemonic.toUtf8();
    QByteArray saltBytes = saltString.toUtf8();
    
    // Allocate 64 bytes for the derived key (BIP39 standard)
    QByteArray seed(64, 0);
    
    // Use OpenSSL's PBKDF2-HMAC-SHA512
    int result = PKCS5_PBKDF2_HMAC(
        mnemonicBytes.constData(), mnemonicBytes.size(),
        reinterpret_cast<const unsigned char*>(saltBytes.constData()), saltBytes.size(),
        2048,  // iterations (BIP39 standard)
        EVP_sha512(),
        64,    // key length (BIP39 standard)
        reinterpret_cast<unsigned char*>(seed.data())
    );
    
    if (result != 1) {
        qWarning() << "LoadAccountFlow: PBKDF2 failed";
        return QByteArray();
    }
    
    qDebug() << "LoadAccountFlow: Mnemonic converted to seed (" << seed.size() << "bytes)";
    return seed;
}

LoadAccountFlow::LoadAccountFlow(FlowManager* manager, const QJsonObject& params, QObject* parent)
    : FlowBase(manager, FlowType::LoadAccount, params, parent)
{
}

LoadAccountFlow::~LoadAccountFlow()
{
}

QJsonObject LoadAccountFlow::execute()
{
    qDebug() << "LoadAccountFlow: Starting";
    
    if (!waitForCard()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "cancelled";
        return error;
    }
    
    if (!selectKeycard()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "select-failed";
        return error;
    }
    
    // Check if card is initialized (pre-initialized cards need initialization first)
    // This matches status-keycard-go behavior: pause and ask for PIN/PUK/pairing
    if (!cardInfo().initialized) {
        qDebug() << "LoadAccountFlow: Card is not initialized (pre-initialized state)";
        qDebug() << "LoadAccountFlow: Pausing to request initialization credentials";
        
        // Request PIN/PUK/pairing for initialization
        pauseAndWait(FlowSignals::ENTER_NEW_PIN, "require-init");
        
        if (isCancelled()) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "cancelled";
            return error;
        }
        
        // Get initialization credentials from params
        QString pin = params()[FlowParams::NEW_PIN].toString();
        QString puk = params()[FlowParams::NEW_PUK].toString();
        QString pairingPassword = params()[FlowParams::NEW_PAIRING].toString();
        
        // Use default pairing password if not provided (matches status-keycard-go)
        if (pairingPassword.isEmpty()) {
            pairingPassword = "KeycardDefaultPairing";
            qDebug() << "LoadAccountFlow: Using default pairing password";
        }
        
        if (pin.isEmpty() || puk.isEmpty()) {
            qWarning() << "LoadAccountFlow: Missing PIN or PUK";
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "missing-credentials";
            return error;
        }
        
        // Initialize the card
        qDebug() << "LoadAccountFlow: Initializing card with provided credentials";
        auto* cmdSet = commandSet();
        Keycard::Secrets secrets(pin, puk, pairingPassword);
        if (!cmdSet || !cmdSet->init(secrets)) {
            qWarning() << "LoadAccountFlow: Card initialization failed:" << (cmdSet ? cmdSet->lastError() : "No CommandSet");
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "init-failed";
            return error;
        }
        
        qDebug() << "LoadAccountFlow: Card initialized successfully";
        
        // After initialization, disconnect and force card re-detection
        // This matches SessionManager::initialize() behavior
        qDebug() << "LoadAccountFlow: Disconnecting from card";
        channel()->disconnect();
        
        qDebug() << "LoadAccountFlow: Forcing card re-scan after initialization";
        channel()->forceScan();
        
        // Wait for card to be re-detected and re-select applet
        // This will now actually wait because we disconnected above
        if (!waitForCard()) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "cancelled";
            return error;
        }
        
        if (!selectKeycard()) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "select-failed";
            return error;
        }
    }
    
    // Authenticate FIRST (this will pause for PIN entry)
    // This matches status-keycard-go: authenticate before checking keys
    if (!openSecureChannelAndAuthenticate(true)) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "auth-failed";
        return error;
    }
    
    // THEN check if card has keys (after authentication)
    // If card already has keys loaded, return error
    if (!requireNoKeys()) {
        qWarning() << "LoadAccountFlow: Card already has keys loaded";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "has-keys";
        return error;
    }
    
    // Get mnemonic from params (or generate indexes and pause to request it)
    QString mnemonic = params()[FlowParams::MNEMONIC].toString();
    if (mnemonic.isEmpty()) {
        // Generate mnemonic indexes on the card
        // This matches status-keycard-go: kc.GenerateMnemonic(mnemonicLength / 3)
        int mnemonicLength = 12; // Default BIP39 mnemonic length
        if (params().contains(FlowParams::MNEMONIC_LEN)) {
            mnemonicLength = params()[FlowParams::MNEMONIC_LEN].toInt();
        }
        int checksumSize = mnemonicLength / 3;
        
        qDebug() << "LoadAccountFlow: Generating mnemonic indexes on card (length:" << mnemonicLength << "checksum:" << checksumSize << ")";
        
        auto* cmdSet = commandSet();
        QVector<int> indexes = cmdSet->generateMnemonic(checksumSize);
        
        if (indexes.isEmpty() || !cmdSet->lastError().isEmpty()) {
            qWarning() << "LoadAccountFlow: Failed to generate mnemonic:" << cmdSet->lastError();
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "generate-failed";
            return error;
        }
        
        qDebug() << "LoadAccountFlow: Generated mnemonic indexes:" << indexes;
        
        // Build pause event with mnemonic indexes
        // This matches Go: pauseAndWaitWithStatus(EnterMnemonic, ErrorLoading, FlowParams{MnemonicIdxs: indexes})
        QJsonObject status = buildCardInfoJson();
        
        // Add mnemonic-indexes array
        QJsonArray indexesArray;
        for (int idx : indexes) {
            indexesArray.append(idx);
        }
        status["mnemonic-indexes"] = indexesArray;
        
        // Pause with "loading-keys" error (matches Go's ErrorLoading)
        pauseAndWaitWithStatus(FlowSignals::ENTER_MNEMONIC, "loading-keys", status);
        
        if (isCancelled()) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "cancelled";
            return error;
        }
        mnemonic = params()[FlowParams::MNEMONIC].toString();
    }
    
    // Get password (optional, defaults to empty string for BIP39)
    QString password = params()["password"].toString();
    
    // Convert mnemonic to seed using BIP39 standard (PBKDF2-HMAC-SHA512)
    qDebug() << "LoadAccountFlow: Converting mnemonic to seed using BIP39 standard";
    QByteArray seed = mnemonicToSeed(mnemonic, password);
    
    if (seed.isEmpty()) {
        qWarning() << "LoadAccountFlow: Failed to convert mnemonic to seed";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "mnemonic-conversion-failed";
        return error;
    }
    
    // Load seed onto card
    qDebug() << "LoadAccountFlow: Loading seed onto card";
    auto* cmdSet = commandSet();
    QByteArray keyUID = cmdSet->loadSeed(seed);
    
    if (keyUID.isEmpty()) {
        qWarning() << "LoadAccountFlow: Failed to load seed onto card";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "load-failed";
        return error;
    }
    
    QJsonObject result = buildCardInfoJson();
    result[FlowParams::KEY_UID] = QString("0x") + keyUID.toHex();
    
    qDebug() << "LoadAccountFlow: Complete";
    return result;
}

} // namespace StatusKeycard

