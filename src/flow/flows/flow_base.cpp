#include "flow_base.h"
#include "../flow_manager.h"
#include "../flow_signals.h"
#include <keycard-qt/keycard_channel.h>
#include <QDebug>
#include <QThread>
#include <QEventLoop>
#include <QTimer>
#include <QCryptographicHash>
#include <QJsonArray>
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace StatusKeycard {

FlowBase::FlowBase(FlowManager* manager, FlowType type, const QJsonObject& params, QObject* parent)
    : QObject(parent)
    , m_manager(manager)
    , m_flowType(type)
    , m_params(params)
    , m_paused(false)
    , m_cancelled(false)
    , m_shouldRestart(false)
{
}

FlowBase::~FlowBase()
{
}

const FlowBase::CardInfo FlowBase::cardInfo() const {
    return buildCardInfo();
}

void FlowBase::resume(const QJsonObject& newParams)
{
    QMutexLocker locker(&m_resumeMutex);
    
    // Merge new params into existing params
    for (auto it = newParams.begin(); it != newParams.end(); ++it) {
        m_params[it.key()] = it.value();
    }
    
    // Wake up flow
    m_paused = false;
    m_resumeCondition.wakeAll();
}

void FlowBase::cancel()
{
    QMutexLocker locker(&m_resumeMutex);
    m_cancelled = true;
    m_resumeCondition.wakeAll();
}

// ============================================================================
// Access to manager resources
// ============================================================================

Keycard::KeycardChannel* FlowBase::channel() const
{
    if (!m_manager) {
        qWarning() << "FlowBase::channel() No FlowManager available";
        return nullptr;
    }
    return m_manager->channel();
}

std::shared_ptr<Keycard::CommandSet> FlowBase::commandSet() const { 
    if (!m_manager) {
        qWarning() << "FlowBase::commandSet() No FlowManager available";
        return nullptr;
    }
    return m_manager->commandSet();
}

// ============================================================================
// Pause/Resume mechanism
// ============================================================================

void FlowBase::pauseAndWait(const QString& action, const QString& error)
{
    pauseAndWaitWithStatus(action, error, QJsonObject());
}

void FlowBase::pauseAndWaitWithStatus(const QString& action, const QString& error, 
                                     const QJsonObject& status)
{
    // iOS: Manage NFC drawer based on action type
    if (action == FlowSignals::INSERT_CARD) {
        // Waiting for card - open NFC drawer
        qDebug() << "FlowBase: Opening NFC drawer to wait for card, action:" << action;
        channel()->setState(Keycard::ChannelState::WaitingForCard);
    } else if (action == FlowSignals::ENTER_PIN || 
               action == FlowSignals::ENTER_PUK || 
               action.contains("enter-") || action.contains("input-")) {
        // Waiting for user input - close NFC drawer so user can interact with UI
        qDebug() << "FlowBase: Closing NFC drawer for user input action:" << action;
        channel()->setState(Keycard::ChannelState::Idle);
    }
    
    // Build event with error and status
    QJsonObject event = status;
    event[FlowParams::ERROR_KEY] = error;
    auto info = cardInfo();

    // Add card info if available
    if (info.freeSlots >= 0) {
        event[FlowParams::INSTANCE_UID] = info.instanceUID;
        event[FlowParams::KEY_UID] = info.keyUID;
        event[FlowParams::FREE_SLOTS] = info.freeSlots;
    }
    
    if (info.pinRetries >= 0) {
        event[FlowParams::PIN_RETRIES] = info.pinRetries;
        event[FlowParams::PUK_RETRIES] = info.pukRetries;
    }
    
    // Emit pause signal
    emit flowPaused(action, event);
    
    // Wait for resume or cancel
    QMutexLocker locker(&m_resumeMutex);
    m_paused = true;
    
    while (m_paused && !m_cancelled) {
        m_resumeCondition.wait(&m_resumeMutex);
    }
}

void FlowBase::pauseAndRestart(const QString& action, const QString& error)
{
    m_shouldRestart = true;
    pauseAndWait(action, error);
}

// ============================================================================
// Card operations
// ============================================================================

bool FlowBase::selectKeycard()
{
    qDebug() << "FlowBase::selectKeycard()";
    
    if (!commandSet()) {
        qCritical() << "FlowBase: No CommandSet available";
        emit flowError("No CommandSet available");
        return false;
    }
    
    // Select keycard applet
    Keycard::ApplicationInfo appInfo = commandSet()->select();
    if (!appInfo.installed) {
        qCritical() << "FlowBase: Keycard applet not installed!";
        emit flowError("Keycard applet not installed");
        return false;
    }
    
    return true;
}

FlowResult FlowBase::initializeKeycard()
{
    // Check if card is initialized (pre-initialized cards need initialization first)
    // This matches status-keycard-go behavior: pause and ask for PIN/PUK/pairing
    QJsonObject result = buildCardInfoJson();

    QString pin = m_params[FlowParams::NEW_PIN].toString();
    if (pin.isEmpty()) {
        pauseAndWait(FlowSignals::ENTER_NEW_PIN, "require-init");
        if (isCancelled()) {
            result[FlowParams::ERROR_KEY] = "cancelled";
            return FlowResult{false, result};
        }
        pin = m_params[FlowParams::NEW_PIN].toString();
    }

    QString puk = m_params[FlowParams::NEW_PUK].toString();
    if (puk.isEmpty()) {
        pauseAndWait(FlowSignals::ENTER_NEW_PUK, "require-init");
        if (isCancelled()) {
            result[FlowParams::ERROR_KEY] = "cancelled";
            return FlowResult{false, result};
        }
        puk = m_params[FlowParams::NEW_PUK].toString();
    }

    QString pairingPassword = m_params[FlowParams::NEW_PAIRING].toString();
    if (pairingPassword.isEmpty()) {
        pairingPassword = "KeycardDefaultPairing";
    }
    
    auto cmdSet = commandSet();
    Keycard::Secrets secrets(pin, puk, pairingPassword);
    if (!cmdSet || !cmdSet->init(secrets)) {
        qWarning() << "FlowBase: Card initialization failed:" << (cmdSet ? cmdSet->lastError() : "No CommandSet");
        result[FlowParams::ERROR_KEY] = "init-failed";
        return FlowResult{false, result};
    }

    return FlowResult{true, buildCardInfoJson()};
}

bool FlowBase::unblockPIN()
{
    qDebug() << "FlowBase: Unblocking PIN...";
    if (!commandSet()) {
        qCritical() << "FlowBase: No CommandSet available";
        emit flowError("No CommandSet available");
        return false;
    }

    QString puk = m_params[FlowParams::PUK].toString();

    if (puk.isEmpty()) {
        pauseAndWait(FlowSignals::ENTER_PUK, "");
        if (m_cancelled) {
            return false;
        }
    }

    QString newPIN = m_params[FlowParams::NEW_PIN].toString();

    if (newPIN.isEmpty()) {
        pauseAndWait(FlowSignals::ENTER_NEW_PIN, "unblocking");
        if (m_cancelled) {
            return false;
        }
        newPIN = m_params[FlowParams::NEW_PIN].toString();
    }

    auto ok = commandSet()->unblockPIN(puk, newPIN);
    if (!ok) {
        if (commandSet()->cachedApplicationStatus().pukRetryCount == 0) {
            return false;
        }
        pauseAndWait(FlowSignals::ENTER_PUK, "puk");
        if (m_cancelled) {
            return false;
        }
        return unblockPIN();
    }

    m_params[FlowParams::PIN] = newPIN;
    
    return true;
}

bool FlowBase::verifyPIN(bool giveup)
{
    qDebug() << "FlowBase: Verifying PIN...";
    if (!commandSet()) {
        qCritical() << "FlowBase: No CommandSet available";
        emit flowError("No CommandSet available");
        return false;
    }

    auto appInfo = commandSet()->select();

    if (!appInfo.initialized) {
        if (!giveup)
            return initializeKeycard().ok;
        return true;
    }

    auto appStatus = commandSet()->getStatus(Keycard::APDU::P1GetStatusApplication);
    if (appStatus.pinRetryCount == 0 && appStatus.valid) {
        qWarning() << "FlowBase: PIN blocked!";
        auto ok = unblockPIN();
        if (m_cancelled) {
            return false;
        }
        if (!ok) {
            pauseAndRestart(FlowSignals::SWAP_CARD, "puk-retries");
            return false;
        }
    }
    
    // Check if PIN already in params
    QString pin = m_params[FlowParams::PIN].toString();
    
    if (pin.isEmpty()) {
        // Request PIN (empty error means normal PIN request, not an error condition)
        pauseAndWait(FlowSignals::ENTER_PIN, "");
        
        if (m_cancelled) {
            return false;
        }
        
        pin = m_params[FlowParams::PIN].toString();
    }
    
    if (pin.isEmpty()) {
        qWarning() << "FlowBase: No PIN provided!";
        emit flowError("No PIN provided");
        return false;
    }
    
    // Verify PIN
    auto response = commandSet()->verifyPIN(pin);
    if (!response) {
        qCritical() << "FlowBase: PIN verification failed!";
        // Wrong PIN, ask again (pauseAndWait will include pinRetries in the event)
        pauseAndWait(FlowSignals::ENTER_PIN, "pin");
        
        if (m_cancelled) {
            return false;
        }
        
        // Retry
        return verifyPIN();
    }
    
    qDebug() << "FlowBase: PIN verified successfully";
    return true;
}

bool FlowBase::requireKeys()
{
    if (!cardInfo().keyUID.isEmpty()) {
        qDebug() << "FlowBase: Card has keys";
        return true;
    }
    
    qWarning() << "FlowBase: Card has no keys!";

    // Request card swap
    pauseAndRestart(FlowSignals::SWAP_CARD, "no-keys");
    
    // If we get here and not cancelled, restart was requested
    return false; // Will restart flow
}

FlowResult FlowBase::requireNoKeys()
{
    QJsonObject result = buildCardInfoJson();
    if (cardInfo().keyUID.isEmpty()) {
        qDebug() << "FlowBase: Card has no keys (as required)";
        return {true, result};
    }
    
    // Check if overwrite allowed
    if (m_params.contains(FlowParams::OVERWRITE) && 
        m_params[FlowParams::OVERWRITE].toBool()) {
        qDebug() << "FlowBase: Card has keys but overwrite allowed";
        return {true, result};
    }
    
    // Request card swap
    pauseAndRestart(FlowSignals::SWAP_CARD, "has-keys");
    
    result[FlowParams::ERROR_KEY] = "has-keys";
    return {false, result}; // Will restart flow
}

// Convert BIP39 mnemonic to binary seed using PBKDF2-HMAC-SHA512
// This matches the BIP39 standard and status-keycard-go implementation
QByteArray FlowBase::mnemonicToSeed(const QString& mnemonic, const QString& password)
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
    
    return seed;
}

FlowResult FlowBase::loadMnemonic()
{
    // Get mnemonic from params (or generate indexes and pause to request it)
    QString mnemonic = m_params[FlowParams::MNEMONIC].toString();
    if (mnemonic.isEmpty()) {
        int mnemonicLength = 12; // Default BIP39 mnemonic length
        if (m_params.contains(FlowParams::MNEMONIC_LEN)) {
            mnemonicLength = m_params[FlowParams::MNEMONIC_LEN].toInt();
        }
        int checksumSize = mnemonicLength / 3;
        
        auto cmdSet = commandSet();
        QVector<int> indexes = cmdSet->generateMnemonic(checksumSize);
        QJsonObject result = buildCardInfoJson();

        if (indexes.isEmpty() || !cmdSet->lastError().isEmpty()) {
            qWarning() << "LoadAccountFlow: Failed to generate mnemonic:" << cmdSet->lastError();
            result[FlowParams::ERROR_KEY] = "generate-failed";
            return FlowResult{false, result};
        }        
        // Add mnemonic-indexes array
        QJsonArray indexesArray;
        for (int idx : indexes) {
            indexesArray.append(idx);
        }
        result[FlowParams::MNEMONIC_IDXS] = indexesArray;

        pauseAndWaitWithStatus(FlowSignals::ENTER_MNEMONIC, "loading-keys", result);
        
        if (isCancelled()) {
            result[FlowParams::ERROR_KEY] = "cancelled";
            return FlowResult{false, result};
        }
        mnemonic = m_params[FlowParams::MNEMONIC].toString();
    }

    // Convert mnemonic to seed using BIP39 standard (PBKDF2-HMAC-SHA512)
    QByteArray seed = mnemonicToSeed(mnemonic, "");
    if (seed.isEmpty()) {
        qWarning() << "LoadAccountFlow: Failed to convert mnemonic to seed";
        QJsonObject result = buildCardInfoJson();
        result[FlowParams::ERROR_KEY] = "mnemonic-conversion-failed";
        return FlowResult{false, result};
    }
    
    // Load seed onto card
    auto cmdSet = commandSet();
    QByteArray keyUID = cmdSet->loadSeed(seed);
    QJsonObject result = buildCardInfoJson();

    if (keyUID.isEmpty()) {
        qWarning() << "LoadAccountFlow: Failed to load seed onto card";
        result[FlowParams::ERROR_KEY] = "load-failed";
        return FlowResult{false, result};
    }

    result[FlowParams::KEY_UID] = QString("0x") + keyUID.toHex();

    return FlowResult{true, result};
}

// ============================================================================
// Card information
// ============================================================================

FlowBase::CardInfo FlowBase::buildCardInfo() const
{
    FlowBase::CardInfo result;
    if (!commandSet())
        return result;

    auto appInfo = commandSet()->applicationInfo();
    auto appStatus = commandSet()->cachedApplicationStatus();

    result.instanceUID = appInfo.instanceUID.toHex();
    result.keyUID = appInfo.keyUID.toHex();
    result.initialized = appInfo.initialized;
    result.freeSlots = appInfo.availableSlots;
    result.keyInitialized = !appInfo.keyUID.isEmpty();
    result.version = (appInfo.appVersion << 8) | appInfo.appVersionMinor;
    
    // Get status to get PIN/PUK retry counts
    // Note: This requires secure channel, so we'll set defaults for now
    // and update later when we have secure channel
    result.pinRetries = appStatus.pinRetryCount;
    result.pukRetries = appStatus.pukRetryCount;
    return result;
}

QJsonObject FlowBase::buildCardInfoJson() const
{
    QJsonObject json;
    auto info = cardInfo();
    
    if (!info.instanceUID.isEmpty()) {
        json[FlowParams::INSTANCE_UID] = info.instanceUID;
    }
    
    if (!info.keyUID.isEmpty()) {
        json[FlowParams::KEY_UID] = info.keyUID;
    }
    
    if (info.freeSlots >= 0) {
        json[FlowParams::FREE_SLOTS] = info.freeSlots;
    }
    
    if (info.pinRetries >= 0) {
        json[FlowParams::PIN_RETRIES] = info.pinRetries;
        json[FlowParams::PUK_RETRIES] = info.pukRetries;
    }
    
    return json;
}

QString FlowBase::publicKeyToAddress(const QByteArray& pubKey) {
    if (pubKey.size() != 65 || pubKey[0] != 0x04) {
        qWarning() << "Invalid public key format";
        return QString();
    }
    
    // Remove 0x04 prefix, hash with Keccak-256, take last 20 bytes
    QByteArray pubKeyData = pubKey.mid(1);
    QByteArray hash = QCryptographicHash::hash(pubKeyData, QCryptographicHash::Keccak_256);
    QByteArray address = hash.right(20);
    
    return QString("0x") + address.toHex();
}

// Helper to parse TLV length (BER-TLV format)
static quint32 parseTlvLength(const QByteArray& data, int& offset) {
    if (offset >= data.size()) {
        return 0;
    }
    
    uint8_t firstByte = static_cast<uint8_t>(data[offset]);
    offset++;
    
    if ((firstByte & 0x80) == 0) {
        // Short form: length is in the lower 7 bits
        return firstByte;
    }
    
    // Long form: lower 7 bits indicate number of length bytes
    int numLengthBytes = firstByte & 0x7F;
    if (numLengthBytes > 4 || offset + numLengthBytes > data.size()) {
        return 0;
    }
    
    quint32 length = 0;
    for (int i = 0; i < numLengthBytes; i++) {
        length = (length << 8) | static_cast<uint8_t>(data[offset]);
        offset++;
    }
    
    return length;
}

// Helper to find a TLV tag in data
static QByteArray findTlvTag(const QByteArray& data, uint8_t targetTag) {
    int offset = 0;
    
    while (offset < data.size()) {
        if (offset >= data.size()) {
            break;
        }
        
        uint8_t tag = static_cast<uint8_t>(data[offset]);
        offset++;
        
        quint32 length = parseTlvLength(data, offset);
        if (length == 0 && offset >= data.size()) {
            break;
        }
        
        if (offset + static_cast<int>(length) > data.size()) {
            break;
        }
        
        if (tag == targetTag) {
            return data.mid(offset, length);
        }
        
        offset += length;
    }
    
    return QByteArray();
}

bool FlowBase::parseExportedKey(const QByteArray& data, QByteArray& publicKey, QByteArray& privateKey) {
    publicKey.clear();
    privateKey.clear();
    
    if (data.isEmpty()) {
        qWarning() << "parseExportedKey: Empty data";
        return false;
    }
    
    // Find template tag 0xA1
    QByteArray template_ = findTlvTag(data, 0xA1);
    if (template_.isEmpty()) {
        qWarning() << "parseExportedKey: Failed to find template tag 0xA1";
        return false;
    }
    
    // Find public key (0x80)
    publicKey = findTlvTag(template_, 0x80);
    
    // Find private key (0x81) if available
    privateKey = findTlvTag(template_, 0x81);
    
    if (publicKey.isEmpty()) {
        qWarning() << "parseExportedKey: No public key found";
        return false;
    }
    
    return true;
}

} // namespace StatusKeycard

