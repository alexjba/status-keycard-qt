#include "session_manager.h"
#include "signal_manager.h"
#include <keycard-qt/types.h>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDebug>
#include <QThread>
#include <QCoreApplication>
#include <QMetaObject>
#include <QCryptographicHash>
#include <QEventLoop>
#include <QTimer>
#include <QtConcurrent/QtConcurrent>

#ifdef KEYCARD_QT_HAS_OPENSSL
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#endif

namespace StatusKeycard {

// LEB128 (Little Endian Base 128) encoding
// Used for encoding wallet path components (matching Go's apdu.WriteLength)
static void writeLEB128(QByteArray& buf, uint32_t value) {
    do {
        uint8_t byte = value & 0x7F;  // Take lower 7 bits
        value >>= 7;
        if (value != 0) {
            byte |= 0x80;  // Set continuation bit if more bytes follow
        }
        buf.append(static_cast<char>(byte));
    } while (value != 0);
}

// Derivation paths matching status-keycard-go/internal/const.go
static const QString PATH_MASTER = "m";
static const QString PATH_WALLET_ROOT = "m/44'/60'/0'/0";
static const QString PATH_WALLET = "m/44'/60'/0'/0/0";
static const QString PATH_EIP1581 = "m/43'/60'/1581'";
static const QString PATH_WHISPER = "m/43'/60'/1581'/0'/0";
static const QString PATH_ENCRYPTION = "m/43'/60'/1581'/1'/0";

SessionManager::SessionManager(QObject* parent)
    : QObject(parent)
    , m_state(SessionState::UnknownReaderState)
    , m_started(false)
    , m_stateCheckTimer(new QTimer(this))
{
    // CRITICAL: Ensure we're in the main Qt thread for NFC events
    QThread* mainThread = QCoreApplication::instance()->thread();
    QThread* currentThread = QThread::currentThread();
    
    qDebug() << "SessionManager: Constructor called in thread:" << currentThread;
    qDebug() << "SessionManager: Main thread is:" << mainThread;
    
    if (currentThread != mainThread) {
        qWarning() << "SessionManager: Created in wrong thread! Moving to main thread...";
        moveToThread(mainThread);
        qDebug() << "SessionManager: Moved to main thread";
    }
}

SessionManager::~SessionManager()
{
    stop();
}

void SessionManager::startCardOperation()
{
    qDebug() << "SessionManager::startCardOperation() ";
    auto channel = m_channel.get();
    if (channel) {
        QMetaObject::invokeMethod(channel, [channel]() {
            qDebug() << "SessionManager::startCardOperation() invoke method " << (channel ? "YES" : "NO");
            channel->setState(Keycard::ChannelState::WaitingForCard);
        }, Qt::QueuedConnection);
    }
}

void SessionManager::operationCompleted()
{
    qDebug() << "SessionManager::operationCompleted()";
    if (m_channel) {
        m_channel->setState(Keycard::ChannelState::Idle);
    }
}

void SessionManager::setCommandSet(std::shared_ptr<Keycard::CommandSet> commandSet)
{
    if (m_commandSet != commandSet) {
        if (m_channel) {
            qDebug() << "SessionManager::setCommandSet() - CommandSet changed, disconnecting old signals";
            QObject::disconnect(m_channel.get(), nullptr, this, nullptr);
        }
        m_channel.reset();
    }
    qDebug() << "SessionManager::setCommandSet() - Setting shared CommandSet";
    m_commandSet = commandSet;

    if (!m_commandSet) {
        qWarning() << "SessionManager: No command set available";
        return;
    }

    m_channel = m_commandSet->channel();
    if (!m_channel) {
        qWarning() << "SessionManager: No channel set";
        return;
    }

    // Connect signals
    connect(m_channel.get(), &Keycard::KeycardChannel::readerAvailabilityChanged,
            this, &SessionManager::onReaderAvailabilityChanged);
    connect(m_channel.get(), &Keycard::KeycardChannel::targetDetected,
            this, &SessionManager::onCardDetected);
    connect(m_channel.get(), &Keycard::KeycardChannel::targetLost,
            this, &SessionManager::onCardRemoved);
    connect(m_channel.get(), &Keycard::KeycardChannel::error,
            this, [](const QString& errorMsg) {
        qWarning() << "SessionManager: KeycardChannel error:" << errorMsg;
    });
}

bool SessionManager::start(bool logEnabled, const QString& logFilePath)
{
    if (m_started) {
        setError("Service already started");
        qWarning() << "SessionManager: Already started!";
        return false;
    }

    if (m_channel) {
        qDebug() << "SessionManager: Starting card detection...";
        m_channel->setState(Keycard::ChannelState::WaitingForCard);
        // Transition to WaitingForCard state
        setState(SessionState::WaitingForCard);
    } else {
        // No channel available - set to waiting for reader
        setState(SessionState::WaitingForReader);
    }

    m_started = true;

    return true;
}

void SessionManager::stop()
{
    if (!m_started) {
        return;
    }
    
    m_started = false;
    m_currentCardUID.clear();

    if (m_channel) {
        m_channel->setState(Keycard::ChannelState::Idle);
    }
    setState(SessionState::UnknownReaderState);
    qDebug() << "SessionManager: Stopped";
}

void SessionManager::setState(SessionState newState)
{
    if (newState == m_state) {
        return;
    }
    
    SessionState oldState = m_state;
    m_state = newState;
    
    // Emit Qt signal - c_api.cpp will forward to SignalManager
    emit stateChanged(newState, oldState);
}

void SessionManager::onReaderAvailabilityChanged(bool available)
{
    qDebug() << "SessionManager: Reader availability changed:" << (available ? "available" : "not available");
    
    if (available) {
        if (m_state == SessionState::UnknownReaderState || m_state == SessionState::WaitingForReader) {
            setState(SessionState::WaitingForCard);
            m_channel->setState(Keycard::ChannelState::WaitingForCard);
        }
    } else {
        setState(SessionState::WaitingForReader);
    }
}

void SessionManager::onCardDetected(const QString& uid)
{
    qDebug() << "========================================";
    qDebug() << " SessionManager: CARD DETECTED! UID:" << uid;
    qDebug() << "   Thread:" << QThread::currentThread();
    qDebug() << "========================================";
    
    // iOS: Ignore re-taps of the same card when already Ready/Authorized
    // This prevents unnecessary secure channel re-establishment while user is at PIN input screen
    if (m_currentCardUID == uid && m_state != SessionState::ConnectionError) {
        qDebug() << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
        qDebug() << "iOS: Same card re-tapped while already Ready/Authorized";
        qDebug() << "iOS: Current state:" << sessionStateToString(m_state);
        qDebug() << "iOS: Ignoring duplicate card detection (already connected)";
        qDebug() << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
        return;  // Don't emit signal, don't change state, don't start new secure channel
    }
    
    m_currentCardUID = uid;

    setState(SessionState::ConnectingCard);
    
    // iOS: Run secure channel opening in background thread to avoid blocking main thread
    // This prevents the QEventLoop in transmit() from blocking Qt's event processing
    // (which would prevent iOS NFC target lost signals from being processed)
    QtConcurrent::run([this]() {
        qDebug() << "SessionManager: Opening secure channel in background thread:" << QThread::currentThread();
        
        // CRITICAL: Serialize card operations to prevent concurrent APDU corruption
        QMutexLocker locker(&m_operationMutex);
        
        if (!m_commandSet) {
            qWarning() << "SessionManager: No command set available";
            QMetaObject::invokeMethod(this, [this]() {
                setError("Failed to create command set");
                setState(SessionState::ConnectionError);
            }, Qt::QueuedConnection);
            return;
        }
        // Select applet (doesn't require pairing/secure channel)
        m_appInfo = m_commandSet->select();
        // Check if select succeeded: initialized cards have instanceUID, pre-initialized cards have secureChannelPublicKey
        if (m_appInfo.instanceUID.isEmpty() && m_appInfo.secureChannelPublicKey.isEmpty()) {
            qWarning() << "SessionManager: Failed to select applet";
            QMetaObject::invokeMethod(this, [this]() {
                setError("Failed to select applet");
                setState(SessionState::ConnectionError);
            }, Qt::QueuedConnection);
            return;
        }
        // Check if card is initialized
        if (!m_appInfo.initialized) {
            qDebug() << "SessionManager: Card is empty (not initialized)";
            QMetaObject::invokeMethod(this, [this]() {
                setState(SessionState::EmptyKeycard);
            }, Qt::QueuedConnection);
            return;
        }

        if (!m_commandSet->ensurePairing()) {
            QMetaObject::invokeMethod(this, [this]() {
                setState(m_appInfo.availableSlots > 0 ? 
                SessionState::PairingError :
                SessionState::NoAvailablePairingSlots);
            }, Qt::QueuedConnection);
            return;
        }

        if (!m_commandSet->ensureSecureChannel()) {
            QMetaObject::invokeMethod(this, [this]() {
                setState(SessionState::ConnectionError);
            }, Qt::QueuedConnection);
            return;
        }

        m_appStatus = m_commandSet->cachedApplicationStatus();
        m_metadata = getMetadata();

        QMetaObject::invokeMethod(this, [this]() {
            setState(SessionState::Ready);
        }, Qt::QueuedConnection);

        operationCompleted();
    });
}

void SessionManager::onCardRemoved()
{
    qDebug() << "========================================";
    qDebug() << "SessionManager: CARD REMOVED";
    qDebug() << "========================================";
#if defined(Q_OS_ANDROID) || defined(Q_OS_IOS)
    qDebug() << "Ignoring card removal";
    return;
#else
    m_currentCardUID.clear();
    
    if (m_started) {
        setState(SessionState::WaitingForCard);
    }
#endif
}

void SessionManager::onChannelError(const QString& error)
{
    qWarning() << "SessionManager: Channel error:" << error;
    setError(error);
    emit this->error(error);
}

void SessionManager::setError(const QString& error)
{
    m_lastError = error;
}

QString SessionManager::currentStateString() const
{
    return sessionStateToString(m_state);
}

SessionManager::Status SessionManager::getStatus() const
{
    Status status;
    status.state = currentStateString();
    
    // Build keycardInfo (if we have appInfo)
    if (!m_appInfo.instanceUID.isEmpty()) {
        status.keycardInfo = new ApplicationInfoV2();
        status.keycardInfo->installed = true; // If we have it, it's installed
        status.keycardInfo->initialized = m_appInfo.initialized;
        status.keycardInfo->instanceUID = m_appInfo.instanceUID.toHex();
        status.keycardInfo->version = QString("%1.%2").arg(m_appInfo.appVersion).arg(m_appInfo.appVersionMinor);
        status.keycardInfo->availableSlots = m_appInfo.availableSlots;
        status.keycardInfo->keyUID = m_appInfo.keyUID.toHex();
    }

    if ((m_state == SessionState::Ready || m_state == SessionState::Authorized) && m_appStatus.pinRetryCount >= 0) {
        status.keycardStatus = new ApplicationStatus();
        status.keycardStatus->remainingAttemptsPIN = m_appStatus.pinRetryCount;
        status.keycardStatus->remainingAttemptsPUK = m_appStatus.pukRetryCount;
        status.keycardStatus->keyInitialized = m_appStatus.keyInitialized;
        status.keycardStatus->path = ""; // TODO: Get from card if available
    }

    // Only include metadata if we have some
    if (!m_metadata.name.isEmpty() || !m_metadata.wallets.isEmpty()) {
        status.metadata = new Metadata();
        status.metadata->name = m_metadata.name;
        status.metadata->wallets = m_metadata.wallets;
    }

    return status;
}

// Card Operations

bool SessionManager::initialize(const QString& pin, const QString& puk, const QString& pairingPassword)
{
    qDebug() << "SessionManager::initialize()";
    QMutexLocker locker(&m_operationMutex);

    
    if (!m_commandSet) {
        setError("No command set available (no card connected)");
        return false;
    }
    QString password = pairingPassword.isEmpty() ? "KeycardDefaultPairing" : pairingPassword;
    Keycard::Secrets secrets(pin, puk, password);
    bool result = m_commandSet->init(secrets);
    if (!result) {
        setError(m_commandSet->lastError());
        return false;
    }

    m_currentCardUID.clear();
    m_appStatus = m_commandSet->cachedApplicationStatus();
    m_appInfo = m_commandSet->select(false);
    setState(SessionState::Ready);
    return true;
}

bool SessionManager::authorize(const QString& pin)
{
    qDebug() << "SessionManager::authorize() - START - Thread:" << QThread::currentThread();
    
    // CRITICAL: Serialize card operations to prevent concurrent APDU corruption
    QMutexLocker locker(&m_operationMutex);
    
    if (m_state != SessionState::Ready) {
        setError("Card not ready (current state: " + currentStateString() + ")");
        return false;
    }
    
    if (!m_commandSet) {
        setError("No command set available (no card connected)");
        return false;
    }

    bool result = m_commandSet->verifyPIN(pin);
    m_appStatus = m_commandSet->cachedApplicationStatus();
    
    if (!result) {
        setError(m_commandSet->lastError());
        int remaining = m_commandSet->remainingPINAttempts();
        if (remaining >= 0) {
            setError(QString("Wrong PIN (%1 attempts remaining)").arg(remaining));
        }
        
        operationCompleted();
        return false;
    }
    
    if (m_appStatus.pinRetryCount >= 0) {
        qDebug() << "SessionManager: Application status updated after authorization";
        qDebug() << "  PIN retry count:" << m_appStatus.pinRetryCount;
        qDebug() << "  PUK retry count:" << m_appStatus.pukRetryCount;
        qDebug() << "  Key initialized:" << m_appStatus.keyInitialized;
    } else {
        qWarning() << "SessionManager: Failed to update application status after PIN verification";
        qWarning() << "SessionManager: This may cause subsequent operations to fail";
    }
    
    setState(SessionState::Authorized);
    operationCompleted();
    return true;
}

bool SessionManager::changePIN(const QString& newPIN)
{
    QMutexLocker locker(&m_operationMutex);

    if (m_state != SessionState::Authorized) {
        setError("Not authorized");
        return false;
    }
    
    bool result = m_commandSet->changePIN(newPIN);
    if (!result) {
        setError(m_commandSet->lastError());
        return false;
    }
    
    qDebug() << "SessionManager: PIN changed";
    
    operationCompleted();
    
    return true;
}

bool SessionManager::changePUK(const QString& newPUK)
{
    QMutexLocker locker(&m_operationMutex);

    if (m_state != SessionState::Authorized) {
        setError("Not authorized");
        return false;
    }
    
    bool result = m_commandSet->changePUK(newPUK);
    if (!result) {
        setError(m_commandSet->lastError());
        return false;
    }
    
    qDebug() << "SessionManager: PUK changed";
    
    operationCompleted();
    
    return true;
}

bool SessionManager::unblockPIN(const QString& puk, const QString& newPIN)
{
    QMutexLocker locker(&m_operationMutex);

    if (m_state != SessionState::Ready && m_state != SessionState::Authorized) {
        setError("Card not ready");
        return false;
    }
    
    bool result = m_commandSet->unblockPIN(puk, newPIN);
    if (!result) {
        setError(m_commandSet->lastError());
        return false;
    }
    
    qDebug() << "SessionManager: PIN unblocked";
    
    operationCompleted();
    
    return true;
}

// Key Operations

QVector<int> SessionManager::generateMnemonic(int length)
{
    QMutexLocker locker(&m_operationMutex);

    if (m_state != SessionState::Authorized) {
        setError("Not authorized");
        return QVector<int>();
    }

    int checksumSize = 4; // Default
    if (length == 15) checksumSize = 5;
    else if (length == 18) checksumSize = 6;
    else if (length == 21) checksumSize = 7;
    else if (length == 24) checksumSize = 8;
    
    QVector<int> indexes = m_commandSet->generateMnemonic(checksumSize);
    if (indexes.isEmpty()) {
        setError(m_commandSet->lastError());
    }

    operationCompleted();
        
    return indexes;
}

QString SessionManager::loadMnemonic(const QString& mnemonic, const QString& passphrase)
{
    QMutexLocker locker(&m_operationMutex);
    
    if (!m_commandSet) {
        setError("No command set available");
        return QString();
    }
    
    // Convert mnemonic to BIP39 seed using PBKDF2
    // Formula: PBKDF2(NFKD(mnemonic), "mnemonic" + NFKD(passphrase), 2048, 64, SHA512)
    
    // Normalize mnemonic and passphrase to NFKD form
    QString mnemonicNormalized = mnemonic.normalized(QString::NormalizationForm_D);
    QString passphraseNormalized = passphrase.normalized(QString::NormalizationForm_D);
    
    // BIP39 salt = "mnemonic" + passphrase
    QString salt = QString("mnemonic") + passphraseNormalized;
    
    // Use PBKDF2 to derive seed (64 bytes)
    QByteArray mnemonicBytes = mnemonicNormalized.toUtf8();
    QByteArray saltBytes = salt.toUtf8();
    
    // Use OpenSSL's PBKDF2
    QByteArray seed(64, 0);
    int result = PKCS5_PBKDF2_HMAC(
        mnemonicBytes.constData(), mnemonicBytes.size(),
        reinterpret_cast<const unsigned char*>(saltBytes.constData()), saltBytes.size(),
        2048,  // iterations
        EVP_sha512(),  // hash function
        64,  // key length
        reinterpret_cast<unsigned char*>(seed.data())
    );
    
    if (result != 1) {
        setError("PBKDF2 derivation failed");
        return QString();
    }
    
    // Load seed onto keycard
    qDebug() << "SessionManager: Loading seed onto keycard (" << seed.size() << " bytes)";
    QByteArray keyUID = m_commandSet->loadSeed(seed);
    
    if (keyUID.isEmpty()) {
        setError(QString("Failed to load seed: %1").arg(m_commandSet->lastError()));
        return QString();
    }
    
    qDebug() << "SessionManager: Seed loaded successfully, keyUID:" << keyUID.toHex();
    
    operationCompleted();
    
    return QString("0x") + keyUID.toHex();
}

bool SessionManager::factoryReset()
{
    QMutexLocker locker(&m_operationMutex);
    
    if (!m_commandSet) {
        setError("No command set available (no card connected)");
        return false;
    }
    
    bool result = m_commandSet->factoryReset();
    if (!result) {
        setError(m_commandSet->lastError());
        return false;
    }
    
    qDebug() << "SessionManager: Factory reset complete";

    m_appInfo = m_commandSet->select(true);

    m_currentCardUID.clear();
    m_appStatus = m_commandSet->cachedApplicationStatus();
    setState(SessionState::EmptyKeycard);
    operationCompleted();

    return true;
}

// Metadata Operations
// NOTE: Implementations moved to after helper functions (line ~945+)
// to avoid forward declaration errors

// Key Export

// BER-TLV parser for exported keys (matching keycard-go implementation)
static quint32 parseTlvLength(const QByteArray& data, int& offset) {
    if (offset >= data.size()) {
        return 0;
    }
    
    quint8 firstByte = static_cast<quint8>(data[offset]);
    offset++;
    
    // Short form: length < 128 (0x80)
    if (firstByte < 0x80) {
        return firstByte;
    }
    
    // Long form: first byte = 0x80 + number of length bytes
    if (firstByte == 0x80) {
        qWarning() << "Unsupported indefinite length (0x80)";
        return 0;
    }
    
    int lengthBytes = firstByte - 0x80;
    if (lengthBytes > 4 || offset + lengthBytes > data.size()) {
        qWarning() << "Invalid length encoding";
        return 0;
    }
    
    // Read length bytes (big-endian)
    quint32 length = 0;
    for (int i = 0; i < lengthBytes; i++) {
        length = (length << 8) | static_cast<quint8>(data[offset]);
        offset++;
    }
    
    return length;
}

static QByteArray findTlvTag(const QByteArray& data, uint8_t targetTag) {
    int offset = 0;
    
    while (offset < data.size()) {
        // Parse tag (we only support single-byte tags for now)
        if (offset >= data.size()) {
            break;
        }
        
        uint8_t tag = static_cast<uint8_t>(data[offset]);
        offset++;
        
        // Parse length (supports multi-byte lengths)
        quint32 length = parseTlvLength(data, offset);
        if (length == 0 && offset >= data.size()) {
            break;
        }
        
        // Check if we have enough data
        if (offset + length > data.size()) {
            qWarning() << "TLV length exceeds data size. Tag:" << QString("0x%1").arg(tag, 2, 16, QChar('0'))
                      << "Length:" << length << "Remaining:" << (data.size() - offset);
            break;
        }
        
        // Found the target tag
        if (tag == targetTag) {
            return data.mid(offset, length);
        }
        
        // Skip to next tag
        offset += length;
    }
    
    return QByteArray();
}

// Compute Ethereum address from public key using Qt's QCryptographicHash
static QString publicKeyToAddress(const QByteArray& pubKey) {
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

// Derive public key from private key using OpenSSL secp256k1
static QByteArray derivePublicKeyFromPrivate(const QByteArray& privKey) {
    if (privKey.size() != 32) {
        qWarning() << "derivePublicKeyFromPrivate: Invalid private key size:" << privKey.size();
        return QByteArray();
    }
    
    // Create EC_KEY for secp256k1
    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!eckey) {
        qWarning() << "derivePublicKeyFromPrivate: Failed to create EC_KEY";
        return QByteArray();
    }
    
    // Set private key
    BIGNUM* priv_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(privKey.data()), privKey.size(), nullptr);
    if (!priv_bn || !EC_KEY_set_private_key(eckey, priv_bn)) {
        qWarning() << "derivePublicKeyFromPrivate: Failed to set private key";
        BN_free(priv_bn);
        EC_KEY_free(eckey);
        return QByteArray();
    }
    
    // Compute public key from private key
    const EC_GROUP* group = EC_KEY_get0_group(eckey);
    EC_POINT* pub_point = EC_POINT_new(group);
    if (!EC_POINT_mul(group, pub_point, priv_bn, nullptr, nullptr, nullptr)) {
        qWarning() << "derivePublicKeyFromPrivate: Failed to compute public key";
        BN_free(priv_bn);
        EC_POINT_free(pub_point);
        EC_KEY_free(eckey);
        return QByteArray();
    }
    
    EC_KEY_set_public_key(eckey, pub_point);
    
    // Export public key in uncompressed format (0x04 + X + Y)
    unsigned char pub_key_bytes[65];
    size_t pub_key_len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, 
                                            pub_key_bytes, sizeof(pub_key_bytes), nullptr);
    
    BN_free(priv_bn);
    EC_POINT_free(pub_point);
    EC_KEY_free(eckey);
    
    if (pub_key_len != 65) {
        qWarning() << "derivePublicKeyFromPrivate: Invalid public key length:" << pub_key_len;
        return QByteArray();
    }
    
    return QByteArray(reinterpret_cast<const char*>(pub_key_bytes), pub_key_len);
}

// Parse exported key TLV response
static SessionManager::KeyPair parseExportedKey(const QByteArray& data) {
    SessionManager::KeyPair keyPair;
    
    if (data.isEmpty()) {
        qWarning() << "parseExportedKey: Empty data";
        return keyPair;
    }
    
    qDebug() << "parseExportedKey: Received" << data.size() << "bytes:";
    qDebug() << "parseExportedKey: Hex dump:" << data.toHex();
    
    // Find template tag 0xA1
    QByteArray template_ = findTlvTag(data, 0xA1);
    if (template_.isEmpty()) {
        qWarning() << "Failed to find template tag 0xA1 in exported key";
        qWarning() << "Raw data size:" << data.size() << "bytes";
        qWarning() << "First 32 bytes:" << data.left(32).toHex();
        return keyPair;
    }
    
    // Find public key (0x80)
    QByteArray pubKey = findTlvTag(template_, 0x80);
    
    // Find private key (0x81) if available
    QByteArray privKey = findTlvTag(template_, 0x81);
    if (!privKey.isEmpty()) {
        keyPair.privateKey = privKey.toHex();
    }
    
    // If public key is missing but private key is present, derive it
    if (pubKey.isEmpty() && !privKey.isEmpty()) {
        qDebug() << "parseExportedKey: Deriving public key from private key";
        pubKey = derivePublicKeyFromPrivate(privKey);
        if (pubKey.isEmpty()) {
            qWarning() << "parseExportedKey: Failed to derive public key";
            return keyPair;
        }
        qDebug() << "parseExportedKey: Derived public key:" << pubKey.toHex();
    }
    
    // Set public key and address
    if (!pubKey.isEmpty()) {
        keyPair.publicKey = pubKey.toHex();
        keyPair.address = publicKeyToAddress(pubKey);
    }
    
    // Find chain code (0x82) if available
    QByteArray chainCode = findTlvTag(template_, 0x82);
    if (!chainCode.isEmpty()) {
        keyPair.chainCode = chainCode.toHex();
    }
    
    return keyPair;
}

SessionManager::LoginKeys SessionManager::exportLoginKeys()
{
    // Serialize card operations to prevent concurrent APDU corruption
    QMutexLocker locker(&m_operationMutex);
    
    // Clear any previous error
    m_lastError.clear();
    
    LoginKeys keys;
    
    if (m_state != SessionState::Authorized) {
        setError("Not authorized");
        return keys;
    }
    
    if (!m_commandSet) {
        setError("No command set available");
        return keys;
    }

    qDebug() << "SessionManager: Exporting whisper key from path:" << PATH_WHISPER;
    QByteArray whisperData = m_commandSet->exportKey(true, true, PATH_WHISPER, Keycard::APDU::P2ExportKeyPrivateAndPublic);
    if (whisperData.isEmpty()) {
        setError(QString("Failed to export whisper key: %1").arg(m_commandSet->lastError()));
        operationCompleted();
        return keys;
    }
    qDebug() << "SessionManager: Whisper key data size:" << whisperData.size();
    keys.whisperPrivateKey = parseExportedKey(whisperData);

    // Export encryption private key
    // Now we can use makeCurrent=false since the whisper export already set the card state
    qDebug() << "SessionManager: Exporting encryption key from path:" << PATH_ENCRYPTION;
    QByteArray encryptionData = m_commandSet->exportKey(true, false, PATH_ENCRYPTION, Keycard::APDU::P2ExportKeyPrivateAndPublic);
    if (encryptionData.isEmpty()) {
        setError(QString("Failed to export encryption key: %1").arg(m_commandSet->lastError()));
        operationCompleted();
        return keys;
    }
    qDebug() << "SessionManager: Encryption key data size:" << encryptionData.size();
    keys.encryptionPrivateKey = parseExportedKey(encryptionData);
    
    qDebug() << "SessionManager: Login keys exported successfully";
    
    operationCompleted();
    return keys;
}

SessionManager::RecoverKeys SessionManager::exportRecoverKeys()
{
    // CRITICAL: Serialize card operations to prevent concurrent APDU corruption
    QMutexLocker locker(&m_operationMutex);
    
    // Clear any previous error
    m_lastError.clear();
    
    RecoverKeys keys;
    
    if (m_state != SessionState::Authorized) {
        setError("Not authorized");
        return keys;
    }
    
    if (!m_commandSet) {
        setError("No command set available");
        return keys;
    }
    
    qDebug() << "SessionManager: Exporting recover keys";
    
    // First export login keys
    keys.loginKeys = exportLoginKeys();
    if (!m_lastError.isEmpty()) {
        return keys;
    }
    
    // Export EIP1581 key (public only)
    QByteArray eip1581Data = m_commandSet->exportKey(true, false, PATH_EIP1581);
    if (eip1581Data.isEmpty()) {
        setError(QString("Failed to export EIP1581 key: %1").arg(m_commandSet->lastError()));
        operationCompleted();
        return keys;
    }
    keys.eip1581 = parseExportedKey(eip1581Data);
    
    // Export wallet root key (extended public if supported, otherwise public only)
    // Check if card supports extended keys (version >= 3.1)
    bool supportsExtended = m_appInfo.appVersion >= 3 && m_appInfo.appVersionMinor >= 1;
    QByteArray walletRootData = supportsExtended ?
        m_commandSet->exportKeyExtended(true, false, PATH_WALLET_ROOT) :
        m_commandSet->exportKey(true, false, PATH_WALLET_ROOT);
    
    if (walletRootData.isEmpty()) {
        setError(QString("Failed to export wallet root key: %1").arg(m_commandSet->lastError()));
        operationCompleted();
        return keys;
    }
    keys.walletRootKey = parseExportedKey(walletRootData);
    
    // Export wallet key (public only)
    QByteArray walletData = m_commandSet->exportKey(true, false, PATH_WALLET);
    if (walletData.isEmpty()) {
        setError(QString("Failed to export wallet key: %1").arg(m_commandSet->lastError()));
        operationCompleted();
        return keys;
    }
    keys.walletKey = parseExportedKey(walletData);
    
    // Export master key (public only, makeCurrent=true for compatibility)
    QByteArray masterData = m_commandSet->exportKey(true, true, PATH_MASTER);
    if (masterData.isEmpty()) {
        setError(QString("Failed to export master key: %1").arg(m_commandSet->lastError()));
        operationCompleted();
        return keys;
    }
    keys.masterKey = parseExportedKey(masterData);
    
    qDebug() << "SessionManager: Recover keys exported successfully";
    
    operationCompleted();
    
    return keys;
}

// Metadata Operations Implementation
// These are defined here (after helper functions) to avoid forward declaration issues

SessionManager::Metadata SessionManager::getMetadata()
{
    QMutexLocker locker(&m_operationMutex);

    Metadata metadata;

    
    if (!m_commandSet) {
        setError("No command set available");
        return metadata;
    }
    
    // Get metadata from card (matching status-keycard-go GetMetadata)
    qDebug() << "SessionManager: Getting metadata from card";
    QByteArray metadataData = m_commandSet->getData(Keycard::APDU::P1StoreDataPublic);  // 0x00
    
    // Check if data looks like a status word (error response)
    if (metadataData.size() == 2) {
        uint16_t sw = (static_cast<uint8_t>(metadataData[0]) << 8) | static_cast<uint8_t>(metadataData[1]);
        if (sw != 0x9000) {  // Not success
            qDebug() << "SessionManager: Card returned status word:" << QString("0x%1").arg(sw, 4, 16, QChar('0'));
            qDebug() << "SessionManager: No metadata on card (error or empty)";
            operationCompleted();
            return metadata;
        }
    }
    
    if (metadataData.isEmpty()) {
        // Not an error - card might not have metadata yet
        qDebug() << "SessionManager: No metadata on card";
        operationCompleted();
        return metadata;
    }
    
    // Parse metadata using Go's custom binary format (matching types/metadata.go ParseMetadata())
    // Format: [version+namelen][name][start/count pairs in LEB128]
    //   Byte 0: version (3 bits) + name length (5 bits)
    //   Bytes 1..namelen: card name
    //   Remaining: series of start/count LEB128 pairs for wallet paths
    
    int offset = 0;
    if (offset >= metadataData.size()) {
        qDebug() << "SessionManager: Metadata too short";
        operationCompleted();
        return metadata;
    }
    
    // Parse header byte
    uint8_t header = static_cast<uint8_t>(metadataData[offset++]);
    uint8_t version = header >> 5;
    uint8_t namelen = header & 0x1F;
    
    qDebug() << "SessionManager: Metadata version:" << version << "namelen:" << namelen;
    
    if (version != 1) {
        qWarning() << "SessionManager: Invalid metadata version:" << version;
        operationCompleted();
        return metadata;
    }
    
    // Parse card name
    if (namelen > 0) {
        if (offset + namelen > metadataData.size()) {
            qWarning() << "SessionManager: Metadata too short for name";
            operationCompleted();
            return metadata;
        }
        QByteArray nameData = metadataData.mid(offset, namelen);
        metadata.name = QString::fromUtf8(nameData);
        offset += namelen;
        qDebug() << "SessionManager: Card name:" << metadata.name;
    }
    
    // Parse wallet paths (LEB128 encoded start/count pairs)
    while (offset < metadataData.size()) {
        // Parse start index (LEB128)
        uint32_t start = 0;
        int shift = 0;
        while (offset < metadataData.size()) {
            uint8_t byte = static_cast<uint8_t>(metadataData[offset++]);
            start |= (byte & 0x7F) << shift;
            if ((byte & 0x80) == 0) break;
            shift += 7;
        }
        
        if (offset >= metadataData.size()) break;
        
        // Parse count (LEB128)
        uint32_t count = 0;
        shift = 0;
        while (offset < metadataData.size()) {
            uint8_t byte = static_cast<uint8_t>(metadataData[offset++]);
            count |= (byte & 0x7F) << shift;
            if ((byte & 0x80) == 0) break;
            shift += 7;
        }
        
        // Add all paths in range [start, start+count]
        // Expand to full paths like Go's ToMetadata() does
        for (uint32_t i = start; i <= start + count; ++i) {
            QString walletPath = PATH_WALLET_ROOT + QString("/%1").arg(i);
            Wallet wallet;
            wallet.path = walletPath;
            // Note: address and publicKey are left empty (not resolved)
            // Use exportKey() separately if you need those
            metadata.wallets.append(wallet);
        }
    }
    
    qDebug() << "SessionManager: Metadata retrieved - name:" << metadata.name
             << "wallets:" << metadata.wallets.size();
    
    operationCompleted();
    
    return metadata;
}

bool SessionManager::storeMetadata(const QString& name, const QStringList& paths)
{
    qDebug() << "SessionManager: Storing metadata - name:" << name << "paths:" << paths.size();
    QMutexLocker locker(&m_operationMutex);

    if (m_state != SessionState::Authorized) {
        setError("Not authorized");
        return false;
    }
    
    if (!m_commandSet) {
        setError("No command set available");
        return false;
    }
    
    qDebug() << "SessionManager: Storing metadata - name:" << name << "paths:" << paths.size();
    
    // Parse paths to extract last component (matching Go implementation)
    // All paths must start with PATH_WALLET_ROOT
    QVector<uint32_t> pathComponents;
    for (const QString& path : paths) {
        if (!path.startsWith(PATH_WALLET_ROOT)) {
            setError(QString("Path '%1' does not start with wallet root path '%2'")
                    .arg(path).arg(PATH_WALLET_ROOT));
            return false;
        }
        
        // Extract last component (after last '/')
        QStringList parts = path.split('/');
        if (parts.isEmpty()) {
            setError(QString("Invalid path format: %1").arg(path));
            return false;
        }
        
        bool ok;
        uint32_t component = parts.last().toUInt(&ok);
        if (!ok) {
            setError(QString("Invalid path component: %1").arg(parts.last()));
            return false;
        }
        
        pathComponents.append(component);
    }
    
    // Sort path components (Go keeps them ordered)
    std::sort(pathComponents.begin(), pathComponents.end());
    
    // Build metadata in Go's custom binary format (matching types/metadata.go Serialize())
    // Format: [version+namelen][name][start/count pairs in LEB128]
    // - Byte 0: 0x20 | namelen (version=1 in top 3 bits, name length in bottom 5 bits)
    // - Bytes 1..namelen: card name (UTF-8)
    // - Remaining: LEB128-encoded start/count pairs for consecutive wallet paths
    QByteArray metadata;
    
    QByteArray nameBytes = name.toUtf8();
    if (nameBytes.size() > 20) {
        setError("Card name exceeds 20 characters");
        return false;
    }
    
    uint8_t header = 0x20 | static_cast<uint8_t>(nameBytes.size());  // Version 1, name length
    metadata.append(static_cast<char>(header));
    metadata.append(nameBytes);
    
    // Encode wallet paths as start/count pairs (consecutive paths are grouped)
    // This matches Go's Serialize() logic
    if (!pathComponents.isEmpty()) {
        uint32_t start = pathComponents[0];
        uint32_t count = 0;
        
        for (int i = 1; i < pathComponents.size(); ++i) {
            if (pathComponents[i] == start + count + 1) {
                // Consecutive path, extend range
                count++;
            } else {
                // Non-consecutive, write current range and start new one
                writeLEB128(metadata, start);
                writeLEB128(metadata, count);
                start = pathComponents[i];
                count = 0;
            }
        }
        
        // Write final range
        writeLEB128(metadata, start);
        writeLEB128(metadata, count);
    }
    
    qDebug() << "SessionManager: Encoded metadata size:" << metadata.size() << "bytes";
    qDebug() << "SessionManager: Metadata hex:" << metadata.toHex();
    
    // Store metadata on card (public data type)
    // Use P1StoreDataPublic (0x00) as defined in status-keycard-go
    bool success = m_commandSet->storeData(0x00, metadata);  // 0x00 = P1StoreDataPublic
    
    if (!success) {
        setError(QString("Failed to store metadata: %1").arg(m_commandSet->lastError()));
        operationCompleted();

        return false;
    }

    m_metadata.name = name;
    for (const QString& path : paths) {
        m_metadata.wallets.append({
            .path = path,
            .address = "",
            .publicKey = ""
        });
    }
    operationCompleted();

    return true;
}

} // namespace StatusKeycard

