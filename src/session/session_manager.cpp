#include "session_manager.h"
#include "storage/pairing_storage.h"
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

#ifdef KEYCARD_QT_HAS_OPENSSL
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#endif

namespace StatusKeycard {

SessionManager::SessionManager(QObject* parent)
    : QObject(parent)
    , m_state(SessionState::UnknownReaderState)
    , m_started(false)
    , m_authorized(false)
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
    
    m_stateCheckTimer->setInterval(100); // Check every 100ms
    connect(m_stateCheckTimer, &QTimer::timeout, this, &SessionManager::checkCardState);
}

SessionManager::~SessionManager()
{
    stop();
}

bool SessionManager::start(const QString& storagePath, bool logEnabled, const QString& logFilePath)
{
    qDebug() << "SessionManager::start() called with storagePath:" << storagePath;
    qDebug() << "SessionManager::start() running in thread:" << QThread::currentThread();
    qDebug() << "SessionManager object is in thread:" << thread();
    
    if (m_started) {
        setError("Service already started");
        qWarning() << "SessionManager: Already started!";
        return false;
    }

    m_storagePath = storagePath;
    
    // CRITICAL: Create KeycardChannel directly in main thread (not move it there!)
    // Qt NFC requires QNearFieldManager to be created in the main thread
    // Moving it after creation breaks signal emission
    qDebug() << "SessionManager: Creating KeycardChannel IN MAIN THREAD...";
    QThread* mainThread = QCoreApplication::instance()->thread();
    QThread* currentThread = QThread::currentThread();
    
    if (currentThread == mainThread) {
        qDebug() << "SessionManager: Already in main thread, creating directly...";
        m_channel = std::make_unique<Keycard::KeycardChannel>();
    } else {
        qWarning() << "SessionManager: In background thread, creating in main thread via invokeMethod...";
        
        // Use a blocking queued connection to create the channel in the main thread
        std::unique_ptr<Keycard::KeycardChannel> tempChannel;
        QMetaObject::invokeMethod(this, [&tempChannel]() {
            qDebug() << "  ↳ Lambda executing in thread:" << QThread::currentThread();
            tempChannel = std::make_unique<Keycard::KeycardChannel>();
            qDebug() << "  ↳ KeycardChannel created at:" << (void*)tempChannel.get();
        }, Qt::BlockingQueuedConnection);
        
        m_channel = std::move(tempChannel);
        qDebug() << "SessionManager: KeycardChannel created in main thread via invokeMethod";
    }
    
    qDebug() << "SessionManager: KeycardChannel thread:" << m_channel->thread();
    qDebug() << "SessionManager: Main thread:" << mainThread;
    qDebug() << "SessionManager: Same thread?" << (m_channel->thread() == mainThread);
    
    m_commandSet = std::make_unique<Keycard::CommandSet>(m_channel.get());
    
    // Connect signals
    qDebug() << "SessionManager: Connecting signals...";
    connect(m_channel.get(), &Keycard::KeycardChannel::targetDetected,
            this, &SessionManager::onCardDetected);
    connect(m_channel.get(), &Keycard::KeycardChannel::targetLost,
            this, &SessionManager::onCardRemoved);
    connect(m_channel.get(), &Keycard::KeycardChannel::error,
            this, [](const QString& errorMsg) {
        qWarning() << "SessionManager: KeycardChannel error:" << errorMsg;
    });
    
    // Start detection
    qDebug() << "SessionManager: Starting card detection...";
    // KeycardChannel is now in main thread, so direct call is safe
    // Qt's internal NFC manager will handle events in the correct thread
    m_channel->startDetection();
    
    m_started = true;
    setState(SessionState::WaitingForCard);
    
    // CRITICAL: Start timer in the object's thread using QMetaObject::invokeMethod
    // This ensures the timer starts in the main thread even if start() is called from background
    QMetaObject::invokeMethod(m_stateCheckTimer, "start", Qt::QueuedConnection);
    
    qDebug() << "SessionManager: Started successfully with storage:" << storagePath;
    qDebug() << "SessionManager: Waiting for NFC card...";
    return true;
}

void SessionManager::stop()
{
    if (!m_started) {
        return;
    }
    
    // Stop timer in the object's thread
    QMetaObject::invokeMethod(m_stateCheckTimer, "stop", Qt::QueuedConnection);
    
    if (m_channel) {
        // KeycardChannel is in main thread, direct calls are safe
        m_channel->stopDetection();
        m_channel->disconnect();
    }
    
    m_channel.reset();
    m_commandSet.reset();
    
    m_started = false;
    m_authorized = false;
    m_currentCardUID.clear();
    
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
    
    qDebug() << "SessionManager: State" << sessionStateToString(oldState)
             << "->" << sessionStateToString(newState);
    
    // Emit Qt signal - c_api.cpp will forward to SignalManager
    emit stateChanged(newState, oldState);
}

void SessionManager::onCardDetected(const QString& uid)
{
    qDebug() << "========================================";
    qDebug() << "SessionManager: CARD DETECTED! UID:" << uid;
    qDebug() << "========================================";
    m_currentCardUID = uid;
    
    emit cardDetected(uid);
    setState(SessionState::ConnectingCard);
    
    // Try to connect and pair
    if (!openSecureChannel()) {
        qWarning() << "SessionManager: Failed to open secure channel";
        setError("Failed to connect to card");
        setState(SessionState::ConnectionError);
        return;
    }
    
    setState(SessionState::Ready);
}

void SessionManager::onCardRemoved()
{
    qDebug() << "========================================";
    qDebug() << "SessionManager: CARD REMOVED";
    qDebug() << "========================================";
    m_currentCardUID.clear();
    m_authorized = false;
    closeSecureChannel();
    
    emit cardRemoved();
    
    if (m_started) {
        setState(SessionState::WaitingForCard);
    }
}

void SessionManager::onChannelError(const QString& error)
{
    qWarning() << "SessionManager: Channel error:" << error;
    setError(error);
    emit this->error(error);
}

void SessionManager::checkCardState()
{
    // Periodic check for card state changes
    // The channel handles most of this via signals
}

bool SessionManager::openSecureChannel()
{
    if (!m_commandSet) {
        return false;
    }
    
    // Select applet
    m_appInfo = m_commandSet->select();
    if (m_appInfo.instanceUID.isEmpty()) {
        qWarning() << "SessionManager: Failed to select applet";
        return false;
    }
    
    qDebug() << "SessionManager: Selected applet, InstanceUID:" << m_appInfo.instanceUID.toHex();
    qDebug() << "SessionManager: Card initialized:" << m_appInfo.initialized;
    qDebug() << "SessionManager: Card installed:" << m_appInfo.installed;
    qDebug() << "SessionManager: App version:" << QString("%1.%2").arg(m_appInfo.appVersion).arg(m_appInfo.appVersionMinor);
    qDebug() << "SessionManager: Available slots:" << m_appInfo.availableSlots;
    qDebug() << "SessionManager: Key UID:" << m_appInfo.keyUID.toHex();
    
    // Check if card needs initialization
    if (!m_appInfo.initialized) {
        qWarning() << "========================================";
        qWarning() << "❌ SessionManager: CARD NOT INITIALIZED!";
        qWarning() << "❌ Card must be initialized before it can be used";
        qWarning() << "========================================";
        qWarning() << "💡 Call KeycardInitialize.init(PIN, PUK, PairingPassword)";
        qWarning() << "💡 Example: init('000000', '000000000000', 'YourPairingPassword')";
        qWarning() << "========================================";
        m_lastError = "Card not initialized";
        return false;
    }
    
    // Try to load saved pairing
    m_pairingInfo = loadPairing(m_appInfo.instanceUID.toHex());
    
    if (!m_pairingInfo.isValid()) {
        // Need to pair
        qDebug() << "SessionManager: No saved pairing, attempting to pair";
        QString pairingPassword = "KeycardDefaultPairing"; // TODO: Make configurable
        qWarning() << "⚠️  Using default pairing password:" << pairingPassword;
        qWarning() << "⚠️  If card was initialized with different password, pairing will fail!";
        m_pairingInfo = m_commandSet->pair(pairingPassword);
        
        if (!m_pairingInfo.isValid()) {
            qWarning() << "========================================";
            qWarning() << "❌ SessionManager: Pairing failed!";
            qWarning() << "❌ Error:" << m_commandSet->lastError();
            qWarning() << "========================================";
            qWarning() << "💡 Possible causes:";
            qWarning() << "💡 1. Wrong pairing password (card was initialized with different password)";
            qWarning() << "💡 2. Card in unexpected state";
            qWarning() << "💡 3. Communication error";
            qWarning() << "========================================";
            m_lastError = m_commandSet->lastError();
            return false;
        }
        
        // Save pairing
        savePairing(m_appInfo.instanceUID.toHex(), m_pairingInfo);
        qDebug() << "SessionManager: Paired successfully";
    }
    
    // Open secure channel
    bool opened = m_commandSet->openSecureChannel(m_pairingInfo);
    if (!opened) {
        qWarning() << "SessionManager: Failed to open secure channel:" << m_commandSet->lastError();
        return false;
    }
    
    qDebug() << "SessionManager: Secure channel opened";
    return true;
}

void SessionManager::closeSecureChannel()
{
    // Secure channel automatically closes when card is removed
    m_pairingInfo = Keycard::PairingInfo();
}

bool SessionManager::savePairing(const QString& instanceUID, const Keycard::PairingInfo& pairingInfo)
{
    PairingStorage storage(m_storagePath);
    if (!storage.load()) {
        qWarning() << "SessionManager: Failed to load pairing storage:" << storage.lastError();
        // Continue anyway, we'll create new storage
    }
    
    if (!storage.storePairing(instanceUID, pairingInfo)) {
        qWarning() << "SessionManager: Failed to store pairing:" << storage.lastError();
        return false;
    }
    
    if (!storage.save()) {
        qWarning() << "SessionManager: Failed to save pairing storage:" << storage.lastError();
        return false;
    }
    
    return true;
}

Keycard::PairingInfo SessionManager::loadPairing(const QString& instanceUID)
{
    PairingStorage storage(m_storagePath);
    if (!storage.load()) {
        qDebug() << "SessionManager: No pairing storage found";
        return Keycard::PairingInfo();
    }
    
    if (!storage.hasPairing(instanceUID)) {
        qDebug() << "SessionManager: No pairing for" << instanceUID;
        return Keycard::PairingInfo();
    }
    
    return storage.loadPairing(instanceUID);
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
    
    // Build keycardStatus (if we're in Ready or Authorized state)
    if (m_state == SessionState::Ready || m_state == SessionState::Authorized) {
        try {
            auto appStatus = m_commandSet->getStatus();
            status.keycardStatus = new ApplicationStatus();
            status.keycardStatus->remainingAttemptsPIN = appStatus.pinRetryCount;
            status.keycardStatus->remainingAttemptsPUK = appStatus.pukRetryCount;
            status.keycardStatus->keyInitialized = appStatus.keyInitialized;
            status.keycardStatus->path = ""; // TODO: Get from card if available
        } catch (...) {
            // Ignore errors, keep null
        }
    }
    
    // Build metadata (if we have it)
    // TODO: Load metadata from card or cache
    
    return status;
}

// Card Operations

bool SessionManager::initialize(const QString& pin, const QString& puk, const QString& pairingPassword)
{
    if (m_state != SessionState::Ready) {
        setError("Card not ready (current state: " + currentStateString() + ")");
        return false;
    }
    
    QString password = pairingPassword.isEmpty() ? "KeycardDefaultPairing" : pairingPassword;
    Keycard::Secrets secrets(pin, puk, password);
    
    bool result = m_commandSet->init(secrets);
    if (!result) {
        setError(m_commandSet->lastError());
        return false;
    }
    
    qDebug() << "SessionManager: Card initialized";
    return true;
}

bool SessionManager::authorize(const QString& pin)
{
    if (m_state != SessionState::Ready) {
        setError("Card not ready (current state: " + currentStateString() + ")");
        return false;
    }
    
    bool result = m_commandSet->verifyPIN(pin);
    if (!result) {
        setError(m_commandSet->lastError());
        int remaining = m_commandSet->remainingPINAttempts();
        if (remaining >= 0) {
            setError(QString("Wrong PIN (%1 attempts remaining)").arg(remaining));
        }
        return false;
    }
    
    m_authorized = true;
    setState(SessionState::Authorized);
    qDebug() << "SessionManager: Authorized";
    return true;
}

bool SessionManager::changePIN(const QString& newPIN)
{
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
    return true;
}

bool SessionManager::changePUK(const QString& newPUK)
{
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
    return true;
}

bool SessionManager::unblockPIN(const QString& puk, const QString& newPIN)
{
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
    return true;
}

// Key Operations

QVector<int> SessionManager::generateMnemonic(int length)
{
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
    
    return indexes;
}

QString SessionManager::loadMnemonic(const QString& mnemonic, const QString& passphrase)
{
    if (m_state != SessionState::Authorized) {
        setError("Not authorized");
        return QString();
    }
    
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
    
#ifdef KEYCARD_QT_HAS_OPENSSL
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
#else
    // Fallback: Use Qt's password-based key derivation (not BIP39 compliant but better than nothing)
    setError("OpenSSL not available - BIP39 seed derivation requires OpenSSL");
    return QString();
#endif
    
    // Load seed onto keycard
    qDebug() << "SessionManager: Loading seed onto keycard (" << seed.size() << " bytes)";
    QByteArray keyUID = m_commandSet->loadSeed(seed);
    
    if (keyUID.isEmpty()) {
        setError(QString("Failed to load seed: %1").arg(m_commandSet->lastError()));
        return QString();
    }
    
    qDebug() << "SessionManager: Seed loaded successfully, keyUID:" << keyUID.toHex();
    return QString("0x") + keyUID.toHex();
}

bool SessionManager::factoryReset()
{
    if (m_state != SessionState::Ready && m_state != SessionState::Authorized) {
        setError("Card not ready");
        return false;
    }
    
    bool result = m_commandSet->factoryReset();
    if (!result) {
        setError(m_commandSet->lastError());
        return false;
    }
    
    // After factory reset, we're back to Ready state
    m_authorized = false;
    setState(SessionState::Ready);
    
    qDebug() << "SessionManager: Factory reset complete";
    return true;
}

// Metadata Operations
// NOTE: Implementations moved to after helper functions (line ~945+)
// to avoid forward declaration errors

// Key Export

// Paths matching status-keycard-go/internal/const.go
static const QString PATH_MASTER = "m";
static const QString PATH_WALLET_ROOT = "m/44'/60'/0'/0";
static const QString PATH_WALLET = "m/44'/60'/0'/0/0";
static const QString PATH_EIP1581 = "m/43'/60'/1581'";
static const QString PATH_WHISPER = "m/43'/60'/1581'/0'/0";
static const QString PATH_ENCRYPTION = "m/43'/60'/1581'/1'/0";

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
#ifdef KEYCARD_QT_HAS_OPENSSL
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
#else
    Q_UNUSED(privKey);
    qWarning() << "derivePublicKeyFromPrivate: OpenSSL not available";
    return QByteArray();
#endif
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
    
    LoginKeys keys;
    
    if (m_state != SessionState::Authorized) {
        setError("Not authorized");
        return keys;
    }
    
    if (!m_commandSet) {
        setError("No command set available");
        return keys;
    }
    
    qDebug() << "SessionManager: Exporting login keys";
    
    // Export whisper private key
    qDebug() << "SessionManager: Exporting whisper key from path:" << PATH_WHISPER;
    QByteArray whisperData = m_commandSet->exportKey(true, false, PATH_WHISPER, Keycard::APDU::P2ExportKeyPrivateAndPublic);
    if (whisperData.isEmpty()) {
        setError(QString("Failed to export whisper key: %1").arg(m_commandSet->lastError()));
        return keys;
    }
    qDebug() << "SessionManager: Whisper key data size:" << whisperData.size();
    keys.whisperPrivateKey = parseExportedKey(whisperData);

    // Export encryption private key
    qDebug() << "SessionManager: Exporting encryption key from path:" << PATH_ENCRYPTION;
    QByteArray encryptionData = m_commandSet->exportKey(true, false, PATH_ENCRYPTION, Keycard::APDU::P2ExportKeyPrivateAndPublic);
    if (encryptionData.isEmpty()) {
        setError(QString("Failed to export encryption key: %1").arg(m_commandSet->lastError()));
        return keys;
    }
    qDebug() << "SessionManager: Encryption key data size:" << encryptionData.size();
    keys.encryptionPrivateKey = parseExportedKey(encryptionData);
    
    qDebug() << "SessionManager: Login keys exported successfully";
    return keys;
}

SessionManager::RecoverKeys SessionManager::exportRecoverKeys()
{
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
        return keys;
    }
    keys.walletRootKey = parseExportedKey(walletRootData);
    
    // Export wallet key (public only)
    QByteArray walletData = m_commandSet->exportKey(true, false, PATH_WALLET);
    if (walletData.isEmpty()) {
        setError(QString("Failed to export wallet key: %1").arg(m_commandSet->lastError()));
        return keys;
    }
    keys.walletKey = parseExportedKey(walletData);
    
    // Export master key (public only, makeCurrent=true for compatibility)
    QByteArray masterData = m_commandSet->exportKey(true, true, PATH_MASTER);
    if (masterData.isEmpty()) {
        setError(QString("Failed to export master key: %1").arg(m_commandSet->lastError()));
        return keys;
    }
    keys.masterKey = parseExportedKey(masterData);
    
    qDebug() << "SessionManager: Recover keys exported successfully";
    return keys;
}

// Metadata Operations Implementation
// These are defined here (after helper functions) to avoid forward declaration issues

SessionManager::Metadata SessionManager::getMetadata()
{
    Metadata metadata;
    
    if (m_state != SessionState::Ready && m_state != SessionState::Authorized) {
        setError("Card not ready");
        return metadata;
    }
    
    if (!m_commandSet) {
        setError("No command set available");
        return metadata;
    }
    
    // Get metadata from card (NDEF data type 0x04)
    qDebug() << "SessionManager: Getting metadata from card";
    QByteArray metadataData = m_commandSet->getData(0x04);  // 0x04 = NDEF data type
    
    if (metadataData.isEmpty()) {
        // Not an error - card might not have metadata yet
        qDebug() << "SessionManager: No metadata on card";
        return metadata;
    }
    
    // Parse metadata TLV format (matching Go implementation)
    // Format: TLV with tag 0xA1 containing:
    //   - 0x80: Name (optional)
    //   - 0x81: Wallet paths array
    
    QByteArray template_ = findTlvTag(metadataData, 0xA1);
    if (template_.isEmpty()) {
        qWarning() << "Failed to find metadata template tag 0xA1";
        return metadata;
    }
    
    // Parse name
    QByteArray nameData = findTlvTag(template_, 0x80);
    if (!nameData.isEmpty()) {
        metadata.name = QString::fromUtf8(nameData);
    }
    
    // Parse wallet paths
    QByteArray walletsData = findTlvTag(template_, 0x81);
    if (!walletsData.isEmpty()) {
        // Each wallet is 4 bytes (uint32 last component of path)
        int offset = 0;
        while (offset + 4 <= walletsData.size()) {
            uint32_t pathComponent = (static_cast<uint32_t>(static_cast<uint8_t>(walletsData[offset])) << 24) |
                                     (static_cast<uint32_t>(static_cast<uint8_t>(walletsData[offset + 1])) << 16) |
                                     (static_cast<uint32_t>(static_cast<uint8_t>(walletsData[offset + 2])) << 8) |
                                     (static_cast<uint32_t>(static_cast<uint8_t>(walletsData[offset + 3])));
            
            // Derive wallet at PATH_WALLET_ROOT / pathComponent
            QString walletPath = PATH_WALLET_ROOT + QString("/%1").arg(pathComponent);
            
            // Export public key for this path
            QByteArray keyData = m_commandSet->exportKey(true, false, walletPath);
            if (!keyData.isEmpty()) {
                KeyPair kp = parseExportedKey(keyData);
                Wallet wallet;
                wallet.path = walletPath;
                wallet.address = kp.address;
                wallet.publicKey = kp.publicKey;
                metadata.wallets.append(wallet);
            }
            
            offset += 4;
        }
    }
    
    qDebug() << "SessionManager: Metadata retrieved - name:" << metadata.name
             << "wallets:" << metadata.wallets.size();
    return metadata;
}

bool SessionManager::storeMetadata(const QString& name, const QStringList& paths)
{
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
    
    // Build metadata TLV
    // Format: 0xA1 { 0x80: name, 0x81: paths_array }
    
    QByteArray nameBytes = name.toUtf8();
    QByteArray nameTlv;
    QByteArray pathsTlv;
    QByteArray metadataTlv;
    
    // Manually encode TLV (since Utils::encodeTLV might not be available)
    // Tag 0x80 (name)
    nameTlv.append(static_cast<char>(0x80));
    if (nameBytes.size() < 128) {
        nameTlv.append(static_cast<char>(nameBytes.size()));
    } else {
        nameTlv.append(static_cast<char>(0x81));  // 1 byte length
        nameTlv.append(static_cast<char>(nameBytes.size()));
    }
    nameTlv.append(nameBytes);
    
    // Encode path components as 4-byte big-endian integers
    QByteArray pathsBytes;
    for (uint32_t component : pathComponents) {
        pathsBytes.append(static_cast<char>((component >> 24) & 0xFF));
        pathsBytes.append(static_cast<char>((component >> 16) & 0xFF));
        pathsBytes.append(static_cast<char>((component >> 8) & 0xFF));
        pathsBytes.append(static_cast<char>(component & 0xFF));
    }
    
    // Tag 0x81 (paths)
    pathsTlv.append(static_cast<char>(0x81));
    if (pathsBytes.size() < 128) {
        pathsTlv.append(static_cast<char>(pathsBytes.size()));
    } else {
        pathsTlv.append(static_cast<char>(0x81));  // 1 byte length
        pathsTlv.append(static_cast<char>(pathsBytes.size()));
    }
    pathsTlv.append(pathsBytes);
    
    // Tag 0xA1 (template)
    QByteArray metadataContent = nameTlv + pathsTlv;
    metadataTlv.append(static_cast<char>(0xA1));
    if (metadataContent.size() < 128) {
        metadataTlv.append(static_cast<char>(metadataContent.size()));
    } else {
        metadataTlv.append(static_cast<char>(0x81));  // 1 byte length
        metadataTlv.append(static_cast<char>(metadataContent.size()));
    }
    metadataTlv.append(metadataContent);
    
    // Store metadata on card (public data type 0x04)
    bool success = m_commandSet->storeData(0x04, metadataTlv);  // 0x04 = public NDEF data
    if (!success) {
        setError(QString("Failed to store metadata: %1").arg(m_commandSet->lastError()));
        return false;
    }
    
    qDebug() << "SessionManager: Metadata stored successfully";
    return true;
}

} // namespace StatusKeycard

