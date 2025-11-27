#include "session_manager.h"
#include "storage/pairing_storage.h"
#include "storage/file_pairing_storage.h"
#include "signal_manager.h"
#include <keycard-qt/types.h>
#include <keycard-qt/backends/keycard_channel_qt_nfc.h>
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
}

SessionManager::~SessionManager()
{
    stop();
}

void SessionManager::operationCompleted()
{
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
    m_channel = m_commandSet->channel();
    if (!m_channel) {
        qWarning() << "SessionManager: No channel set";
        return;
    }

    m_channel->startDetection();

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
        m_channel->startDetection();
    }

    m_started = true;

    return true;
}

void SessionManager::stop()
{
    if (!m_started) {
        return;
    }

    // CRITICAL: Lock operation mutex to prevent race with background openSecureChannel()
    // If a background thread is running openSecureChannel() and we destroy m_channel/m_commandSet,
    // the background thread will crash when accessing these objects.
    // The mutex ensures we wait for any in-flight operations to complete before destroying.
    qDebug() << "SessionManager::stop(): Acquiring lock to safely destroy channel/commandSet";
    {
        QMutexLocker locker(&m_operationMutex);
        qDebug() << "SessionManager::stop(): Lock acquired, safe to destroy";
        
        if (m_channel) {
            // KeycardChannel is in main thread, direct calls are safe
            // Explicitly transition to Idle to close iOS NFC drawer
            m_channel->setState(Keycard::ChannelState::Idle);
            m_channel->disconnect();
        }
    }
    qDebug() << "SessionManager::stop(): Channel and CommandSet destroyed safely";
    
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
    
    // Emit Qt signal - c_api.cpp will forward to SignalManager
    emit stateChanged(newState, oldState);
}

void SessionManager::onReaderAvailabilityChanged(bool available)
{
    qDebug() << "SessionManager: Reader availability changed:" << (available ? "available" : "not available");
    
    if (available) {
        // CRITICAL: Only reset connection if we're in an initial state
        // If we're already connected (Ready/Authorized/ConnectingCard), DON'T destroy CommandSet!
        // iOS auto-resume temporarily stops/starts detection, which would destroy active CommandSet
        if (m_state == SessionState::UnknownReaderState || m_state == SessionState::WaitingForReader) {
            // Initial state - safe to reset any stale connection
            if (m_commandSet || m_channel->isConnected()) {
                qDebug() << "SessionManager: Clearing stale card connection (initial state, reader availability changed)";
                closeSecureChannel();
            }
            
            // Transition to WaitingForCard
            // This matches Go's connectCard() line 252: kc.status.Reset(WaitingForCard)
            setState(SessionState::WaitingForCard);
            
            // iOS: Open NFC drawer for initial login flow
            // When user is at Login screen and selects "Login with Keycard", show the drawer
            // This is the ONLY place where we automatically open the drawer for Session API
            qDebug() << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
            qDebug() << "SessionManager: Opening NFC drawer for initial Login flow";
            qDebug() << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
            m_channel->setState(Keycard::ChannelState::WaitingForCard);
            // This allows user to enter PIN, etc. before showing iOS NFC drawer
        } else {
            // Already connected or in progress - ignore this signal
            // This happens during iOS auto-resume when detection is restarted temporarily
            qDebug() << "SessionManager: Reader availability signal ignored (already connected, current state:" << currentStateString() << ")";
        }
    } else {
        // No readers present - clear any connection and transition to WaitingForReader
        // This matches Go's connectCard() line 242: kc.status.Reset(WaitingForReader)
        if (m_commandSet || m_channel->isConnected()) {
            qDebug() << "SessionManager: Clearing card connection (no readers)";
            closeSecureChannel();
        }
        
        if (m_state == SessionState::UnknownReaderState || m_state == SessionState::WaitingForCard) {
            setState(SessionState::WaitingForReader);
        }
    }
}

void SessionManager::onCardDetected(const QString& uid)
{
    qDebug() << "========================================";
    qDebug() << "🎴 SessionManager: CARD DETECTED! UID:" << uid;
    qDebug() << "🎴   Thread:" << QThread::currentThread();
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
    
    emit cardDetected(uid);
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
        
        qDebug() << "SessionManager: Selected applet, InstanceUID:" << m_appInfo.instanceUID.toHex();
        qDebug() << "SessionManager: Card initialized:" << m_appInfo.initialized;
        qDebug() << "SessionManager: Available slots:" << m_appInfo.availableSlots;
        
        // Marshal back to main thread for state updates
        QMetaObject::invokeMethod(this, [this]() {
            // Check if card is initialized
            if (!m_appInfo.initialized) {
                qDebug() << "SessionManager: Card is empty (not initialized)";
                setState(SessionState::EmptyKeycard);
            } else {
                // Check if card has no available pairing slots
                setState(SessionState::Ready);
            }
            
            // iOS: Close NFC drawer now that we've read the card data
            // User can now see card info and decide what to do (pair, factory reset, etc.)
            qDebug() << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
            qDebug() << "SessionManager: Card data read successfully (metadata available without pairing)";
            qDebug() << "SessionManager: Closing NFC drawer + stopping detection (iOS)";
            qDebug() << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
            if (m_channel) {
                // Transition to Idle - on iOS this automatically stops NFC session and detection
                m_channel->setState(Keycard::ChannelState::Idle);
            }
        }, Qt::QueuedConnection);
    });
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
        
        // Note: iOS NFC session will restart automatically on next transmit()
        // No need to manually restart here
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

// bool SessionManager::openSecureChannel()
// {
//     // CRITICAL: Serialize card operations to prevent concurrent APDU corruption
//     QMutexLocker locker(&m_operationMutex);
    
//     // CRITICAL FIX: Always recreate CommandSet before opening secure channel
//     // This ensures fresh SecureChannel state regardless of:
//     // 1. Card inserted after startup (CommandSet sat idle)
//     // 2. Card removed and reinserted (stale session state)
//     // 3. Previous failed attempts (corrupted state)
//     if (m_channel) {
//         qDebug() << "SessionManager: Creating fresh CommandSet with dependency injection for new secure channel session";
//         m_commandSet = std::make_unique<Keycard::CommandSet>(
//             m_channel.get(),
//             m_pairingStorage.get(),
//             [this](const QString& cardUID) { return getPairingPassword(cardUID); }
//         );
//     }
    
//     if (!m_commandSet) {
//         qWarning() << "SessionManager: No command set available";
//         return false;
//     }
    
//     // Select applet
//     m_appInfo = m_commandSet->select();
//     // Check if select succeeded: initialized cards have instanceUID, pre-initialized cards have secureChannelPublicKey
//     if (m_appInfo.instanceUID.isEmpty() && m_appInfo.secureChannelPublicKey.isEmpty()) {
//         qWarning() << "SessionManager: Failed to select applet";
//         return false;
//     }
    
//     qDebug() << "SessionManager: Selected applet, InstanceUID:" << m_appInfo.instanceUID.toHex();
//     qDebug() << "SessionManager: Card initialized:" << m_appInfo.initialized;
//     qDebug() << "SessionManager: Card installed:" << m_appInfo.installed;
//     qDebug() << "SessionManager: App version:" << QString("%1.%2").arg(m_appInfo.appVersion).arg(m_appInfo.appVersionMinor);
//     qDebug() << "SessionManager: Available slots:" << m_appInfo.availableSlots;
//     qDebug() << "SessionManager: Key UID:" << m_appInfo.keyUID.toHex();
    
//     // Check if card needs initialization
//     if (!m_appInfo.initialized) {
//         qWarning() << "========================================";
//         qWarning() << "⚠️  SessionManager: CARD NOT INITIALIZED";
//         qWarning() << "⚠️  Card detected but needs initialization before use";
//         qWarning() << "========================================";
//         qWarning() << "💡 Use Init flow to initialize the card";
//         qWarning() << "💡 Call KeycardInitialize.init(PIN, PUK, PairingPassword)";
//         qWarning() << "========================================";
//         // Return true to allow Init flow to proceed - this is not an error
//         return true;
//     }
    
//     // CommandSet now handles pairing and secure channel automatically via dependency injection
//     // No need for manual pairing loading/injection - it's all handled transparently
//     qDebug() << "SessionManager: Card initialized, pairing will be handled automatically by CommandSet";
    
//     // CRITICAL: Initialize card state after opening secure channel
//     // This matches status-keycard-go's connectKeycard() flow (line 420-437)
//     // The card expects a GET_STATUS command after opening secure channel to properly
//     // initialize internal state. Without this, subsequent commands like VERIFY_PIN
//     // may fail with unexpected errors (0x6F05, 0x6985, etc.)
//     qDebug() << "SessionManager: Fetching application status to initialize card state";
//     m_appStatus = m_commandSet->getStatus(Keycard::APDU::P1GetStatusApplication);
//     if (m_appStatus.pinRetryCount < 0) {
//         qWarning() << "SessionManager: Failed to get application status:" << m_commandSet->lastError();
//         qWarning() << "SessionManager: Continuing anyway, but card operations may fail";
//         // Don't return false - this is initialization, not critical
//     } else {
//         qDebug() << "SessionManager: Application status fetched successfully";
//         qDebug() << "  PIN retry count:" << m_appStatus.pinRetryCount;
//         qDebug() << "  PUK retry count:" << m_appStatus.pukRetryCount;
//         qDebug() << "  Key initialized:" << m_appStatus.keyInitialized;
//     }
    
//     // Fetch metadata proactively (matches status-keycard-go line 432: updateMetadata())
//     // Metadata contains wallet account addresses, names, and derivation paths
//     // This is done during connection so the app has account info available immediately
//     qDebug() << "SessionManager: Fetching metadata from card";
//     try {
//         Metadata metadata = getMetadata();
//         if (!metadata.wallets.isEmpty()) {
//             qDebug() << "SessionManager: Loaded metadata with" << metadata.wallets.size() << "wallet(s)";
//             qDebug() << "  Name:" << metadata.name;
//             for (const auto& wallet : metadata.wallets) {
//                 qDebug() << "    Wallet address:" << wallet.address;
//             }
//         } else {
//             qDebug() << "SessionManager: No metadata found on card (empty or not set)";
//         }
//     } catch (...) {
//         qWarning() << "SessionManager: Failed to fetch metadata, continuing anyway";
//         // Don't fail connection if metadata fetch fails - it's not critical
//         // Metadata can be fetched later on-demand
//     }
    
//     // CRITICAL: Clear any error from metadata fetch
//     // getMetadata() may set an error if called before state transition completes,
//     // but we don't want that error to affect subsequent operations
//     m_lastError.clear();
    
//     return true;
// }

void SessionManager::closeSecureChannel()
{
    // CRITICAL: Lock to prevent race with background openSecureChannel()
    // If openSecureChannel() is creating a new CommandSet while we're destroying it,
    // we could have a use-after-free or double-delete
    QMutexLocker locker(&m_operationMutex);
    
    // CRITICAL: Check if command set exists before accessing
    if (m_commandSet) {
        m_commandSet->resetSecureChannel();
        qDebug() << "SessionManager: Secure channel closed, crypto state reset";
    } else {
        qDebug() << "SessionManager: Secure channel already closed (no CommandSet)";
    }
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
    
    // Build metadata (if we have it)
    // TODO: Load metadata from card or cache
    
    return status;
}

// Card Operations

bool SessionManager::initialize(const QString& pin, const QString& puk, const QString& pairingPassword)
{
    qDebug() << "SessionManager::initialize()";
    QMutexLocker locker(&m_operationMutex);

    if (m_state != SessionState::Ready && m_state != SessionState::EmptyKeycard) {
        setError("Card not ready for initialization (current state: " + currentStateString() + ")");
        return false;
    }
    
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
    
    qDebug() << "SessionManager: Card initialized successfully";
    
    // After initialization, card has new credentials (PIN, PUK, pairing)
    // Current connection is no longer valid - must reset and re-detect card
    // This matches status-keycard-go: resetCardConnection() + forceScan()
    qDebug() << "SessionManager: Resetting connection to establish pairing and secure channel";
    
    closeSecureChannel();
    
    // CRITICAL: After INIT command, card is in a session state that blocks pairing
    // MUST physically disconnect and reconnect to reset card session state
    // This matches status-keycard-go: resetCardConnection() + forceScan()
    // On Android: disconnect() stops reader mode, forceScan() restarts it -> fresh IsoDep session
    // On iOS/PCSC: disconnect() closes connection, forceScan() triggers re-detection
    qDebug() << "SessionManager: Disconnecting and forcing card re-scan (all platforms)";
    m_currentCardUID.clear();
    m_authorized = false;
    m_channel->disconnect();
    m_channel->forceScan();
    
    operationCompleted();

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
    
    // // CRITICAL: Update application status after PIN verification
    // // This matches status-keycard-go's onAuthorizeInteractions() (line 614-622)
    // // After successful PIN verification, card's internal state changes
    // // GET_STATUS synchronizes this state with the client
    // qDebug() << "SessionManager: PIN verified successfully, updating application status";
    // m_appStatus = m_commandSet->getStatus(Keycard::APDU::P1GetStatusApplication);
    if (m_appStatus.pinRetryCount >= 0) {
        qDebug() << "SessionManager: Application status updated after authorization";
        qDebug() << "  PIN retry count:" << m_appStatus.pinRetryCount;
        qDebug() << "  PUK retry count:" << m_appStatus.pukRetryCount;
        qDebug() << "  Key initialized:" << m_appStatus.keyInitialized;
    } else {
        qWarning() << "SessionManager: Failed to update application status after PIN verification";
        qWarning() << "SessionManager: This may cause subsequent operations to fail";
    }
    
    m_authorized = true;
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

    if (m_state != SessionState::Ready && m_state != SessionState::Authorized) {
        setError("Card not ready");
        return false;
    }
    
    bool result = m_commandSet->factoryReset();
    if (!result) {
        setError(m_commandSet->lastError());
        return false;
    }
    
    qDebug() << "SessionManager: Factory reset complete";

    closeSecureChannel();

    m_currentCardUID.clear();
    m_authorized = false;
    m_channel->disconnect();
    m_channel->forceScan();

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
    
    qDebug() << "SessionManager: Exporting login keys";
    
    // Export whisper private key
    // CRITICAL: Use makeCurrent=true for the FIRST export after opening secure channel!
    // The keycard has an internal "current key" pointer that must be set before derivation.
    // After opening a secure channel, this pointer is unset. The first exportKey call
    // with makeCurrent=true will set it, allowing subsequent exports to work.
    qDebug() << "SessionManager: Exporting whisper key from path:" << PATH_WHISPER;
    QByteArray whisperData = m_commandSet->exportKey(true, true, PATH_WHISPER, Keycard::APDU::P2ExportKeyPrivateAndPublic);
    if (whisperData.isEmpty()) {
        setError(QString("Failed to export whisper key: %1").arg(m_commandSet->lastError()));
        // CRITICAL: Close drawer even on error (iOS)
        m_channel->setState(Keycard::ChannelState::Idle);
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
        // CRITICAL: Close drawer even on error (iOS)
        m_channel->setState(Keycard::ChannelState::Idle);
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
        // CRITICAL: Close drawer even on error (iOS)
        m_channel->setState(Keycard::ChannelState::Idle);
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
        // CRITICAL: Close drawer even on error (iOS)
        m_channel->setState(Keycard::ChannelState::Idle);
        return keys;
    }
    keys.walletRootKey = parseExportedKey(walletRootData);
    
    // Export wallet key (public only)
    QByteArray walletData = m_commandSet->exportKey(true, false, PATH_WALLET);
    if (walletData.isEmpty()) {
        setError(QString("Failed to export wallet key: %1").arg(m_commandSet->lastError()));
        // CRITICAL: Close drawer even on error (iOS)
        m_channel->setState(Keycard::ChannelState::Idle);
        return keys;
    }
    keys.walletKey = parseExportedKey(walletData);
    
    // Export master key (public only, makeCurrent=true for compatibility)
    QByteArray masterData = m_commandSet->exportKey(true, true, PATH_MASTER);
    if (masterData.isEmpty()) {
        setError(QString("Failed to export master key: %1").arg(m_commandSet->lastError()));
        // CRITICAL: Close drawer even on error (iOS)
        m_channel->setState(Keycard::ChannelState::Idle);
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
    
    if (m_state != SessionState::Ready && m_state != SessionState::Authorized) {
        setError("Card not ready");
        return metadata;
    }
    
    if (!m_commandSet) {
        setError("No command set available");
        return metadata;
    }
    
    // Get metadata from card (public data type)
    // Use P1StoreDataPublic (0x00) to match what we used in storeData
    qDebug() << "SessionManager: Getting metadata from card";
    QByteArray metadataData = m_commandSet->getData(Keycard::APDU::P1StoreDataPublic);  // 0x00 = P1StoreDataPublic
    
    if (metadataData.isEmpty()) {
        // Not an error - card might not have metadata yet
        qDebug() << "SessionManager: No metadata on card";
        operationCompleted();
        return metadata;
    }
    
    // Parse metadata TLV format (matching Go implementation)
    // Format: TLV with tag 0xA1 containing:
    //   - 0x80: Name (optional)
    //   - 0x81: Wallet paths array
    
    QByteArray template_ = findTlvTag(metadataData, 0xA1);
    if (template_.isEmpty()) {
        qWarning() << "Failed to find metadata template tag 0xA1";
        operationCompleted();
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
    
    operationCompleted();

    return true;
}

} // namespace StatusKeycard

