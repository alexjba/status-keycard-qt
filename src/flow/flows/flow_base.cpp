#include "flow_base.h"
#include "../flow_manager.h"
#include "../flow_signals.h"
#include "../../storage/pairing_storage.h"
#include <keycard-qt/keycard_channel.h>
#include <QDebug>
#include <QThread>

namespace StatusKeycard {

FlowBase::FlowBase(FlowManager* manager, FlowType type, const QJsonObject& params, QObject* parent)
    : QObject(parent)
    , m_manager(manager)
    , m_flowType(type)
    , m_params(params)
    , m_paused(false)
    , m_cancelled(false)
    , m_shouldRestart(false)
    , m_commandSet(nullptr)
{
    qDebug() << "FlowBase: Created flow type:" << static_cast<int>(type);
}

FlowBase::~FlowBase()
{
    qDebug() << "FlowBase: Destroyed flow type:" << static_cast<int>(m_flowType);
}

void FlowBase::resume(const QJsonObject& newParams)
{
    qDebug() << "FlowBase: Resuming flow with new params";
    
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
    qDebug() << "FlowBase: Cancelling flow";
    
    QMutexLocker locker(&m_resumeMutex);
    m_cancelled = true;
    m_resumeCondition.wakeAll();
}

// ============================================================================
// Access to manager resources
// ============================================================================

Keycard::KeycardChannel* FlowBase::channel()
{
    return m_manager->channel();
}

PairingStorage* FlowBase::storage()
{
    return m_manager->storage();
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
    qDebug() << "FlowBase: Pausing flow, action:" << action << "error:" << error;
    
    // Build event with error and status
    QJsonObject event = status;
    event[FlowParams::ERROR_KEY] = error;
    
    // Add card info if available
    if (m_cardInfo.freeSlots >= 0) {
        event[FlowParams::INSTANCE_UID] = m_cardInfo.instanceUID;
        event[FlowParams::KEY_UID] = m_cardInfo.keyUID;
        event[FlowParams::FREE_SLOTS] = m_cardInfo.freeSlots;
    }
    
    if (m_cardInfo.pinRetries >= 0) {
        event[FlowParams::PIN_RETRIES] = m_cardInfo.pinRetries;
        event[FlowParams::PUK_RETRIES] = m_cardInfo.pukRetries;
    }
    
    // Emit pause signal
    emit flowPaused(action, event);
    
    // Wait for resume or cancel
    QMutexLocker locker(&m_resumeMutex);
    m_paused = true;
    
    while (m_paused && !m_cancelled) {
        m_resumeCondition.wait(&m_resumeMutex);
    }
    
    qDebug() << "FlowBase: Flow resumed, cancelled:" << m_cancelled;
}

void FlowBase::pauseAndRestart(const QString& action, const QString& error)
{
    qDebug() << "FlowBase: Pausing and requesting restart";
    m_shouldRestart = true;
    pauseAndWait(action, error);
}

void FlowBase::resetCardInfo()
{
    m_cardInfo = CardInfo();  // Reset to default values
    m_cardInfo.freeSlots = -1;
    m_cardInfo.pinRetries = -1;
    m_cardInfo.pukRetries = -1;
    m_cardInfo.version = -1;
}

// ============================================================================
// Card operations
// ============================================================================

bool FlowBase::waitForCard()
{
    qDebug() << "FlowBase: Waiting for card...";
    
    // Check if cancelled before accessing manager resources
    if (m_cancelled) {
        qDebug() << "FlowBase: Cancelled before card check";
        return false;
    }
    
    // Check if card already present at flow start
    // If so, don't emit card-inserted (matching Go behavior)
    if (channel()->isConnected()) {
        qDebug() << "FlowBase: Card already connected";
        return true;
    }
    
    // Wait 150ms for card (matching Go: time.NewTimer(150 * time.Millisecond))
    qDebug() << "FlowBase: Waiting 150ms for card...";
    QThread::msleep(150);
    
    // Check if cancelled during sleep (BEFORE accessing manager resources)
    if (m_cancelled) {
        qDebug() << "FlowBase: Cancelled during card wait";
        return false;
    }
    
    // Check again after wait
    if (channel()->isConnected()) {
        qDebug() << "FlowBase: Card detected after 150ms wait";
        return true;
    }
    
    // Loop until card detected (matching Go's connect() pattern)
    while (true) {
        // Still no card after 150ms - pause and wait for user
        qDebug() << "FlowBase: No card after 150ms, pausing...";
        pauseAndWait(FlowSignals::INSERT_CARD, "connection-error");
        
        if (m_cancelled) {
            qDebug() << "FlowBase: Cancelled while waiting for card";
            return false;
        }
        
        // After resume, check if card is now present
        if (channel()->isConnected()) {
            qDebug() << "FlowBase: Card inserted after pause";
            // ONLY emit card-inserted if we were paused (matching Go behavior!)
            FlowSignals::emitCardInserted();
            return true;
        }
        
        // User resumed - check for card again (loop back)
        qDebug() << "FlowBase: Resumed, checking for card again...";
    }
}

bool FlowBase::selectKeycard()
{
    qDebug() << "FlowBase: Selecting keycard applet...";
    
    // Make sure we have a card
    if (!channel()->isConnected()) {
        qWarning() << "FlowBase: No card connection!";
        if (!waitForCard()) {
            return false;
        }
    }
    
    // Create CommandSet if needed
    // Use FlowManager's persistent CommandSet (maintains secure channel across flows)
    if (!m_commandSet) {
        m_commandSet = m_manager->commandSet();
        if (!m_commandSet) {
            qCritical() << "FlowBase: FlowManager CommandSet not initialized!";
            emit flowError("Internal error: CommandSet not initialized");
            return false;
        }
    }
    
    // Select keycard applet
    Keycard::ApplicationInfo appInfo = m_commandSet->select();
    if (!appInfo.installed) {
        qCritical() << "FlowBase: Keycard applet not installed!";
        emit flowError("Keycard applet not installed");
        return false;
    }
    
    // Update card info
    updateCardInfo(appInfo);
    
    qDebug() << "FlowBase: Keycard selected. InstanceUID:" << m_cardInfo.instanceUID
             << "KeyUID:" << m_cardInfo.keyUID;
    
    return true;
}

bool FlowBase::openSecureChannelAndAuthenticate(bool authenticate)
{
    qDebug() << "FlowBase: Opening secure channel, authenticate:" << authenticate;
    
    // Try to find pairing for this card
    Keycard::PairingInfo pairing = storage()->loadPairing(m_cardInfo.instanceUID);
    
    if (!pairing.isValid()) {
        qDebug() << "FlowBase: No pairing found, attempting to pair";
        
        // Try default pairing password first (matching status-keycard-go behavior)
        QString pairingPassword = "KeycardDefaultPairing";
        qDebug() << "FlowBase: Trying default pairing password:" << pairingPassword;
        
        Keycard::PairingInfo pairingInfo = m_commandSet->pair(pairingPassword);
        
        // If default pairing fails, check why
        if (!pairingInfo.isValid()) {
            QString error = m_commandSet->lastError();
            qDebug() << "FlowBase: Default pairing failed, error:" << error;
            
            // Check if failure is due to no available pairing slots
            if (error.contains("No available slots") || error.contains("6a84")) {
                qCritical() << "FlowBase: Card has no available pairing slots!";
                qCritical() << "FlowBase: Cannot pair with this card - all slots full";
                emit flowError("No available pairing slots");
                return false;
            }
            
            // Otherwise, ask user for custom pairing password
            qDebug() << "FlowBase: Requesting user to provide pairing password";
            
            // Request pairing password from user
            pauseAndWait(FlowSignals::ENTER_PAIRING, "enter-pairing");
            
            if (m_cancelled) {
                return false;
            }
            
            // Get pairing password from params
            pairingPassword = m_params[FlowParams::PAIRING_PASS].toString();
            if (pairingPassword.isEmpty()) {
                qCritical() << "FlowBase: No pairing password provided!";
                emit flowError("No pairing password provided");
                return false;
            }
            
            // Try pairing with user-provided password
            qDebug() << "FlowBase: Trying user-provided pairing password";
            pairingInfo = m_commandSet->pair(pairingPassword);
            if (!pairingInfo.isValid()) {
                qCritical() << "FlowBase: Pairing failed with user password!";
                emit flowError("Pairing failed");
                return false;
            }
        }
        
        qDebug() << "FlowBase: Pairing successful!";
        
        // Save pairing to memory and persist to disk
        storage()->storePairing(m_cardInfo.instanceUID, pairingInfo);
        if (!storage()->save()) {
            qWarning() << "FlowBase: Failed to persist pairing to disk:" << storage()->lastError();
            qWarning() << "FlowBase: Pairing will be lost on restart!";
        } else {
            qDebug() << "FlowBase: Pairing saved to disk";
        }
        pairing = pairingInfo;
        
        qDebug() << "FlowBase: Paired successfully";
    }
    
    // Open secure channel
    bool opened = m_commandSet->openSecureChannel(pairing);
    
    if (!opened) {
        qCritical() << "FlowBase: Failed to open secure channel!";
        emit flowError("Failed to open secure channel");
        return false;
    }
    
    qDebug() << "FlowBase: Secure channel opened";
    
    // Authenticate if requested
    if (authenticate) {
        return verifyPIN();
    }
    
    return true;
}

bool FlowBase::verifyPIN()
{
    qDebug() << "FlowBase: Verifying PIN...";
    
    // Check if PIN already in params
    QString pin = m_params[FlowParams::PIN].toString();
    
    if (pin.isEmpty()) {
        // Request PIN
        pauseAndWait(FlowSignals::ENTER_PIN, "enter-pin");
        
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
    auto response = m_commandSet->verifyPIN(pin);
    if (!response) {
        qCritical() << "FlowBase: PIN verification failed!";
        
        // Update retry count
        m_cardInfo.pinRetries--;
        
        if (m_cardInfo.pinRetries <= 0) {
            emit flowError("PIN blocked");
            return false;
        }
        
        // Wrong PIN, ask again
        pauseAndWait(FlowSignals::ENTER_PIN, "wrong-pin");
        
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
    if (!m_cardInfo.keyUID.isEmpty()) {
        qDebug() << "FlowBase: Card has keys";
        return true;
    }
    
    qWarning() << "FlowBase: Card has no keys!";
    
    // Build card info
    QJsonObject cardInfo = buildCardInfoJson();
    
    // Request card swap
    pauseAndRestart(FlowSignals::SWAP_CARD, "no-keys");
    
    // If we get here and not cancelled, restart was requested
    return false; // Will restart flow
}

bool FlowBase::requireNoKeys()
{
    if (m_cardInfo.keyUID.isEmpty()) {
        qDebug() << "FlowBase: Card has no keys (as required)";
        return true;
    }
    
    // Check if overwrite allowed
    if (m_params.contains(FlowParams::OVERWRITE) && 
        m_params[FlowParams::OVERWRITE].toBool()) {
        qDebug() << "FlowBase: Card has keys but overwrite allowed";
        return true;
    }
    
    qWarning() << "FlowBase: Card already has keys!";
    
    // Build card info
    QJsonObject cardInfo = buildCardInfoJson();
    
    // Request card swap
    pauseAndRestart(FlowSignals::SWAP_CARD, "has-keys");
    
    return false; // Will restart flow
}

// ============================================================================
// Card information
// ============================================================================

void FlowBase::updateCardInfo(const Keycard::ApplicationInfo& appInfo)
{
    m_cardInfo.instanceUID = appInfo.instanceUID.toHex();
    m_cardInfo.keyUID = appInfo.keyUID.toHex();
    m_cardInfo.initialized = appInfo.initialized;
    m_cardInfo.freeSlots = appInfo.availableSlots;
    m_cardInfo.keyInitialized = !appInfo.keyUID.isEmpty();
    m_cardInfo.version = (appInfo.appVersion << 8) | appInfo.appVersionMinor;
    
    // Get status to get PIN/PUK retry counts
    // Note: This requires secure channel, so we'll set defaults for now
    // and update later when we have secure channel
    m_cardInfo.pinRetries = -1;
    m_cardInfo.pukRetries = -1;
    
    qDebug() << "FlowBase: Card info updated:"
             << "initialized:" << m_cardInfo.initialized
             << "keyInitialized:" << m_cardInfo.keyInitialized
             << "version:" << QString("0x%1").arg(m_cardInfo.version, 0, 16);
}

QJsonObject FlowBase::buildCardInfoJson() const
{
    QJsonObject json;
    
    if (!m_cardInfo.instanceUID.isEmpty()) {
        json[FlowParams::INSTANCE_UID] = m_cardInfo.instanceUID;
    }
    
    if (!m_cardInfo.keyUID.isEmpty()) {
        json[FlowParams::KEY_UID] = m_cardInfo.keyUID;
    }
    
    if (m_cardInfo.freeSlots >= 0) {
        json[FlowParams::FREE_SLOTS] = m_cardInfo.freeSlots;
    }
    
    if (m_cardInfo.pinRetries >= 0) {
        json[FlowParams::PIN_RETRIES] = m_cardInfo.pinRetries;
        json[FlowParams::PUK_RETRIES] = m_cardInfo.pukRetries;
    }
    
    return json;
}

} // namespace StatusKeycard

