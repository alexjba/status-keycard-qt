#include "flow_manager.h"
#include "flow_signals.h"
#include "flows/flow_base.h"
#include "flows/login_flow.h"
#include "flows/get_app_info_flow.h"
#include "flows/recover_account_flow.h"
#include "flows/load_account_flow.h"
#include "flows/sign_flow.h"
#include "flows/change_pin_flow.h"
#include "flows/change_puk_flow.h"
#include "flows/change_pairing_flow.h"
#include "flows/export_public_flow.h"
#include "flows/get_metadata_flow.h"
#include "flows/store_metadata_flow.h"
#include "../storage/pairing_storage.h"
#include <keycard-qt/keycard_channel.h>
#include <keycard-qt/command_set.h>
#include <QDebug>
#include <QMutexLocker>
#include <QThread>
#include <QTimer>
#include <QtConcurrent>

namespace StatusKeycard {

// Singleton initialization
FlowManager* FlowManager::s_instance = nullptr;
QMutex FlowManager::s_instanceMutex;

FlowManager* FlowManager::instance()
{
    QMutexLocker locker(&s_instanceMutex);
    if (!s_instance) {
        s_instance = new FlowManager();
    }
    return s_instance;
}

void FlowManager::destroyInstance()
{
    QMutexLocker locker(&s_instanceMutex);
    if (s_instance) {
        qDebug() << "FlowManager: Destroying singleton instance";
        
        // Cancel any running flow before destroying
        // This ensures clean shutdown without race conditions
        s_instance->cancelFlow();
        
        // Wait for async operations to complete
        // Need longer wait to ensure QtConcurrent tasks finish
        locker.unlock();
        QThread::msleep(200);
        
        // Process Qt events to ensure deleteLater() executes
        QCoreApplication::processEvents();
        QThread::msleep(50);
        
        locker.relock();
        
        delete s_instance;
        s_instance = nullptr;
    }
}

FlowManager::FlowManager(QObject* parent)
    : QObject(parent)
    , m_stateMachine(new FlowStateMachine(this))
    , m_currentFlow(nullptr)
    , m_currentFlowType(FlowType::GetAppInfo) // Default
    , m_waitingForCard(false)
    , m_continuousDetectionRunning(false)
    , m_currentCardUid("")
{
    qDebug() << "FlowManager: Created";
}

FlowManager::~FlowManager()
{
    qDebug() << "FlowManager: Destructor called";
    
    // Stop continuous detection if running
    if (m_continuousDetectionRunning) {
        stopContinuousDetection();
    }
    
    // Cleanup any running flow
    cleanupFlow();
    
    qDebug() << "FlowManager: Destroyed";
}

bool FlowManager::init(const QString& storageDir, Keycard::KeycardChannel* channel)
{
    QMutexLocker locker(&m_mutex);
    
    qDebug() << "FlowManager: Initializing with storage:" << storageDir;
    
    m_storageDir = storageDir;
    
    // Create pairing storage
    m_storage = std::make_unique<PairingStorage>(storageDir);
    
    // Load existing pairings from file
    if (!m_storage->load()) {
        qWarning() << "FlowManager: Failed to load pairings:" << m_storage->lastError();
        qWarning() << "FlowManager: Will continue with empty pairings";
    } else {
        qDebug() << "FlowManager: Loaded" << m_storage->listInstanceUIDs().size() << "saved pairings";
    }
    
    // Use provided channel or create default
    if (channel) {
        qDebug() << "FlowManager: Using injected channel";
        m_channel.reset(channel);
    } else {
        qDebug() << "FlowManager: Creating default platform channel";
        m_channel = std::make_unique<Keycard::KeycardChannel>();
    }
    
    // Create persistent CommandSet (maintains secure channel across flows)
    // This matches status-keycard-go's behavior where the secure channel stays open
    m_commandSet = std::make_unique<Keycard::CommandSet>(m_channel.get());
    qDebug() << "FlowManager: Created persistent CommandSet";
    
    // Connect NFC events
    connect(m_channel.get(), &Keycard::KeycardChannel::targetDetected,
            this, &FlowManager::onCardDetected);
    
    connect(m_channel.get(), &Keycard::KeycardChannel::targetLost,
            this, &FlowManager::onCardRemoved);
    
    // DON'T start detection here - call startContinuousDetection() separately
    // This matches status-keycard-go's behavior
    qDebug() << "FlowManager: Initialized successfully";
    return true;
}

void FlowManager::startContinuousDetection()
{
    QMutexLocker locker(&m_mutex);
    
    if (m_continuousDetectionRunning) {
        qDebug() << "FlowManager: Continuous detection already running";
        return;
    }
    
    if (!m_channel) {
        qWarning() << "FlowManager: Cannot start detection - no channel";
        return;
    }
    
    qDebug() << "FlowManager: Starting continuous card detection...";
    
    // Unlock before starting detection (it may block briefly)
    locker.unlock();
    m_channel->startDetection();
    
    m_continuousDetectionRunning = true;
    qDebug() << "FlowManager: Continuous detection started";
}

void FlowManager::stopContinuousDetection()
{
    QMutexLocker locker(&m_mutex);
    
    if (!m_continuousDetectionRunning) {
        qDebug() << "FlowManager: Continuous detection not running";
        return;
    }
    
    if (m_channel) {
        qDebug() << "FlowManager: Stopping continuous card detection...";
        locker.unlock();
        m_channel->stopDetection();
    }
    
    m_continuousDetectionRunning = false;
    qDebug() << "FlowManager: Continuous detection stopped";
}

void FlowManager::setChannel(Keycard::KeycardChannel* channel)
{
    QMutexLocker locker(&m_mutex);
    
    if (m_stateMachine->state() != FlowState::Idle) {
        qWarning() << "FlowManager: Cannot set channel while flow is running";
        return;
    }
    
    if (m_channel) {
        m_channel->stopDetection();
        disconnect(m_channel.get(), nullptr, this, nullptr);
    }
    
    m_channel.reset(channel);
    qDebug() << "FlowManager: Custom channel set";
}

bool FlowManager::startFlow(int flowType, const QJsonObject& params)
{
    QMutexLocker locker(&m_mutex);
    
    qDebug() << "FlowManager: Starting flow type:" << flowType;
    
    // Check state
    if (m_stateMachine->state() != FlowState::Idle) {
        m_lastError = "Flow already running";
        qWarning() << "FlowManager: Cannot start flow - already running";
        return false;
    }
    
    // Store flow info
    m_currentFlowType = static_cast<FlowType>(flowType);
    m_currentParams = params;
    
    // Create flow
    m_currentFlow = createFlow(m_currentFlowType, m_currentParams);
    if (!m_currentFlow) {
        m_lastError = "Failed to create flow";
        qCritical() << "FlowManager: Failed to create flow type:" << flowType;
        return false;
    }
    
    qDebug() << "FlowManager: Flow created, connecting signals...";
    
    // Connect flow signals
    connect(m_currentFlow, &FlowBase::flowPaused,
            this, &FlowManager::onFlowPaused);
    
    connect(m_currentFlow, &FlowBase::flowCompleted,
            this, &FlowManager::onFlowCompleted);
    
    connect(m_currentFlow, &FlowBase::flowError,
            this, &FlowManager::onFlowError);
    
    qDebug() << "FlowManager: Signals connected, transitioning to Running state...";
    
    // Transition to Running
    if (!m_stateMachine->transition(FlowState::Running)) {
        m_lastError = "Failed to transition to Running state";
        cleanupFlow();
        return false;
    }
    
    qDebug() << "FlowManager: State transitioned to Running";
    
    // Detection is already running continuously (started in KeycardInitFlow)
    // No need to start/stop it per-flow
    locker.unlock();
    
    qDebug() << "FlowManager: Running flow asynchronously...";
    runFlowAsync();
    
    qDebug() << "FlowManager: Flow started successfully";
    return true;
}

bool FlowManager::resumeFlow(const QJsonObject& params)
{
    QMutexLocker locker(&m_mutex);
    
    qDebug() << "FlowManager: Resuming flow";
    
    // Check state
    if (m_stateMachine->state() != FlowState::Paused) {
        m_lastError = "Flow not paused";
        qWarning() << "FlowManager: Cannot resume - not paused";
        return false;
    }
    
    // Check flow exists
    if (!m_currentFlow) {
        m_lastError = "No flow to resume";
        qCritical() << "FlowManager: No flow to resume!";
        return false;
    }
    
    // Transition to Resuming
    if (!m_stateMachine->transition(FlowState::Resuming)) {
        m_lastError = "Failed to transition to Resuming state";
        return false;
    }
    
    // Resume flow
    m_currentFlow->resume(params);
    
    // Transition back to Running
    m_stateMachine->transition(FlowState::Running);
    
    qDebug() << "FlowManager: Flow resumed";
    return true;
}

bool FlowManager::cancelFlow()
{
    QMutexLocker locker(&m_mutex);
    
    qDebug() << "FlowManager: Cancelling flow";
    
    // Check flow exists
    if (!m_currentFlow) {
        qWarning() << "FlowManager: No flow to cancel";
        return true; // Not an error
    }
    
    // Transition to Cancelling
    if (!m_stateMachine->transition(FlowState::Cancelling)) {
        m_lastError = "Failed to transition to Cancelling state";
        return false;
    }
    
    // Cancel flow
    m_currentFlow->cancel();
    
    // Cleanup
    locker.unlock();
    cleanupFlow();
    
    qDebug() << "FlowManager: Flow cancelled";
    return true;
}

FlowState FlowManager::state() const
{
    return m_stateMachine->state();
}

int FlowManager::currentFlowType() const
{
    QMutexLocker locker(&m_mutex);
    if (m_currentFlow) {
        return static_cast<int>(m_currentFlowType);
    }
    return -1;
}

QString FlowManager::lastError() const
{
    QMutexLocker locker(&m_mutex);
    return m_lastError;
}

// ============================================================================
// Card events
// ============================================================================

void FlowManager::onCardDetected(const QString& uid)
{
    QMutexLocker locker(&m_mutex);
    
    // Debounce: Ignore if it's the same card we already know about
    if (m_currentCardUid == uid) {
        return;  // Same card, already detected
    }
    
    qDebug() << "FlowManager: Card detected:" << uid;
    m_currentCardUid = uid;  // Track this card
    
    if (m_waitingForCard && m_currentFlow) {
        qDebug() << "FlowManager: Card arrived while flow waiting";
        m_waitingForCard = false;
        
        // Resume flow if paused
        if (m_stateMachine->state() == FlowState::Paused) {
            locker.unlock();
            resumeFlow(QJsonObject()); // No new params
        }
    }
}

void FlowManager::onCardRemoved()
{
    qDebug() << "FlowManager: Card removed";
    
    QMutexLocker locker(&m_mutex);
    
    // Clear current card tracking
    m_currentCardUid.clear();
    
    if (m_stateMachine->state() == FlowState::Running && m_currentFlow) {
        qWarning() << "FlowManager: Card removed during flow - pausing";
        m_waitingForCard = true;
        
        // Flow will pause itself when it tries to use the card
    }
}

// ============================================================================
// Flow events
// ============================================================================

void FlowManager::onFlowPaused(const QString& action, const QJsonObject& event)
{
    qDebug() << "FlowManager: Flow paused, action:" << action;
    
    // Transition to Paused
    m_stateMachine->transition(FlowState::Paused);
    
    // Check if waiting for card
    if (action == FlowSignals::INSERT_CARD) {
        QMutexLocker locker(&m_mutex);
        m_waitingForCard = true;
    }
    
    // Emit signal
    emit flowSignal(action, event);
}

void FlowManager::onFlowCompleted(const QJsonObject& result)
{
    qDebug() << "FlowManager: Flow completed successfully";
    
    // Emit result signal
    FlowSignals::emitFlowResult(result);
    
    // Cleanup
    cleanupFlow();
}

void FlowManager::onFlowError(const QString& error)
{
    qCritical() << "FlowManager: Flow error:" << error;
    
    QMutexLocker locker(&m_mutex);
    m_lastError = error;
    locker.unlock();
    
    // Emit error result
    QJsonObject result;
    result[FlowParams::ERROR_KEY] = error;
    FlowSignals::emitFlowResult(result);
    
    // Cleanup
    cleanupFlow();
}

// ============================================================================
// Flow management
// ============================================================================

FlowBase* FlowManager::createFlow(FlowType flowType, const QJsonObject& params)
{
    qDebug() << "FlowManager: Creating flow type:" << static_cast<int>(flowType);
    
    switch (flowType) {
        case FlowType::Login:
            return new LoginFlow(this, params);
            
        case FlowType::GetAppInfo:
            return new GetAppInfoFlow(this, params);
            
        case FlowType::RecoverAccount:
            return new RecoverAccountFlow(this, params);
            
        case FlowType::LoadAccount:
            return new LoadAccountFlow(this, params);
            
        case FlowType::Sign:
            return new SignFlow(this, params);
            
        case FlowType::GetMetadata:
            return new GetMetadataFlow(this, params);
            
        case FlowType::StoreMetadata:
            return new StoreMetadataFlow(this, params);
            
        case FlowType::ChangePIN:
            return new ChangePINFlow(this, params);
            
        case FlowType::ChangePUK:
            return new ChangePUKFlow(this, params);
            
        case FlowType::ChangePairing:
            return new ChangePairingFlow(this, params);
            
        case FlowType::ExportPublic:
            return new ExportPublicFlow(this, params);
            
        default:
            qWarning() << "FlowManager: Unknown flow type:" << static_cast<int>(flowType);
            break;
    }
    
    return nullptr;
}

void FlowManager::runFlowAsync()
{
    qDebug() << "FlowManager: Running flow asynchronously";
    
    // Run flow in thread pool and store future for proper cleanup
    m_flowFuture = QtConcurrent::run([this]() {
        QMutexLocker locker(&m_mutex);
        
        if (!m_currentFlow) {
            qCritical() << "FlowManager: No flow to run!";
            return;
        }
        
        FlowBase* flow = m_currentFlow;
        locker.unlock();
        
        // Restart loop (matching status-keycard-go behavior)
        // Flow can request restart by calling pauseAndRestart()
        QJsonObject result;
        bool shouldRestart = false;
        
        do {
            // Reset state for restart (matching Go: f.cardInfo = cardStatus{...})
            if (shouldRestart) {
                qDebug() << "FlowManager: Restarting flow from beginning";
                flow->resetCardInfo();
                flow->resetRestartFlag();
            }
            
            // Execute flow
            try {
                result = flow->execute();
                
                // Check if cancelled
                if (flow->isCancelled()) {
                    qDebug() << "FlowManager: Flow was cancelled";
                    return;  // Exit without emitting completion
                }
                
                // Check if restart requested (matching Go: if _, ok := err.(*restartError))
                shouldRestart = flow->shouldRestart();
                
                if (shouldRestart) {
                    qDebug() << "FlowManager: Flow requested restart (card swap)";
                    // Loop will restart execution
                } else {
                    // Flow completed successfully
                    qDebug() << "FlowManager: Flow execution completed";
                    emit flow->flowCompleted(result);
                }
                
            } catch (const std::exception& e) {
                qCritical() << "FlowManager: Exception in flow execution:" << e.what();
                emit flow->flowError(QString("Exception: %1").arg(e.what()));
                return;  // Exit on exception
            } catch (...) {
                qCritical() << "FlowManager: Unknown exception in flow execution";
                emit flow->flowError("Unknown exception");
                return;  // Exit on exception
            }
            
        } while (shouldRestart && !flow->isCancelled());
        
        qDebug() << "FlowManager: Flow loop exited";
    });
}

void FlowManager::cleanupFlow()
{
    qDebug() << "FlowManager: Cleaning up flow";
    
    // Wait for async flow execution to complete before cleaning up
    if (m_flowFuture.isValid() && !m_flowFuture.isFinished()) {
        qDebug() << "FlowManager: Waiting for async flow to finish...";
        m_flowFuture.waitForFinished();
        qDebug() << "FlowManager: Async flow finished";
    }
    
    QMutexLocker locker(&m_mutex);
    
    // Don't stop detection - it runs continuously
    // Detection will keep running for next flow
    
    // Clear card tracking so next flow starts fresh
    m_currentCardUid.clear();
    
    if (m_currentFlow) {
        // Disconnect all signals to prevent callbacks on deleted object
        m_currentFlow->disconnect();
        m_currentFlow->deleteLater();
        m_currentFlow = nullptr; // Set to null IMMEDIATELY to prevent double cleanup
    }
    
    m_waitingForCard = false;
    m_stateMachine->reset();
    
    qDebug() << "FlowManager: Cleanup complete";
}

} // namespace StatusKeycard

