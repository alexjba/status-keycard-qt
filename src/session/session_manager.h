#pragma once

#include "session_state.h"
#include <keycard-qt/keycard_channel.h>
#include <keycard-qt/command_set.h>
#include <QObject>
#include <QTimer>
#include <QMutex>
#include <memory>

namespace StatusKeycard {

/**
 * @brief Manages keycard session lifecycle
 * 
 * Responsibilities:
 * - Card/reader detection and monitoring
 * - Automatic connection management
 * - State machine management
 * - Signal emission for state changes
 */
class SessionManager : public QObject {
    Q_OBJECT

public:
    explicit SessionManager(QObject* parent = nullptr);
    ~SessionManager();

    // Session lifecycle
    bool start(const QString& storagePath, bool logEnabled = false, const QString& logFilePath = QString());
    void stop();
    bool isStarted() const { return m_started; }

    // Current state
    SessionState currentState() const { return m_state; }
    QString currentStateString() const;
    
    // Card operations (require Authorized state for most)
    bool initialize(const QString& pin, const QString& puk, const QString& pairingPassword);
    bool authorize(const QString& pin);
    bool changePIN(const QString& newPIN);
    bool changePUK(const QString& newPUK);
    bool unblockPIN(const QString& puk, const QString& newPIN);
    
    // Key operations
    QVector<int> generateMnemonic(int length);
    QString loadMnemonic(const QString& mnemonic, const QString& passphrase);
    bool factoryReset();
    
    // Forward-declare nested types for method signatures
    struct Metadata;
    
    // Metadata operations
    Metadata getMetadata();
    bool storeMetadata(const QString& name, const QStringList& paths);
    
    // Key export
    struct KeyPair {
        QString address;
        QString publicKey;
        QString privateKey;  // Optional
        QString chainCode;   // Optional (for extended keys)
    };
    
    struct LoginKeys {
        KeyPair whisperPrivateKey;
        KeyPair encryptionPrivateKey;
    };
    LoginKeys exportLoginKeys();
    
    struct RecoverKeys {
        LoginKeys loginKeys;
        KeyPair eip1581;
        KeyPair walletRootKey;
        KeyPair walletKey;
        KeyPair masterKey;
    };
    RecoverKeys exportRecoverKeys();
    
    // Channel access (for Android JNI bridge)
    Keycard::KeycardChannel* getChannel() { return m_channel.get(); }
    
    // Status structures (matching status-keycard-go exactly)
    struct Wallet {
        QString path;
        QString address;
        QString publicKey;
    };
    
    struct Metadata {
        QString name;
        QVector<Wallet> wallets;
    };
    
    struct ApplicationInfoV2 {
        bool installed;
        bool initialized;
        QString instanceUID;
        QString version;
        int availableSlots;
        QString keyUID;
    };
    
    struct ApplicationStatus {
        int remainingAttemptsPIN;
        int remainingAttemptsPUK;
        bool keyInitialized;
        QString path;
    };
    
    struct Status {
        QString state;  // State string (e.g., "ready", "authorized")
        ApplicationInfoV2* keycardInfo;  // Can be null
        ApplicationStatus* keycardStatus;  // Can be null
        Metadata* metadata;  // Can be null
        
        Status() : keycardInfo(nullptr), keycardStatus(nullptr), metadata(nullptr) {}
        ~Status() {
            delete keycardInfo;
            delete keycardStatus;
            delete metadata;
        }
    };
    Status getStatus() const;
    
    // Error handling
    QString lastError() const { return m_lastError; }

signals:
    void stateChanged(SessionState newState, SessionState oldState);
    void cardDetected(const QString& uid);
    void cardRemoved();
    void readerConnected();
    void readerDisconnected();
    void error(const QString& message);

private slots:
    void onCardDetected(const QString& uid);
    void onCardRemoved();
    void onChannelError(const QString& error);
    void checkCardState();

private:
    void setState(SessionState newState);
    bool openSecureChannel();
    void closeSecureChannel();
    bool savePairing(const QString& instanceUID, const Keycard::PairingInfo& pairingInfo);
    Keycard::PairingInfo loadPairing(const QString& instanceUID);
    void setError(const QString& error);

    // State
    SessionState m_state;
    bool m_started;
    QString m_lastError;
    QString m_storagePath;
    
    // Keycard components
    std::unique_ptr<Keycard::KeycardChannel> m_channel;
    std::unique_ptr<Keycard::CommandSet> m_commandSet;
    Keycard::ApplicationInfo m_appInfo;
    Keycard::PairingInfo m_pairingInfo;
    
    // Monitoring
    QTimer* m_stateCheckTimer;
    QString m_currentCardUID;
    bool m_authorized;
    
    // Thread safety - protects all card operations
    mutable QMutex m_operationMutex;
};

} // namespace StatusKeycard

