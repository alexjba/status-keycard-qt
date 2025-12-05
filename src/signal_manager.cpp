#include "signal_manager.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDebug>

namespace StatusKeycard {

SignalManager* SignalManager::s_instance = nullptr;

SignalManager::SignalManager()
    : QObject(nullptr)
    , m_callback(nullptr)
{
}

SignalManager::~SignalManager()
{
}

SignalManager* SignalManager::instance()
{
    if (!s_instance) {
        s_instance = new SignalManager();
    }
    return s_instance;
}

void SignalManager::setCallback(SignalCallback callback)
{
    m_callback = callback;
    qDebug() << "SignalManager: Callback" << (callback ? "set" : "cleared");
}

void SignalManager::emitStatusChanged(const SessionManager::Status& status)
{
    // Build the event object with the exact structure from status-keycard-go
    QJsonObject event;
    event["state"] = status.state;
    
    // keycardInfo (nullable)
    if (status.keycardInfo) {
        QJsonObject info;
        info["installed"] = status.keycardInfo->installed;
        info["initialized"] = status.keycardInfo->initialized;
        info["instanceUID"] = status.keycardInfo->instanceUID;
        info["version"] = status.keycardInfo->version;
        info["availableSlots"] = status.keycardInfo->availableSlots;
        info["keyUID"] = status.keycardInfo->keyUID;
        event["keycardInfo"] = info;
    } else {
        event["keycardInfo"] = QJsonValue::Null;
    }
    
    // keycardStatus (nullable)
    if (status.keycardStatus) {
        QJsonObject cardStatus;
        cardStatus["remainingAttemptsPIN"] = status.keycardStatus->remainingAttemptsPIN;
        cardStatus["remainingAttemptsPUK"] = status.keycardStatus->remainingAttemptsPUK;
        cardStatus["keyInitialized"] = status.keycardStatus->keyInitialized;
        cardStatus["path"] = status.keycardStatus->path;
        event["keycardStatus"] = cardStatus;
    } else {
        event["keycardStatus"] = QJsonValue::Null;
    }
    
    // metadata (nullable)
    if (status.metadata) {
        QJsonObject meta;
        meta["name"] = status.metadata->name;
        
        QJsonArray walletsArray;
        for (const auto& wallet : status.metadata->wallets) {
            QJsonObject w;
            w["path"] = wallet.path;
            w["address"] = wallet.address;
            w["publicKey"] = wallet.publicKey;
            walletsArray.append(w);
        }
        meta["wallets"] = walletsArray;
        event["metadata"] = meta;
    } else {
        event["metadata"] = QJsonValue::Null;
    }
    
    // Wrap in signal envelope
    QJsonObject signal;
    signal["type"] = "status-changed";
    signal["event"] = event;
    
    QJsonDocument doc(signal);
    QString jsonString = QString::fromUtf8(doc.toJson(QJsonDocument::Compact));
    
    sendSignal(jsonString);
}

void SignalManager::emitError(const QString& error)
{
    QJsonObject event;
    event["error"] = error;
    
    QJsonObject signal;
    signal["type"] = "error";
    signal["event"] = event;
    
    QJsonDocument doc(signal);
    QString jsonString = QString::fromUtf8(doc.toJson(QJsonDocument::Compact));
    
    sendSignal(jsonString);
}

void SignalManager::emitSignal(const QString& jsonSignal)
{
    sendSignal(jsonSignal);
}

void SignalManager::emitChannelStateChanged(const QString& state)
{
    QJsonObject event;
    event["state"] = state;
    
    QJsonObject signal;
    signal["type"] = "channel-state-changed";
    signal["event"] = event;
    
    QJsonDocument doc(signal);
    QString jsonString = QString::fromUtf8(doc.toJson(QJsonDocument::Compact));
    
    sendSignal(jsonString);
}

void SignalManager::sendSignal(const QString& jsonSignal)
{
    if (!m_callback) {
        qDebug() << "SignalManager: No callback set, signal dropped:" << jsonSignal;
        return;
    }
    
    // Convert QString to char* for C callback
    QByteArray signalBytes = jsonSignal.toUtf8();
    m_callback(signalBytes.constData());
}

} // namespace StatusKeycard

