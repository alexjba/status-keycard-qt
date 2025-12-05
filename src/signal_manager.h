#pragma once

#include "../include/status-keycard-qt/status_keycard.h"
#include "session/session_state.h"
#include "session/session_manager.h"
#include <QObject>
#include <QString>

namespace StatusKeycard {

/**
 * @brief Manages signal callbacks to Nim/C code
 * 
 * Bridges Qt signals to C callback mechanism.
 */
class SignalManager : public QObject {
    Q_OBJECT

public:
    static SignalManager* instance();
    
    void setCallback(SignalCallback callback);
    void emitStatusChanged(const SessionManager::Status& status);
    void emitError(const QString& error);
    void emitSignal(const QString& jsonSignal);
    void emitChannelStateChanged(const QString& state);

private:
    SignalManager();
    ~SignalManager();
    
    void sendSignal(const QString& jsonSignal);
    
    SignalCallback m_callback;
    static SignalManager* s_instance;
};

} // namespace StatusKeycard

