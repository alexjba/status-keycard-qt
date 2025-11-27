#include "change_pin_flow.h"
#include "../flow_manager.h"
#include "../flow_params.h"
#include "../flow_signals.h"
#include <keycard-qt/command_set.h>

namespace StatusKeycard {

ChangePINFlow::ChangePINFlow(FlowManager* mgr, const QJsonObject& params, QObject* parent)
    : FlowBase(mgr, FlowType::ChangePIN, params, parent) {}

QJsonObject ChangePINFlow::execute()
{
    if (!verifyPIN()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "auth-failed";
        return error;
    }
    
    QString newPIN = params()[FlowParams::NEW_PIN].toString();
    if (newPIN.isEmpty()) {
        // Request new PIN (empty error means normal request, not an error condition)
        pauseAndWait(FlowSignals::ENTER_NEW_PIN, "changing-credentials");
        if (isCancelled()) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "cancelled";
            return error;
        }
        newPIN = params()[FlowParams::NEW_PIN].toString();
    }
    
    if (!commandSet()->changePIN(newPIN)) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "change-failed";
        return error;
    }
    
    return buildCardInfoJson();
}

} // namespace StatusKeycard

