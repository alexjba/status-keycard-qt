#include "change_puk_flow.h"
#include "../flow_manager.h"
#include "../flow_params.h"
#include "../flow_signals.h"
#include <keycard-qt/command_set.h>

namespace StatusKeycard {

ChangePUKFlow::ChangePUKFlow(FlowManager* mgr, const QJsonObject& params, QObject* parent)
    : FlowBase(mgr, FlowType::ChangePUK, params, parent) {}

QJsonObject ChangePUKFlow::execute()
{
    if (!selectKeycard()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "card-error";
        return error;
    }
    
    if (!verifyPIN()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "auth-failed";
        return error;
    }
    
    QString newPUK = params()[FlowParams::NEW_PUK].toString();
    if (newPUK.isEmpty()) {
        // Request new PUK (empty error = normal request)
        pauseAndWait(FlowSignals::ENTER_NEW_PUK, "changing-credentials");
        if (isCancelled()) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "cancelled";
            return error;
        }
        newPUK = params()[FlowParams::NEW_PUK].toString();
    }
    
    if (!commandSet()->changePUK(newPUK)) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "change-failed";
        return error;
    }
    
    return buildCardInfoJson();
}

} // namespace StatusKeycard

