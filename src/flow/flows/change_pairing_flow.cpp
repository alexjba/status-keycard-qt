#include "change_pairing_flow.h"
#include "../flow_manager.h"
#include "../flow_params.h"
#include "../flow_signals.h"
#include <keycard-qt/command_set.h>

namespace StatusKeycard {

ChangePairingFlow::ChangePairingFlow(FlowManager* mgr, const QJsonObject& params, QObject* parent)
    : FlowBase(mgr, FlowType::ChangePairing, params, parent) {}

QJsonObject ChangePairingFlow::execute()
{
    if (!waitForCard() || !selectKeycard()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "card-error";
        return error;
    }
    
    if (!openSecureChannelAndAuthenticate(true)) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "auth-failed";
        return error;
    }
    
    QString newPairing = params()[FlowParams::NEW_PAIRING].toString();
    if (newPairing.isEmpty()) {
        pauseAndWait(FlowSignals::ENTER_NEW_PAIRING, "enter-new-pairing");
        if (isCancelled()) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "cancelled";
            return error;
        }
        newPairing = params()[FlowParams::NEW_PAIRING].toString();
    }
    
    if (!commandSet()->changePairingSecret(newPairing)) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "change-failed";
        return error;
    }
    
    return buildCardInfoJson();
}

} // namespace StatusKeycard

