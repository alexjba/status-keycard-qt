#include "store_metadata_flow.h"
#include "../flow_manager.h"
#include "../flow_params.h"
#include "../flow_signals.h"
#include <keycard-qt/command_set.h>

namespace StatusKeycard {

StoreMetadataFlow::StoreMetadataFlow(FlowManager* mgr, const QJsonObject& params, QObject* parent)
    : FlowBase(mgr, FlowType::StoreMetadata, params, parent) {}

QJsonObject StoreMetadataFlow::execute()
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
    
    QString cardName = params()[FlowParams::CARD_NAME].toString();
    if (cardName.isEmpty()) {
        pauseAndWait(FlowSignals::ENTER_NAME, "enter-cardname");
        if (isCancelled()) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "cancelled";
            return error;
        }
        cardName = params()[FlowParams::CARD_NAME].toString();
    }
    
    // TODO: Implement actual metadata storage
    // For now, just return success
    
    return buildCardInfoJson();
}

} // namespace StatusKeycard

