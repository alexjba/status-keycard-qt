#include "load_account_flow.h"
#include "../flow_manager.h"
#include "../flow_params.h"
#include "../flow_signals.h"
#include <keycard-qt/command_set.h>
#include <keycard-qt/types.h>
#include <keycard-qt/keycard_channel.h>
#include <QDebug>
#include <QJsonArray>

namespace StatusKeycard {

LoadAccountFlow::LoadAccountFlow(FlowManager* manager, const QJsonObject& params, QObject* parent)
    : FlowBase(manager, FlowType::LoadAccount, params, parent)
{
}

LoadAccountFlow::~LoadAccountFlow()
{
}

QJsonObject LoadAccountFlow::execute()
{
    qDebug() << "LoadAccountFlow::execute()";
    
    if (!selectKeycard()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "select-failed";
        return error;
    }

    auto flowResult = requireNoKeys();
    if (!flowResult.ok) {
        qWarning() << "LoadAccountFlow: Card already has keys loaded";
        return flowResult.result;
    }

    if (!verifyPIN()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "auth-failed";
        return error;
    }

    return loadMnemonic().result;
    
    // // Check if card is initialized (pre-initialized cards need initialization first)
    // // This matches status-keycard-go behavior: pause and ask for PIN/PUK/pairing
    // if (!cardInfo().initialized) {
    //     QString puk = params()[FlowParams::NEW_PUK].toString();

        
    //     if (pin.isEmpty() || puk.isEmpty()) {
    //         qWarning() << "LoadAccountFlow: Missing PIN or PUK";
    //         QJsonObject error;
    //         error[FlowParams::ERROR_KEY] = "missing-credentials";
    //         return error;
    //     }
        
    //     // Standard reconnection flow (all platforms)
    //     // After init, card has new credentials - need fresh connection
    //     // - Android: disconnect() stops reader mode, forceScan() restarts it
    //     // - iOS/PCSC: disconnect() closes connection, forceScan() triggers re-detection
    //     channel()->disconnect();
    //     channel()->forceScan();
        
    //     if (!selectKeycard()) {
    //         QJsonObject error;
    //         error[FlowParams::ERROR_KEY] = "select-failed";
    //         return error;
    //     }
    // }
    
    // // Authenticate FIRST (this will pause for PIN entry)
    // // This matches status-keycard-go: authenticate before checking keys
    // if (!verifyPIN()) {
    //     QJsonObject error;
    //     error[FlowParams::ERROR_KEY] = "auth-failed";
    //     return error;
    // }
    
    // THEN check if card has keys (after authentication)
    // If card already has keys loaded, return error
    
    // if (keyUID.isEmpty()) {
    //     qWarning() << "LoadAccountFlow: Failed to load seed onto card";
    //     QJsonObject error;
    //     error[FlowParams::ERROR_KEY] = "load-failed";
    //     return error;
    // }
    
    // QJsonObject result = buildCardInfoJson();
    // result[FlowParams::KEY_UID] = QString("0x") + keyUID.toHex();
    
    // return result;
}

} // namespace StatusKeycard

