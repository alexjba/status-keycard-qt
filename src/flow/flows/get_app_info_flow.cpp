#include "get_app_info_flow.h"
#include "../flow_manager.h"
#include "../flow_params.h"
#include <keycard-qt/command_set.h>
#include <keycard-qt/types.h>
#include <keycard-qt/keycard_channel.h>
#include <QDebug>

namespace StatusKeycard {

GetAppInfoFlow::GetAppInfoFlow(FlowManager* manager, const QJsonObject& params, QObject* parent)
    : FlowBase(manager, FlowType::GetAppInfo, params, parent)
{
}

GetAppInfoFlow::~GetAppInfoFlow()
{
}

QJsonObject GetAppInfoFlow::execute()
{
    qDebug() << "GetAppInfoFlow: Starting execution";
    
    // Check if factory reset is requested
    bool factoryReset = params().value("factory reset").toBool();
    if (factoryReset) {
        qDebug() << "GetAppInfoFlow: Factory reset requested";
    }
    
    // 1. Select keycard applet
    if (!selectKeycard()) {
        qCritical() << "GetAppInfoFlow: Failed to select keycard";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "select-failed";
        return error;
    }
    
    // 2. If factory reset requested, execute it BEFORE checking card state
    if (factoryReset && cardInfo().initialized) {
        qDebug() << "GetAppInfoFlow: Executing factory reset";
        
        // Factory reset does NOT require authentication or PIN
        // (matches status-keycard-go behavior - only requires SELECT)
        
        // Execute factory reset via CommandSet
        auto cmdSet = commandSet();
        if (!cmdSet || !cmdSet->factoryReset()) {
            qWarning() << "GetAppInfoFlow: Factory reset failed:" << (cmdSet ? cmdSet->lastError() : "No CommandSet");
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "factory-reset-failed";
            return error;
        }

        if (cardInfo().initialized) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "factory-reset-failed";
            return error;
        }
                
        // After factory reset, card session must be reset (all platforms)
        // On Android: disconnect() stops reader mode, forceScan() restarts it -> fresh IsoDep session
        // On iOS/PCSC: disconnect() closes connection, forceScan() triggers re-detection
        qDebug() << "GetAppInfoFlow: Disconnecting and forcing card re-scan";
        channel()->disconnect();
        channel()->forceScan();

        selectKeycard();
    }
    
    // 3. Build basic app info result
    QJsonObject appInfo;
    appInfo[FlowParams::INSTANCE_UID] = cardInfo().instanceUID;
    appInfo[FlowParams::KEY_UID] = cardInfo().keyUID;
    appInfo["initialized"] = cardInfo().initialized;
    appInfo["key-initialized"] = cardInfo().keyInitialized;
    appInfo["available-slots"] = cardInfo().freeSlots;
    appInfo["version"] = QString("%1.%2")
        .arg((cardInfo().version >> 8) & 0xFF)
        .arg(cardInfo().version & 0xFF);
    
    QJsonObject result;
    result[FlowParams::ERROR_KEY] = "ok";
    result[FlowParams::APP_INFO] = appInfo;
    
    // 4. Try to authenticate (to check if paired)
    //    This may pause for pairing password or PIN
    //    If user cancels, that's OK - we just mark as not paired
    if (!verifyPIN(true)) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "auth-failed";
        error[FlowParams::PAIRED] = false;
        return error;
    }
    
    result[FlowParams::PAIRED] = true;
    qDebug() << "GetAppInfoFlow: Execution completed successfully";
    return result;
}

} // namespace StatusKeycard

