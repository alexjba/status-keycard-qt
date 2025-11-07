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
    qDebug() << "GetAppInfoFlow: Created";
}

GetAppInfoFlow::~GetAppInfoFlow()
{
    qDebug() << "GetAppInfoFlow: Destroyed";
}

QJsonObject GetAppInfoFlow::execute()
{
    qDebug() << "GetAppInfoFlow: Starting execution";
    
    // Check if factory reset is requested
    bool factoryReset = params().value("factory reset").toBool();
    if (factoryReset) {
        qDebug() << "GetAppInfoFlow: Factory reset requested";
    }
    
    // 1. Wait for card
    if (!waitForCard()) {
        qWarning() << "GetAppInfoFlow: Card wait cancelled";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "cancelled";
        return error;
    }
    
    // 2. Select keycard applet
    if (!selectKeycard()) {
        qCritical() << "GetAppInfoFlow: Failed to select keycard";
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "select-failed";
        return error;
    }
    
    // 3. If factory reset requested, execute it BEFORE checking card state
    if (factoryReset) {
        qDebug() << "GetAppInfoFlow: Executing factory reset";
        
        // Factory reset does NOT require authentication or PIN
        // (matches status-keycard-go behavior - only requires SELECT)
        
        // Execute factory reset via CommandSet
        auto* cmdSet = commandSet();
        if (!cmdSet || !cmdSet->factoryReset()) {
            qWarning() << "GetAppInfoFlow: Factory reset failed:" << (cmdSet ? cmdSet->lastError() : "No CommandSet");
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "factory-reset-failed";
            return error;
        }
        
        qDebug() << "GetAppInfoFlow: Factory reset completed successfully";
        
        // After factory reset, trigger card re-detection
        // This matches SessionManager::factoryReset() behavior
        qDebug() << "GetAppInfoFlow: Forcing card re-scan after factory reset";
        channel()->forceScan();
        
        // Return success - card will be re-detected as pre-initialized (empty)
        QJsonObject result;
        result[FlowParams::ERROR_KEY] = "ok";
        result["factory-reset"] = true;
        return result;
    }
    
    // 4. Build basic app info result
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
    bool authenticated = openSecureChannelAndAuthenticate(true);
    
    if (isCancelled()) {
        // User cancelled authentication - mark as not paired
        qDebug() << "GetAppInfoFlow: Authentication cancelled, marking as not paired";
        result[FlowParams::PAIRED] = false;
    } else if (authenticated) {
        // Successfully authenticated
        qDebug() << "GetAppInfoFlow: Successfully authenticated";
        result[FlowParams::PAIRED] = true;
        
        // Get PIN/PUK retry counts via getStatus
        auto* cmdSet = commandSet();
        if (cmdSet) {
            try {
                Keycard::ApplicationStatus status = cmdSet->getStatus();
                result[FlowParams::PIN_RETRIES] = static_cast<int>(status.pinRetryCount);
                result[FlowParams::PUK_RETRIES] = static_cast<int>(status.pukRetryCount);
                qDebug() << "GetAppInfoFlow: PIN retries:" << status.pinRetryCount
                        << "PUK retries:" << status.pukRetryCount;
            } catch (...) {
                qWarning() << "GetAppInfoFlow: Failed to get status";
                // Non-fatal, continue
            }
        }
    } else {
        // Authentication failed
        qDebug() << "GetAppInfoFlow: Authentication failed";
        result[FlowParams::PAIRED] = false;
    }
    
    qDebug() << "GetAppInfoFlow: Execution completed successfully";
    return result;
}

} // namespace StatusKeycard

