#include "export_public_flow.h"
#include "../flow_manager.h"
#include "../flow_params.h"
#include "../flow_signals.h"
#include <keycard-qt/command_set.h>
#include <QJsonArray>

namespace StatusKeycard {

ExportPublicFlow::ExportPublicFlow(FlowManager* mgr, const QJsonObject& params, QObject* parent)
    : FlowBase(mgr, FlowType::ExportPublic, params, parent) {}

QJsonObject ExportPublicFlow::execute()
{
    if (!waitForCard() || !selectKeycard() || !requireKeys()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "card-error";
        return error;
    }
    
    if (!openSecureChannelAndAuthenticate(true)) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "auth-failed";
        return error;
    }
    
    // Handle both single path (string) and multiple paths (array)
    QJsonValue pathValue = params()[FlowParams::BIP44_PATH];
    QStringList paths;
    bool inputWasArray = pathValue.isArray();
    
    if (inputWasArray) {
        // Multiple paths case
        QJsonArray pathArray = pathValue.toArray();
        for (const QJsonValue& val : pathArray) {
            paths.append(val.toString());
        }
    } else if (pathValue.isString()) {
        // Single path case
        QString path = pathValue.toString();
        if (!path.isEmpty()) {
            paths.append(path);
        }
    }
    
    if (paths.isEmpty()) {
        pauseAndWait(FlowSignals::ENTER_PATH, "enter-bip44-path");
        if (isCancelled()) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "cancelled";
            return error;
        }
        // After resume, check again
        pathValue = params()[FlowParams::BIP44_PATH];
        if (pathValue.isArray()) {
            QJsonArray pathArray = pathValue.toArray();
            for (const QJsonValue& val : pathArray) {
                paths.append(val.toString());
            }
        } else {
            paths.append(pathValue.toString());
        }
    }
    
    // Export keys for all paths
    QJsonArray exportedKeys;
    for (const QString& path : paths) {
        QByteArray keyData = commandSet()->exportKey(true, false, path, Keycard::APDU::P2ExportKeyPublicOnly);
        if (keyData.isEmpty()) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "export-failed";
            return error;
        }
        
        QJsonObject keyPair;
        keyPair["publicKey"] = QString("0x") + keyData.left(65).toHex();
        keyPair["address"] = "";
        exportedKeys.append(keyPair);
    }
    
    QJsonObject result = buildCardInfoJson();
    // Return format matches input format: array input -> array output, string input -> single object output
    if (inputWasArray) {
        result[FlowParams::EXPORTED_KEY] = exportedKeys;
    } else {
        result[FlowParams::EXPORTED_KEY] = exportedKeys[0];
    }
    
    return result;
}

} // namespace StatusKeycard

