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
}

} // namespace StatusKeycard

