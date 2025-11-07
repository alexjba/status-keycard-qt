#ifndef CHANGE_PAIRING_FLOW_H
#define CHANGE_PAIRING_FLOW_H

#include "flow_base.h"

namespace StatusKeycard {

class ChangePairingFlow : public FlowBase {
    Q_OBJECT
public:
    ChangePairingFlow(FlowManager* mgr, const QJsonObject& params, QObject* parent = nullptr);
    QJsonObject execute() override;
};

} // namespace StatusKeycard

#endif

