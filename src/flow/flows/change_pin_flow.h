#ifndef CHANGE_PIN_FLOW_H
#define CHANGE_PIN_FLOW_H

#include "flow_base.h"

namespace StatusKeycard {

class ChangePINFlow : public FlowBase {
    Q_OBJECT
public:
    ChangePINFlow(FlowManager* mgr, const QJsonObject& params, QObject* parent = nullptr);
    QJsonObject execute() override;
};

} // namespace StatusKeycard

#endif

