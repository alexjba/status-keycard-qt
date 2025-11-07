#ifndef CHANGE_PUK_FLOW_H
#define CHANGE_PUK_FLOW_H

#include "flow_base.h"

namespace StatusKeycard {

class ChangePUKFlow : public FlowBase {
    Q_OBJECT
public:
    ChangePUKFlow(FlowManager* mgr, const QJsonObject& params, QObject* parent = nullptr);
    QJsonObject execute() override;
};

} // namespace StatusKeycard

#endif

