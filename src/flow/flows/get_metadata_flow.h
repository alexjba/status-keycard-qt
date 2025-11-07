#ifndef GET_METADATA_FLOW_H
#define GET_METADATA_FLOW_H

#include "flow_base.h"

namespace StatusKeycard {

class GetMetadataFlow : public FlowBase {
    Q_OBJECT
public:
    GetMetadataFlow(FlowManager* mgr, const QJsonObject& params, QObject* parent = nullptr);
    QJsonObject execute() override;
};

} // namespace StatusKeycard

#endif

