#ifndef STORE_METADATA_FLOW_H
#define STORE_METADATA_FLOW_H

#include "flow_base.h"

namespace StatusKeycard {

class StoreMetadataFlow : public FlowBase {
    Q_OBJECT
public:
    StoreMetadataFlow(FlowManager* mgr, const QJsonObject& params, QObject* parent = nullptr);
    QJsonObject execute() override;
};

} // namespace StatusKeycard

#endif

