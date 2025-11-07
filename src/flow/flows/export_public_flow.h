#ifndef EXPORT_PUBLIC_FLOW_H
#define EXPORT_PUBLIC_FLOW_H

#include "flow_base.h"

namespace StatusKeycard {

class ExportPublicFlow : public FlowBase {
    Q_OBJECT
public:
    ExportPublicFlow(FlowManager* mgr, const QJsonObject& params, QObject* parent = nullptr);
    QJsonObject execute() override;
};

} // namespace StatusKeycard

#endif

