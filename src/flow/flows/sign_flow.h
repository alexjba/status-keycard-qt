#ifndef SIGN_FLOW_H
#define SIGN_FLOW_H

#include "flow_base.h"

namespace StatusKeycard {

/**
 * @brief Sign Flow - Sign transaction hash
 */
class SignFlow : public FlowBase {
    Q_OBJECT
    
public:
    SignFlow(FlowManager* manager, const QJsonObject& params, QObject* parent = nullptr);
    ~SignFlow();
    
    QJsonObject execute() override;
};

} // namespace StatusKeycard

#endif // SIGN_FLOW_H

