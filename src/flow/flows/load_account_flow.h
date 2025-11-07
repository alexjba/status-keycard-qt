#ifndef LOAD_ACCOUNT_FLOW_H
#define LOAD_ACCOUNT_FLOW_H

#include "flow_base.h"

namespace StatusKeycard {

/**
 * @brief LoadAccount Flow - Load mnemonic onto empty card
 * 
 * Takes a BIP39 mnemonic and loads it onto an empty keycard.
 * Card must NOT have keys already (or overwrite param must be set).
 */
class LoadAccountFlow : public FlowBase {
    Q_OBJECT
    
public:
    LoadAccountFlow(FlowManager* manager, const QJsonObject& params, QObject* parent = nullptr);
    ~LoadAccountFlow();
    
    QJsonObject execute() override;
};

} // namespace StatusKeycard

#endif // LOAD_ACCOUNT_FLOW_H

