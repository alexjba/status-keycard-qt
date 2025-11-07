#ifndef GET_APP_INFO_FLOW_H
#define GET_APP_INFO_FLOW_H

#include "flow_base.h"

namespace StatusKeycard {

/**
 * @brief GetAppInfo Flow - Get card information
 * 
 * Returns basic card information:
 * - Application info (version, initialized, etc.)
 * - Pairing status (if can authenticate)
 * - PIN/PUK retry counts (if paired)
 * 
 * This is the simplest flow - no keys exported.
 * 
 * Result format:
 * {
 *   "error": "ok",
 *   "application-info": {
 *     "instance-uid": "...",
 *     "key-uid": "...",
 *     "initialized": true,
 *     "available-slots": 3,
 *     "version": "3.0"
 *   },
 *   "paired": true,
 *   "pin-retries": 3,
 *   "puk-retries": 5
 * }
 */
class GetAppInfoFlow : public FlowBase {
    Q_OBJECT
    
public:
    GetAppInfoFlow(FlowManager* manager, const QJsonObject& params, QObject* parent = nullptr);
    ~GetAppInfoFlow();
    
    /**
     * @brief Execute the get app info flow
     * @return Flow result JSON
     */
    QJsonObject execute() override;
};

} // namespace StatusKeycard

#endif // GET_APP_INFO_FLOW_H

