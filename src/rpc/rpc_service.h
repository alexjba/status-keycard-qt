#pragma once

#include <QObject>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>
#include <memory>
#include "session/session_manager.h"

namespace Keycard {
    class CommandSet;
}

namespace StatusKeycard {

/**
 * @brief JSON-RPC service for Keycard operations
 * 
 * Implements the exact JSON-RPC interface expected by nim-keycard-go.
 * All methods match status-keycard-go's Session API.
 */
class RpcService : public QObject {
    Q_OBJECT

public:
    explicit RpcService(QObject* parent = nullptr);
    ~RpcService();

    /**
     * @brief Process a JSON-RPC request and return JSON response
     * 
     * @param requestJson JSON-RPC request string
     * @return JSON-RPC response string (must be freed by caller with Free())
     */
    QString processRequest(const QString& requestJson);

    /**
     * @brief Get the session manager
     */
    SessionManager* sessionManager() { return m_sessionManager.get(); }

    /**
     * @brief Get the command set
     */
    std::shared_ptr<Keycard::CommandSet> commandSet() { return m_commandSet; }

    /**
     * @brief Set the shared command set
     * @param commandSet Shared command set
     */
    void setSharedCommandSet(std::shared_ptr<Keycard::CommandSet> commandSet);

private:
    /**
     * @brief Create a JSON-RPC success response
     */
    QJsonObject createSuccessResponse(const QString& id, const QJsonValue& result);

    /**
     * @brief Create a JSON-RPC error response
     */
    QJsonObject createErrorResponse(const QString& id, int code, const QString& message);

    /**
     * @brief Convert SessionManager::Status to JSON
     */
    QJsonObject statusToJson(const SessionManager::Status& status);

    // RPC method handlers
    QJsonObject handleStart(const QString& id, const QJsonObject& params);
    QJsonObject handleStop(const QString& id, const QJsonObject& params);
    QJsonObject handleGetStatus(const QString& id, const QJsonObject& params);
    QJsonObject handleInitialize(const QString& id, const QJsonObject& params);
    QJsonObject handleAuthorize(const QString& id, const QJsonObject& params);
    QJsonObject handleChangePIN(const QString& id, const QJsonObject& params);
    QJsonObject handleChangePUK(const QString& id, const QJsonObject& params);
    QJsonObject handleUnblock(const QString& id, const QJsonObject& params);
    QJsonObject handleGenerateMnemonic(const QString& id, const QJsonObject& params);
    QJsonObject handleLoadMnemonic(const QString& id, const QJsonObject& params);
    QJsonObject handleFactoryReset(const QString& id, const QJsonObject& params);
    QJsonObject handleGetMetadata(const QString& id, const QJsonObject& params);
    QJsonObject handleStoreMetadata(const QString& id, const QJsonObject& params);
    QJsonObject handleExportLoginKeys(const QString& id, const QJsonObject& params);
    QJsonObject handleExportRecoverKeys(const QString& id, const QJsonObject& params);

    std::unique_ptr<SessionManager> m_sessionManager;
    std::shared_ptr<Keycard::CommandSet> m_commandSet;
};

} // namespace StatusKeycard
