#include "store_metadata_flow.h"
#include "../flow_manager.h"
#include "../flow_params.h"
#include "../flow_signals.h"
#include <keycard-qt/command_set.h>
#include <algorithm>
#include <QJsonArray>

namespace StatusKeycard {

// LEB128 (Little Endian Base 128) encoding
// Used for encoding wallet path components (matching Go's apdu.WriteLength)
static void writeLEB128(QByteArray& buf, uint32_t value) {
    do {
        uint8_t byte = value & 0x7F;  // Take lower 7 bits
        value >>= 7;
        if (value != 0) {
            byte |= 0x80;  // Set continuation bit if more bytes follow
        }
        buf.append(static_cast<char>(byte));
    } while (value != 0);
}

StoreMetadataFlow::StoreMetadataFlow(FlowManager* mgr, const QJsonObject& params, QObject* parent)
    : FlowBase(mgr, FlowType::StoreMetadata, params, parent) {}

QJsonObject StoreMetadataFlow::execute()
{    
    qDebug() << "StoreMetadataFlow: Starting execution" << params();
    QString cardName = params()[FlowParams::CARD_NAME].toString();
    if (cardName.isEmpty()) {
        // Request card name (empty error = normal request)
        pauseAndWait(FlowSignals::ENTER_NAME, "");
        if (isCancelled()) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "cancelled";
            return error;
        }
        cardName = params()[FlowParams::CARD_NAME].toString();
    }
    
    // Truncate card name to 20 characters (matching status-keycard-go)
    const int maxCardNameLength = 20;
    if (cardName.length() > maxCardNameLength) {
        qDebug() << "StoreMetadataFlow: Truncating card name from" << cardName.length() 
                 << "to" << maxCardNameLength << "characters";
        cardName = cardName.left(maxCardNameLength);
    }
    
    qDebug() << "StoreMetadataFlow: Storing card name:" << cardName;
    
    // Get wallet paths (optional)
    QJsonArray walletPathsArray = params()[FlowParams::WALLET_PATHS].toArray();
    QVector<uint32_t> pathComponents;
    
    // Parse wallet paths (matching Go implementation)
    // Only store the last component of each path
    const QString walletRootPath = "m/44'/60'/0'/0";
    for (const QJsonValue& pathValue : walletPathsArray) {
        QString path = pathValue.toString();
        if (!path.startsWith(walletRootPath)) {
            qWarning() << "StoreMetadataFlow: Path" << path << "does not start with" << walletRootPath;
            continue;
        }
        
        // Extract last component (after last '/')
        QStringList parts = path.split('/');
        if (parts.isEmpty()) {
            qWarning() << "StoreMetadataFlow: Invalid path format:" << path;
            continue;
        }
        
        bool ok;
        uint32_t component = parts.last().toUInt(&ok);
        if (!ok) {
            qWarning() << "StoreMetadataFlow: Invalid path component:" << parts.last();
            continue;
        }
        
        pathComponents.append(component);
    }
    
    // Sort path components (Go keeps them ordered)
    std::sort(pathComponents.begin(), pathComponents.end());
    
    // Build metadata in Go's custom binary format (matching types/metadata.go Serialize())
    // Format: [version+namelen][name][start/count pairs in LEB128]
    // - Byte 0: 0x20 | namelen (version=1 in top 3 bits, name length in bottom 5 bits)
    // - Bytes 1..namelen: card name (UTF-8)
    // - Remaining: LEB128-encoded start/count pairs for consecutive wallet paths
    QByteArray metadata;
    
    QByteArray nameBytes = cardName.toUtf8();
    uint8_t header = 0x20 | static_cast<uint8_t>(nameBytes.size());  // Version 1, name length
    metadata.append(static_cast<char>(header));
    metadata.append(nameBytes);
    
    // Encode wallet paths as start/count pairs (consecutive paths are grouped)
    // This matches Go's Serialize() logic
    if (!pathComponents.isEmpty()) {
        uint32_t start = pathComponents[0];
        uint32_t count = 0;
        
        for (int i = 1; i < pathComponents.size(); ++i) {
            if (pathComponents[i] == start + count + 1) {
                // Consecutive path, extend range
                count++;
            } else {
                // Non-consecutive, write current range and start new one
                writeLEB128(metadata, start);
                writeLEB128(metadata, count);
                start = pathComponents[i];
                count = 0;
            }
        }
        
        // Write final range
        writeLEB128(metadata, start);
        writeLEB128(metadata, count);
    }
    
    if (!verifyPIN()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "auth-failed";
        return error;
    }

    if (isCancelled()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "cancelled";
        return error;
    }
    
    // Store metadata using PUBLIC data type (0x00) - matching Go implementation
    auto cmdSet = commandSet();
    if (!cmdSet->storeData(Keycard::APDU::P1StoreDataPublic, metadata)) {
        qWarning() << "StoreMetadataFlow: Failed to store metadata:" << cmdSet->lastError();
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "store-failed";
        return error;
    }
    
    qDebug() << "StoreMetadataFlow: Metadata stored successfully";
    
    return buildCardInfoJson();
}

} // namespace StatusKeycard

