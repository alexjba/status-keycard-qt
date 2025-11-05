#pragma once

#include <keycard-qt/types.h>
#include <QString>
#include <QMap>

namespace StatusKeycard {

/**
 * @brief Manages persistent storage of pairing information
 * 
 * Stores pairing keys in JSON format compatible with status-keycard-go.
 * File format: pairings.json
 * {
 *   "instance_uid_hex": {
 *     "index": 0,
 *     "key": "pairing_key_hex"
 *   },
 *   ...
 * }
 */
class PairingStorage {
public:
    explicit PairingStorage(const QString& filePath);
    ~PairingStorage();

    // Load/save operations
    bool load();
    bool save();
    
    // Pairing management
    bool storePairing(const QString& instanceUID, const Keycard::PairingInfo& pairingInfo);
    Keycard::PairingInfo loadPairing(const QString& instanceUID);
    bool hasPairing(const QString& instanceUID) const;
    bool removePairing(const QString& instanceUID);
    
    // Bulk operations
    QStringList listInstanceUIDs() const;
    void clear();
    
    // Error handling
    QString lastError() const { return m_lastError; }

private:
    QString m_filePath;
    QString m_lastError;
    QMap<QString, Keycard::PairingInfo> m_pairings;
    bool m_modified;
};

} // namespace StatusKeycard

