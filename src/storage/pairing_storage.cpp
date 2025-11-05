#include "storage/pairing_storage.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDebug>
#include <QDir>
#include <QStandardPaths>

// Helper: Create directories without using Qt 6.10-specific APIs
// This ensures compatibility with Qt 6.9 runtime even when built with Qt 6.10
static bool ensureDirectoryExists(const QString& path) {
    QDir dir(path);
    if (dir.exists()) {
        return true;
    }
    
    // Split path and create each component
    QStringList parts = path.split('/', Qt::SkipEmptyParts);
    QString currentPath;
    
    // Handle absolute vs relative paths
    if (path.startsWith('/')) {
        currentPath = "/";
    }
    
    for (const QString& part : parts) {
        if (!currentPath.isEmpty() && !currentPath.endsWith('/')) {
            currentPath += "/";
        }
        currentPath += part;
        
        QDir current(currentPath);
        if (!current.exists()) {
            // Use QDir's parent to create this directory
            // Create parent dir object for the path we want to create
            QString parentPath = currentPath;
            int lastSlash = parentPath.lastIndexOf('/');
            QString dirName = part;
            
            if (lastSlash > 0) {
                parentPath = parentPath.left(lastSlash);
            } else {
                parentPath = ".";
            }
            
            QDir parent(parentPath);
            if (!parent.exists()) {
                continue; // Will be created in next iteration
            }
            
            // Force the QString-only overload by using explicit function pointer
            // This avoids the Qt 6.10 overload with optional permissions parameter
            bool (QDir::*mkdirFunc)(const QString&) const = &QDir::mkdir;
            bool success = (parent.*mkdirFunc)(dirName);
            if (!success && !current.exists()) {
                return false;
            }
        }
    }
    
    return QDir(path).exists();
}

namespace StatusKeycard {

PairingStorage::PairingStorage(const QString& filePath)
    : m_filePath(filePath)
    , m_modified(false)
{
}

PairingStorage::~PairingStorage()
{
    if (m_modified) {
        qWarning() << "PairingStorage: Unsaved changes in" << m_filePath;
    }
}

bool PairingStorage::load()
{
    QFile file(m_filePath);
    
    if (!file.exists()) {
        qDebug() << "PairingStorage: File doesn't exist, starting fresh:" << m_filePath;
        m_pairings.clear();
        return true; // Not an error
    }
    
    if (!file.open(QIODevice::ReadOnly)) {
        m_lastError = QString("Failed to open file: %1").arg(file.errorString());
        return false;
    }
    
    QByteArray data = file.readAll();
    file.close();
    
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(data, &parseError);
    
    if (parseError.error != QJsonParseError::NoError) {
        m_lastError = QString("JSON parse error: %1").arg(parseError.errorString());
        return false;
    }
    
    if (!doc.isObject()) {
        m_lastError = "Root element must be an object";
        return false;
    }
    
    QJsonObject root = doc.object();
    m_pairings.clear();
    
    for (auto it = root.begin(); it != root.end(); ++it) {
        QString instanceUID = it.key();
        QJsonObject pairingObj = it.value().toObject();
        
        if (!pairingObj.contains("index") || !pairingObj.contains("key")) {
            qWarning() << "PairingStorage: Invalid pairing entry for" << instanceUID;
            continue;
        }
        
        int index = pairingObj["index"].toInt();
        QString keyHex = pairingObj["key"].toString();
        QByteArray key = QByteArray::fromHex(keyHex.toUtf8());
        
        if (key.isEmpty()) {
            qWarning() << "PairingStorage: Invalid key for" << instanceUID;
            continue;
        }
        
        Keycard::PairingInfo pairingInfo(key, index);
        m_pairings[instanceUID] = pairingInfo;
    }
    
    qDebug() << "PairingStorage: Loaded" << m_pairings.size() << "pairings from" << m_filePath;
    m_modified = false;
    return true;
}

bool PairingStorage::save()
{
    // Create directory if it doesn't exist
    QFileInfo fileInfo(m_filePath);
    QDir dir = fileInfo.absoluteDir();
    if (!dir.exists()) {
        // Use custom directory creation to avoid Qt 6.10 API
        if (!ensureDirectoryExists(dir.absolutePath())) {
            m_lastError = QString("Failed to create directory: %1").arg(dir.absolutePath());
            return false;
        }
    }
    
    QJsonObject root;
    
    for (auto it = m_pairings.begin(); it != m_pairings.end(); ++it) {
        QString instanceUID = it.key();
        const Keycard::PairingInfo& pairingInfo = it.value();
        
        QJsonObject pairingObj;
        pairingObj["index"] = pairingInfo.index;
        pairingObj["key"] = QString::fromUtf8(pairingInfo.key.toHex());
        
        root[instanceUID] = pairingObj;
    }
    
    QJsonDocument doc(root);
    QByteArray json = doc.toJson(QJsonDocument::Indented);
    
    QFile file(m_filePath);
    if (!file.open(QIODevice::WriteOnly)) {
        m_lastError = QString("Failed to open file for writing: %1").arg(file.errorString());
        return false;
    }
    
    qint64 written = file.write(json);
    file.close();
    
    if (written != json.size()) {
        m_lastError = "Failed to write complete file";
        return false;
    }
    
    qDebug() << "PairingStorage: Saved" << m_pairings.size() << "pairings to" << m_filePath;
    m_modified = false;
    return true;
}

bool PairingStorage::storePairing(const QString& instanceUID, const Keycard::PairingInfo& pairingInfo)
{
    if (instanceUID.isEmpty()) {
        m_lastError = "Instance UID cannot be empty";
        return false;
    }
    
    if (!pairingInfo.isValid()) {
        m_lastError = "Invalid pairing info";
        return false;
    }
    
    m_pairings[instanceUID] = pairingInfo;
    m_modified = true;
    
    qDebug() << "PairingStorage: Stored pairing for" << instanceUID 
             << "at index" << pairingInfo.index;
    return true;
}

Keycard::PairingInfo PairingStorage::loadPairing(const QString& instanceUID)
{
    if (!hasPairing(instanceUID)) {
        m_lastError = QString("No pairing found for %1").arg(instanceUID);
        return Keycard::PairingInfo();
    }
    
    return m_pairings[instanceUID];
}

bool PairingStorage::hasPairing(const QString& instanceUID) const
{
    return m_pairings.contains(instanceUID);
}

bool PairingStorage::removePairing(const QString& instanceUID)
{
    if (!hasPairing(instanceUID)) {
        m_lastError = QString("No pairing found for %1").arg(instanceUID);
        return false;
    }
    
    m_pairings.remove(instanceUID);
    m_modified = true;
    
    qDebug() << "PairingStorage: Removed pairing for" << instanceUID;
    return true;
}

QStringList PairingStorage::listInstanceUIDs() const
{
    return m_pairings.keys();
}

void PairingStorage::clear()
{
    if (!m_pairings.isEmpty()) {
        m_pairings.clear();
        m_modified = true;
        qDebug() << "PairingStorage: Cleared all pairings";
    }
}

} // namespace StatusKeycard

