#include "file_pairing_storage.h"
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QJsonDocument>
#include <QDebug>

namespace StatusKeycard {

FilePairingStorage::FilePairingStorage()
{
}   

void FilePairingStorage::setPath(const QString& filePath)
{
    m_filePath = filePath;
}

QJsonObject FilePairingStorage::loadAllPairings()
{
    QFile file(m_filePath);

    if (!file.exists()) {
        QFileInfo fileInfo(m_filePath);
        QDir dir = fileInfo.dir();
        if (!dir.exists()) {
            if (!dir.mkpath(".")) {
                qWarning() << "FilePairingStorage: Failed to create storage directory:" << dir.absolutePath();
                return QJsonObject();
            }
        }

        if (!file.open(QIODevice::WriteOnly)) {
            qWarning() << "FilePairingStorage: Failed to create storage file:" << m_filePath;
            return QJsonObject();
        }
        file.write("{}");
        file.close();
    }
    
    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "FilePairingStorage: Failed to open storage file:" << m_filePath;
        return QJsonObject();
    }
    
    QByteArray data = file.readAll();
    file.close();
    
    if (data.isEmpty()) {
        qDebug() << "FilePairingStorage: Storage file is empty";
        return QJsonObject();
    }
    
    QJsonDocument doc = QJsonDocument::fromJson(data);
    if (!doc.isObject()) {
        qWarning() << "FilePairingStorage: Invalid JSON in storage file";
        return QJsonObject();
    }
    
    return doc.object();
}

bool FilePairingStorage::saveAllPairings(const QJsonObject& pairings)
{
    QFile file(m_filePath);
    
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qWarning() << "FilePairingStorage: Failed to open storage file for writing:" << m_filePath;
        return false;
    }
    
    QJsonDocument doc(pairings);
    QByteArray data = doc.toJson(QJsonDocument::Compact);
    
    qint64 written = file.write(data);
    file.close();
    
    if (written != data.size()) {
        qWarning() << "FilePairingStorage: Failed to write complete data";
        return false;
    }
    
    return true;
}

Keycard::PairingInfo FilePairingStorage::load(const QString& cardInstanceUID)
{
    qDebug() << "FilePairingStorage: Loading pairing for card:" << cardInstanceUID;
    
    QJsonObject allPairings = loadAllPairings();
    
    if (!allPairings.contains(cardInstanceUID)) {
        qDebug() << "FilePairingStorage: No pairing found for card:" << cardInstanceUID;
        return Keycard::PairingInfo();
    }
    
    QJsonValue pairingValue = allPairings[cardInstanceUID];
    if (!pairingValue.isObject()) {
        qWarning() << "FilePairingStorage: Invalid pairing data for card:" << cardInstanceUID;
        return Keycard::PairingInfo();
    }
    
    QJsonObject pairingObj = pairingValue.toObject();
    
    // Parse pairing info
    Keycard::PairingInfo pairing;
    pairing.key = QByteArray::fromHex(pairingObj["key"].toString().toUtf8());
    pairing.index = pairingObj["index"].toInt();
    
    if (!pairing.isValid()) {
        qWarning() << "FilePairingStorage: Loaded invalid pairing data for card:" << cardInstanceUID;
        return Keycard::PairingInfo();
    }
    
    qDebug() << "FilePairingStorage: Successfully loaded pairing, index:" << pairing.index;
    return pairing;
}

bool FilePairingStorage::save(const QString& cardInstanceUID, const Keycard::PairingInfo& pairing)
{
    qDebug() << "FilePairingStorage: Saving pairing for card:" << cardInstanceUID << "index:" << pairing.index;
    
    if (!pairing.isValid()) {
        qWarning() << "FilePairingStorage: Cannot save invalid pairing";
        return false;
    }
    
    // Load all existing pairings
    QJsonObject allPairings = loadAllPairings();
    
    // Create pairing object
    QJsonObject pairingObj;
    pairingObj["key"] = QString(pairing.key.toHex());
    pairingObj["index"] = pairing.index;
    
    // Add/update this card's pairing
    allPairings[cardInstanceUID] = pairingObj;
    
    // Save all pairings back
    if (!saveAllPairings(allPairings)) {
        qWarning() << "FilePairingStorage: Failed to save pairings";
        return false;
    }
    
    qDebug() << "FilePairingStorage: Successfully saved pairing for card:" << cardInstanceUID;
    return true;
}

bool FilePairingStorage::remove(const QString& cardInstanceUID)
{
    qDebug() << "FilePairingStorage: Removing pairing for card:" << cardInstanceUID;
    
    // Load all existing pairings
    QJsonObject allPairings = loadAllPairings();
    
    if (!allPairings.contains(cardInstanceUID)) {
        qDebug() << "FilePairingStorage: No pairing found to remove for card:" << cardInstanceUID;
        return true;  // Already gone
    }
    
    // Remove this card's pairing
    allPairings.remove(cardInstanceUID);
    
    // Save updated pairings back
    if (!saveAllPairings(allPairings)) {
        qWarning() << "FilePairingStorage: Failed to save pairings after removal";
        return false;
    }
    
    qDebug() << "FilePairingStorage: Successfully removed pairing for card:" << cardInstanceUID;
    return true;
}

} // namespace StatusKeycard
