#include "get_metadata_flow.h"
#include "../flow_manager.h"
#include "../flow_params.h"
#include <keycard-qt/command_set.h>
#include <QJsonArray>
#include <QCryptographicHash>

namespace StatusKeycard {

// Helper: Find TLV tag in data
static QByteArray findTlvTag(const QByteArray& data, uint8_t tag) {
    int offset = 0;
    while (offset < data.size()) {
        if (offset + 2 > data.size()) break;
        
        uint8_t t = static_cast<uint8_t>(data[offset]);
        if (t == tag) {
            // Found the tag, parse length
            int lenOffset = offset + 1;
            int length = static_cast<uint8_t>(data[lenOffset]);
            int dataOffset = lenOffset + 1;
            
            // Handle extended length (if bit 7 is set)
            if (length & 0x80) {
                int numLengthBytes = length & 0x7F;
                if (dataOffset + numLengthBytes > data.size()) break;
                length = 0;
                for (int i = 0; i < numLengthBytes; i++) {
                    length = (length << 8) | static_cast<uint8_t>(data[dataOffset + i]);
                }
                dataOffset += numLengthBytes;
            }
            
            if (dataOffset + length > data.size()) break;
            return data.mid(dataOffset, length);
        }
        
        // Skip this tag
        int lenOffset = offset + 1;
        if (lenOffset >= data.size()) break;
        int length = static_cast<uint8_t>(data[lenOffset]);
        int dataOffset = lenOffset + 1;
        
        if (length & 0x80) {
            int numLengthBytes = length & 0x7F;
            if (dataOffset + numLengthBytes > data.size()) break;
            length = 0;
            for (int i = 0; i < numLengthBytes; i++) {
                length = (length << 8) | static_cast<uint8_t>(data[dataOffset + i]);
            }
            dataOffset += numLengthBytes;
        }
        
        offset = dataOffset + length;
    }
    
    return QByteArray();
}

GetMetadataFlow::GetMetadataFlow(FlowManager* mgr, const QJsonObject& params, QObject* parent)
    : FlowBase(mgr, FlowType::GetMetadata, params, parent) {}

QJsonObject GetMetadataFlow::execute()
{
    // Get metadata from card (matching status-keycard-go)
    qDebug() << "GetMetadataFlow: Getting metadata from card";
    QByteArray metadataData = commandSet()->getData(Keycard::APDU::P1StoreDataPublic);  // 0x00
    
    // Check if data looks like a status word (error response)
    // Status words are 2 bytes: SW1 SW2 (e.g. 0x6a86 = no data available)
    if (metadataData.size() == 2) {
        uint16_t sw = (static_cast<uint8_t>(metadataData[0]) << 8) | static_cast<uint8_t>(metadataData[1]);
        if (sw != 0x9000) {  // Not success
            qDebug() << "GetMetadataFlow: Card returned status word:" << QString("0x%1").arg(sw, 4, 16, QChar('0'));
            qDebug() << "GetMetadataFlow: No metadata on card (error or empty)";
            QJsonObject metadata;
            metadata["name"] = "";
            metadata["wallets"] = QJsonArray();
            
            QJsonObject result = buildCardInfoJson();
            result[FlowParams::CARD_META] = metadata;
            return result;
        }
    }
    
    // If no metadata on card, return error "no-data" (matching Go behavior)
    if (metadataData.isEmpty()) {
        qDebug() << "GetMetadataFlow: No metadata on card";
        QJsonObject result = buildCardInfoJson();
        result[FlowParams::ERROR_KEY] = "no-data";
        return result;
    }
    
    // Parse metadata using Go's custom binary format (matching types/metadata.go ParseMetadata())
    // Format: [version+namelen][name][start/count pairs in LEB128]
    //   Byte 0: version (3 bits) + name length (5 bits)
    //   Bytes 1..namelen: card name
    //   Remaining: series of start/count LEB128 pairs for wallet paths
    
    QJsonObject metadata;
    metadata["name"] = "";
    metadata["wallets"] = QJsonArray();
    
    int offset = 0;
    if (offset >= metadataData.size()) {
        qDebug() << "GetMetadataFlow: Metadata too short";
        QJsonObject result = buildCardInfoJson();
        result[FlowParams::CARD_META] = metadata;
        return result;
    }
    
    // Parse header byte
    uint8_t header = static_cast<uint8_t>(metadataData[offset++]);
    uint8_t version = header >> 5;
    uint8_t namelen = header & 0x1F;
    
    if (version != 1) {
        qWarning() << "GetMetadataFlow: Invalid metadata version:" << version;
        QJsonObject result = buildCardInfoJson();
        result[FlowParams::CARD_META] = metadata;
        return result;
    }
    
    // Parse card name
    if (namelen > 0) {
        if (offset + namelen > metadataData.size()) {
            qWarning() << "GetMetadataFlow: Metadata too short for name";
            QJsonObject result = buildCardInfoJson();
            result[FlowParams::CARD_META] = metadata;
            return result;
        }
        QByteArray nameData = metadataData.mid(offset, namelen);
        metadata["name"] = QString::fromUtf8(nameData);
        offset += namelen;
        qDebug() << "GetMetadataFlow: Card name:" << metadata["name"].toString();
    }
    
    // Parse wallet paths (LEB128 encoded start/count pairs)
    QJsonArray wallets;
    while (offset < metadataData.size()) {
        // Parse start index (LEB128)
        uint32_t start = 0;
        int shift = 0;
        while (offset < metadataData.size()) {
            uint8_t byte = static_cast<uint8_t>(metadataData[offset++]);
            start |= (byte & 0x7F) << shift;
            if ((byte & 0x80) == 0) break;
            shift += 7;
        }
        
        if (offset >= metadataData.size()) break;
        
        // Parse count (LEB128)
        uint32_t count = 0;
        shift = 0;
        while (offset < metadataData.size()) {
            uint8_t byte = static_cast<uint8_t>(metadataData[offset++]);
            count |= (byte & 0x7F) << shift;
            if ((byte & 0x80) == 0) break;
            shift += 7;
        }
        
        // Add all paths in range [start, start+count]
        for (uint32_t i = start; i <= start + count; ++i) {
            QString walletPath = QString("m/44'/60'/0'/0/%1").arg(i);
            QJsonObject wallet;
            wallet["path"] = walletPath;
            wallets.append(wallet);
        }
    }
    
    metadata["wallets"] = wallets;
    qDebug() << "GetMetadataFlow: Found" << wallets.size() << "wallets";
    
    // If resolve-addresses requested, authenticate and export keys
    // (matching Go: authenticate ONCE before wallet loop, even if no wallets)
    bool resolveAddr = params().value(FlowParams::RESOLVE_ADDR).toBool();
    if (resolveAddr) {
        // Check if card has keys
        if (cardInfo().keyUID.isEmpty()) {
            qWarning() << "GetMetadataFlow: Cannot resolve addresses - card has no keys";
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "no-keys";
            error[FlowParams::INSTANCE_UID] = cardInfo().instanceUID;
            error[FlowParams::KEY_UID] = cardInfo().keyUID;
            error[FlowParams::CARD_META] = metadata;
            return error;
        }
        
        // Authenticate ONCE (will pause for PIN if needed - matching Go behavior)
        qDebug() << "GetMetadataFlow: Authenticating for address resolution";
        if (!verifyPIN()) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "auth-failed";
            return error;
        }
        
        // Export master address if requested
        bool exportMaster = params().value(FlowParams::EXPORT_MASTER).toBool();
        if (exportMaster) {
            qDebug() << "GetMetadataFlow: Exporting master address";
            QByteArray masterKeyData = commandSet()->exportKey(true, false, "m");
            if (!masterKeyData.isEmpty()) {
                // Parse TLV structure to extract public key, private key, and chain code
                QByteArray publicKey;
                QByteArray privateKey;
                QByteArray chainCode;
                
                // Find tag 0xA1 (ExportKeyTemplate)
                int offset = 0;
                if (offset < masterKeyData.size() && static_cast<uint8_t>(masterKeyData[offset]) == 0xA1) {
                    offset++; // Skip tag
                    if (offset < masterKeyData.size()) {
                        int templateLen = static_cast<uint8_t>(masterKeyData[offset++]);
                        
                        // Search for tags 0x80 (public key), 0x81 (private key), and 0x82 (chain code)
                        while (offset < masterKeyData.size() && offset < templateLen + 2) {
                            uint8_t tag = static_cast<uint8_t>(masterKeyData[offset++]);
                            if (offset >= masterKeyData.size()) break;
                            
                            uint8_t len = static_cast<uint8_t>(masterKeyData[offset++]);
                            if (offset + len > masterKeyData.size()) break;
                            
                            if (tag == 0x80) {  // Public key tag
                                publicKey = masterKeyData.mid(offset, len);
                            } else if (tag == 0x81) {  // Private key tag
                                privateKey = masterKeyData.mid(offset, len);
                            } else if (tag == 0x82) {  // Chain code tag
                                chainCode = masterKeyData.mid(offset, len);
                            }
                            offset += len;
                        }
                    }
                }
                
                if (publicKey.size() == 65 && static_cast<uint8_t>(publicKey[0]) == 0x04) {
                    // Derive Ethereum address from master public key
                    QByteArray pubKeyData = publicKey.mid(1);  // Remove 0x04 prefix
                    QByteArray hash = QCryptographicHash::hash(pubKeyData, QCryptographicHash::Keccak_256);
                    QByteArray addressBytes = hash.right(20);  // Last 20 bytes
                    QString masterAddress = QString("0x") + addressBytes.toHex();
                    
                    // Store master key data in metadata
                    metadata["masterAddress"] = masterAddress;
                    metadata["masterPublicKey"] = QString::fromLatin1(publicKey.toHex());
                    if (!privateKey.isEmpty()) {
                        metadata["masterPrivateKey"] = QString::fromLatin1(privateKey.toHex());
                    }
                    if (!chainCode.isEmpty()) {
                        metadata["masterChainCode"] = QString::fromLatin1(chainCode.toHex());
                    }
                } else {
                    qWarning() << "GetMetadataFlow: Invalid master public key format, size=" << publicKey.size();
                }
            }
        }
        
        // Now export keys for each wallet
        QJsonArray wallets = metadata["wallets"].toArray();
        for (int i = 0; i < wallets.size(); ++i) {
            QJsonObject wallet = wallets[i].toObject();
            QString walletPath = wallet["path"].toString();
            
            QByteArray keyData = commandSet()->exportKey(true, false, walletPath);
            if (!keyData.isEmpty()) {
                // Parse TLV structure to extract public key, private key, and chain code
                // Format: Tag 0xA1 (template) -> Tag 0x80 (public key), Tag 0x81 (private key), Tag 0x82 (chain code)
                QByteArray publicKey;
                QByteArray privateKey;
                QByteArray chainCode;
                
                // Find tag 0xA1 (ExportKeyTemplate)
                int offset = 0;
                if (offset < keyData.size() && static_cast<uint8_t>(keyData[offset]) == 0xA1) {
                    offset++; // Skip tag
                    if (offset < keyData.size()) {
                        int templateLen = static_cast<uint8_t>(keyData[offset++]);
                        
                        // Search for tags 0x80 (public key), 0x81 (private key), and 0x82 (chain code)
                        while (offset < keyData.size() && offset < templateLen + 2) {
                            uint8_t tag = static_cast<uint8_t>(keyData[offset++]);
                            if (offset >= keyData.size()) break;
                            
                            uint8_t len = static_cast<uint8_t>(keyData[offset++]);
                            if (offset + len > keyData.size()) break;
                            
                            if (tag == 0x80) {  // Public key tag
                                publicKey = keyData.mid(offset, len);
                            } else if (tag == 0x81) {  // Private key tag
                                privateKey = keyData.mid(offset, len);
                            } else if (tag == 0x82) {  // Chain code tag
                                chainCode = keyData.mid(offset, len);
                            }
                            offset += len;
                        }
                    }
                }
                
                if (publicKey.size() == 65 && static_cast<uint8_t>(publicKey[0]) == 0x04) {
                    // Store hex-encoded public key
                    wallet["publicKey"] = QString::fromLatin1(publicKey.toHex());
                    wallet["address"] = FlowBase::publicKeyToAddress(publicKey);
                    
                    // Store hex-encoded private key (if present) - marked as omitempty in Go
                    if (!privateKey.isEmpty()) {
                        wallet["privateKey"] = QString::fromLatin1(privateKey.toHex());
                    }
                    
                    // Store hex-encoded chain code (if present)
                    if (!chainCode.isEmpty()) {
                        wallet["chainCode"] = QString::fromLatin1(chainCode.toHex());
                    }
                    
                } else {
                    qWarning() << "GetMetadataFlow: Invalid public key format, size=" << publicKey.size();
                }
            }
            
            wallets[i] = wallet;
        }
        metadata["wallets"] = wallets;
    }
    
    QJsonObject result = buildCardInfoJson();
    result[FlowParams::CARD_META] = metadata;
    
    return result;
}

} // namespace StatusKeycard

