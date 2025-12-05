#include "sign_flow.h"
#include "../flow_manager.h"
#include "../flow_params.h"
#include "../flow_signals.h"
#include <keycard-qt/command_set.h>
#include <QDebug>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

namespace StatusKeycard {

// Helper function to calculate recovery ID (V value) from signature
// Tries both possible V values (0 and 1) and returns the one that matches expectedPubKey
// Returns -1 if neither works
static int calculateRecoveryId(const QByteArray& hash, const QByteArray& r, const QByteArray& s, 
                                const QByteArray& expectedPubKey)
{
    if (hash.size() != 32 || r.size() != 32 || s.size() != 32 || expectedPubKey.size() != 65) {
        return -1;
    }
    
    // Create EC_KEY and set up for secp256k1
    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!eckey) {
        return -1;
    }
    
    const EC_GROUP* group = EC_KEY_get0_group(eckey);
    
    // Parse the expected public key
    EC_POINT* expected_point = EC_POINT_new(group);
    if (!expected_point || !EC_POINT_oct2point(group, expected_point, 
            reinterpret_cast<const unsigned char*>(expectedPubKey.data()), 65, nullptr)) {
        if (expected_point) EC_POINT_free(expected_point);
        EC_KEY_free(eckey);
        return -1;
    }
    
    // Convert r to a point on the curve
    // For ECDSA recovery, we need to find the point R on the curve where R.x = r
    // There are two possible points (with even and odd Y coordinates)
    BIGNUM* r_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(r.data()), 32, nullptr);
    BN_CTX* ctx = BN_CTX_new();
    
    int result = -1;
    
    // Try both possible Y coordinates (recovery ID 0 and 1)
    for (int rec_id = 0; rec_id <= 1; rec_id++) {
        EC_POINT* R = EC_POINT_new(group);
        if (!R) continue;
        
        // Set R.x = r and calculate R.y using the curve equation
        // y^2 = x^3 + 7 (for secp256k1)
        if (EC_POINT_set_compressed_coordinates(group, R, r_bn, rec_id, ctx) == 1) {
            // Now perform ECDSA recovery: Q = r^-1 * (s*R - e*G)
            // Where Q is the public key, e is the hash, G is the generator
            
            BIGNUM* s_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(s.data()), 32, nullptr);
            BIGNUM* e_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(hash.data()), 32, nullptr);
            BIGNUM* order = BN_new();
            BIGNUM* r_inv = BN_new();
            
            EC_GROUP_get_order(group, order, ctx);
            
            // Calculate r^-1 mod order
            if (BN_mod_inverse(r_inv, r_bn, order, ctx)) {
                // Calculate s*R
                EC_POINT* sR = EC_POINT_new(group);
                EC_POINT_mul(group, sR, nullptr, R, s_bn, ctx);
                
                // Calculate e*G
                EC_POINT* eG = EC_POINT_new(group);
                EC_POINT_mul(group, eG, e_bn, nullptr, nullptr, ctx);
                
                // Calculate s*R - e*G
                EC_POINT_invert(group, eG, ctx);
                EC_POINT_add(group, sR, sR, eG, ctx);
                
                // Calculate Q = r^-1 * (s*R - e*G)
                EC_POINT* Q = EC_POINT_new(group);
                EC_POINT_mul(group, Q, nullptr, sR, r_inv, ctx);
                
                // Compare with expected public key
                if (EC_POINT_cmp(group, Q, expected_point, ctx) == 0) {
                    result = rec_id;
                }
                
                EC_POINT_free(Q);
                EC_POINT_free(eG);
                EC_POINT_free(sR);
            }
            
            BN_free(r_inv);
            BN_free(order);
            BN_free(e_bn);
            BN_free(s_bn);
        }
        
        EC_POINT_free(R);
        
        if (result != -1) break;  // Found it!
    }
    
    BN_CTX_free(ctx);
    BN_free(r_bn);
    EC_POINT_free(expected_point);
    EC_KEY_free(eckey);
    
    return result;
}

SignFlow::SignFlow(FlowManager* manager, const QJsonObject& params, QObject* parent)
    : FlowBase(manager, FlowType::Sign, params, parent)
{
}

SignFlow::~SignFlow()
{
}

QJsonObject SignFlow::execute()
{
    qDebug() << "SignFlow: Starting";
    
    if (!selectKeycard() || !requireKeys()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "card-error";
        return error;
    }
    
    if (!verifyPIN()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "auth-failed";
        return error;
    }
    
    // Get tx hash
    QString txHash = params()[FlowParams::TX_HASH].toString();
    if (txHash.isEmpty()) {
        // Request transaction hash (empty error = normal request)
        pauseAndWait(FlowSignals::ENTER_TX_HASH, "");
        if (isCancelled()) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "cancelled";
            return error;
        }
        txHash = params()[FlowParams::TX_HASH].toString();
    }
    
    // Get path
    QString path = params()[FlowParams::BIP44_PATH].toString();
    if (path.isEmpty()) {
        // Request BIP44 path (empty error = normal request)
        pauseAndWait(FlowSignals::ENTER_PATH, "");
        if (isCancelled()) {
            QJsonObject error;
            error[FlowParams::ERROR_KEY] = "cancelled";
            return error;
        }
        path = params()[FlowParams::BIP44_PATH].toString();
    }
    
    // Sign with the specified path - use the full response version to get TLV data
    auto cmdSet = commandSet();
    QByteArray hashBytes = QByteArray::fromHex(txHash.toLatin1());
    QByteArray tlvResponse = cmdSet->signWithPathFullResponse(hashBytes, path);
    
    if (tlvResponse.isEmpty()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "sign-failed";
        return error;
    }
    
    // Extract signature and public key from TLV response
    // The response format (like Go's status-keycard-go):
    // - Template tag 0xA0 or 0xA1 contains:
    //   - Tag 0x80 (65 bytes): Public key
    //   - Tag 0x30 (variable): DER signature
    //
    // Strategy: Find template tag first, then scan inside it
    
    QByteArray publicKey;
    QByteArray derSignature;
    QByteArray scanData = tlvResponse;
    
    // First, check if response starts with template tag 0xA0 or 0xA1
        qDebug() << "SignFlow: tlvResponse size:" << tlvResponse.size() << "first byte:" << QString("0x%1").arg((uint8_t)tlvResponse[0], 2, 16, QChar('0'));
    if (tlvResponse.size() > 2) {
        uint8_t firstTag = static_cast<uint8_t>(tlvResponse[0]);
        qDebug() << "SignFlow: firstTag:" << QString("0x%1").arg(firstTag, 2, 16, QChar('0'));
        if (firstTag == 0xa0 || firstTag == 0xa1) {
            // Parse the template length and extract the inner data
            int idx = 1;
            uint8_t lenByte = static_cast<uint8_t>(tlvResponse[idx++]);
            int templateLen = 0;
            qDebug() << "SignFlow: Template lenByte:" << QString("0x%1").arg(lenByte, 2, 16, QChar('0'));
            
            if (lenByte & 0x80) {
                // Multi-byte length
                int numLenBytes = lenByte & 0x7F;
                qDebug() << "SignFlow: Multi-byte length, numLenBytes:" << numLenBytes << "idx:" << idx << "tlvResponse.size:" << tlvResponse.size();
                if (numLenBytes <= 3 && idx + numLenBytes <= tlvResponse.size()) {
                    for (int i = 0; i < numLenBytes; i++) {
                        templateLen = (templateLen << 8) | static_cast<uint8_t>(tlvResponse[idx++]);
                    }
                    qDebug() << "SignFlow: Found template tag, length:" << templateLen << "extracting from idx:" << idx;
                    // Scan inside the template data
                    scanData = tlvResponse.mid(idx, templateLen);
                    qDebug() << "SignFlow: scanData size:" << scanData.size() << "first byte:" << QString("0x%1").arg((uint8_t)scanData[0], 2, 16, QChar('0'));
                } else {
                    qWarning() << "SignFlow: Template extraction failed - numLenBytes:" << numLenBytes << "check failed";
                }
            } else {
                // Single-byte length
                templateLen = lenByte;
                qDebug() << "SignFlow: Found template tag, single-byte length:" << templateLen;
                scanData = tlvResponse.mid(idx, templateLen);
            }
        } else {
            qDebug() << "SignFlow: No template tag found, scanning raw response";
        }
    }
    
    // Now scan the data (either template contents or raw response) for public key and DER signature
    bool foundPubKey = false;
    bool foundDERSig = false;
    
    int idx = 0;
    while (idx < scanData.size() - 1 && !(foundPubKey && foundDERSig)) {
        uint8_t tag = static_cast<uint8_t>(scanData[idx++]);
        
        // Parse length (for ALL tags, even ones we don't care about)
        int length = 0;
        if (idx >= scanData.size()) break;
        uint8_t lenByte = static_cast<uint8_t>(scanData[idx++]);
        if (lenByte & 0x80) {
            int numLenBytes = lenByte & 0x7F;
            if (numLenBytes > 3 || idx + numLenBytes > scanData.size()) {
                qWarning() << "SignFlow: Invalid length encoding at idx" << (idx-1) << "numLenBytes:" << numLenBytes;
                break;
            }
            for (int i = 0; i < numLenBytes; i++) {
                length = (length << 8) | static_cast<uint8_t>(scanData[idx++]);
            }
        } else {
            length = lenByte;
        }
        
        // Validate length
        if (length < 0 || idx + length > scanData.size()) {
            qWarning() << "SignFlow: TLV length" << length << "exceeds data at idx" << idx;
            break;
        }
        
        // Process tags we care about (like Go's FindTag matching logic)
        if (tag == 0x80 && length == 65) {
            if (!foundPubKey) {
                publicKey = scanData.mid(idx, 65);
                foundPubKey = true;
                qDebug() << "SignFlow: Found public key at idx" << idx;
            }
        } else if (tag == 0x30) {
            // DER signature - include tag and length bytes
            int derStart = idx - 2;
            derSignature = scanData.mid(derStart, length + 2);
            foundDERSig = true;
            qDebug() << "SignFlow: Found DER signature at idx" << derStart << ", length:" << length;
        } else {
            // Unknown tag (including 0x00 null tags) - just log and skip
            qDebug() << "SignFlow: Skipping tag" << QString("0x%1").arg(tag, 2, 16, QChar('0')) << "length" << length << "at idx" << (idx-2);
        }
        
        // ALWAYS advance by the data length (critical for proper parsing!)
        idx += length;
    }
    
    if (!foundDERSig) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "der-signature-not-found";
        return error;
    }
    
    // Parse DER signature to extract R and S
    // DER format: 30 <len> 02 <rlen> <r> 02 <slen> <s>
    // Like Go's DERSignatureToRS, find the first and second 0x02 tags
    QByteArray r, s;
    
    int dIdx = 0;
    if (derSignature.size() < 6 || derSignature[dIdx++] != 0x30) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "invalid-der-format";
        return error;
    }
    
    // Skip DER sequence length byte
    dIdx++;
    
    // Find first INTEGER (tag 0x02) for R
    if (dIdx >= derSignature.size() || derSignature[dIdx++] != 0x02) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "der-r-tag-not-found";
        return error;
    }
    
    int rLen = static_cast<uint8_t>(derSignature[dIdx++]);
    if (dIdx + rLen > derSignature.size()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "der-r-length-invalid";
        return error;
    }
    
    QByteArray rValue = derSignature.mid(dIdx, rLen);
    dIdx += rLen;
    
    // DER pads with 0x00 if MSB is set - strip it to get 32 bytes
    if (rValue.size() > 32) {
        rValue = rValue.right(32);
    }
    // Pad if needed
    while (rValue.size() < 32) {
        rValue.prepend('\0');
    }
    r = rValue;
    
    // Find second INTEGER (tag 0x02) for S
    if (dIdx >= derSignature.size() || derSignature[dIdx++] != 0x02) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "der-s-tag-not-found";
        return error;
    }
    
    int sLen = static_cast<uint8_t>(derSignature[dIdx++]);
    if (dIdx + sLen > derSignature.size()) {
        QJsonObject error;
        error[FlowParams::ERROR_KEY] = "der-s-length-invalid";
        return error;
    }
    
    QByteArray sValue = derSignature.mid(dIdx, sLen);
    
    // DER pads with 0x00 if MSB is set - strip it to get 32 bytes
    if (sValue.size() > 32) {
        sValue = sValue.right(32);
    }
    // Pad if needed
    while (sValue.size() < 32) {
        sValue.prepend('\0');
    }
    s = sValue;
    
    // Calculate V using ECDSA recovery (like Go's calculateV)
    // Try recovery IDs 0-3 and pick the one that recovers to the correct public key
    uint8_t v = 27; // Default
    
    if (publicKey.isEmpty()) {
        qWarning() << "SignFlow: No public key found, defaulting V=27";
    } else {
        int recoveryId = calculateRecoveryId(hashBytes, r, s, publicKey);
        if (recoveryId == -1) {
            qWarning() << "SignFlow: ECDSA recovery failed, defaulting V=27";
        } else {
            v = static_cast<uint8_t>(recoveryId + 27);
            qDebug() << "SignFlow: Calculated V=" << v << "(recovery ID" << recoveryId << ")";
        }
    }
    
    // Build signature object with r, s, v components
    QJsonObject sigObj;
    sigObj["r"] = QString::fromLatin1(r.toHex());
    sigObj["s"] = QString::fromLatin1(s.toHex());
    sigObj["v"] = static_cast<int>(v);
    
    QJsonObject result = buildCardInfoJson();
    result[FlowParams::TX_SIGNATURE] = sigObj;
    
    qDebug() << "SignFlow: Complete";
    return result;
}

} // namespace StatusKeycard

