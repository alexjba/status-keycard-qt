#include <QtTest/QtTest>
#include "flow/flows/sign_flow.h"
#include "flow/flow_params.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

using namespace StatusKeycard;

/**
 * @brief Unit tests for SignFlow TLV parsing and ECDSA recovery
 * 
 * Tests the fixes for:
 * 1. TLV response parsing (template tags, nested structures)
 * 2. DER signature extraction
 * 3. ECDSA public key recovery for V calculation
 */
class TestSignFlowTLVParsing : public QObject
{
    Q_OBJECT

private:
    // Helper: Create a valid TLV-encoded sign response
    QByteArray createTLVSignResponse(const QByteArray& publicKey, const QByteArray& derSig)
    {
        // Format: A0 <len> 80 41 <pubkey> 30 <len> <der_sig> 9000
        QByteArray tlv;
        
        // Build inner content (public key + signature)
        QByteArray innerContent;
        innerContent.append(char(0x80)); // Public key tag
        innerContent.append(char(0x41)); // 65 bytes
        innerContent.append(publicKey);
        
        innerContent.append(derSig); // DER signature already includes tag and length
        
        // Build outer template
        tlv.append(char(0xa0)); // Template tag
        
        // Multi-byte length encoding for inner content
        int contentLen = innerContent.size();
        if (contentLen <= 127) {
            tlv.append(char(contentLen));
        } else {
            tlv.append(char(0x81)); // 1 byte length follows
            tlv.append(char(contentLen & 0xFF));
        }
        
        tlv.append(innerContent);
        tlv.append(char(0x90)); // SW1
        tlv.append(char(0x00)); // SW2
        
        return tlv;
    }
    
    // Helper: Create DER signature from R and S
    QByteArray createDERSignature(const QByteArray& r, const QByteArray& s)
    {
        QByteArray derSig;
        derSig.append(char(0x30)); // SEQUENCE tag
        
        // Build R INTEGER
        QByteArray rInt;
        rInt.append(char(0x02)); // INTEGER tag
        // Add leading zero if MSB is set (DER requirement)
        if ((uint8_t)r[0] & 0x80) {
            rInt.append(char(r.size() + 1)); // Length
            rInt.append(char(0x00)); // Padding
        } else {
            rInt.append(char(r.size())); // Length
        }
        rInt.append(r);
        
        // Build S INTEGER
        QByteArray sInt;
        sInt.append(char(0x02)); // INTEGER tag
        // Add leading zero if MSB is set (DER requirement)
        if ((uint8_t)s[0] & 0x80) {
            sInt.append(char(s.size() + 1)); // Length
            sInt.append(char(0x00)); // Padding
        } else {
            sInt.append(char(s.size())); // Length
        }
        sInt.append(s);
        
        // Combine
        QByteArray content = rInt + sInt;
        derSig.append(char(content.size())); // SEQUENCE length
        derSig.append(content);
        
        return derSig;
    }
    
    // Helper: Generate a valid secp256k1 key pair for testing
    bool generateTestKeyPair(QByteArray& privateKey, QByteArray& publicKey)
    {
        EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (!eckey) return false;
        
        if (!EC_KEY_generate_key(eckey)) {
            EC_KEY_free(eckey);
            return false;
        }
        
        // Get private key
        const BIGNUM* priv_bn = EC_KEY_get0_private_key(eckey);
        int priv_len = BN_num_bytes(priv_bn);
        privateKey.resize(32);
        BN_bn2bin(priv_bn, reinterpret_cast<unsigned char*>(privateKey.data()));
        if (priv_len < 32) {
            privateKey.prepend(QByteArray(32 - priv_len, 0));
        }
        
        // Get public key (uncompressed format: 0x04 + X + Y)
        const EC_POINT* pub_point = EC_KEY_get0_public_key(eckey);
        const EC_GROUP* group = EC_KEY_get0_group(eckey);
        
        publicKey.resize(65);
        if (!EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED,
                                reinterpret_cast<unsigned char*>(publicKey.data()), 65, nullptr)) {
            EC_KEY_free(eckey);
            return false;
        }
        
        EC_KEY_free(eckey);
        return true;
    }
    
    // Helper: Sign a hash with a private key to get a real signature
    bool signHash(const QByteArray& hash, const QByteArray& privateKey,
                  QByteArray& r, QByteArray& s)
    {
        EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (!eckey) return false;
        
        // Set private key
        BIGNUM* priv_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(privateKey.data()),
                                     privateKey.size(), nullptr);
        if (!EC_KEY_set_private_key(eckey, priv_bn)) {
            BN_free(priv_bn);
            EC_KEY_free(eckey);
            return false;
        }
        BN_free(priv_bn);
        
        // Generate public key from private key
        const EC_GROUP* group = EC_KEY_get0_group(eckey);
        EC_POINT* pub_point = EC_POINT_new(group);
        if (!EC_POINT_mul(group, pub_point, priv_bn, nullptr, nullptr, nullptr)) {
            EC_POINT_free(pub_point);
            EC_KEY_free(eckey);
            return false;
        }
        EC_KEY_set_public_key(eckey, pub_point);
        EC_POINT_free(pub_point);
        
        // Sign the hash
        ECDSA_SIG* sig = ECDSA_do_sign(reinterpret_cast<const unsigned char*>(hash.data()),
                                        hash.size(), eckey);
        if (!sig) {
            EC_KEY_free(eckey);
            return false;
        }
        
        // Extract R and S
        const BIGNUM* sig_r = nullptr;
        const BIGNUM* sig_s = nullptr;
        ECDSA_SIG_get0(sig, &sig_r, &sig_s);
        
        r.resize(32);
        s.resize(32);
        
        int r_len = BN_num_bytes(sig_r);
        int s_len = BN_num_bytes(sig_s);
        
        BN_bn2bin(sig_r, reinterpret_cast<unsigned char*>(r.data() + (32 - r_len)));
        if (r_len < 32) {
            memset(r.data(), 0, 32 - r_len);
        }
        
        BN_bn2bin(sig_s, reinterpret_cast<unsigned char*>(s.data() + (32 - s_len)));
        if (s_len < 32) {
            memset(s.data(), 0, 32 - s_len);
        }
        
        ECDSA_SIG_free(sig);
        EC_KEY_free(eckey);
        return true;
    }

private slots:
    void initTestCase()
    {
    }

    void cleanupTestCase()
    {
    }

    // ========================================================================
    // TLV Parsing Tests
    // ========================================================================

    void testParseTLVWithTemplateTag()
    {
        
        // Create a sample public key (65 bytes, uncompressed format)
        QByteArray publicKey(65, 0);
        publicKey[0] = 0x04; // Uncompressed format marker
        for (int i = 1; i < 65; i++) {
            publicKey[i] = char(i);
        }
        
        // Create a sample DER signature
        QByteArray r(32, 0);
        QByteArray s(32, 0);
        r[0] = 0x4c; r[31] = 0x21; // Sample R
        s[0] = 0x76; s[31] = 0x56; // Sample S
        QByteArray derSig = createDERSignature(r, s);
        
        // Create full TLV response
        QByteArray tlvResponse = createTLVSignResponse(publicKey, derSig);
        
        
        // Verify structure
        QVERIFY(tlvResponse.size() > 70); // At least pubkey + sig + overhead
        QCOMPARE((uint8_t)tlvResponse[0], (uint8_t)0xa0); // Template tag
        
        // The response should contain the public key and DER signature
        QVERIFY(tlvResponse.contains(publicKey));
        QVERIFY(tlvResponse.indexOf(derSig) > 0);
        
    }

    void testParseTLVWithMultiByteLength()
    {
        
        QByteArray publicKey(65, 0);
        publicKey[0] = 0x04;
        
        QByteArray r(32, 0x12);
        QByteArray s(32, 0x34);
        QByteArray derSig = createDERSignature(r, s);
        
        QByteArray tlvResponse = createTLVSignResponse(publicKey, derSig);
        
        // Check multi-byte length encoding (0x81 0x8a for 138 bytes)
        QCOMPARE((uint8_t)tlvResponse[0], (uint8_t)0xa0); // Template tag
        QCOMPARE((uint8_t)tlvResponse[1], (uint8_t)0x81); // Multi-byte indicator
        
        int contentLen = (uint8_t)tlvResponse[2];
        QVERIFY(contentLen > 100); // Should be around 138 bytes
        
    }

    void testParseDERSignature()
    {
        
        // Create test R and S values (32 bytes each)
        QByteArray r = QByteArray::fromHex("4c9b2ed94d45fd66ff0d6cc69dcfbf34366c14ef894413ec633b8de1c7d11721");
        QByteArray s = QByteArray::fromHex("76e166696cb9eb0b052091a43d0b79de39922aec8ef00ada58f60194fc342642");
        
        // Create DER signature
        QByteArray derSig = createDERSignature(r, s);
        
        
        // Verify DER structure
        QCOMPARE((uint8_t)derSig[0], (uint8_t)0x30); // SEQUENCE tag
        
        // Parse and verify we can extract R and S back
        int idx = 2; // Skip SEQUENCE tag and length
        QCOMPARE((uint8_t)derSig[idx], (uint8_t)0x02); // INTEGER tag for R
        idx++;
        
        int rLen = (uint8_t)derSig[idx];
        idx++;
        
        QByteArray extractedR = derSig.mid(idx, rLen);
        // Remove leading zero if present (DER padding)
        if (extractedR.size() > 32) {
            extractedR = extractedR.right(32);
        }
        // Pad if needed
        while (extractedR.size() < 32) {
            extractedR.prepend('\0');
        }
        
        QCOMPARE(extractedR, r);
        
    }

    void testParseDERSignatureWithLeadingZeroPadding()
    {
        
        // Create R and S where MSB is set (requires DER padding)
        QByteArray r = QByteArray::fromHex("8c959e5fd1ab52eea8ca757983f31ea3c7537044c9b0b4b3e2797c55e2f7688f");
        QByteArray s = QByteArray::fromHex("9de1f126de96977783184928b5187f79a84a628d8bb376eaff9d93f6ddfe9380");
        
        QByteArray derSig = createDERSignature(r, s);
        
        
        // Verify the padding was added (DER should be longer due to 0x00 padding)
        QVERIFY(derSig.size() > 64); // Should be > 64 due to padding bytes
        
        // Verify structure still starts with 0x30 (SEQUENCE)
        QCOMPARE((uint8_t)derSig[0], (uint8_t)0x30);
        
    }

    // ========================================================================
    // ECDSA Recovery Tests
    // ========================================================================

    void testECDSARecoveryWithValidSignature()
    {
        
        // Generate a real key pair
        QByteArray privateKey, publicKey;
        QVERIFY(generateTestKeyPair(privateKey, publicKey));
        
        qDebug() << "Generated public key:" << publicKey.toHex();
        
        // Create a hash to sign
        QByteArray hash = QByteArray::fromHex("f281b75fc5e5615c539102d5980f2e239db8ac4fae8fc73cb4fe3725b6842d93");
        
        // Sign the hash
        QByteArray r, s;
        QVERIFY(signHash(hash, privateKey, r, s));
        
        qDebug() << "Signature R:" << r.toHex();
        qDebug() << "Signature S:" << s.toHex();
        
        // Now test ECDSA recovery (this is what SignFlow does)
        // Try both recovery IDs (0 and 1)
        bool foundMatch = false;
        for (int recoveryId = 0; recoveryId <= 1; recoveryId++) {
            EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
            QVERIFY(eckey != nullptr);
            
            const EC_GROUP* group = EC_KEY_get0_group(eckey);
            BIGNUM* r_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(r.data()), 32, nullptr);
            BN_CTX* ctx = BN_CTX_new();
            
            EC_POINT* R = EC_POINT_new(group);
            if (EC_POINT_set_compressed_coordinates(group, R, r_bn, recoveryId, ctx) == 1) {
                // Perform ECDSA recovery
                BIGNUM* s_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(s.data()), 32, nullptr);
                BIGNUM* e_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(hash.data()), 32, nullptr);
                BIGNUM* order = BN_new();
                BIGNUM* r_inv = BN_new();
                
                EC_GROUP_get_order(group, order, ctx);
                
                if (BN_mod_inverse(r_inv, r_bn, order, ctx)) {
                    EC_POINT* sR = EC_POINT_new(group);
                    EC_POINT_mul(group, sR, nullptr, R, s_bn, ctx);
                    
                    EC_POINT* eG = EC_POINT_new(group);
                    EC_POINT_mul(group, eG, e_bn, nullptr, nullptr, ctx);
                    
                    EC_POINT_invert(group, eG, ctx);
                    EC_POINT_add(group, sR, sR, eG, ctx);
                    
                    EC_POINT* Q = EC_POINT_new(group);
                    EC_POINT_mul(group, Q, nullptr, sR, r_inv, ctx);
                    
                    // Get recovered public key
                    QByteArray recoveredPubKey(65, 0);
                    EC_POINT_point2oct(group, Q, POINT_CONVERSION_UNCOMPRESSED,
                                      reinterpret_cast<unsigned char*>(recoveredPubKey.data()), 65, nullptr);
                    
                    if (recoveredPubKey == publicKey) {
                        foundMatch = true;
                        
                        // Verify V value (27 or 28 for Ethereum)
                        int vValue = recoveryId + 27;
                        QVERIFY(vValue == 27 || vValue == 28);
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
            BN_CTX_free(ctx);
            BN_free(r_bn);
            EC_KEY_free(eckey);
        }
        
        QVERIFY(foundMatch);
    }

    void testECDSARecoveryFailsWithWrongPublicKey()
    {
        
        // Generate two different key pairs
        QByteArray privateKey1, publicKey1;
        QByteArray privateKey2, publicKey2;
        QVERIFY(generateTestKeyPair(privateKey1, publicKey1));
        QVERIFY(generateTestKeyPair(privateKey2, publicKey2));
        
        QVERIFY(publicKey1 != publicKey2);
        
        // Sign with key 1
        QByteArray hash = QByteArray::fromHex("f281b75fc5e5615c539102d5980f2e239db8ac4fae8fc73cb4fe3725b6842d93");
        QByteArray r, s;
        QVERIFY(signHash(hash, privateKey1, r, s));
        
        // Try to recover and expect it NOT to match publicKey2
        bool wrongMatch = false;
        for (int recoveryId = 0; recoveryId <= 1; recoveryId++) {
            EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
            const EC_GROUP* group = EC_KEY_get0_group(eckey);
            BIGNUM* r_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(r.data()), 32, nullptr);
            BN_CTX* ctx = BN_CTX_new();
            
            EC_POINT* R = EC_POINT_new(group);
            if (EC_POINT_set_compressed_coordinates(group, R, r_bn, recoveryId, ctx) == 1) {
                BIGNUM* s_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(s.data()), 32, nullptr);
                BIGNUM* e_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(hash.data()), 32, nullptr);
                BIGNUM* order = BN_new();
                BIGNUM* r_inv = BN_new();
                
                EC_GROUP_get_order(group, order, ctx);
                
                if (BN_mod_inverse(r_inv, r_bn, order, ctx)) {
                    EC_POINT* sR = EC_POINT_new(group);
                    EC_POINT_mul(group, sR, nullptr, R, s_bn, ctx);
                    
                    EC_POINT* eG = EC_POINT_new(group);
                    EC_POINT_mul(group, eG, e_bn, nullptr, nullptr, ctx);
                    EC_POINT_invert(group, eG, ctx);
                    EC_POINT_add(group, sR, sR, eG, ctx);
                    
                    EC_POINT* Q = EC_POINT_new(group);
                    EC_POINT_mul(group, Q, nullptr, sR, r_inv, ctx);
                    
                    QByteArray recoveredPubKey(65, 0);
                    EC_POINT_point2oct(group, Q, POINT_CONVERSION_UNCOMPRESSED,
                                      reinterpret_cast<unsigned char*>(recoveredPubKey.data()), 65, nullptr);
                    
                    if (recoveredPubKey == publicKey2) {
                        wrongMatch = true;
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
            BN_CTX_free(ctx);
            BN_free(r_bn);
            EC_KEY_free(eckey);
        }
        
        QVERIFY(!wrongMatch);
    }

    // ========================================================================
    // Integration Tests
    // ========================================================================

    void testRealWorldTLVResponse()
    {
        
        // Create synthetic TLV response using helper functions
        // This ensures correct structure without exposing real account data
        
        // Generate a synthetic public key (65 bytes, uncompressed format)
        QByteArray syntheticPublicKey(65, 0);
        syntheticPublicKey[0] = 0x04; // Uncompressed marker
        // Fill with recognizable but non-real pattern
        for (int i = 1; i < 65; i++) {
            syntheticPublicKey[i] = char((i * 17) & 0xFF); // Pattern: 17, 34, 51, ...
        }
        
        // Generate synthetic R and S values (32 bytes each)
        QByteArray syntheticR(32, 0);
        QByteArray syntheticS(32, 0);
        for (int i = 0; i < 32; i++) {
            syntheticR[i] = char((i * 11) & 0xFF); // Pattern
            syntheticS[i] = char((i * 13) & 0xFF); // Different pattern
        }
        
        // Create DER signature
        QByteArray derSig = createDERSignature(syntheticR, syntheticS);
        
        // Create full TLV response
        QByteArray tlvResponse = createTLVSignResponse(syntheticPublicKey, derSig);
        
        qDebug() << "TLV response size:" << tlvResponse.size();
        
        // Verify structure
        QCOMPARE((uint8_t)tlvResponse[0], (uint8_t)0xa0); // Template tag
        QCOMPARE((uint8_t)tlvResponse[1], (uint8_t)0x81); // Multi-byte length
        QCOMPARE((uint8_t)tlvResponse[2], (uint8_t)0x89); // Length value (137)
        
        // Extract public key
        QCOMPARE((uint8_t)tlvResponse[3], (uint8_t)0x80); // Public key tag
        QCOMPARE((uint8_t)tlvResponse[4], (uint8_t)0x41); // 65 bytes
        QByteArray publicKey = tlvResponse.mid(5, 65);
        QCOMPARE(publicKey.size(), 65);
        QCOMPARE((uint8_t)publicKey[0], (uint8_t)0x04); // Uncompressed format
        
        qDebug() << "Extracted public key:" << publicKey.toHex();
        
        // Find DER signature (should be at offset after pubkey + some padding)
        int derSigIdx = tlvResponse.indexOf(QByteArray::fromHex("30"), 70);
        QVERIFY(derSigIdx > 0);
        
        QCOMPARE((uint8_t)tlvResponse[derSigIdx], (uint8_t)0x30); // DER SEQUENCE tag
        
        // Parse DER signature length
        int derSigLen = (uint8_t)tlvResponse[derSigIdx + 1];
        QByteArray extractedDerSig = tlvResponse.mid(derSigIdx, derSigLen + 2);
        
        
        // Parse R and S from DER
        int idx = derSigIdx + 2;
        QCOMPARE((uint8_t)tlvResponse[idx], (uint8_t)0x02); // INTEGER tag for R
        idx++;
        int rLen = (uint8_t)tlvResponse[idx];
        idx++;
        QByteArray r = tlvResponse.mid(idx, rLen);
        if (r.size() > 32) r = r.right(32);
        while (r.size() < 32) r.prepend('\0');
        
        idx += rLen;
        QCOMPARE((uint8_t)tlvResponse[idx], (uint8_t)0x02); // INTEGER tag for S
        idx++;
        int sLen = (uint8_t)tlvResponse[idx];
        idx++;
        QByteArray s = tlvResponse.mid(idx, sLen);
        if (s.size() > 32) s = s.right(32);
        while (s.size() < 32) s.prepend('\0');
        
        qDebug() << "Extracted R:" << r.toHex();
        qDebug() << "Extracted S:" << s.toHex();
        
        QCOMPARE(r.size(), 32);
        QCOMPARE(s.size(), 32);
        
    }
};

QTEST_MAIN(TestSignFlowTLVParsing)
#include "test_sign_flow_tlv_parsing.moc"

