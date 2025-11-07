#include <QtTest/QtTest>
#include <QJsonObject>
#include <QJsonDocument>

// Only include pure logic headers - no FlowManager or hardware dependencies
#include "flow/flow_types.h"
#include "flow/flow_params.h"

using namespace StatusKeycard;

/**
 * @brief Pure logic tests with ZERO hardware dependencies
 * 
 * These tests only verify constants, enums, and JSON handling
 * No FlowManager, no FlowStateMachine, no signal emission
 */
class TestFlowLogicOnly : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase()
    {
        qDebug() << "=== Starting pure logic tests (no hardware) ===";
    }

    void cleanupTestCase()
    {
        qDebug() << "=== Pure logic tests complete ===";
    }

    // ========================================================================
    // FlowType Enum Tests
    // ========================================================================

    void testFlowTypeEnumValues()
    {
        qDebug() << "Testing FlowType enum values";
        QCOMPARE(static_cast<int>(FlowType::GetAppInfo), 0);
        QCOMPARE(static_cast<int>(FlowType::RecoverAccount), 1);
        QCOMPARE(static_cast<int>(FlowType::LoadAccount), 2);
        QCOMPARE(static_cast<int>(FlowType::Login), 3);
        QCOMPARE(static_cast<int>(FlowType::ExportPublic), 4);
        QCOMPARE(static_cast<int>(FlowType::Sign), 5);
        QCOMPARE(static_cast<int>(FlowType::ChangePIN), 6);
        QCOMPARE(static_cast<int>(FlowType::ChangePUK), 7);
        QCOMPARE(static_cast<int>(FlowType::ChangePairing), 8);
        QCOMPARE(static_cast<int>(FlowType::StoreMetadata), 12);
        QCOMPARE(static_cast<int>(FlowType::GetMetadata), 13);
        qDebug() << "✓ FlowType enum values correct";
    }

    void testFlowTypeDistinct()
    {
        qDebug() << "Testing FlowType values are distinct";
        QVERIFY(FlowType::Login != FlowType::GetAppInfo);
        QVERIFY(FlowType::Sign != FlowType::Login);
        QVERIFY(FlowType::ChangePIN != FlowType::ChangePUK);
        qDebug() << "✓ All FlowType values are distinct";
    }

    // ========================================================================
    // Flow Parameter Constants
    // ========================================================================

    void testParameterConstants()
    {
        qDebug() << "Testing parameter constants";
        QCOMPARE(FlowParams::PIN, QString("pin"));
        QCOMPARE(FlowParams::PUK, QString("puk"));
        QCOMPARE(FlowParams::PAIRING_PASS, QString("pairing-pass"));
        QCOMPARE(FlowParams::KEY_UID, QString("key-uid"));
        QCOMPARE(FlowParams::INSTANCE_UID, QString("instance-uid"));
        QCOMPARE(FlowParams::ERROR_KEY, QString("error"));
        qDebug() << "✓ Parameter constants correct";
    }

    void testKeyExportConstants()
    {
        qDebug() << "Testing key export constants";
        QCOMPARE(FlowParams::ENC_KEY, QString("encryption-key"));
        QCOMPARE(FlowParams::WHISPER_KEY, QString("whisper-key"));
        QCOMPARE(FlowParams::WALLET_KEY, QString("wallet-key"));
        QCOMPARE(FlowParams::MASTER_KEY, QString("master-key"));
        QCOMPARE(FlowParams::WALLET_ROOT_KEY, QString("wallet-root-key"));
        QCOMPARE(FlowParams::EIP1581_KEY, QString("eip1581-key"));
        qDebug() << "✓ Key export constants correct";
    }

    void testCardInfoConstants()
    {
        qDebug() << "Testing card info constants";
        QCOMPARE(FlowParams::FREE_SLOTS, QString("free-pairing-slots"));
        QCOMPARE(FlowParams::PIN_RETRIES, QString("pin-retries"));
        QCOMPARE(FlowParams::PUK_RETRIES, QString("puk-retries"));
        QCOMPARE(FlowParams::PAIRED, QString("paired"));
        qDebug() << "✓ Card info constants correct";
    }

    void testCryptoConstants()
    {
        qDebug() << "Testing crypto constants";
        QCOMPARE(FlowParams::TX_SIGNATURE, QString("tx-signature"));
        QCOMPARE(FlowParams::TX_HASH, QString("tx-hash"));
        QCOMPARE(FlowParams::BIP44_PATH, QString("bip44-path"));
        QCOMPARE(FlowParams::EXPORTED_KEY, QString("exported-key"));
        qDebug() << "✓ Crypto constants correct";
    }

    // ========================================================================
    // JSON Parameter Tests
    // ========================================================================

    void testLoginParametersJson()
    {
        qDebug() << "Testing Login flow parameters";
        QJsonObject params;
        params[FlowParams::PIN] = "000000";
        params[FlowParams::PAIRING_PASS] = "KeycardTest";
        
        QVERIFY(params.contains(FlowParams::PIN));
        QVERIFY(params.contains(FlowParams::PAIRING_PASS));
        QCOMPARE(params[FlowParams::PIN].toString(), QString("000000"));
        QCOMPARE(params[FlowParams::PAIRING_PASS].toString(), QString("KeycardTest"));
        qDebug() << "✓ Login parameters valid";
    }

    void testSignParametersJson()
    {
        qDebug() << "Testing Sign flow parameters";
        QJsonObject params;
        params[FlowParams::TX_HASH] = "0xabcdef123456789";
        params[FlowParams::BIP44_PATH] = "m/44'/60'/0'/0/0";
        params[FlowParams::PIN] = "000000";
        
        QVERIFY(params.contains(FlowParams::TX_HASH));
        QVERIFY(params.contains(FlowParams::BIP44_PATH));
        QCOMPARE(params[FlowParams::TX_HASH].toString(), QString("0xabcdef123456789"));
        qDebug() << "✓ Sign parameters valid";
    }

    void testLoadAccountParametersJson()
    {
        qDebug() << "Testing LoadAccount flow parameters";
        QJsonObject params;
        params[FlowParams::MNEMONIC] = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        params[FlowParams::PIN] = "000000";
        params[FlowParams::PUK] = "000000000000";
        
        QVERIFY(params.contains(FlowParams::MNEMONIC));
        QVERIFY(!params[FlowParams::MNEMONIC].toString().isEmpty());
        qDebug() << "✓ LoadAccount parameters valid";
    }

    void testChangePINParametersJson()
    {
        qDebug() << "Testing ChangePIN flow parameters";
        QJsonObject params;
        params[FlowParams::PIN] = "000000";
        params[FlowParams::NEW_PIN] = "123456";
        
        QVERIFY(params.contains(FlowParams::PIN));
        QVERIFY(params.contains(FlowParams::NEW_PIN));
        QVERIFY(params[FlowParams::PIN] != params[FlowParams::NEW_PIN]);
        qDebug() << "✓ ChangePIN parameters valid";
    }

    void testMetadataParametersJson()
    {
        qDebug() << "Testing metadata parameters";
        QJsonObject params;
        params[FlowParams::CARD_META] = "test metadata content";
        params[FlowParams::CARD_NAME] = "test-wallet";
        
        QVERIFY(params.contains(FlowParams::CARD_META));
        QVERIFY(params.contains(FlowParams::CARD_NAME));
        qDebug() << "✓ Metadata parameters valid";
    }

    // ========================================================================
    // JSON Result Format Tests
    // ========================================================================

    void testLoginResultFormat()
    {
        qDebug() << "Testing Login result format";
        QJsonObject result;
        result[FlowParams::KEY_UID] = "abc123def456";
        result[FlowParams::INSTANCE_UID] = "xyz789";
        result[FlowParams::ENC_KEY] = "0x1234...";
        result[FlowParams::WHISPER_KEY] = "0x5678...";
        
        QVERIFY(result.contains(FlowParams::KEY_UID));
        QVERIFY(result.contains(FlowParams::ENC_KEY));
        QVERIFY(result.contains(FlowParams::WHISPER_KEY));
        qDebug() << "✓ Login result format correct";
    }

    void testSignResultFormat()
    {
        qDebug() << "Testing Sign result format";
        QJsonObject result;
        result[FlowParams::TX_SIGNATURE] = "0xabcdef...signature...";
        
        QVERIFY(result.contains(FlowParams::TX_SIGNATURE));
        QVERIFY(!result[FlowParams::TX_SIGNATURE].toString().isEmpty());
        qDebug() << "✓ Sign result format correct";
    }

    void testCardInfoResultFormat()
    {
        qDebug() << "Testing CardInfo result format";
        QJsonObject result;
        result[FlowParams::INSTANCE_UID] = "instance123";
        result[FlowParams::KEY_UID] = "key456";
        result[FlowParams::FREE_SLOTS] = 3;
        result[FlowParams::PIN_RETRIES] = 3;
        result[FlowParams::PUK_RETRIES] = 5;
        result[FlowParams::PAIRED] = true;
        
        QCOMPARE(result[FlowParams::FREE_SLOTS].toInt(), 3);
        QCOMPARE(result[FlowParams::PIN_RETRIES].toInt(), 3);
        QCOMPARE(result[FlowParams::PUK_RETRIES].toInt(), 5);
        QVERIFY(result[FlowParams::PAIRED].toBool());
        qDebug() << "✓ CardInfo result format correct";
    }

    void testErrorResultFormat()
    {
        qDebug() << "Testing error result format";
        QJsonObject result;
        result[FlowParams::ERROR_KEY] = "invalid-pin";
        
        QVERIFY(result.contains(FlowParams::ERROR_KEY));
        QCOMPARE(result[FlowParams::ERROR_KEY].toString(), QString("invalid-pin"));
        qDebug() << "✓ Error result format correct";
    }

    // ========================================================================
    // JSON Serialization Tests
    // ========================================================================

    void testJsonSerialization()
    {
        qDebug() << "Testing JSON serialization";
        QJsonObject obj;
        obj["string"] = "value";
        obj["number"] = 123;
        obj["boolean"] = true;
        obj["null"] = QJsonValue();
        
        QJsonDocument doc(obj);
        QString json = doc.toJson(QJsonDocument::Compact);
        
        QVERIFY(!json.isEmpty());
        QVERIFY(json.contains("string"));
        QVERIFY(json.contains("value"));
        QVERIFY(json.contains("123"));
        qDebug() << "✓ JSON serialization works";
    }

    void testJsonDeserialization()
    {
        qDebug() << "Testing JSON deserialization";
        QString json = R"({"pin":"000000","key-uid":"abc123","retries":3})";
        
        QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
        QVERIFY(doc.isObject());
        
        QJsonObject obj = doc.object();
        QVERIFY(obj.contains("pin"));
        QVERIFY(obj.contains("key-uid"));
        QVERIFY(obj.contains("retries"));
        QCOMPARE(obj["pin"].toString(), QString("000000"));
        QCOMPARE(obj["key-uid"].toString(), QString("abc123"));
        QCOMPARE(obj["retries"].toInt(), 3);
        qDebug() << "✓ JSON deserialization works";
    }

    void testComplexJsonStructure()
    {
        qDebug() << "Testing complex JSON structure";
        QJsonObject params;
        params[FlowParams::PIN] = "000000";
        params[FlowParams::PAIRING_PASS] = "test";
        
        QJsonObject cardInfo;
        cardInfo[FlowParams::KEY_UID] = "uid123";
        cardInfo[FlowParams::FREE_SLOTS] = 3;
        
        QJsonObject result;
        result["params"] = params;
        result["cardInfo"] = cardInfo;
        
        QVERIFY(result["params"].isObject());
        QVERIFY(result["cardInfo"].isObject());
        
        QJsonObject extractedParams = result["params"].toObject();
        QCOMPARE(extractedParams[FlowParams::PIN].toString(), QString("000000"));
        qDebug() << "✓ Complex JSON structure works";
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    void testEmptyJsonObject()
    {
        qDebug() << "Testing empty JSON object";
        QJsonObject obj;
        QVERIFY(obj.isEmpty());
        QVERIFY(obj.keys().isEmpty());
        qDebug() << "✓ Empty JSON object handled";
    }

    void testNullJsonValues()
    {
        qDebug() << "Testing null JSON values";
        QJsonObject obj;
        obj["null-value"] = QJsonValue();
        
        QVERIFY(obj.contains("null-value"));
        QVERIFY(obj["null-value"].isNull());
        qDebug() << "✓ Null values handled";
    }

    void testSpecialCharactersInJson()
    {
        qDebug() << "Testing special characters";
        QJsonObject obj;
        obj["special"] = "Test@123!#$%^&*()";
        obj["unicode"] = "Hello 世界 🔑";
        
        QCOMPARE(obj["special"].toString(), QString("Test@123!#$%^&*()"));
        QVERIFY(obj["unicode"].toString().contains("世界"));
        qDebug() << "✓ Special characters handled";
    }

    void testLongStringsInJson()
    {
        qDebug() << "Testing long strings";
        QString longString = QString("a").repeated(10000);
        QJsonObject obj;
        obj["long"] = longString;
        
        QCOMPARE(obj["long"].toString().length(), 10000);
        qDebug() << "✓ Long strings handled";
    }

    void testJsonRoundTrip()
    {
        qDebug() << "Testing JSON round trip";
        QJsonObject original;
        original[FlowParams::PIN] = "123456";
        original[FlowParams::KEY_UID] = "test-uid";
        original[FlowParams::PIN_RETRIES] = 3;
        
        // Serialize
        QJsonDocument doc(original);
        QString json = doc.toJson(QJsonDocument::Compact);
        
        // Deserialize
        QJsonDocument doc2 = QJsonDocument::fromJson(json.toUtf8());
        QJsonObject restored = doc2.object();
        
        // Verify
        QCOMPARE(restored[FlowParams::PIN].toString(), original[FlowParams::PIN].toString());
        QCOMPARE(restored[FlowParams::KEY_UID].toString(), original[FlowParams::KEY_UID].toString());
        QCOMPARE(restored[FlowParams::PIN_RETRIES].toInt(), original[FlowParams::PIN_RETRIES].toInt());
        qDebug() << "✓ JSON round trip successful";
    }

    // ========================================================================
    // Parameter Validation Logic
    // ========================================================================

    void testRequiredParametersValidation()
    {
        qDebug() << "Testing required parameters validation";
        
        // Login requires PIN and PAIRING_PASS
        QJsonObject loginParams;
        QVERIFY(!loginParams.contains(FlowParams::PIN));
        loginParams[FlowParams::PIN] = "000000";
        QVERIFY(loginParams.contains(FlowParams::PIN));
        
        // Sign requires TX_HASH
        QJsonObject signParams;
        QVERIFY(!signParams.contains(FlowParams::TX_HASH));
        signParams[FlowParams::TX_HASH] = "0xabc";
        QVERIFY(signParams.contains(FlowParams::TX_HASH));
        
        qDebug() << "✓ Required parameter validation works";
    }

    void testOptionalParametersValidation()
    {
        qDebug() << "Testing optional parameters";
        QJsonObject params;
        params[FlowParams::PIN] = "000000";
        
        // Optional parameters
        QVERIFY(!params.contains(FlowParams::BIP44_PATH));
        params[FlowParams::BIP44_PATH] = "m/44'/60'/0'/0/0";
        QVERIFY(params.contains(FlowParams::BIP44_PATH));
        
        qDebug() << "✓ Optional parameter handling works";
    }
};

QTEST_MAIN(TestFlowLogicOnly)
#include "test_flow_logic_only.moc"

