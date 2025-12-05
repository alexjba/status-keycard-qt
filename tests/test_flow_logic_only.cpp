#include <QtTest/QtTest>
#include <QJsonObject>
#include <QJsonDocument>
#include "flow/flow_types.h"
#include "flow/flow_params.h"

using namespace StatusKeycard;

class TestFlowLogicOnly : public QObject
{
    Q_OBJECT

private slots:
    void testFlowTypeEnumValues()
    {
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
    }

    void testFlowTypeDistinct()
    {
        QVERIFY(FlowType::Login != FlowType::GetAppInfo);
        QVERIFY(FlowType::Sign != FlowType::Login);
        QVERIFY(FlowType::ChangePIN != FlowType::ChangePUK);
    }

    void testParameterConstants()
    {
        QCOMPARE(FlowParams::PIN, QString("pin"));
        QCOMPARE(FlowParams::PUK, QString("puk"));
        QCOMPARE(FlowParams::PAIRING_PASS, QString("pairing-pass"));
        QCOMPARE(FlowParams::KEY_UID, QString("key-uid"));
        QCOMPARE(FlowParams::INSTANCE_UID, QString("instance-uid"));
        QCOMPARE(FlowParams::ERROR_KEY, QString("error"));
    }

    void testKeyExportConstants()
    {
        QCOMPARE(FlowParams::ENC_KEY, QString("encryption-key"));
        QCOMPARE(FlowParams::WHISPER_KEY, QString("whisper-key"));
        QCOMPARE(FlowParams::WALLET_KEY, QString("wallet-key"));
        QCOMPARE(FlowParams::MASTER_KEY, QString("master-key"));
        QCOMPARE(FlowParams::WALLET_ROOT_KEY, QString("wallet-root-key"));
        QCOMPARE(FlowParams::EIP1581_KEY, QString("eip1581-key"));
    }

    void testCardInfoConstants()
    {
        QCOMPARE(FlowParams::FREE_SLOTS, QString("free-pairing-slots"));
        QCOMPARE(FlowParams::PIN_RETRIES, QString("pin-retries"));
        QCOMPARE(FlowParams::PUK_RETRIES, QString("puk-retries"));
        QCOMPARE(FlowParams::PAIRED, QString("paired"));
    }

    void testCryptoConstants()
    {
        QCOMPARE(FlowParams::TX_SIGNATURE, QString("tx-signature"));
        QCOMPARE(FlowParams::TX_HASH, QString("tx-hash"));
        QCOMPARE(FlowParams::BIP44_PATH, QString("bip44-path"));
        QCOMPARE(FlowParams::EXPORTED_KEY, QString("exported-key"));
    }

    void testLoginParametersJson()
    {
        QJsonObject params;
        params[FlowParams::PIN] = "000000";
        params[FlowParams::PAIRING_PASS] = "KeycardTest";
        
        QVERIFY(params.contains(FlowParams::PIN));
        QVERIFY(params.contains(FlowParams::PAIRING_PASS));
        QCOMPARE(params[FlowParams::PIN].toString(), QString("000000"));
        QCOMPARE(params[FlowParams::PAIRING_PASS].toString(), QString("KeycardTest"));
    }

    void testSignParametersJson()
    {
        QJsonObject params;
        params[FlowParams::TX_HASH] = "0xabcdef123456789";
        params[FlowParams::BIP44_PATH] = "m/44'/60'/0'/0/0";
        params[FlowParams::PIN] = "000000";
        
        QVERIFY(params.contains(FlowParams::TX_HASH));
        QVERIFY(params.contains(FlowParams::BIP44_PATH));
        QCOMPARE(params[FlowParams::TX_HASH].toString(), QString("0xabcdef123456789"));
    }

    void testLoadAccountParametersJson()
    {
        QJsonObject params;
        params[FlowParams::MNEMONIC] = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        params[FlowParams::PIN] = "000000";
        params[FlowParams::PUK] = "000000000000";
        
        QVERIFY(params.contains(FlowParams::MNEMONIC));
        QVERIFY(!params[FlowParams::MNEMONIC].toString().isEmpty());
    }

    void testChangePINParametersJson()
    {
        QJsonObject params;
        params[FlowParams::PIN] = "000000";
        params[FlowParams::NEW_PIN] = "123456";
        
        QVERIFY(params.contains(FlowParams::PIN));
        QVERIFY(params.contains(FlowParams::NEW_PIN));
        QVERIFY(params[FlowParams::PIN] != params[FlowParams::NEW_PIN]);
    }

    void testMetadataParametersJson()
    {
        QJsonObject params;
        params[FlowParams::CARD_META] = "test metadata content";
        params[FlowParams::CARD_NAME] = "test-wallet";
        
        QVERIFY(params.contains(FlowParams::CARD_META));
        QVERIFY(params.contains(FlowParams::CARD_NAME));
    }

    void testLoginResultFormat()
    {
        QJsonObject result;
        result[FlowParams::KEY_UID] = "abc123def456";
        result[FlowParams::INSTANCE_UID] = "xyz789";
        result[FlowParams::ENC_KEY] = "0x1234...";
        result[FlowParams::WHISPER_KEY] = "0x5678...";
        
        QVERIFY(result.contains(FlowParams::KEY_UID));
        QVERIFY(result.contains(FlowParams::ENC_KEY));
        QVERIFY(result.contains(FlowParams::WHISPER_KEY));
    }

    void testSignResultFormat()
    {
        QJsonObject result;
        result[FlowParams::TX_SIGNATURE] = "0xabcdef...signature...";
        
        QVERIFY(result.contains(FlowParams::TX_SIGNATURE));
        QVERIFY(!result[FlowParams::TX_SIGNATURE].toString().isEmpty());
    }

    void testCardInfoResultFormat()
    {
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
    }

    void testErrorResultFormat()
    {
        QJsonObject result;
        result[FlowParams::ERROR_KEY] = "invalid-pin";
        
        QVERIFY(result.contains(FlowParams::ERROR_KEY));
        QCOMPARE(result[FlowParams::ERROR_KEY].toString(), QString("invalid-pin"));
    }

    void testJsonSerialization()
    {
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
    }

    void testJsonDeserialization()
    {
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
    }

    void testComplexJsonStructure()
    {
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
    }

    void testEmptyJsonObject()
    {
        QJsonObject obj;
        QVERIFY(obj.isEmpty());
        QVERIFY(obj.keys().isEmpty());
    }

    void testNullJsonValues()
    {
        QJsonObject obj;
        obj["null-value"] = QJsonValue();
        
        QVERIFY(obj.contains("null-value"));
        QVERIFY(obj["null-value"].isNull());
    }

    void testSpecialCharactersInJson()
    {
        QJsonObject obj;
        obj["special"] = "Test@123!#$%^&*()";
        obj["unicode"] = "Hello 世界 🔑";
        
        QCOMPARE(obj["special"].toString(), QString("Test@123!#$%^&*()"));
        QVERIFY(obj["unicode"].toString().contains("世界"));
    }

    void testLongStringsInJson()
    {
        QString longString = QString("a").repeated(10000);
        QJsonObject obj;
        obj["long"] = longString;
        
        QCOMPARE(obj["long"].toString().length(), 10000);
    }

    void testJsonRoundTrip()
    {
        QJsonObject original;
        original[FlowParams::PIN] = "123456";
        original[FlowParams::KEY_UID] = "test-uid";
        original[FlowParams::PIN_RETRIES] = 3;
        
        QJsonDocument doc(original);
        QString json = doc.toJson(QJsonDocument::Compact);
        
        QJsonDocument doc2 = QJsonDocument::fromJson(json.toUtf8());
        QJsonObject restored = doc2.object();
        
        QCOMPARE(restored[FlowParams::PIN].toString(), original[FlowParams::PIN].toString());
        QCOMPARE(restored[FlowParams::KEY_UID].toString(), original[FlowParams::KEY_UID].toString());
        QCOMPARE(restored[FlowParams::PIN_RETRIES].toInt(), original[FlowParams::PIN_RETRIES].toInt());
    }

    void testRequiredParametersValidation()
    {
        QJsonObject loginParams;
        QVERIFY(!loginParams.contains(FlowParams::PIN));
        loginParams[FlowParams::PIN] = "000000";
        QVERIFY(loginParams.contains(FlowParams::PIN));
        
        QJsonObject signParams;
        QVERIFY(!signParams.contains(FlowParams::TX_HASH));
        signParams[FlowParams::TX_HASH] = "0xabc";
        QVERIFY(signParams.contains(FlowParams::TX_HASH));
    }

    void testOptionalParametersValidation()
    {
        QJsonObject params;
        params[FlowParams::PIN] = "000000";
        
        QVERIFY(!params.contains(FlowParams::BIP44_PATH));
        params[FlowParams::BIP44_PATH] = "m/44'/60'/0'/0/0";
        QVERIFY(params.contains(FlowParams::BIP44_PATH));
    }
};

QTEST_MAIN(TestFlowLogicOnly)
#include "test_flow_logic_only.moc"
