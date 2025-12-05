#include "mock_keycard_backend.h"
#include <QDebug>
#include <QRandomGenerator>
#include <QMessageAuthenticationCode>
#include <QCryptographicHash>

namespace StatusKeycardTest {

// Helper: PBKDF2-HMAC-SHA256 for pairing password derivation
// Must match the implementation in CommandSet
static QByteArray derivePairingToken(const QString& password)
{
    QByteArray salt = "Keycard Pairing Password Salt";
    QByteArray passwordBytes = password.toUtf8();
    int iterations = 50000;
    int keyLength = 32;
    
    QByteArray result(keyLength, 0);
    QByteArray U, T;
    
    // PBKDF2: derived_key = PBKDF2(password, salt, iterations, keyLength)
    // Using HMAC-SHA256
    for (int block = 1; block <= (keyLength + 31) / 32; ++block) {
        // U_1 = HMAC(password, salt || INT(block))
        QByteArray blockData = salt;
        blockData.append((char)((block >> 24) & 0xFF));
        blockData.append((char)((block >> 16) & 0xFF));
        blockData.append((char)((block >> 8) & 0xFF));
        blockData.append((char)(block & 0xFF));
        
        U = QMessageAuthenticationCode::hash(blockData, passwordBytes, QCryptographicHash::Sha256);
        T = U;
        
        // U_2 through U_iterations
        for (int i = 1; i < iterations; ++i) {
            U = QMessageAuthenticationCode::hash(U, passwordBytes, QCryptographicHash::Sha256);
            // T = U_1 XOR U_2 XOR ... XOR U_iterations
            for (int j = 0; j < U.size(); ++j) {
                T[j] = T[j] ^ U[j];
            }
        }
        
        // Copy to result
        int bytesToCopy = qMin(32, keyLength - (block - 1) * 32);
        for (int i = 0; i < bytesToCopy; ++i) {
            result[(block - 1) * 32 + i] = T[i];
        }
    }
    
    return result;
}

MockKeycardBackend::MockKeycardBackend(QObject* parent)
    : KeycardChannelBackend(parent)
    , m_autoConnect(true)
    , m_connected(false)
    , m_detecting(false)
    , m_initialized(true)
    , m_paired(false)
    , m_pin("000000")
    , m_puk("000000000000")
    , m_pairingPassword("KeycardDefaultPairing")
    , m_keyUID(QByteArray::fromHex("0123456789ABCDEF0123456789ABCDEF"))
    , m_instanceUID(QByteArray::fromHex("FEDCBA9876543210FEDCBA9876543210"))
    , m_pinRetries(3)
    , m_pukRetries(5)
    , m_autoConnectTimer(new QTimer(this))
    , m_channelState(Keycard::ChannelState::Idle)
{
    m_autoConnectTimer->setSingleShot(true);
    connect(m_autoConnectTimer, &QTimer::timeout, this, [this]() {
        if (m_autoConnect && m_detecting && !m_connected) {
            simulateCardInserted();
        }
    });
}

MockKeycardBackend::~MockKeycardBackend()
{
}

void MockKeycardBackend::setAutoConnect(bool autoConnect)
{
    m_autoConnect = autoConnect;
}

void MockKeycardBackend::setCardInitialized(bool initialized)
{
    m_initialized = initialized;
}

void MockKeycardBackend::setPIN(const QString& pin)
{
    m_pin = pin;
}

void MockKeycardBackend::setPUK(const QString& puk)
{
    m_puk = puk;
}

void MockKeycardBackend::setPairingPassword(const QString& password)
{
    m_pairingPassword = password;
}

void MockKeycardBackend::setKeyUID(const QByteArray& keyUID)
{
    m_keyUID = keyUID;
}

void MockKeycardBackend::setInstanceUID(const QByteArray& instanceUID)
{
    m_instanceUID = instanceUID;
}

void MockKeycardBackend::simulateCardInserted()
{
    if (m_connected) {
        return;
    }
    
    m_connected = true;
    m_pinRetries = 3;
    m_pukRetries = 5;
    qDebug() << "[MockBackend] Card inserted";
    emit targetDetected(m_instanceUID.toHex());
}

void MockKeycardBackend::simulateCardRemoved()
{
    if (!m_connected) {
        return;
    }
    
    m_connected = false;
    m_paired = false;
    qDebug() << "[MockBackend] Card removed";
    emit cardRemoved();  // KeycardChannelBackend signal
}

bool MockKeycardBackend::isConnected() const
{
    return m_connected;
}

void MockKeycardBackend::startDetection()
{
    m_detecting = true;
    qDebug() << "[MockBackend] Detection started";
    
    if (m_autoConnect) {
        m_autoConnectTimer->start(50); // Auto-connect after 50ms
    }
}

void MockKeycardBackend::stopDetection()
{
    m_detecting = false;
    m_autoConnectTimer->stop();
    qDebug() << "[MockBackend] Detection stopped";
}

void MockKeycardBackend::disconnect()
{
    if (m_connected) {
        simulateCardRemoved();
    }
}

void MockKeycardBackend::setState(Keycard::ChannelState state)
{
    m_channelState = state;
}

void MockKeycardBackend::forceScan()
{
    qDebug() << "[MockBackend] Force scan requested";
    // For mock, we can trigger a scan if detection is active
    if (m_detecting && !m_connected && m_autoConnect) {
        m_autoConnectTimer->start(10); // Trigger faster auto-connect
    }
}

QByteArray MockKeycardBackend::transmit(const QByteArray& apdu)
{
    if (!m_connected) {
        qWarning() << "[MockBackend] APDU sent without connection";
        return errorResponse(0x6F, 0x00); // Unknown error
    }
    
    if (apdu.isEmpty()) {
        return errorResponse(0x6F, 0x00);
    }
    
    quint8 cla = static_cast<quint8>(apdu[0]);
    quint8 ins = static_cast<quint8>(apdu[1]);
    
    qDebug() << "[MockBackend] APDU: CLA=" << Qt::hex << cla << "INS=" << ins;
    
    // Check if this is an encrypted command (CLA=0x80 and data includes IV+encrypted)
    // Encrypted APDUs have: CLA=0x80, and data=[IV(16)][encrypted_data]
    if (cla == 0x80 && apdu.size() > 21) {
        // This is an encrypted command - we can't decrypt it properly in the mock,
        // but we can return mock encrypted responses
        qDebug() << "[MockBackend] Encrypted APDU detected, returning mock encrypted response";
        
        // Encrypted response format: [MAC(16)][encrypted_data]
        // For simplicity, return success with just MAC (no data)
        QByteArray mockMAC = QByteArray(16, 0xAA); // Mock MAC
        return successResponse(mockMAC);
    }
    
    // Parse APDU command
    if (ins == 0xA4) {
        // SELECT command
        return generateSelectResponse();
    } else if (ins == 0xF2) {
        // GET STATUS command
        return generateGetStatusResponse();
    } else if (ins == 0x10) {
        // OPEN SECURE CHANNEL
        return generateOpenSecureChannelResponse();
    } else if (ins == 0x11) {
        // MUTUALLY_AUTHENTICATE (sent via secure channel)
        qDebug() << "[MockBackend] MUTUALLY_AUTHENTICATE: returning success";
        return successResponse(QByteArray()); // Just return success
    } else if (ins == 0x12) {
        // PAIR command (INS_PAIR = 0x12)
        m_paired = true;
        return generatePairResponse(apdu);
    } else if (ins == 0x20) {
        // VERIFY PIN
        QString pin = QString::fromUtf8(apdu.mid(5));
        return generateVerifyPINResponse(pin);
    } else if (ins == 0xC0) {
        // EXPORT KEY
        return generateExportKeyResponse();
    } else if (ins == 0xC1 || ins == 0xF0) {
        // SIGN
        return generateSignResponse();
    } else if (ins == 0x21) {
        // CHANGE PIN
        return generateChangePINResponse();
    } else if (ins == 0x22) {
        // CHANGE PUK
        return generateChangePUKResponse();
    } else if (ins == 0x23) {
        // CHANGE PAIRING
        return generateChangePairingResponse();
    } else if (ins == 0xCA) {
        // GET METADATA
        return generateGetMetadataResponse();
    } else if (ins == 0xCB) {
        // STORE METADATA
        return generateStoreMetadataResponse();
    }
    
    // Unknown command
    qWarning() << "[MockBackend] Unknown APDU command:" << Qt::hex << ins;
    return successResponse(); // Just return success for now
}

QByteArray MockKeycardBackend::generateSelectResponse()
{
    // Helper to build TLV: tag + length + value
    auto buildTLV = [](uint8_t tag, const QByteArray& value) -> QByteArray {
        QByteArray tlv;
        tlv.append(static_cast<char>(tag));
        tlv.append(static_cast<char>(value.size()));
        tlv.append(value);
        return tlv;
    };
    
    // SELECT response uses TLV format:
    // 0xA4 [length] { 0x8F [instanceUID], 0x80 [pubkey], 0x02 [version], 0x02 [slots], 0x8E [keyUID] }
    
    QByteArray innerData;
    
    // Instance UID (tag 0x8F)
    innerData.append(buildTLV(0x8F, m_instanceUID));
    
    // Secure channel public key (tag 0x80) - 65 bytes uncompressed secp256k1 key
    // Format: 0x04 + X (32 bytes) + Y (32 bytes)
    QByteArray mockPublicKey = QByteArray(65, 0);
    mockPublicKey[0] = 0x04; // Uncompressed point marker
    for (int i = 1; i < 65; ++i) {
        mockPublicKey[i] = QRandomGenerator::global()->bounded(256);
    }
    innerData.append(buildTLV(0x80, mockPublicKey));
    
    // Version (tag 0x02) - major, minor
    QByteArray version;
    version.append(static_cast<char>(3)); // Major version
    version.append(static_cast<char>(0)); // Minor version
    innerData.append(buildTLV(0x02, version));
    
    // Available slots (tag 0x02)
    QByteArray availableSlots;
    availableSlots.append(static_cast<char>(3)); // 3 free pairing slots
    innerData.append(buildTLV(0x02, availableSlots));
    
    // Key UID (tag 0x8E)
    if (m_initialized && !m_keyUID.isEmpty()) {
        innerData.append(buildTLV(0x8E, m_keyUID));
    }
    
    // Wrap in application info template (tag 0xA4)
    QByteArray response = buildTLV(0xA4, innerData);
    
    qDebug() << "[MockBackend] SELECT response size:" << response.size() << "bytes";
    return successResponse(response);
}

QByteArray MockKeycardBackend::generateGetStatusResponse()
{
    return generateSelectResponse(); // Same format
}

QByteArray MockKeycardBackend::generateOpenSecureChannelResponse()
{
    // OPEN_SECURE_CHANNEL response format: salt (32 bytes) + iv (16 bytes)
    QByteArray salt = QByteArray(32, 0);
    for (int i = 0; i < 32; ++i) {
        salt[i] = QRandomGenerator::global()->bounded(256);
    }
    
    QByteArray iv = QByteArray(16, 0);
    for (int i = 0; i < 16; ++i) {
        iv[i] = QRandomGenerator::global()->bounded(256);
    }
    
    qDebug() << "[MockBackend] OPEN_SECURE_CHANNEL: returning salt + iv (48 bytes)";
    return successResponse(salt + iv);
}

QByteArray MockKeycardBackend::generatePairResponse(const QByteArray& apdu)
{
    // PAIR protocol:
    // Step 1 (P1=0): Client sends challenge (32 bytes)
    //   Response: card_cryptogram (32 bytes) + card_challenge (32 bytes) + salt (32 bytes)
    // Step 2 (P1=1): Client sends cryptogram (32 bytes)
    //   Response: pairing_index (1 byte) + pairing_key (32 bytes) + pairing_iv (16 bytes)
    
    if (apdu.size() < 5) {
        return errorResponse(0x6A, 0x80); // Wrong data
    }
    
    quint8 p1 = static_cast<quint8>(apdu[2]); // P1 byte indicates step
    
    if (p1 == 0x00) {
        // Step 1: Compute proper cryptogram using client's challenge
        
        // Extract client challenge from APDU data (after CLA, INS, P1, P2, Lc)
        if (apdu.size() < 5 + 32) {
            qWarning() << "[MockBackend] PAIR step 1: insufficient data";
            return errorResponse(0x6A, 0x80);
        }
        
        QByteArray clientChallenge = apdu.mid(5, 32);
        qDebug() << "[MockBackend] PAIR step 1: client challenge:" << clientChallenge.toHex();
        
        // Derive secret using PBKDF2 with pairing password
        QByteArray secret = derivePairingToken(m_pairingPassword);
        qDebug() << "[MockBackend] PAIR: derived secret using password:" << m_pairingPassword;
        
        // Compute card cryptogram: SHA256(secret + clientChallenge)
        QCryptographicHash hash(QCryptographicHash::Sha256);
        hash.addData(secret);
        hash.addData(clientChallenge);
        QByteArray cardCryptogram = hash.result();
        
        // Generate card challenge (random or deterministic for testing)
        QByteArray cardChallenge = QByteArray(32, 0);
        for (int i = 0; i < 32; ++i) {
            cardChallenge[i] = QRandomGenerator::global()->bounded(256);
        }
        
        // Generate salt (can be empty or random)
        QByteArray salt = QByteArray(32, 0);
        
        QByteArray response;
        response.append(cardCryptogram);
        response.append(cardChallenge);
        response.append(salt);
        
        qDebug() << "[MockBackend] PAIR step 1: returning cryptogram:" << cardCryptogram.toHex();
        
        return successResponse(response);
    } else if (p1 == 0x01) {
        // Step 2: Verify client cryptogram, then return pairing info
        
        // For mock, we skip cryptogram verification and just return pairing data
        QByteArray response;
        response.append(static_cast<char>(0x00)); // Pairing index 0
        response.append(QByteArray(32, 0x47)); // Pairing key (mock)
        response.append(QByteArray(16, 0x48)); // Pairing IV (mock)
        m_paired = true;
        
        qDebug() << "[MockBackend] PAIR step 2: pairing completed";
        
        return successResponse(response);
    }
    
    return errorResponse(0x6A, 0x86); // Incorrect P1/P2
}

QByteArray MockKeycardBackend::generateVerifyPINResponse(const QString& pin)
{
    if (pin == m_pin) {
        m_pinRetries = 3;
        return successResponse();
    } else {
        m_pinRetries--;
        if (m_pinRetries <= 0) {
            return errorResponse(0x63, 0xC0); // PIN blocked
        }
        return errorResponse(0x63, 0xC0 | m_pinRetries);
    }
}

QByteArray MockKeycardBackend::generateExportKeyResponse()
{
    // Generate a mock 65-byte public key (0x04 + 32 bytes X + 32 bytes Y)
    QByteArray pubKey;
    pubKey.append(static_cast<char>(0x04)); // Uncompressed point
    
    // Generate deterministic but fake key data
    for (int i = 0; i < 64; i++) {
        pubKey.append(static_cast<char>(0xAA + (i % 16)));
    }
    
    return successResponse(pubKey);
}

QByteArray MockKeycardBackend::generateSignResponse()
{
    // Generate a mock ECDSA signature (2 x 32 bytes)
    QByteArray signature;
    for (int i = 0; i < 64; i++) {
        signature.append(static_cast<char>(0xBB + (i % 16)));
    }
    return successResponse(signature);
}

QByteArray MockKeycardBackend::generateChangePINResponse()
{
    return successResponse();
}

QByteArray MockKeycardBackend::generateChangePUKResponse()
{
    return successResponse();
}

QByteArray MockKeycardBackend::generateChangePairingResponse()
{
    return successResponse();
}

QByteArray MockKeycardBackend::generateGetMetadataResponse()
{
    // Return empty metadata for now
    QByteArray metadata = QByteArray::fromHex("7B7D"); // "{}"
    return successResponse(metadata);
}

QByteArray MockKeycardBackend::generateStoreMetadataResponse()
{
    return successResponse();
}

QByteArray MockKeycardBackend::successResponse(const QByteArray& data)
{
    QByteArray response = data;
    response.append(static_cast<char>(0x90)); // SW1
    response.append(static_cast<char>(0x00)); // SW2
    return response;
}

QByteArray MockKeycardBackend::errorResponse(quint8 sw1, quint8 sw2)
{
    QByteArray response;
    response.append(static_cast<char>(sw1));
    response.append(static_cast<char>(sw2));
    return response;
}

} // namespace StatusKeycardTest

