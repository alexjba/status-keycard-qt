#ifndef MOCK_KEYCARD_BACKEND_H
#define MOCK_KEYCARD_BACKEND_H

#include <keycard-qt/backends/keycard_channel_backend.h>
#include <QByteArray>
#include <QTimer>

namespace StatusKeycardTest {

/**
 * @brief Mock keycard backend that simulates a real keycard
 * 
 * Inherits from KeycardChannelBackend (not KeycardChannel) to avoid
 * any initialization of real hardware. Can be injected into KeycardChannel
 * via the DI constructor.
 * 
 * Simulates all APDU responses for testing without real hardware.
 */
class MockKeycardBackend : public Keycard::KeycardChannelBackend {
    Q_OBJECT
    
public:
    explicit MockKeycardBackend(QObject* parent = nullptr);
    ~MockKeycardBackend();
    
    // Control simulation
    void setAutoConnect(bool autoConnect);
    void setCardInitialized(bool initialized);
    void setPIN(const QString& pin);
    void setPUK(const QString& puk);
    void setPairingPassword(const QString& password);
    void setKeyUID(const QByteArray& keyUID);
    void setInstanceUID(const QByteArray& instanceUID);
    
    // Simulate card events
    void simulateCardInserted();
    void simulateCardRemoved();
    
    // Override KeycardChannelBackend interface
    QByteArray transmit(const QByteArray& apdu) override;
    bool isConnected() const override;
    void startDetection() override;
    void stopDetection() override;
    void disconnect() override;
    QString backendName() const override { return "Mock Backend"; }
    void setState(Keycard::ChannelState state) override;
    Keycard::ChannelState state() const override { return m_channelState; }
    void forceScan() override;
    
private:
    // Simulation state
    bool m_autoConnect;
    bool m_connected;
    bool m_detecting;
    bool m_initialized;
    bool m_paired;
    QString m_pin;
    QString m_puk;
    QString m_pairingPassword;
    QByteArray m_keyUID;
    QByteArray m_instanceUID;
    int m_pinRetries;
    int m_pukRetries;
    QTimer* m_autoConnectTimer;
    Keycard::ChannelState m_channelState;
    
    // APDU response generators
    QByteArray generateSelectResponse();
    QByteArray generateGetStatusResponse();
    QByteArray generateOpenSecureChannelResponse();
    QByteArray generatePairResponse(const QByteArray& apdu);
    QByteArray generateVerifyPINResponse(const QString& pin);
    QByteArray generateExportKeyResponse();
    QByteArray generateSignResponse();
    QByteArray generateChangePINResponse();
    QByteArray generateChangePUKResponse();
    QByteArray generateChangePairingResponse();
    QByteArray generateGetMetadataResponse();
    QByteArray generateStoreMetadataResponse();
    
    // Helper to create success response
    QByteArray successResponse(const QByteArray& data = QByteArray());
    QByteArray errorResponse(quint8 sw1, quint8 sw2);
};

} // namespace StatusKeycardTest

#endif // MOCK_KEYCARD_BACKEND_H

