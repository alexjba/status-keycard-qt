#include "flow_signals.h"
#include "../signal_manager.h"
#include "flow_params.h"
#include <QJsonDocument>
#include <QDebug>

namespace StatusKeycard {

// Signal type constants (matching status-keycard-go)
const QString FlowSignals::FLOW_RESULT = "keycard.flow-result";
const QString FlowSignals::INSERT_CARD = "keycard.action.insert-card";
const QString FlowSignals::CARD_INSERTED = "keycard.action.card-inserted";
const QString FlowSignals::SWAP_CARD = "keycard.action.swap-card";
const QString FlowSignals::ENTER_PAIRING = "keycard.action.enter-pairing";
const QString FlowSignals::ENTER_PIN = "keycard.action.enter-pin";
const QString FlowSignals::ENTER_PUK = "keycard.action.enter-puk";
const QString FlowSignals::ENTER_NEW_PAIRING = "keycard.action.enter-new-pairing";
const QString FlowSignals::ENTER_NEW_PIN = "keycard.action.enter-new-pin";
const QString FlowSignals::ENTER_NEW_PUK = "keycard.action.enter-new-puk";
const QString FlowSignals::ENTER_TX_HASH = "keycard.action.enter-tx-hash";
const QString FlowSignals::ENTER_PATH = "keycard.action.enter-bip44-path";
const QString FlowSignals::ENTER_MNEMONIC = "keycard.action.enter-mnemonic";
const QString FlowSignals::ENTER_NAME = "keycard.action.enter-cardname";
const QString FlowSignals::ENTER_WALLETS = "keycard.action.enter-wallets";

QJsonObject FlowSignals::buildSignal(const QString& type, const QJsonObject& event)
{
    QJsonObject signal;
    signal["type"] = type;
    signal["event"] = event;
    return signal;
}

void FlowSignals::emitSignal(const QJsonObject& signal)
{
    QString json = QJsonDocument(signal).toJson(QJsonDocument::Compact);
    qDebug() << "FlowSignals: Emitting signal:" << json;
    SignalManager::instance()->emitSignal(json);
}

void FlowSignals::emitFlowResult(const QJsonObject& result)
{
    QJsonObject signal = buildSignal(FLOW_RESULT, result);
    emitSignal(signal);
}

void FlowSignals::emitInsertCard()
{
    QJsonObject event;
    event[FlowParams::ERROR_KEY] = "connection-error";
    QJsonObject signal = buildSignal(INSERT_CARD, event);
    emitSignal(signal);
}

void FlowSignals::emitCardInserted()
{
    QJsonObject event;
    QJsonObject signal = buildSignal(CARD_INSERTED, event);
    emitSignal(signal);
}

void FlowSignals::emitSwapCard(const QString& error, const QJsonObject& cardInfo)
{
    QJsonObject event = cardInfo;
    event[FlowParams::ERROR_KEY] = error;
    QJsonObject signal = buildSignal(SWAP_CARD, event);
    emitSignal(signal);
}

void FlowSignals::emitEnterPairing(int retriesLeft)
{
    QJsonObject event;
    event[FlowParams::ERROR_KEY] = "enter-pairing";
    if (retriesLeft >= 0) {
        event[FlowParams::FREE_SLOTS] = retriesLeft;
    }
    QJsonObject signal = buildSignal(ENTER_PAIRING, event);
    emitSignal(signal);
}

void FlowSignals::emitEnterPIN(int retriesLeft)
{
    QJsonObject event;
    event[FlowParams::ERROR_KEY] = "enter-pin";
    event[FlowParams::PIN_RETRIES] = retriesLeft;
    QJsonObject signal = buildSignal(ENTER_PIN, event);
    emitSignal(signal);
}

void FlowSignals::emitEnterPUK(int retriesLeft)
{
    QJsonObject event;
    event[FlowParams::ERROR_KEY] = "enter-puk";
    event[FlowParams::PUK_RETRIES] = retriesLeft;
    QJsonObject signal = buildSignal(ENTER_PUK, event);
    emitSignal(signal);
}

void FlowSignals::emitEnterNewPairing()
{
    QJsonObject event;
    event[FlowParams::ERROR_KEY] = "enter-new-pairing";
    QJsonObject signal = buildSignal(ENTER_NEW_PAIRING, event);
    emitSignal(signal);
}

void FlowSignals::emitEnterNewPIN()
{
    QJsonObject event;
    event[FlowParams::ERROR_KEY] = "enter-new-pin";
    QJsonObject signal = buildSignal(ENTER_NEW_PIN, event);
    emitSignal(signal);
}

void FlowSignals::emitEnterNewPUK()
{
    QJsonObject event;
    event[FlowParams::ERROR_KEY] = "enter-new-puk";
    QJsonObject signal = buildSignal(ENTER_NEW_PUK, event);
    emitSignal(signal);
}

void FlowSignals::emitEnterTxHash()
{
    QJsonObject event;
    event[FlowParams::ERROR_KEY] = "enter-tx-hash";
    QJsonObject signal = buildSignal(ENTER_TX_HASH, event);
    emitSignal(signal);
}

void FlowSignals::emitEnterPath()
{
    QJsonObject event;
    event[FlowParams::ERROR_KEY] = "enter-bip44-path";
    QJsonObject signal = buildSignal(ENTER_PATH, event);
    emitSignal(signal);
}

void FlowSignals::emitEnterMnemonic()
{
    QJsonObject event;
    event[FlowParams::ERROR_KEY] = "enter-mnemonic";
    QJsonObject signal = buildSignal(ENTER_MNEMONIC, event);
    emitSignal(signal);
}

void FlowSignals::emitEnterName()
{
    QJsonObject event;
    event[FlowParams::ERROR_KEY] = "enter-cardname";
    QJsonObject signal = buildSignal(ENTER_NAME, event);
    emitSignal(signal);
}

void FlowSignals::emitEnterWallets()
{
    QJsonObject event;
    event[FlowParams::ERROR_KEY] = "enter-wallets";
    QJsonObject signal = buildSignal(ENTER_WALLETS, event);
    emitSignal(signal);
}

} // namespace StatusKeycard

