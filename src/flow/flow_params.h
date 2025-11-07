#ifndef FLOW_PARAMS_H
#define FLOW_PARAMS_H

#include <QString>

namespace StatusKeycard {
namespace FlowParams {

/**
 * @brief Parameter keys for Flow API
 * 
 * These MUST match status-keycard-go/pkg/flow/types.go exactly
 */

// Error and status keys
const QString ERROR_KEY = "error";
const QString INSTANCE_UID = "instance-uid";
const QString KEY_UID = "key-uid";
const QString FREE_SLOTS = "free-pairing-slots";
const QString PIN_RETRIES = "pin-retries";
const QString PUK_RETRIES = "puk-retries";

// Authentication parameters
const QString PAIRING_PASS = "pairing-pass";
const QString PAIRED = "paired";
const QString PIN = "pin";
const QString NEW_PIN = "new-pin";
const QString PUK = "puk";
const QString NEW_PUK = "new-puk";
const QString NEW_PAIRING = "new-pairing-pass";

// Key export parameters
const QString MASTER_KEY = "master-key";
const QString MASTER_ADDR = "master-key-address";
const QString WALLET_ROOT_KEY = "wallet-root-key";
const QString WALLET_KEY = "wallet-key";
const QString EIP1581_KEY = "eip1581-key";
const QString WHISPER_KEY = "whisper-key";
const QString ENC_KEY = "encryption-key";
const QString EXPORTED_KEY = "exported-key";

// Mnemonic parameters
const QString MNEMONIC = "mnemonic";
const QString MNEMONIC_LEN = "mnemonic-length";
const QString MNEMONIC_IDXS = "mnemonic-indexes";

// Transaction parameters
const QString TX_HASH = "tx-hash";
const QString TX_SIGNATURE = "tx-signature";
const QString BIP44_PATH = "bip44-path";

// Metadata parameters
const QString CARD_META = "card-metadata";
const QString CARD_NAME = "card-name";
const QString WALLET_PATHS = "wallet-paths";

// Operation flags
const QString FACTORY_RESET = "factory reset";
const QString OVERWRITE = "overwrite";
const QString RESOLVE_ADDR = "resolve-addresses";
const QString EXPORT_MASTER = "export-master-address";
const QString EXPORT_PRIV = "export-private";
const QString SKIP_AUTH_UID = "skip-auth-uid";

// Application info
const QString APP_INFO = "application-info";

} // namespace FlowParams
} // namespace StatusKeycard

#endif // FLOW_PARAMS_H

