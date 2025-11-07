#ifndef FLOW_TYPES_H
#define FLOW_TYPES_H

namespace StatusKeycard {

/**
 * @brief Flow types matching status-keycard-go exactly
 * 
 * These values MUST match the enum in status-keycard-go/pkg/flow/types.go
 * and status-desktop/src/app_service/service/keycard/service.nim
 */
enum class FlowType {
    GetAppInfo = 0,              // Get card information
    RecoverAccount = 1,          // Export all keys for recovery
    LoadAccount = 2,             // Load mnemonic to card
    Login = 3,                   // Export login keys (whisper + encryption)
    ExportPublic = 4,            // Export public key at path
    Sign = 5,                    // Sign transaction hash
    ChangePIN = 6,               // Change PIN
    ChangePUK = 7,               // Change PUK
    ChangePairing = 8,           // Change pairing password
    UnpairThis = 9,              // Unpair current slot (not used by status-desktop)
    UnpairOthers = 10,           // Unpair other slots (not used by status-desktop)
    DeleteAccountAndUnpair = 11, // Delete account + unpair (not used by status-desktop)
    StoreMetadata = 12,          // Store metadata to card
    GetMetadata = 13             // Get metadata from card
};

/**
 * @brief Flow state machine states
 */
enum class FlowState {
    Idle,        // No flow running
    Running,     // Flow executing
    Paused,      // Waiting for user input (card, PIN, etc.)
    Resuming,    // User provided input, resuming execution
    Cancelling   // Flow being cancelled
};

} // namespace StatusKeycard

#endif // FLOW_TYPES_H

