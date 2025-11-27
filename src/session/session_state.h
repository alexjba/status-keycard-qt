#pragma once

#include <QString>

namespace StatusKeycard {

/**
 * @brief Session states matching status-keycard-go EXACTLY
 * 
 * These string values MUST match the Go implementation:
 * https://github.com/status-im/status-keycard-go/blob/main/internal/keycard_context_v2_state.go
 */
enum class SessionState {
    UnknownReaderState,      // "unknown-reader-state"
    NoReadersFound,          // "no-readers-found"
    WaitingForReader,        // "waiting-for-reader"
    ReaderConnectionError,   // "reader-connection-error"
    WaitingForCard,          // "waiting-for-card"
    ConnectingCard,          // "connecting-card"
    EmptyKeycard,            // "empty-keycard"
    NotKeycard,              // "not-keycard"
    ConnectionError,         // "connection-error"
    PairingError,            // "pairing-error"
    BlockedPIN,              // "blocked-pin"
    BlockedPUK,              // "blocked-puk"
    Ready,                   // "ready"
    Authorized,              // "authorized"
    FactoryResetting,        // "factory-resetting"
    InternalError,            // "internal-error"
    NoAvailablePairingSlots,  // "no-available-pairing-slots"
};

inline QString sessionStateToString(SessionState state) {
    switch (state) {
        case SessionState::UnknownReaderState:    return "unknown-reader-state";
        case SessionState::NoReadersFound:        return "no-readers-found";
        case SessionState::WaitingForReader:      return "waiting-for-reader";
        case SessionState::ReaderConnectionError: return "reader-connection-error";
        case SessionState::WaitingForCard:        return "waiting-for-card";
        case SessionState::ConnectingCard:        return "connecting-card";
        case SessionState::EmptyKeycard:          return "empty-keycard";
        case SessionState::NotKeycard:            return "not-keycard";
        case SessionState::ConnectionError:       return "connection-error";
        case SessionState::PairingError:          return "pairing-error";
        case SessionState::BlockedPIN:            return "blocked-pin";
        case SessionState::BlockedPUK:            return "blocked-puk";
        case SessionState::Ready:                 return "ready";
        case SessionState::Authorized:            return "authorized";
        case SessionState::FactoryResetting:      return "factory-resetting";
        case SessionState::InternalError:         return "internal-error";
        case SessionState::NoAvailablePairingSlots: return "no-available-pairing-slots";
    }
    return "unknown-reader-state";
}

} // namespace StatusKeycard

