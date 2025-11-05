# status-keycard-qt Architecture

## Design Philosophy

**Simple and Direct** - No unnecessary abstractions. Direct C functions that do exactly what they say.

## Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│  Application Layer (Nim / status-desktop)                   │
│  - Import: keycard_go.nim                                   │
│  - Calls: keycardStart(), keycardAuthorize(), etc.          │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│  C API Layer (status_keycard.h)                             │
│  - 15 direct C functions                                    │
│  - KeycardResult* return type                               │
│  - Signal callback system                                   │
│                                                              │
│  Functions:                                                 │
│  • keycard_initialize()                                     │
│  • keycard_start(storage_path, log_enabled, log_path)       │
│  • keycard_stop()                                           │
│  • keycard_get_status()                                     │
│  • keycard_initialize_card(pin, puk, pairing_password)      │
│  • keycard_authorize(pin)                                   │
│  • keycard_change_pin(new_pin)                              │
│  • keycard_change_puk(new_puk)                              │
│  • keycard_unblock_pin(puk, new_pin)                        │
│  • keycard_generate_mnemonic(length)                        │
│  • keycard_load_mnemonic(mnemonic, passphrase)              │
│  • keycard_export_login_keys()                              │
│  • keycard_export_recover_keys()                            │
│  • keycard_get_metadata()                                   │
│  • keycard_store_metadata(name, paths, count)               │
│  • keycard_factory_reset()                                  │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│  C++ Implementation Layer (c_api.cpp)                       │
│  - Converts C calls → SessionManager calls                  │
│  - Error handling & result construction                     │
│  - String marshalling (QString ↔ char*)                     │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│  SessionManager (C++/Qt)                                    │
│  - State machine: NotStarted → Started → CardDetected       │
│                   → Ready → Authorized                      │
│  - Card/reader monitoring (QTimer)                          │
│  - Automatic connection & pairing                           │
│  - All keycard operations                                   │
│  - Emit Qt signals on state changes                         │
└──────────────┬───────────────────┬──────────────────────────┘
               │                   │
       ┌───────▼────────┐  ┌──────▼───────────┐
       │ PairingStorage │  │  SignalManager   │
       │                │  │                  │
       │ • Load/save    │  │ • Qt signal →    │
       │   pairings.json│  │   C callback     │
       │ • Compatible   │  │ • JSON events    │
       │   with Go      │  │                  │
       └────────────────┘  └──────────────────┘
               │
┌──────────────▼──────────────────────────────────────────────┐
│  keycard-qt (Low-level APDU library)                        │
│  - CommandSet: 26 methods                                   │
│  - SecureChannel: ECDH + AES-256 + MAC                      │
│  - KeycardChannel: PC/SC (desktop) + NFC (mobile)           │
└─────────────────────────────────────────────────────────────┘
```

## File Structure

```
status-keycard-qt/
├── include/status-keycard-qt/
│   └── status_keycard.h              # Public C API
│
├── src/
│   ├── c_api.cpp                     # C API → SessionManager bridge
│   │
│   ├── session/
│   │   ├── session_manager.h/.cpp    # Core session logic
│   │   └── session_state.h           # State enum
│   │
│   ├── storage/
│   │   └── pairing_storage.h/.cpp    # pairings.json management
│   │
│   └── signal_manager.h/.cpp         # Signal/callback system
│
├── tests/
│   ├── test_session_manager.cpp
│   ├── test_c_api.cpp
│   └── test_pairing_storage.cpp
│
├── examples/
│   └── simple_usage.c
│
├── nim/
│   ├── keycard_go/
│   │   └── impl.nim                  # C function imports
│   └── keycard_go.nim                # High-level Nim wrappers
│
├── CMakeLists.txt
└── README.md
```

## State Machine

```
┌─────────────┐
│ NotStarted  │ ← Initial state
└──────┬──────┘
       │ keycard_start()
       ▼
┌─────────────┐
│   Started   │ ← Monitoring for cards
└──────┬──────┘
       │ Card detected
       ▼
┌─────────────┐
│CardDetected │ ← Connecting & pairing
└──────┬──────┘
       │ Connection established
       ▼
┌─────────────┐
│    Ready    │ ← Can call: initialize_card, get_status
└──────┬──────┘
       │ keycard_authorize(pin)
       ▼
┌─────────────┐
│ Authorized  │ ← Can call: all operations
└──────┬──────┘
       │ Card removed / keycard_stop()
       ▼
   (back to Started or NotStarted)
```

## Data Flow Examples

### Example 1: Start Service

```
Nim:  keycardStart("./pairings.json", false)
  ↓
C:    keycard_start(storage_path, log_enabled, log_path)
  ↓
C++:  SessionManager::start(storagePath, logEnabled, logFilePath)
  ↓
      - Create KeycardChannel
      - Load pairing storage
      - Start timer for card detection
      - Set state = Started
      - Emit signal: status-changed
  ↓
Signal: {"type":"status-changed","event":{"state":"Started",...}}
  ↓
Nim:  onSignal callback receives JSON
```

### Example 2: Authorize with PIN

```
Nim:  keycardAuthorize("123456")
  ↓
C:    keycard_authorize(pin)
  ↓
C++:  SessionManager::authorize(pin)
  ↓
      - Check state == Ready
      - Call CommandSet::verifyPIN(pin)
      - If success: state = Authorized
      - Emit signal: status-changed
      - Return result
  ↓
C:    Construct KeycardResult
      {success=true, data="{\"authorized\":true}"}
  ↓
Nim:  Parse result, check success
```

## Key Design Decisions

### 1. Direct C Functions (Not JSON-RPC)
- **Pro:** Simpler, faster, type-safe
- **Con:** More functions to implement (15 vs 1)
- **Decision:** Worth it for simplicity

### 2. SessionManager Owns State
- **Pro:** Single source of truth
- **Con:** Must be thread-safe
- **Decision:** Use Qt's thread model

### 3. Signals via C Callback
- **Pro:** Real-time notifications
- **Con:** JSON serialization needed
- **Decision:** Use QJsonDocument (fast enough)

### 4. Compatible pairings.json Format
- **Pro:** Can share storage with Go version
- **Con:** Must match exact format
- **Decision:** Worth it for migration

## Performance Characteristics

| Operation | Latency | Notes |
|-----------|---------|-------|
| `keycard_start()` | ~50ms | One-time setup |
| `keycard_authorize()` | ~200ms | APDU + crypto |
| `keycard_change_pin()` | ~300ms | Two APDUs |
| `keycard_sign()` | ~400ms | ECDSA on card |
| Signal emission | ~1ms | JSON serialization |
| Card detection | 100ms poll | Via QTimer |

## Memory Management

### Rule: Caller Frees Results

```c
KeycardResult* result = keycard_start(...);
if (result->success) {
    // Use result->data
}
keycard_free_result(result);  // ← MUST call
```

### Why Not Return by Value?

- C doesn't have RAII
- Need to return variable-length strings
- Pointers + explicit free = clear ownership

## Error Handling

All errors return via `KeycardResult`:

```c
typedef struct {
    bool success;
    char* error;      // Human-readable message
    char* data;       // NULL on error
} KeycardResult;
```

Example errors:
- `"Service not started"`
- `"Card not present"`
- `"Wrong PIN (2 attempts remaining)"`
- `"Not authorized (call keycard_authorize first)"`

## Signal Format

All signals are JSON:

```json
{
  "type": "status-changed",
  "event": {
    "state": "Authorized",
    "cardUID": "abc123",
    "instanceUID": "def456",
    "cardPresent": true,
    "keyInitialized": true,
    "pinRetryCount": 3,
    "pukRetryCount": 5
  }
}
```

