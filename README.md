# status-keycard-qt

High-level Session API for Status Keycard operations. Drop-in replacement for [status-keycard-go](../status-keycard-go).

## Overview

This library provides a **simple C API** for keycard operations, designed to integrate seamlessly with [status-desktop](../../) via Nim bindings.

**Built on:** [keycard-qt](https://github.com/alexjba/keycard-qt) - Low-level APDU library

## Architecture

```
┌──────────────────────────────────────────┐
│  status-desktop (Nim)                    │
│  Direct C function calls                 │
└──────────────┬───────────────────────────┘
               │
┌──────────────▼───────────────────────────┐
│  status-keycard-qt (C API)               │
│  • keycard_start()                       │
│  • keycard_authorize()                   │
│  • keycard_change_pin()                  │
│  • ... 15 functions                      │
└──────────────┬───────────────────────────┘
               │
┌──────────────▼───────────────────────────┐
│  SessionManager (C++/Qt)                 │
│  • Card/reader monitoring                │
│  • Auto-connection management            │
│  • State machine                         │
│  • Pairing storage                       │
└──────────────┬───────────────────────────┘
               │
┌──────────────▼───────────────────────────┐
│  keycard-qt                              │
│  • CommandSet (26 methods)               │
│  • SecureChannel (AES-256)               │
│  • KeycardChannel (PC/SC + NFC)          │
└──────────────────────────────────────────┘
```

## Features

- **Direct C API** - Simple function calls, no JSON
- **Session Management** - Auto-detection, state machine, persistent pairing
- **Signal System** - Real-time status-changed notifications
- **Cross-platform** - Linux, macOS, Windows, Android, iOS
- **Thread-safe** - Safe for concurrent access
- **Drop-in replacement** - Compatible with nim-keycard-go

## API

### Core Functions

```c
// Session management
KeycardResult* keycard_initialize(void);
KeycardResult* keycard_start(const char* storage_path, bool log_enabled, const char* log_path);
KeycardResult* keycard_stop(void);
KeycardResult* keycard_get_status(void);

// Card operations
KeycardResult* keycard_initialize_card(const char* pin, const char* puk, const char* pairing_password);
KeycardResult* keycard_authorize(const char* pin);
KeycardResult* keycard_change_pin(const char* new_pin);
KeycardResult* keycard_change_puk(const char* new_puk);
KeycardResult* keycard_unblock_pin(const char* puk, const char* new_pin);

// Key operations
KeycardResult* keycard_generate_mnemonic(int length);
KeycardResult* keycard_load_mnemonic(const char* mnemonic, const char* passphrase);
KeycardResult* keycard_export_login_keys(void);
KeycardResult* keycard_export_recover_keys(void);

// Metadata
KeycardResult* keycard_get_metadata(void);
KeycardResult* keycard_store_metadata(const char* name, const char** paths, int paths_count);

// Utilities
KeycardResult* keycard_factory_reset(void);
void keycard_free_result(KeycardResult* result);
```

### Result Structure

```c
typedef struct {
    bool success;       // Operation succeeded
    char* error;        // Error message (NULL if success)
    char* data;         // JSON data for complex results
} KeycardResult;
```

### Signal Callback

```c
typedef void (*KeycardSignalCallback)(const char* signal);
void keycard_set_signal_callback(KeycardSignalCallback callback);
```

Signal format:
```json
{
  "type": "status-changed",
  "event": {
    "state": "Ready",
    "cardUID": "abc123",
    "cardPresent": true,
    "keyInitialized": true,
    "pinRetryCount": 3,
    "pukRetryCount": 5
  }
}
```

## Building

```bash
# Prerequisites
# 1. Build keycard-qt first
cd ../qt-keycard/build
cmake .. && make

# 2. Build status-keycard-qt
cd ../../status-keycard-qt
mkdir build && cd build
cmake ..
make
```

### Dependencies

- Qt 6.9.2+ (Core)
- OpenSSL 3.x
- keycard-qt (built)
- CMake 3.16+
- C++17 compiler

## Usage Example

### C API

```c
#include <status-keycard-qt/status_keycard.h>
#include <stdio.h>

void on_signal(const char* signal) {
    printf("Signal: %s\n", signal);
}

int main() {
    KeycardResult* result;
    
    // Initialize
    result = keycard_initialize();
    if (!result->success) {
        printf("Init failed: %s\n", result->error);
        return 1;
    }
    keycard_free_result(result);
    
    // Set callback
    keycard_set_signal_callback(on_signal);
    
    // Start service
    result = keycard_start("./pairings.json", false, NULL);
    if (!result->success) {
        printf("Start failed: %s\n", result->error);
        return 1;
    }
    keycard_free_result(result);
    
    // Wait for card detection (via signals)...
    
    // Authorize
    result = keycard_authorize("123456");
    if (result->success) {
        printf("Authorized!\n");
    } else {
        printf("Auth failed: %s\n", result->error);
    }
    keycard_free_result(result);
    
    // Cleanup
    keycard_stop();
    keycard_reset();
    
    return 0;
}
```

### Nim Bindings

```nim
# keycard_go/impl.nim
type KeycardResult* = object
  success*: bool
  error*: cstring
  data*: cstring

proc keycard_initialize*(): ptr KeycardResult {.importc.}
proc keycard_start*(storage_path: cstring, log_enabled: bool, log_path: cstring): ptr KeycardResult {.importc.}
proc keycard_authorize*(pin: cstring): ptr KeycardResult {.importc.}
proc keycard_free_result*(result: ptr KeycardResult) {.importc.}

type KeycardSignalCallback* = proc(signal: cstring): void {.cdecl.}
proc keycard_set_signal_callback*(callback: KeycardSignalCallback) {.importc.}
```

```nim
# keycard_go.nim
import keycard_go/impl

proc keycardInitialize*(): string =
  let res = keycard_initialize()
  defer: keycard_free_result(res)
  if not res.success:
    return $res.error
  return "ok"

proc keycardStart*(storagePath: string, logEnabled: bool = false): string =
  let res = keycard_start(storagePath.cstring, logEnabled, nil)
  defer: keycard_free_result(res)
  if not res.success:
    return $res.error
  return "ok"

proc keycardAuthorize*(pin: string): tuple[ok: bool, authorized: bool] =
  let res = keycard_authorize(pin.cstring)
  defer: keycard_free_result(res)
  if not res.success:
    return (false, false)
  # Parse res.data JSON to get authorized field
  return (true, true)  # simplified
```

## Development Status

**Current Phase:** Phase 2 - Architecture Complete, Implementation Next

- [x] Project structure
- [x] Simplified C API (no JSON-RPC!)
- [x] Session manager design
- [X] Implementation (.cpp files)
- [X] Tests
- [X] Nim bindings
- [ ] Integration testing

## Testing

```bash
cd build
make test
```

## License

Same as keycard-qt (TBD)

## Related Projects

- [keycard-qt](https://github.com/alexjba/keycard-qt) - Low-level APDU library
- [status-keycard-go](https://github.com/status-im/status-go) - Original Go implementation
- [nim-keycard-go](https://github.com/status-im/status-im/nim-keycard-go) - Nim bindings (to be updated)
- [status-desktop](https://github.com/status-im/status-desktop) - Status Desktop application
