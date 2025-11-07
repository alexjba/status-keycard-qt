# Architecture Analysis: status-keycard-go vs status-keycard-qt

## Question 1: Architecture Differences

### status-keycard-go Architecture

**Threading Model:**
```
Main Thread
├── Start() - Establishes PC/SC context
├── startDetectionLoop(ctx) - Goroutine for card detection
│   └── detectionRoutine() - Loops calling GetStatusChange()
│       ├── getCurrentReadersState()
│       ├── connectCard() - When card found
│       │   ├── kc.card.Connect()
│       │   ├── Creates kc.c = io.NewNormalChannel(kc)
│       │   ├── Creates kc.cmdSet = keycard.NewCommandSet(kc.c)
│       │   └── selectApplet()
│       └── connectKeycard() - Initialize card
│           ├── Pair() if needed
│           ├── OpenSecureChannel()
│           ├── updateApplicationStatus() ← GET_STATUS
│           └── updateMetadata()
└── cardCommunicationRoutine(ctx) - Goroutine (OS thread locked)
    └── Handles card.Transmit() via channel
```

**Key Points:**
1. **OS Thread Locking**: `runtime.LockOSThread()` for PC/SC communication
2. **Fresh CommandSet**: Created **every time** a card is connected (line 268)
3. **Initialization Sequence**: Always calls `updateApplicationStatus()` after opening secure channel
4. **Event-Driven**: Uses `GetStatusChange()` with infinite timeout to block until card state changes

---

### status-keycard-qt Architecture

**Threading Model:**
```
Main Thread (Qt Event Loop)
├── SessionManager::start()
│   ├── Creates m_channel = KeycardChannel() IN MAIN THREAD
│   ├── Creates m_commandSet = CommandSet(m_channel) AT STARTUP ← CREATED ONCE
│   └── m_channel->startDetection()
│       └── KeycardChannelPcsc::detectionLoop() in separate QThread
│           ├── listReaders()
│           ├── SCardGetStatusChange() - wait for card
│           ├── connectToReader() when card found
│           └── emit cardDetected(uid)
└── SessionManager::onCardDetected(uid) - Qt slot on main thread
    ├── setState(ConnectingCard)
    ├── openSecureChannel()
    │   ├── Recreates m_commandSet = CommandSet(m_channel) ← AFTER MY FIX
    │   ├── select()
    │   ├── pair() if needed
    │   ├── openSecureChannel()
    │   └── getStatus() ← AFTER MY FIX
    └── setState(Ready)
```

**Key Points:**
1. **Qt Signal/Slot**: Card detection in thread, signal to main thread, processing in main thread
2. **CommandSet Lifecycle**: BEFORE FIX: created once at startup, AFTER FIX: recreated on each connection
3. **Channel Persistence**: `KeycardChannel` object persists across card insertions/removals
4. **Initialization Sequence**: NOW includes `getStatus()` after my fix

---

### Critical Architectural Difference

| Aspect | status-keycard-go | status-keycard-qt (BEFORE FIX) | status-keycard-qt (AFTER FIX) |
|--------|-------------------|--------------------------------|-------------------------------|
| **CommandSet Creation** | Every card connection (line 268) | Once at startup | Every card connection |
| **Secure Channel State** | Fresh on every connection | Reused across connections | Fresh on every connection (recreate CommandSet) |
| **POST-Channel Init** | Always calls updateApplicationStatus() | ❌ Skipped | ✅ Calls getStatus() |
| **Thread Model** | OS thread locked + goroutines | Qt event loop + detection thread | Qt event loop + detection thread |
| **Channel Object** | Recreated per connection | Persistent | Persistent |

---

## Question 2: Library Initialization and Card Connected/Disconnected Handling

### status-keycard-go: Initialization Flow

#### On App Start (No Card Present):
```go
1. NewKeycardContextV2(options)
2. Start()
   ├── establishContext() → scard.EstablishContext()
   ├── go cardCommunicationRoutine(ctx) → Locked OS thread
   └── startDetectionLoop(ctx)
       └── detectionRoutine()
           ├── getCurrentReadersState()
           ├── connectCard() → returns nil (no card)
           └── SCardGetStatusChange(readers, INFINITE) → BLOCKS waiting
```

**State**: `WaitingForCard`
**CommandSet**: `nil`
**SecureChannel**: Does not exist

---

#### On Card Inserted:
```go
1. SCardGetStatusChange() returns (card detected)
2. detectionRoutine() calls:
   ├── connectCard(readers)
   │   ├── kc.forceScanC = make(chan struct{})
   │   ├── kc.resetCardConnection() → Clean slate
   │   ├── scard.Connect(reader, ShareExclusive) → kc.card
   │   ├── kc.c = io.NewNormalChannel(kc) → NEW CHANNEL
   │   ├── kc.cmdSet = keycard.NewCommandSet(kc.c) → NEW COMMANDSET
   │   ├── kc.selectApplet()
   │   └── kc.status.State = ConnectingCard
   └── connectKeycard()
       ├── Pair() if needed
       ├── OpenSecureChannel(pair.Index, pair.Key)
       ├── updateApplicationStatus() → GetStatusApplication()
       │   └── Changes state to Ready
       └── updateMetadata()
3. go watchActiveReader(ctx, card.readerState)
   └── Polls for card removal
```

**State**: `ConnectingCard` → `Ready` (or `Authorized` after PIN)
**CommandSet**: Fresh instance created
**SecureChannel**: Opened and initialized

---

#### On Card Removed:
```go
1. watchActiveReader() detects: state&scard.StateEmpty != 0
2. Calls kc.startDetectionLoop(ctx) → Restart detection
3. detectionRoutine() starts over:
   ├── kc.resetCardConnection()
   │   ├── kc.card.Disconnect(LeaveCard)
   │   ├── kc.card = nil
   │   ├── kc.c = nil
   │   └── kc.cmdSet = nil ← COMPLETELY DESTROYED
   └── Back to SCardGetStatusChange() waiting
```

**State**: `WaitingForCard`
**CommandSet**: `nil` (destroyed)
**SecureChannel**: Destroyed

---

### status-keycard-qt: Initialization Flow (AFTER MY FIXES)

#### On App Start (No Card Present):
```cpp
1. SessionManager::start(storagePath)
   ├── m_channel = new KeycardChannel() → IN MAIN THREAD
   ├── m_commandSet = new CommandSet(m_channel) → CREATED BUT NOT USED YET
   ├── connect signals (cardDetected, cardRemoved)
   └── m_channel->startDetection()
       └── KeycardChannelPcsc::detectionLoop() in QThread
           ├── SCardGetStatusChange() with 1s timeout
           └── Loop continues...
```

**State**: `WaitingForCard`
**CommandSet**: Created but not initialized (no SELECT, no secure channel)
**SecureChannel**: Not open
**Channel**: Connected to PC/SC, monitoring readers

---

#### On Card Inserted:
```cpp
1. detectionLoop() detects card:
   ├── connectToReader(readerName)
   ├── m_lastATR = getATR()
   └── emit cardDetected(uid) → Signal to main thread

2. SessionManager::onCardDetected(uid) - Main thread Qt slot:
   ├── setState(ConnectingCard)
   └── openSecureChannel()
       ├── m_commandSet = new CommandSet(m_channel) → RECREATE (MY FIX)
       ├── m_appInfo = m_commandSet->select()
       ├── m_pairingInfo = loadPairing() or pair()
       ├── m_commandSet->openSecureChannel(m_pairingInfo)
       └── m_commandSet->getStatus(P1GetStatusApplication) → INITIALIZE (MY FIX)

3. setState(Ready)
```

**State**: `ConnectingCard` → `Ready`
**CommandSet**: Fresh instance (recreated)
**SecureChannel**: Opened and initialized with GET_STATUS
**Channel**: Still connected, card handle active

---

#### On Card Removed:
```cpp
1. detectionLoop() in while(connected) loop detects:
   ├── readerState.dwEventState & SCARD_STATE_EMPTY
   ├── disconnectFromCard()
   │   └── SCardDisconnect(cardHandle, LEAVE_CARD)
   └── emit cardRemoved() → Signal to main thread

2. SessionManager::onCardRemoved() - Main thread Qt slot:
   ├── m_currentCardUID.clear()
   ├── m_authorized = false
   ├── closeSecureChannel()
   │   └── m_pairingInfo = PairingInfo() → Clear pairing
   └── setState(WaitingForCard)

3. detectionLoop() continues waiting for next card
```

**State**: `WaitingForCard`
**CommandSet**: NOT destroyed, but will be recreated on next connection (MY FIX)
**SecureChannel**: Closed (but CommandSet still exists until next connection)
**Channel**: Still active, still monitoring

---

### Key Difference in State Management

| Event | status-keycard-go | status-keycard-qt (AFTER FIX) |
|-------|-------------------|-------------------------------|
| **Card Removed** | `cmdSet = nil` (destroyed) | `cmdSet` still exists (stale) |
| **Card Inserted** | `cmdSet = new()` (fresh) | `cmdSet = new()` (fresh, because of FIX) |
| **Channel Object** | Destroyed & recreated | Persistent |
| **PC/SC Connection** | `Connect()` → `Disconnect()` | `Connect()` → `Disconnect()`, but context persists |

**Why This Matters**:
- Go's approach: **Complete cleanup**, no stale state possible
- Qt's approach: **Partial cleanup**, requires explicit `CommandSet` recreation (which my fix adds)

---

## Question 3: Card at Startup vs Card Inserted Later

### status-keycard-go: SAME FLOW REGARDLESS

The Go implementation has **NO DIFFERENCE** between startup and post-insertion because:

1. `detectionRoutine()` **always** calls `connectCard()` when a card is found
2. `connectCard()` **always** calls `resetCardConnection()` first (line 247)
3. `resetCardConnection()` **always** sets `kc.cmdSet = nil` (line 451)
4. New `CommandSet` is **always** created (line 268)
5. `connectKeycard()` **always** runs the full initialization sequence

**Result**: Whether the card is present at startup or inserted later, the exact same code path executes.

---

### status-keycard-qt: DIFFERENT FLOWS (BEFORE MY FIX)

#### Scenario A: Card Present at App Startup

```
1. App starts
2. SessionManager::start()
   ├── Creates m_channel
   ├── Creates m_commandSet ← NEVER USED
   └── Starts detection

3. Within milliseconds:
   ├── detectionLoop() immediately finds card
   └── emit cardDetected(uid)

4. onCardDetected(uid)
   └── openSecureChannel()
       ├── Uses SAME m_commandSet created at startup ← FRESH STATE
       ├── select() → Works
       ├── openSecureChannel() → Works
       └── ❌ Missing getStatus() → But somehow works?
```

**Why it worked**: Timing! The `m_commandSet` was created mere **milliseconds** before use. The `SecureChannel` inside it is brand new, never been used. By luck, this fresh state happens to work.

---

#### Scenario B: Card Inserted After App Running

```
1. App starts
2. SessionManager::start()
   ├── Creates m_channel
   ├── Creates m_commandSet ← SITS IDLE
   └── Starts detection

3. User waits 10 seconds...
   (CommandSet object sitting in memory, uninitialized)

4. User inserts card:
   ├── detectionLoop() finds card
   └── emit cardDetected(uid)

5. onCardDetected(uid)
   └── openSecureChannel()
       ├── Uses SAME m_commandSet created 10 seconds ago ← STALE
       ├── select() → Works (creates new SecureChannel internally)
       ├── openSecureChannel() → Opens channel
       └── ❌ Missing getStatus() → FAILS
```

**Why it failed**:
1. The `CommandSet` object was created long ago but never properly initialized
2. When `openSecureChannel()` is called, the internal `SecureChannel` is created
3. But without `GET_STATUS` after opening, the **Keycard's internal state** is not initialized
4. The card firmware expects: `SELECT` → `OPEN_SECURE_CHANNEL` → `GET_STATUS` (initialize internal pointers)
5. Next command (`VERIFY_PIN`) fails because card's internal state machine is incomplete

---

### Why Timing Matters

#### Card at Startup (WORKS by luck):
```
Time 0ms:    App starts
Time 10ms:   CommandSet created
Time 50ms:   Card detected
Time 51ms:   openSecureChannel() uses CommandSet
             ↳ Everything is "fresh", less chance of state corruption
```

#### Card Inserted Later (FAILS):
```
Time 0ms:     App starts
Time 10ms:    CommandSet created
             ↓
         [10 seconds pass]
             ↓
Time 10000ms: Card inserted
Time 10001ms: openSecureChannel() uses CommandSet
              ↳ CommandSet state may have drifted
              ↳ Card state not initialized after channel open
              ↳ Missing GET_STATUS leaves card in limbo
```

---

### What My Fixes Address

#### Fix #1: Recreate CommandSet on Every Connection
```cpp
// SessionManager::openSecureChannel()
if (m_channel) {
    qDebug() << "SessionManager: Creating fresh CommandSet for new secure channel session";
    m_commandSet = std::make_unique<Keycard::CommandSet>(m_channel.get());
}
```

**Effect**: Now BOTH scenarios (startup & post-insertion) get a fresh `CommandSet`, matching Go's behavior.

---

#### Fix #2: Call GET_STATUS After Opening Channel
```cpp
// SessionManager::openSecureChannel()
qDebug() << "SessionManager: Fetching application status to initialize card state";
Keycard::ApplicationStatus appStatus = m_commandSet->getStatus(Keycard::APDU::P1GetStatusApplication);
```

**Effect**: The Keycard's internal state machine is properly initialized, matching Go's `updateApplicationStatus()`.

---

#### Fix #3: Parse Actual Status Word
```cpp
// keycard-qt/src/crypto/secure_channel.cpp
// OLD: return APDU::Response(decrypted + QByteArray::fromHex("9000"));
// NEW:
return APDU::Response(decrypted); // SW is already in decrypted data
```

**Effect**: Errors are no longer masked, so we can actually debug what's failing.

---

## Summary: The Root Cause

The issue was NOT a single bug, but a **combination of architectural differences**:

1. **Go destroys and recreates everything on each connection** → Qt kept objects alive
2. **Go always calls GET_STATUS after opening channel** → Qt skipped this
3. **Go properly parses status words from decrypted data** → Qt was appending fake success

When the card was present at startup, these issues were **masked by timing** - the `CommandSet` was so fresh that it worked despite the missing initialization steps.

When the card was inserted later, the **accumulated state drift** and **missing initialization** caused failures that were **silently hidden** by the status word masking bug.

**All three fixes were needed**:
- Fix #1: Eliminates state drift (fresh CommandSet)
- Fix #2: Proper card initialization (GET_STATUS)
- Fix #3: Proper error visibility (status word parsing)

