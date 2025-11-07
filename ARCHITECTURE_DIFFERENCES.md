# Architecture Differences: status-keycard-go vs status-keycard-qt

## Overview

After comparing the two implementations, I've identified critical architectural differences that explain why status-desktop works fine with status-keycard-go but has issues with status-keycard-qt.

## 1. Card Detection Loop

### status-keycard-go (Working)
```go
func (kc *KeycardContext) waitForCard(ctx *scard.Context, readers []string) (int, error) {
    rs := make([]scard.ReaderState, len(readers))
    
    for i := range rs {
        rs[i].Reader = readers[i]
        rs[i].CurrentState = scard.StateUnaware
    }
    
    for {
        // Check if card already present
        for i := range rs {
            if rs[i].EventState&scard.StatePresent != 0 {
                return i, nil
            }
            rs[i].CurrentState = rs[i].EventState
        }
        
        // **KEY DIFFERENCE**: Blocking wait for state changes
        err := ctx.GetStatusChange(rs, -1)  // -1 = wait forever
        if err != nil {
            return -1, err
        }
    }
}
```

**How it works:**
- Uses `SCardGetStatusChange()` with timeout = -1 (infinite)
- **Blocks** until the PC/SC subsystem reports a state change
- Event-driven, efficient, low CPU usage
- Immediately wakes up when card is inserted/removed

### status-keycard-qt (Current)
```cpp
void KeycardChannelPcsc::startDetection() {
    establishContext();
    // Start polling timer
    m_pollTimer->start(m_pollingInterval);  // 100ms
    checkForCards();
}

void KeycardChannelPcsc::checkForCards() {
    QStringList readers = listReaders();
    
    if (readers.isEmpty()) {
        if (m_connected) {
            disconnectFromCard();
            emit cardRemoved();
        }
        return;
    }
    
    // Try to connect to first reader with a card
    for (const QString& reader : readers) {
        if (connectToReader(reader)) {
            QString uid = m_lastATR.right(4).toHex();
            emit targetDetected(uid);
            return;
        }
    }
}
```

**How it works:**
- Uses QTimer to poll every 100ms
- Calls `SCardListReaders()` and `SCardConnect()` on every poll
- Polling-based, higher CPU usage
- 100ms delay before detecting card insertion

**Problem:** This creates timing issues with the flow state machine and can cause loops.

## 2. Flow Management - Flow Connection

### status-keycard-go (Working)
```go
func (f *KeycardFlow) connect() (*internal.KeycardContext, error) {
    kc, err := internal.StartKeycardContext()
    if err != nil {
        return nil, err
    }
    
    t := time.NewTimer(150 * time.Millisecond)
    
    for {
        select {
        case <-f.wakeUp:
            if f.state != Cancelling {
                panic("Resuming not expected during connection")
            }
            return nil, giveupErr()
        case <-kc.Connected():  // **Blocks until card connected**
            if kc.RunErr() != nil {
                return nil, restartErr()
            }
            t.Stop()
            if f.state == Paused {
                f.state = Running
                signal.Send(CardInserted, FlowStatus{})
            }
            return kc, nil
        case <-t.C:
            // No card after 150ms - pause and emit signal
            f.pause(InsertCard, internal.ErrorConnection, FlowParams{})
        }
    }
}
```

**Flow:**
1. Start KeycardContext (which starts detection loop in goroutine)
2. Wait 150ms with timer
3. If card detected within 150ms → continue immediately
4. If not → pause flow and emit `InsertCard` signal
5. When resumed → loop back and wait again

### status-keycard-qt (Current)
```cpp
bool FlowBase::waitForCard() {
    qDebug() << "FlowBase: Waiting for card...";
    
    while (true) {
        // Check if card already present
        if (channel()->isConnected()) {
            qDebug() << "FlowBase: Card detected";
            FlowSignals::emitCardInserted();
            return true;
        }
        
        // Wait 150ms
        QThread::msleep(150);
        
        // Check again
        if (channel()->isConnected()) {
            qDebug() << "FlowBase: Card detected after wait";
            FlowSignals::emitCardInserted();
            return true;
        }
        
        // No card - pause and wait
        qDebug() << "FlowBase: No card after 150ms, pausing...";
        pauseAndWait(FlowSignals::INSERT_CARD, "connection");
        
        if (m_cancelled) {
            return false;
        }
        
        // User resumed - loop back and check again
    }
}
```

**Issues:**
1. Polls `isConnected()` instead of waiting for event
2. When detection timer fires (every 100ms) it may not align with the flow's 150ms wait
3. Can create race conditions where flow thinks card is there but connection fails

## 3. State Machine

### status-keycard-go
- Flow runs in a goroutine
- Can pause/resume via channels
- State transitions are clean

### status-keycard-qt
- Flow runs in Qt thread pool
- Pause/resume via mutex/condition variable
- State machine is separate (FlowStateMachine)

## Root Cause of the Loop Issue

When you click "show what's on keycard" the following happens:

### status-keycard-go behavior:
1. GetMetadataFlow starts
2. Calls `connect()` which waits for card
3. Card is already there (from the event-driven detection)
4. Flow proceeds immediately
5. Requests PIN
6. Flow pauses and waits for PIN
7. User enters PIN
8. Flow completes and emits result
9. Desktop state machine transitions to next state

### status-keycard-qt behavior:
1. GetMetadataFlow starts  
2. Calls `waitForCard()` which polls  
3. Card might not be "detected" yet by polling timer
4. Flow waits 150ms, checks again
5. Polling timer fires and detects card
6. `isConnected()` returns true
7. Flow proceeds
8. **BUT** - there's a timing issue where the detection event fires AGAIN
9. Desktop state machine gets confused by extra card detection event
10. **LOOP**: State machine thinks card was inserted again and starts over

## Solution Required

To fix status-keycard-qt, we need to:

### 1. Replace Polling with Event-Driven Detection

```cpp
// Use SCardGetStatusChange() instead of polling
void KeycardChannelPcsc::startDetection() {
    // Start detection thread
    m_detectionThread = QThread::create([this]() {
        waitForCardChanges();
    });
    m_detectionThread->start();
}

void KeycardChannelPcsc::waitForCardChanges() {
    std::vector<SCARD_READERSTATE> readerStates;
    
    // Initialize reader states
    QStringList readers = listReaders();
    for (const QString& reader : readers) {
        SCARD_READERSTATE rs;
        rs.szReader = reader.toUtf8().constData();
        rs.dwCurrentState = SCARD_STATE_UNAWARE;
        readerStates.push_back(rs);
    }
    
    while (!m_stopDetection) {
        // **BLOCKING WAIT** for state changes (event-driven)
        LONG rv = SCardGetStatusChange(
            m_pcscState->context,
            INFINITE,  // or use a timeout like 1000ms
            readerStates.data(),
            readerStates.size()
        );
        
        if (rv != SCARD_S_SUCCESS) {
            continue;
        }
        
        // Check for card present
        for (auto& rs : readerStates) {
            if (rs.dwEventState & SCARD_STATE_PRESENT) {
                // Card detected!
                emit targetDetected(uid);
            }
            if (rs.dwEventState & SCARD_STATE_EMPTY) {
                // Card removed!
                emit cardRemoved();
            }
            
            // Update current state
            rs.dwCurrentState = rs.dwEventState;
        }
    }
}
```

### 2. Match Flow Connection Pattern

Make `waitForCard()` in FlowBase match the Go pattern:
- Start detection if not already running
- Use a channel/signal to wait for detection event
- 150ms timer before pausing
- Clean pause/resume cycle

### 3. Prevent Duplicate Detection Events

Ensure that when a card is detected:
- Only ONE `targetDetected` signal is emitted
- Subsequent checks don't emit again until card is removed and re-inserted
- Track last detected UID to prevent duplicates

## Next Steps

1. Refactor `KeycardChannelPcsc` to use `SCardGetStatusChange()` instead of polling
2. Update `FlowBase::waitForCard()` to match Go's connection pattern
3. Add proper state tracking to prevent duplicate detection events
4. Test the "show what's on keycard" flow to ensure no loops

This will make status-keycard-qt behave identically to status-keycard-go and fix the loop issue.

