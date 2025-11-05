#include <status-keycard-qt/status_keycard.h>
#include <stdio.h>
#include <unistd.h>

// Signal handler
void on_signal(const char* signal) {
    printf("\n📡 Signal received: %s\n\n", signal);
}

int main() {
    printf("=== Status Keycard Qt - Simple Usage Example ===\n\n");
    
    KeycardResult* result;
    
    // 1. Initialize
    printf("1. Initializing...\n");
    result = keycard_initialize();
    if (!result->success) {
        printf("   ❌ Failed: %s\n", result->error);
        return 1;
    }
    printf("   ✅ Initialized\n\n");
    keycard_free_result(result);
    
    // 2. Set signal callback
    printf("2. Setting up signal callback...\n");
    keycard_set_signal_callback(on_signal);
    printf("   ✅ Callback set\n\n");
    
    // 3. Start service
    printf("3. Starting keycard service...\n");
    result = keycard_start("./pairings.json", false, NULL);
    if (!result->success) {
        printf("   ❌ Failed: %s\n", result->error);
        keycard_free_result(result);
        return 1;
    }
    printf("   ✅ Service started\n\n");
    keycard_free_result(result);
    
    // 4. Get status
    printf("4. Getting status...\n");
    result = keycard_get_status();
    if (result->success && result->data) {
        printf("   Status: %s\n\n", result->data);
    } else {
        printf("   ❌ Failed: %s\n", result->error ? result->error : "unknown");
    }
    keycard_free_result(result);
    
    // 5. Wait for card
    printf("5. Waiting for keycard (insert card now)...\n");
    printf("   Press Ctrl+C to exit\n\n");
    
    // Keep running to receive signals
    for (int i = 0; i < 30; i++) {
        sleep(1);
        
        // Check status periodically
        if (i % 5 == 0) {
            result = keycard_get_status();
            if (result->success && result->data) {
                printf("   [Status check] %s\n", result->data);
            }
            keycard_free_result(result);
        }
    }
    
    // 6. Stop service
    printf("\n6. Stopping service...\n");
    result = keycard_stop();
    if (result->success) {
        printf("   ✅ Service stopped\n");
    }
    keycard_free_result(result);
    
    // 7. Cleanup
    printf("7. Cleaning up...\n");
    keycard_reset();
    printf("   ✅ Done\n\n");
    
    return 0;
}

