#include <jni.h>
#include <QString>
#include <QDebug>
#include <QMetaObject>
#include <QCoreApplication>
#include <keycard-qt/keycard_channel.h>
#include "session/session_manager.h"
#include "rpc/rpc_service.h"
#include <vector>
#include <algorithm>

// Global list of ALL RpcService instances (multiple contexts may exist)
static std::vector<StatusKeycard::RpcService*> g_rpcServices;

// Helper to register RpcService from C API
extern "C" void android_nfc_bridge_set_rpc_service(void* rpcService) {
    auto* service = reinterpret_cast<StatusKeycard::RpcService*>(rpcService);
    
    // Add to list if not already present
    auto it = std::find(g_rpcServices.begin(), g_rpcServices.end(), service);
    if (it == g_rpcServices.end()) {
        g_rpcServices.push_back(service);
        qWarning() << "JNI Bridge: RpcService registered:" << (void*)service 
                   << "| Total registered:" << g_rpcServices.size();
    } else {
        qWarning() << "JNI Bridge: RpcService already registered:" << (void*)service;
    }
}

// Helper to convert jstring to QString
static QString jstringToQString(JNIEnv* env, jstring jstr) {
    if (!jstr) return QString();
    
    const char* chars = env->GetStringUTFChars(jstr, nullptr);
    QString result = QString::fromUtf8(chars);
    env->ReleaseStringUTFChars(jstr, chars);
    return result;
}

// Called from Java when NFC tag is detected via Foreground Dispatch
extern "C" JNIEXPORT void JNICALL
Java_app_status_mobile_StatusQtActivity_nativeOnNfcTagDetected(
    JNIEnv* env, jobject thiz, jstring jUid, jobjectArray jTechList)
{
    qDebug() << "JNI: nativeOnNfcTagDetected() called";
    
    // Convert UID from Java string to QString
    QString uid = jstringToQString(env, jUid);
    qDebug() << "JNI: Card UID:" << uid;
    
    // Get tech list
    jsize techCount = env->GetArrayLength(jTechList);
    qDebug() << "JNI: Tech count:" << techCount;
    
    QStringList techList;
    for (jsize i = 0; i < techCount; i++) {
        jstring jTech = (jstring)env->GetObjectArrayElement(jTechList, i);
        QString tech = jstringToQString(env, jTech);
        techList << tech;
        env->DeleteLocalRef(jTech);
    }
    qDebug() << "JNI: Tech list:" << techList;
    
    // Check if we have IsoDep (keycard technology)
    bool hasIsoDep = techList.contains("android.nfc.tech.IsoDep");
    bool hasNfcA = techList.contains("android.nfc.tech.NfcA");
    qDebug() << "JNI: Has IsoDep:" << hasIsoDep << "Has NfcA:" << hasNfcA;
    
    if (!hasIsoDep) {
        qWarning() << "JNI: Card is not IsoDep - not a keycard?";
    }
    
    // Find an RpcService with a valid KeycardChannel
    if (g_rpcServices.empty()) {
        qWarning() << "JNI: ERROR - No RpcService registered! Cannot notify KeycardChannel";
        return;
    }
    
    qDebug() << "JNI: Card detected - letting Qt NFC handle naturally";
    
    // NOTE: We do NOT manually call channel->notifyCardDetected() because:
    // 
    // Problem: Manual notification causes crash "Not connected to any target"
    // - KeycardChannel needs a QNearFieldTarget object to send APDU commands
    // - We only have the UID string, not the actual target
    // - Qt NFC creates QNearFieldTarget when processing the NFC intent
    // 
    // Solution: Let Qt NFC detect the card naturally
    // - onNewIntent() already called setIntent() in Java
    // - Qt NFC manager should process that intent
    // - It will create proper QNearFieldTarget and emit targetDetected signal
    // - KeycardChannel (in main thread) will receive the signal with full target
    // 
    // This JNI function now serves only as diagnostic logging.
}

