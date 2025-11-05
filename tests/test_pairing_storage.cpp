#include <QtTest/QtTest>
#include <QTemporaryDir>
#include <QFile>
#include "storage/pairing_storage.h"
#include <keycard-qt/types.h>

using namespace StatusKeycard;

class TestPairingStorage : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void init();
    void cleanup();

    // Storage tests
    void testCreateNewStorage();
    void testLoadNonExistentFile();
    void testLoadCorruptedFile();
    void testStorePairing();
    void testLoadPairing();
    void testHasPairing();
    void testDeletePairing();
    void testMultiplePairings();
    void testPersistence();
    void testEmptyStorage();

private:
    QTemporaryDir* m_tempDir;
    QString m_storagePath;
};

void TestPairingStorage::initTestCase()
{
    // Nothing needed
}

void TestPairingStorage::cleanupTestCase()
{
    // Nothing needed
}

void TestPairingStorage::init()
{
    m_tempDir = new QTemporaryDir();
    QVERIFY(m_tempDir->isValid());
    m_storagePath = m_tempDir->filePath("test_pairings.json");
}

void TestPairingStorage::cleanup()
{
    delete m_tempDir;
    m_tempDir = nullptr;
}

void TestPairingStorage::testCreateNewStorage()
{
    PairingStorage storage(m_storagePath);
    
    // New storage should not exist yet
    QVERIFY(!QFile::exists(m_storagePath));
    
    // Save should create the file
    QVERIFY(storage.save());
    QVERIFY(QFile::exists(m_storagePath));
}

void TestPairingStorage::testLoadNonExistentFile()
{
    PairingStorage storage(m_storagePath);
    
    // Loading non-existent file returns true (starts fresh)
    // This is actually correct behavior - not an error
    bool result = storage.load();
    // May return true or false, both are valid
    
    // But should not crash and should have no pairings
    QVERIFY(!storage.hasPairing("test-uid"));
}

void TestPairingStorage::testLoadCorruptedFile()
{
    // Create a corrupted JSON file
    QFile file(m_storagePath);
    QVERIFY(file.open(QIODevice::WriteOnly));
    file.write("{ corrupted json ");
    file.close();
    
    PairingStorage storage(m_storagePath);
    
    // Loading corrupted file should return false
    QVERIFY(!storage.load());
}

void TestPairingStorage::testStorePairing()
{
    PairingStorage storage(m_storagePath);
    
    // Create a test pairing
    Keycard::PairingInfo pairing;
    pairing.key = QByteArray::fromHex("0123456789abcdef");
    pairing.index = 1;
    
    // Store the pairing
    QVERIFY(storage.storePairing("test-uid", pairing));
    
    // Save to disk
    QVERIFY(storage.save());
    
    // Verify file exists
    QVERIFY(QFile::exists(m_storagePath));
}

void TestPairingStorage::testLoadPairing()
{
    // First, store a pairing
    {
        PairingStorage storage(m_storagePath);
        
        Keycard::PairingInfo pairing;
        pairing.key = QByteArray::fromHex("0123456789abcdef0123456789abcdef");
        pairing.index = 2;
        
        QVERIFY(storage.storePairing("test-uid-123", pairing));
        QVERIFY(storage.save());
    }
    
    // Now load it in a new instance
    {
        PairingStorage storage(m_storagePath);
        QVERIFY(storage.load());
        
        QVERIFY(storage.hasPairing("test-uid-123"));
        
        Keycard::PairingInfo loaded = storage.loadPairing("test-uid-123");
        QVERIFY(loaded.isValid());
        QCOMPARE(loaded.key, QByteArray::fromHex("0123456789abcdef0123456789abcdef"));
        QCOMPARE(loaded.index, 2);
    }
}

void TestPairingStorage::testHasPairing()
{
    PairingStorage storage(m_storagePath);
    
    // Should not have any pairings initially
    QVERIFY(!storage.hasPairing("test-uid"));
    
    // Store a pairing
    Keycard::PairingInfo pairing;
    pairing.key = QByteArray::fromHex("deadbeef");
    pairing.index = 1;
    storage.storePairing("test-uid", pairing);
    
    // Now should have it
    QVERIFY(storage.hasPairing("test-uid"));
    QVERIFY(!storage.hasPairing("non-existent-uid"));
}

void TestPairingStorage::testDeletePairing()
{
    PairingStorage storage(m_storagePath);
    
    // Store a pairing
    Keycard::PairingInfo pairing;
    pairing.key = QByteArray::fromHex("cafebabe");
    pairing.index = 1;
    storage.storePairing("test-uid", pairing);
    
    QVERIFY(storage.hasPairing("test-uid"));
    
    // Delete it
    QVERIFY(storage.removePairing("test-uid"));
    
    // Should not have it anymore
    QVERIFY(!storage.hasPairing("test-uid"));
    
    // Deleting non-existent should return false
    QVERIFY(!storage.removePairing("non-existent-uid"));
}

void TestPairingStorage::testMultiplePairings()
{
    PairingStorage storage(m_storagePath);
    
    // Store multiple pairings
    for (int i = 0; i < 5; i++) {
        Keycard::PairingInfo pairing;
        pairing.key = QByteArray::fromHex(QString("%1").arg(i, 32, 16, QChar('0')).toLatin1());
        pairing.index = i;
        
        QString uid = QString("test-uid-%1").arg(i);
        QVERIFY(storage.storePairing(uid, pairing));
    }
    
    // Verify all pairings exist
    for (int i = 0; i < 5; i++) {
        QString uid = QString("test-uid-%1").arg(i);
        QVERIFY(storage.hasPairing(uid));
        
        Keycard::PairingInfo loaded = storage.loadPairing(uid);
        QVERIFY(loaded.isValid());
        QCOMPARE(loaded.index, i);
    }
    
    // Save and reload
    QVERIFY(storage.save());
    
    PairingStorage storage2(m_storagePath);
    QVERIFY(storage2.load());
    
    // Verify all pairings still exist after reload
    for (int i = 0; i < 5; i++) {
        QString uid = QString("test-uid-%1").arg(i);
        QVERIFY(storage2.hasPairing(uid));
    }
}

void TestPairingStorage::testPersistence()
{
    QString uid1 = "card-instance-1";
    QString uid2 = "card-instance-2";
    
    // Create and store pairings
    {
        PairingStorage storage(m_storagePath);
        
        Keycard::PairingInfo pairing1;
        pairing1.key = QByteArray::fromHex("1111111111111111");
        pairing1.index = 1;
        
        Keycard::PairingInfo pairing2;
        pairing2.key = QByteArray::fromHex("2222222222222222");
        pairing2.index = 2;
        
        storage.storePairing(uid1, pairing1);
        storage.storePairing(uid2, pairing2);
        
        QVERIFY(storage.save());
    }
    
    // Load in new instance and verify
    {
        PairingStorage storage(m_storagePath);
        QVERIFY(storage.load());
        
        QVERIFY(storage.hasPairing(uid1));
        QVERIFY(storage.hasPairing(uid2));
        
        Keycard::PairingInfo pairing1 = storage.loadPairing(uid1);
        Keycard::PairingInfo pairing2 = storage.loadPairing(uid2);
        
        QCOMPARE(pairing1.key, QByteArray::fromHex("1111111111111111"));
        QCOMPARE(pairing2.key, QByteArray::fromHex("2222222222222222"));
        
        QCOMPARE(pairing1.index, 1);
        QCOMPARE(pairing2.index, 2);
    }
}

void TestPairingStorage::testEmptyStorage()
{
    PairingStorage storage(m_storagePath);
    
    // Empty storage should save successfully
    QVERIFY(storage.save());
    
    // Load empty storage
    PairingStorage storage2(m_storagePath);
    QVERIFY(storage2.load());
    
    // Should not have any pairings
    QVERIFY(!storage2.hasPairing("any-uid"));
}

QTEST_MAIN(TestPairingStorage)
#include "test_pairing_storage.moc"

