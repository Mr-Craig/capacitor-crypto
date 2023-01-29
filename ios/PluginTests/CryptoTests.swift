import XCTest
@testable import Plugin

@available(iOS 14.0, *)
class CryptoTests: XCTestCase {
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func testEcho() {
        // This is an example of a functional test case for a plugin.
        // Use XCTAssert and related functions to verify your tests produce the correct results.

        let implementation = Crypto()
        let value = "Hello, World!"
        let result = implementation.echo(value)

        XCTAssertEqual(value, result)
    }
    
    func testGenerateKeys() {
        let implementation = Crypto();
        let keysArray = implementation.generateKeyPair();
        
        XCTAssertEqual(keysArray.count, 2);
    }
    
    func testRandomBytes() throws {
        let implementation = Crypto();
        let randomBytesBase64 = try implementation.generateRandomBytes(32);
        guard let randomBytes = Data(base64Encoded: randomBytesBase64) else {
            throw NSError(domain: "Error converting random bytes from base64 to Data!", code:1);
        }
        
        XCTAssertEqual(randomBytes.count, 32);
    }
    
    func testSharedSecret() throws {
        let implementation = Crypto();
        
        let BobKeys = implementation.generateKeyPair();
        let AliceKeys = implementation.generateKeyPair();
        
        let Salt = try implementation.generateRandomBytes(16);
        
        let BobSharedSecret = try! implementation.generateSharedSecret(BobKeys.lastObject as! String, AliceKeys.firstObject as! String, Salt);
        let AliceSharedSecret = try! implementation.generateSharedSecret(AliceKeys.lastObject as! String, BobKeys.firstObject as! String, Salt);
            
        XCTAssertEqual(BobSharedSecret, AliceSharedSecret);
    }
    
    func testEncryption() throws {
        let implementation = Crypto();
        
        let BobKeys = implementation.generateKeyPair();
        let AliceKeys = implementation.generateKeyPair();
        
        let Salt = try implementation.generateRandomBytes(16);
        
        let BobSharedSecret = try! implementation.generateSharedSecret(BobKeys.lastObject as! String, AliceKeys.firstObject as! String, Salt);
        let AliceSharedSecret = try! implementation.generateSharedSecret(AliceKeys.lastObject as! String, BobKeys.firstObject as! String, Salt);
        
        let testEncryptionString = "Hello, Testing! 🔥🔥🔥🔥";
        
        let BobEncrypted = try! implementation.encrypt(BobSharedSecret, testEncryptionString);
        let AliceDecrypted = try! implementation.decrypt(AliceSharedSecret, BobEncrypted[0] as! String, BobEncrypted[1] as! String, BobEncrypted[2] as! String);
        
        XCTAssertEqual(testEncryptionString, AliceDecrypted);
    }
    
    func testWebDecryption() throws {
        // output from web
        let webPrivateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgohwy/7Hl57p3GeZWy3Ae4pGlNqrwGrvGvlLsiEw8R++hRANCAAT6jwWlr8QzQeFb/7kqgqpj+IVADzek58GiUJ9xJRft0Q9bIyZcPHN0WLxeZilCKq+doMSVAuruZSHxP5hzG/aR";
        let webPublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+o8Fpa/EM0HhW/+5KoKqY/iFQA83pOfBolCfcSUX7dEPWyMmXDxzdFi8XmYpQiqvnaDElQLq7mUh8T+Ycxv2kQ==";
        
        let iosPublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzwC7EpEJlrgEaSLYbLDcTGvCj09vT4FBeKv6/VizgBMvgORq8Yd8CgcDhLL49lIrMNm5/1nVyrDQU/IpMtj1CA==";
        let iosPrivateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGPLJtAC1onmm2WeeHZye5d7m9wOp+wFfj78uGVEI9eShRANCAATPALsSkQmWuARpIthssNxMa8KPT29PgUF4q/r9WLOAEy+A5Grxh3wKBwOEsvj2Uisw2bn/WdXKsNBT8iky2PUI";
        
        let salt = "aZhr5Op9wI1i8rcmrcJCCg==";
        
        let webSharedSecret = "MfHcVKelgsXEmPdy5vKfeogV3FxoyBIvyefyG2Q+Pxw=";
        
        let implementation = Crypto();
        
        let iosSharedSecret = try! implementation.generateSharedSecret(iosPrivateKey, webPublicKey, salt);
        
        XCTAssertEqual(webSharedSecret, iosSharedSecret);
        
        let sharedSecret = "NLSOGZX4BXhx32tG9UGMs9uS9Gwfrb4vkIyxdMQQpXw=";
        let encryptedData = "c9OhmsuPwBTV7uEbEO+D";
        let tag = "fRZ4V/m7P4GSc/WZe2pNnA==";
        let iv = "eAGFKX/vo8AlukxK";
        
        let decryptedString = try! implementation.decrypt(sharedSecret, encryptedData, tag, iv);
        
        XCTAssertEqual(decryptedString, "Hello, Testing!");
    }
    
    func testAndroidDecryption() throws {
        // output from android
        let sharedSecret = "kVqdH5ozORnjvr4VwspIT+HA1I6hheoITnOA2feU2/k=";
        let encryptedData = "c2bzRgCbf3DK3MraUMYr";
        let tag = "sRhz87dzlrXuzU/kEkZkSA==";
        let iv = "kSFDdaD8vyuLVvQG";
        
        let implementation = Crypto();
        
        let decryptedString = try! implementation.decrypt(sharedSecret, encryptedData, tag, iv);
        
        XCTAssertEqual(decryptedString, "Hello, Testing!");
    }
    
    func testHashing() throws {
        let hashedString = "Hello, Testing!"
        let hashedResult = "ecf39aff4e3f57f1fdb82e161fd4e6d622d5cbc3a06bbc1c51b93f87b6a4e2c272da2787b6c511cd071dd7add45e87d18a118e501fba39709b1bec931f26eec0";
        let implementation = Crypto();
        
        let hashTest = try! implementation.hash(hashedString);
        
        XCTAssertEqual(hashedResult, hashTest);
    }
}
