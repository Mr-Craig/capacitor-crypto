import Foundation
import Capacitor

/**
 * Please read the Capacitor iOS Plugin Development Guide
 * here: https://capacitorjs.com/docs/plugins/ios
 */
@available(iOS 14.0, *)
@objc(CryptoPlugin)
public class CryptoPlugin: CAPPlugin {
    private let implementation = Crypto();

    @objc func echo(_ call: CAPPluginCall) {
        let value = call.getString("value") ?? ""
        call.resolve([
            "value": implementation.echo(value)
        ])
    }
    
    @objc func generateKeyPair(_ call: CAPPluginCall) {
        let generatedKeyPair = implementation.generateKeyPair();
        call.resolve([
            "publicKey": generatedKeyPair.firstObject as! String,
            "privateKey": generatedKeyPair.lastObject as! String
        ])
    }
    
    @objc func generateRandomBytes(_ call: CAPPluginCall) {
        let bytesToGen = call.getInt("count") ?? 0;
        
        do {
            let randomBytes = try implementation.generateRandomBytes(bytesToGen);
            
            call.resolve([
                "bytesBase64": randomBytes
            ])
        } catch let error as NSError {
            call.reject("NSError: \(error.domain) \(error.localizedDescription) \(error.localizedFailureReason ?? "")");
        }
    }
    
    @objc func generateSharedSecret(_ call: CAPPluginCall) {
        do
        {
            let secretKey = try implementation.generateSharedSecret(call.getString("privateKey") ?? "", call.getString("publicKey") ?? "", call.getString("salt") ?? "")
            
            call.resolve([
                "sharedSecret": secretKey
            ]);
        } catch let error as NSError {
            call.reject("NSError: \(error.domain) \(error.localizedDescription) \(error.localizedFailureReason ?? "")");
        }
    }
    @objc func decrypt(_ call: CAPPluginCall) {
        do {
            guard let key = call.options["key"] as? String else {
                call.reject("Must provide a key")
                return
            }
            guard let encryptedData = call.options["encryptedData"] as? String else {
                call.reject("Must provide encryptedData")
                return
            }
            guard let tag = call.options["tag"] as? String else {
                call.reject("Must provide a tag")
                return
            }
            guard let iv = call.options["iv"] as? String else {
                call.reject("Must provide an iv")
                return
            }
            
            let res = try implementation.decrypt(key, encryptedData, tag, iv);

            call.resolve([
                "unencryptedData": res
            ]);
        } catch let error as NSError {
            call.reject("NSError: \(error.domain) \(error.localizedDescription) \(error.localizedFailureReason ?? "")");
        }
    }
    @objc func encrypt(_ call: CAPPluginCall)
    {
        do {
            guard let key = call.options["key"] as? String else {
                call.reject("Must provide a key")
                return
            }
            guard let data = call.options["data"] as? String else {
                call.reject("Must provide data")
                return
            }
            
            let res = try implementation.encrypt(key, data);

            call.resolve([
                "encryptedData": res[0],
                "tag": res[1],
                "iv": res[2]
            ]);
        } catch let error as NSError {
            call.reject("NSError: \(error.domain) \(error.localizedDescription) \(error.localizedFailureReason ?? "")");
        }
    }
    @objc func hash(_ call: CAPPluginCall) 
    {
        do {
            guard let data = call.options["data"] as? String else {
                call.reject("Must Provide Data");
                return;
            }
            
            let hash = try implementation.hash(data);
            call.resolve([
                "hash": hash
            ]);
        } catch let error as NSError {
            call.reject("NSError: \(error.domain) \(error.localizedDescription) \(error.localizedFailureReason ?? "")");
        }
    }
}
