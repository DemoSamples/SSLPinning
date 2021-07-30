//
//  NetworkManager.swift
//  SSL.Public.Pinning
//
//  Created by user on 30/07/2021.
//

import Foundation
import Security
import CommonCrypto
import CryptoKit


enum PinningOption {
    case certificate
    case publicKey
}

extension Data {
    var prettyPrintedJSONString: NSString? { /// NSString gives us a nice sanitized debugDescription
        guard let object = try? JSONSerialization.jsonObject(with: self, options: []),
              let data = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted]),
              let prettyPrintedString = NSString(data: data, encoding: String.Encoding.utf8.rawValue) else { return nil }
        
        return prettyPrintedString
    }
}

// CryptoKit.Digest utils
extension Digest {
    var bytes: [UInt8] { Array(makeIterator()) }
    var data: Data { Data(bytes) }
    
    var hexStr: String {
        bytes.map { String(format: "%02X", $0) }.joined()
    }
}

class NetworkManager: NSObject,URLSessionDelegate{
    
    let pinningOption: PinningOption
    //static let publicKeyHash = "tZGz8psKrhHcAJIy2mvsTLCnbleplWEyuvJRBJYXRcY="
    static let publicKeyHash = "Ues/xSDzybWMEgs2jgMiz7GJUgX1dYZ6gKFXJso8nXU="
    
    init(option: PinningOption) {
        self.pinningOption = option
    }
    
    //    let rsa2048Asn1Header:[UInt8] = [
    //        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    //        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
    //    ]
    //
    //    private func sha256(data : Data) -> String {
    //        var keyWithHeader = Data(rsa2048Asn1Header)
    //        keyWithHeader.append(data)
    //        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
    //        keyWithHeader.withUnsafeBytes {
    //            _ = CC_SHA256($0, CC_LONG(keyWithHeader.count), &hash)
    //        }
    //        return Data(hash).base64EncodedString()
    //    }
    //
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        print(">>>>>> didReceive: ", challenge)
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        guard let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        switch self.pinningOption {
        //certificate pinning
        case .certificate:
            
            // SSL Policies for domain name check
            let policy = NSMutableArray()
            policy.add(SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString))
            
            //evaluate server certifiacte
            let isServerTrusted = SecTrustEvaluateWithError(serverTrust, nil)
            
            //Remote certificate Data
            let remoteCertificateData:NSData =  SecCertificateCopyData(serverCertificate)
            
            //let pathToCertificate = Bundle.main.path(forResource: "api.github.com", ofType: "cer")
            let pathToCertificate = Bundle.main.path(forResource: "github.com", ofType: "der")
            let localCertificateData:NSData = NSData(contentsOfFile: pathToCertificate!)!
            //Compare certificates
            if(isServerTrusted && remoteCertificateData.isEqual(to: localCertificateData as Data)){
                let credential:URLCredential =  URLCredential(trust:serverTrust)
                print("Certificate pinning is successfully completed")
                completionHandler(.useCredential, credential)
                
            }else{
                print("Certificate pinning is failed")
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
          
        //public key pinning
        case .publicKey:
            // Server public key
            let serverPublicKey = SecCertificateCopyKey(serverCertificate)
            let serverPublicKeyData = SecKeyCopyExternalRepresentation(serverPublicKey!, nil )!
            let data:Data = serverPublicKeyData as Data
            
            // Server Hash key
            //let serverHashKey = sha256(data: data)
            let serverHashKey = SHA256.hash(data: data).data.base64EncodedString()
            
            
            // Local Hash Key
            let publickKeyLocal = type(of: self).publicKeyHash
            if (serverHashKey == publickKeyLocal) {
                // Success! This is our server
                print("Public key pinning is successfully completed")
                let credential:URLCredential =  URLCredential(trust:serverTrust)
                
                completionHandler(.useCredential, credential)
                
            }else{
                print("Public key pinning is failed ")
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
            
            
            
        }
    }
    
    
    func apiCall() {
        
        let urlString = "https://api.github.com/user/repos"
        guard let url = URL(string: urlString) else {
            print("Invalid URL")
            return
        }
        
        var request = URLRequest(url: url,timeoutInterval: Double.infinity)
        request.addValue("Bearer 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", forHTTPHeaderField: "Authorization")
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let session = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
        let task = session.dataTask(with: request) { data, response, error in
            
            if error != nil {
                print(error!.localizedDescription)
            }else{
                guard let data = data else {
                    print(String(describing: error))
                    
                    return
                }
                
                print(data.prettyPrintedJSONString!)
                
            }
        }
        
        task.resume()
        
        
    }
}
