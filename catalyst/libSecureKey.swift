/*
 Copyright 2025 SAS Institute, Inc., Cary, NC USA

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */
//
//  libSecureKey.swift
//  catalyst
//
//  Created by Henry Kon on 5/15/24.
//

import Foundation
import CryptoKit
import os

private let logger = Logger(
    subsystem: Bundle.main.bundleIdentifier!,
    category: String(describing: "Catalyst.libSecureKey")
)

/**
 The object definition for an `EnclaveKey` object, containing a representation of the Secure Enclave-backed cryptographic key and a cryptographic salt for derivation of a symmetric key.
 */
public struct EnclaveKey: Codable {
    let privateKeyDataRepresentation: Data
    let salt: Data
}

/**
 Enumerations for thrown errors in this module.
 */
public enum EnclaveWrapperError: Error {
    /// The Secure Enclave is not supported on this device or is not available to the program.
    case secureEnclaveUnavailable
    /// The symmetric encryption key could not be generated due to a cryptographic error.
    case keyGenerationFailed
    /// The EnclaveKey object could not be found or could not be decoded.
    case keysNotFound
    /// The EnclaveKey object could not be stored in the Keychain.
    case keyCacheSaveFailed
    /// The EnclaveKey object could not be encoded for storage
    case keyCacheEncodingFailed
    /// The EnclaveKey object could not be decoded from its representation in the Keychain
    case keyCacheDecodingFailed
    /// The EnclaveKey object could not be retrieved from the Keychain.
    case keyCacheFetchFailed
    /// Data could not be encypted using the provided cryptographic information.
    case keyEncryptionFailed
    /// Data could not be decrypted using the provided cryptographic information.
    case keyDecryptionFailed
}

/**
 Object extension for an `EnclaveKey` object
 */
extension EnclaveKey {
    /**
     Derives a symmetric cryptographic key from the wrapped Secure Enclave Key Representation and the stored cryptographic salt.
    - Throws: `EnclaveWrapperError.keyGenerationFailed` if the symmetric encryption key could not be generated due to a cryptographic error.
     */
    func symmetricKey() throws -> SymmetricKey {
        let privateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: self.privateKeyDataRepresentation)
        let publicKey = privateKey.publicKey
        do {
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
            return sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self,
                                                        salt: self.salt,
                                                        sharedInfo: Data(),
                                                        outputByteCount: 32)
        } catch {
            throw EnclaveWrapperError.keyGenerationFailed
        }
    }
}

/**
 Execution class for cryptographic operations using the Secure Enclave for key generation and management.
 
 Cryptographic keys are generated by the Secure Enclave, and a reference to the object in the Secure Enclave (the representation) is stored in an `EnclaveKey` object and then stored on the device's Keychain.
 Keys are created, stored and managed using private functions to prevent other methods from retrieving or improperly using the key representations. To use the keys for cryptographic sealing or unsealing of data, the public functions `sealData()` and `openSealedData()` are used.
 */
public class SecureEncryption {
    /**
     Retrieves a cryptographic key representation wrapped in a `EnclaveKey` object for cryptographic operations. If no key is already stored, a new one is generated and stored.
      - Parameters:
        - service: The reference label for the key object. This label must be used for the function to know which object to search for in the Keychain. Defaults to `catalyst-pk`
      - Returns: The Secure Enclave key representation wrapped in an `EnclaveKey` object.
      - Throws:`EnclaveWrapperError.keyCacheDecodingFailed` if the `EnclaveKey` object could not be properly decoded from the Keychain.
     */
    private func getKey(service: String="catalyst-pk") throws -> EnclaveKey {
        let dec = JSONDecoder()
        // attempt to get
        let query : [String : Any] = [
            kSecClass as String        : kSecClassGenericPassword as String,
            kSecAttrService as String  : service,
            kSecAttrAccount as String  : String(describing: Bundle.main.bundleIdentifier!),
            kSecReturnData as String  : kCFBooleanTrue!,
        ]
        do {
            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)
            if(status == errSecItemNotFound) {
                // create and store new keyset
                let newPrivateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey()
                let newKey = EnclaveKey(privateKeyDataRepresentation: newPrivateKey.dataRepresentation,
                                               salt: generateRandomSalt())
                try storeEnclaveKey(key: newKey)
                return newKey
            }
            let decodedKey = try dec.decode(EnclaveKey.self, from: item as! Data)
            return decodedKey
        } catch {
            throw EnclaveWrapperError.keyCacheDecodingFailed
        }
    }
    
    /**
     Stores a Secure Enclave key representation on the device's Keychain.
     - Parameters:
        - key: The Secure Enclave key representation wrapped in an `EnclaveKey` object.
        - service: The reference label for the key object. This label must be used for the function to know what to name the object in the Keychain. Defaults to `catalyst-pk`
     - Returns: Void
     - Throws: `EnclaveWrapperError.keyCacheEncodingFailed` if the key representation object could not be properly encoded for storage. `EnclaveWrapperError.keyCacheSaveFailed` if the function was unable to store the encoded object in the Keychain.
     */
    private func storeEnclaveKey(key: EnclaveKey, service: String="catalyst-pk") throws {
        // convert to json
        let enc = JSONEncoder()
        enc.outputFormatting = .prettyPrinted
        do {
            let codedKey = try enc.encode(key)
            let query : [String : Any] = [
                kSecClass as String        : kSecClassGenericPassword as String,
                kSecAttrService as String  : service,
                kSecAttrAccount as String  : String(describing: Bundle.main.bundleIdentifier!),
                kSecValueData as String    : codedKey,
                kSecAttrIsInvisible as String : kCFBooleanTrue!,
            ]
            // init audit var
            var stat: OSStatus
            // Remove old keychain entry, if exists
            SecItemDelete(query as CFDictionary)
            // Create new keychain entry, audit for success
            stat = SecItemAdd(query as CFDictionary, nil)
            if(stat == errSecSuccess) {
                return
            } else {
                throw EnclaveWrapperError.keyCacheSaveFailed
            }
        } catch {
            throw EnclaveWrapperError.keyCacheEncodingFailed
        }
    }
    
    /**
     Encrypts an encodable data object using the Secure Enclave.
     - Parameters:
        - data: The raw encodable data to encrypt
     - Returns: A ChaChaPoly-encrypted sealed box containing the raw data, encoded to JSON format.
     - Throws: `EnclaveWrapperError.keysNotFound` if the Secure Enclave key representation could not be created or retrieved. `EnclaveWrapperError.keyEncryptionFailed` if the data could not be encrypted due to a cryptographic error.
     */
    public func sealData<T: Encodable>(data: T) throws -> Data {
        var enclaveKey: EnclaveKey;
        do {
            enclaveKey = try getKey()
        } catch {
            throw EnclaveWrapperError.keysNotFound
        }
        do {
            let symmetricKey = try enclaveKey.symmetricKey()
            let encodedData = try JSONEncoder().encode(data)
            return try ChaChaPoly.seal(encodedData, using: symmetricKey).combined
        } catch {
            throw EnclaveWrapperError.keyEncryptionFailed
        }
    }
    
    /**
     Decrypts a ChaChaPoly-encrypted encodable data object using the Secure Enclave.
     - Parameters:
        - type: The encoding schema to restore the encrypted data to.
        - data: The sealed box to decrypt into decoded data.
     - Returns: A decoded `Data` object.
     - Throws: `EnclaveWrapperError.keysNotFound` if the Secure Enclave key representation could not be created or retrieved. `EnclaveWrapperError.keyDecryptionFailed` if the data could not be decrypted due to a cryptographic error.
     */
    public func openSealedData<T: Decodable>(type: T.Type, data: Data) throws -> Data {
        guard SecureEnclave.isAvailable else {
            throw EnclaveWrapperError.secureEnclaveUnavailable
        }
        var enclaveKey: EnclaveKey;
        do {
            //if we dont have a cached key, opening sealed data will not work
            enclaveKey = try getKey()
        } catch {
            throw EnclaveWrapperError.keysNotFound
        }
        
        let symmetricKey = try enclaveKey.symmetricKey()
        do {
            let sealedBox = try ChaChaPoly.SealedBox(combined: data)
            let decrypted = try ChaChaPoly.open(sealedBox, using: symmetricKey)
            return try JSONDecoder().decode(Data.self, from: decrypted)
        } catch {
            print("Unwrap error: \(error).")
            throw EnclaveWrapperError.keyDecryptionFailed
        }
    }
    
    /**
     Generates a cryptographic salt to feed the secure enclave for derivation of a symmetric encryption key
      - Returns: A 32-bit `Data` object containing random `Byte`s
     */
    private func generateRandomSalt() -> Data {
        var data = Data(count: 32)
        _ = data.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, 32, buffer.baseAddress!)
        }
        return data
    }
}

/**
 Execution class for cryptographic operations using legacy cryptographic key generation based on device information.
 > Warning: Using the InsecureEncryption class for crypto operations is vulnerable to low-skill decryption by an attacker and is only provided for backwards compatibility or debugging. Please consider using SecureEncryption instead.
 */
public class InsecureEncryption {
    /**
     Derives a `SymmetricKey` object using the SHA-256 hash of the UTF8 representation of the device's serial number
     - Returns: A `SymmetricKey` object containing a cryptographic key
     */
    private func getKey() throws -> SymmetricKey {
        let sn = try getSerialNumber()
        let fallback = Bundle.main.bundleIdentifier
        return CryptoKit.SymmetricKey.init(data: SHA256.hash(data: (sn.data(using: .utf8) ?? fallback?.data(using: .utf8))!))
    }
    
    /**
     Encrypts an encodable data object using Insecure Encryption.
     - Parameters:
        - data: The raw encodable data to encrypt
     - Returns: A ChaChaPoly-encrypted sealed box containing the raw data, encoded to JSON format.
     - Throws: `EnclaveWrapperError.keyEncryptionFailed` if the data could not be encrypted due to a cryptographic error.
     */
    public func sealData<T: Encodable>(data: T) throws -> Data {
        do {
            let enclaveKey = try getKey()
            let encodedData = try JSONEncoder().encode(data)
            return try ChaChaPoly.seal(encodedData, using: enclaveKey).combined
        } catch {
            print("Wrap error: \(error).")
            throw EnclaveWrapperError.keyEncryptionFailed
        }
    }
    
    /**
     Decrypts a ChaChaPoly-encrypted encodable data object using Insecure Encryption.
     - Parameters:
        - type: The encoding schema to restore the encrypted data to.
        - data: The sealed box to decrypt into decoded data.
     - Returns: A decoded `Data` object.
     - Throws: `EnclaveWrapperError.keysNotFound` if the Insecure Encryption key could not be derived. `EnclaveWrapperError.keyDecryptionFailed` if the data could not be decrypted due to a cryptographic error.
     */
    public func openSealedData<T: Decodable>(type: T.Type, data: Data) throws -> Data {
        guard SecureEnclave.isAvailable else {
            throw EnclaveWrapperError.secureEnclaveUnavailable
        }
        var enclaveKey: SymmetricKey;
        do {
            //if we dont have a cached key, opening sealed data will not work
            enclaveKey = try getKey()
        } catch {
            throw EnclaveWrapperError.keysNotFound
        }
        do {
            let sealedBox = try ChaChaPoly.SealedBox(combined: data)
            let decrypted = try ChaChaPoly.open(sealedBox, using: enclaveKey)
            return try JSONDecoder().decode(Data.self, from: decrypted)
        } catch {
            print("Unwrap error: \(error).")
            throw EnclaveWrapperError.keyDecryptionFailed
        }
    }
}

