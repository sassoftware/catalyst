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
//  libKeychain.swift
//  CloudLAPS
//
//  Created by Henry Kon on 4/23/24.
//  Contains code from the macOSLAPS project by Joshua D. Miller
//


import Security
import CryptoKit
import os
import Foundation

private let logger = Logger(
    subsystem: Bundle.main.bundleIdentifier!,
    category: String(describing: "Catalyst.libKeychain")
)

/// Contains functions for interacting with the device's Keychain.
class KeychainService {
    /**
     Encrypts and stores a password to the device's Keychain, using the Secure Enclave for encryption if available and enabled.
     - Parameters:
        - service: The service name/label to use for referencing the Keychain object.
        - secret: The secret/password to encrypt and store in the Keychain.
     - Returns: An `OSStatus` containing a system status code for the Keychain action, or codes `8086` or `8087` if there was an error during encryption.
     */
    class func savePassword(service: String, secret: String) -> OSStatus {
        let useSecureEnclaveIfAvailable = Defaults.bool(forKey: "UseSecureEnclaveIfAvailable")
        var dataSeal: Data
        if(SecureEnclave.isAvailable && useSecureEnclaveIfAvailable) {
            do {
                dataSeal = try SecureEncryption().sealData(data: secret.data(using: .utf8))
            } catch {
                logger.error("Could not seal secret for storage")
                return OSStatus(8086)
            }
        } else {
            // encrypt using device serial number
            do {
                dataSeal = try InsecureEncryption().sealData(data: secret.data(using: .utf8))
            } catch {
                logger.error("Could not seal secret for storage")
                return OSStatus(8087)
            }
        }

        let query : [String : Any] = [
            kSecClass as String        : kSecClassGenericPassword as String,
            kSecAttrService as String  : service,
            kSecAttrAccount as String  : String(describing: Bundle.main.bundleIdentifier!),
            kSecValueData as String    : dataSeal,
            kSecAttrIsInvisible as String : kCFBooleanTrue!,
        ]
        
        // Remove old keychain entry
        SecItemDelete(query as CFDictionary)
        // Create new keychain entry
        SecItemAdd(query as CFDictionary, nil)
        
        // Add Creation Date as Comment
        // This seemed to require another query and update as it failed with the original
        let creation_date = getDateString()
        let newquery : [ String : Any ] = [
            kSecClass as String       : kSecClassGenericPassword,
            kSecAttrIsInvisible as String  : kCFBooleanTrue!,
            kSecAttrService as String : service,
        ]
        let comment_attribute : [ String : Any ] = [
            kSecAttrComment as String : "Created: \(creation_date)"
        ]
        return SecItemUpdate(newquery as CFDictionary, comment_attribute as CFDictionary)
    }
    
    /**
     Loads and decrypts the password entry from the device Keychain.
     - Parameter service: The service name/label used to refer to the Keychain object.
     - Returns: A  2-object `String` array containing the secret creation date and the secret, respectively. Alternatively, [nil,"Not Found"] if the Keychain entry could not be found, or [nil,nil] if an error was encountered.
     */
    class func loadPassword(service: String) -> (String?, String?) {
        let useSecureEnclaveIfAvailable = Defaults.bool(forKey: "UseSecureEnclaveIfAvailable")
        var dataUnseal: Data
        var password = ""
        // Instantiate a new default keychain query
        // Tell the query to return a result
        let query : [String : Any] = [
            kSecClass as String            : kSecClassGenericPassword,
            kSecAttrService as String      : service,
            kSecReturnData as String       : kCFBooleanTrue!,
            kSecReturnAttributes as String : kCFBooleanTrue!,
            kSecAttrIsInvisible as String  : kCFBooleanTrue!,
            kSecMatchLimit as String       : kSecMatchLimitOne,
        ]
        var item: AnyObject? = nil
        let status: OSStatus = SecItemCopyMatching(query as CFDictionary, &item)
        if status == noErr {
            if(SecureEnclave.isAvailable && useSecureEnclaveIfAvailable) {
                do {
                    dataUnseal = try SecureEncryption().openSealedData(type: Data.self, data: (item![kSecValueData] as? Data)!)
                    password = String(data: dataUnseal, encoding: .utf8)!
                } catch {
                    logger.error("Could not unseal secret")
                }
            } else {
                do {
                    dataUnseal = try InsecureEncryption().openSealedData(type: Data.self, data: (item![kSecValueData] as? Data)!)
                    password = String(data: dataUnseal, encoding: .utf8)!
                } catch {
                    logger.error("Could not unseal secret")
                }
            }
            guard let comment = item?[String(kSecAttrComment)] as? String else {
                logger.warning("There is currently no expiration date comment")
                return(password, nil)
            }
            let r = comment.index(comment.startIndex, offsetBy: 9)..<comment.endIndex
            let creationdate = String(comment[r])
            return (password, creationdate)
        } else if status == -25300 {
            // Keychain Entry Not Found
            return(nil, "Not Found")
        }
        return(nil,nil)
    }
    
    /**
     Deletes an item matching the given service name from the Keychain.
     - Parameter service: The service name/label of the Keychain object to delete.
     - Returns: An `OSStatus` object containing the status code of the function invocation.
     */
    class func deleteExport(service: String) -> OSStatus {
        let query : [String : Any] = [
            kSecClass as String            : kSecClassGenericPassword,
            kSecAttrService as String      : service,
            kSecReturnData as String       : kCFBooleanTrue!,
            kSecReturnAttributes as String : kCFBooleanTrue!,
            kSecAttrIsInvisible as String : kCFBooleanTrue!,
            kSecMatchLimit as String       : kSecMatchLimitOne,
        ]
        return SecItemDelete(query as CFDictionary)
    }
}
