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
//  libClient.swift
//  CloudLAPS
//
//  Created by Henry Kon on 4/23/24.
//  Contains code from the macOSLAPS Project by Joshua D. Miller
//


import Foundation
import OpenDirectory
import CryptoKit
import os

/**
 Enumerations for thrown errors in this module.
 */
enum clientError: LocalizedError {
    /// A connection to the device OpenDirectory node could not be established.
    case localNodeConnectionError
    /// Could not derive the secret creation date from the Keychain.
    case creationDateUnwrapError
    /// Could not retrieve the Local Administrator account record from the OpenDirectory node because it does not exist or is unavailable on the system.
    case localAdminRecordError
    /// The Local Administrator account is secure token enabled and the first rotation password configured is invalid.
    case firstPasswordChangeError
    /// The Local Administrator account is secure token enabled and the stored password in the Keychain is invalid.
    case passwordChangeFromKeychainError
    /// An error was encountered during password rotation and Catalyst was unable to revert to the previous password.
    case passwordRevertError
    /// The initial password rotation attempt was successful, but the new password could not be saved to the Keychain. An attempt was made to revert the password change.
    case passwordKeychainSaveError
    /// OpenDirectory reported a successful password change but the new password was invalid when Catalyst attemped to verify.
    case passwordDidNotStickError
    /// Catalyst was unable to derive the secret expiration date using the information stored in the Keychain.
    case dateUnwrapError
    /// The First Rotation password was not defined as a preference or was of an invalid data type.
    case cannotRetrieveFirstPassword
    /// The intended amount of days to secret expiration was not defined as a preference or was of an invalid data type.
    case cannotRetrieveDaysToExpiration
}

private let logger = Logger(
    subsystem: Bundle.main.bundleIdentifier!,
    category: String(describing: "Catalyst.libClient")
)

// Retrieve preferences
private let useFirstPassword = Defaults.bool(forKey: "UseFirstPassword")
private let firstPassword = try! getFirstPassword()
private let removeKeychain = Defaults.bool(forKey: "RemoveKeychain")
private let daysToExpiration = Defaults.integer(forKey: "DaysToExpiration")

/**
 Determines if the Local Administrator account has a Secure Token or if the account is a FileVault user.
 - Returns: A `Boolean` value of `True` if the Local Administrator account has a Secure Token or FileVault privileges, `False` otherwise.
 */
private func Determine_secureToken() -> Bool {
    // Check OS Version as that will determine how we proceed
    if ProcessInfo.processInfo.isOperatingSystemAtLeast(OperatingSystemVersion.init(majorVersion: 10, minorVersion: 13, patchVersion: 0)) {
        // Check for secureToken
        let secure_token_status = Shell.run(launchPath: "/usr/bin/dscl", arguments: [".", "-read", "/Users/" + adminUsername, "AuthenticationAuthority"])
        if secure_token_status.contains(";SecureToken;") {
            logger.info("The local admin: \(adminUsername) has been detected to have a secureToken. Performing secure password change...")
            return(true)
        }
        else {
            return(false)
        }
    }
    else {
        // Determine if FileVault is Enabled
        let fv_status = Shell.run(launchPath: "/usr/bin/fdesetup", arguments: ["status"])
        if (fv_status.contains("FileVault is On.")) {
        // Check if Local Admin is a FileVault User
            let fv_user_cmd = Shell.run(launchPath: "/usr/bin/fdesetup", arguments: ["list"])
            let fv_user_list = fv_user_cmd.components(separatedBy: [",", "\n"])
            // Is Our Admin User a FileVault User?
            if (fv_user_list.contains(adminUsername)) {
                logger.info("The local admin: \(adminUsername) is currently a FileVault user. Performing secure password change...")
                return(true)
            }
            else {
                return(false)
            }
        }
        else {
            return(false)
        }
    }
}

/**
 Contains functions for rotating the Local Administrator password.
 */
class LocalTools: NSObject {
    /**
     Initializes the OpenDirectory connection to the device and attempts to read the Local Administrator account record, if it exists.
     - Returns: The `ODRecord` object representing the Local Administrator account
     - Throws: `clientError.localAdminRecordError` if the Local Administrator account does not exist or is unavailable on the system.
     */
    class func connect() throws -> ODRecord {
        // Pull Local Administrator Record
        do {
            let local_node = try ODNode.init(session: ODSession.default(), type: UInt32(kODNodeTypeLocalNodes))
            let local_admin_record = try local_node.record(withRecordType: kODRecordTypeUsers, name: adminUsername, attributes: kODAttributeTypeRecordName)
            return(local_admin_record)
        } catch {
            logger.error("Unable to connect to local directory node using the administrator account specified. Please check to make sure the administrator account is correct and is available on the system.")
            throw clientError.localAdminRecordError
        }
    }
    
    /**
     Attempts to derive the expiration date of an existing secret using the creation date noted in the Keychain object.
     If the Keychain object does not exist, a date 7 days in the past is used instead.
     - Returns: The `Date` object representing the expiration date of the stored secret, or a date 7 days in the past if the Keychain object does not exist.
     - Throws: `clientError.dateUnwrapError` if a Keychain object exists but the expiration date could not be derived from it.
     */
    class func getExpirationDate() throws -> Date {
        let (_, creationDate) = KeychainService.loadPassword(service: "catalyst")
        if(creationDate == "Not Found" || creationDate == nil) {
            return Calendar.current.date(byAdding: .day, value: -7, to: Date())!
        } else {
            do {
                let formattedDate = try getDateFromString(date: creationDate!)
                let expDate = Calendar.current.date(byAdding: .day, value: daysToExpiration, to: formattedDate)
                if(expDate == nil) {
                    throw clientError.dateUnwrapError
                }
                return expDate!
            } catch clientError.dateUnwrapError {
                logger.error("Unable to derive expiration date from keychain entry.")
                throw clientError.creationDateUnwrapError
            }
        }
    }
    
    /**
     Executes a password change on the Local Administrator account.
     - Parameters:
        - newPassword: The new password to set for the Local Administrator account.
     - Throws: `clientError.localNodeConnectionError` if an OpenDirectory connection to the device could not be established. `clientError.localAdminRecordError` if the Local Administrator account does not exist or is unavailable on the system. `clientError.firstPasswordChangeError` if the Local Administrator account is secure token enabled and the first rotation password configured is invalid. `clientError.passwordChangeFromKeychainError` if the Local Administrator account is secure token enabled and the stored password in the Keychain is invalid. `clientError.passwordDidNotStickError` if OpenDirectory reported a successful password change but the new password was invalid when Catalyst attemped to verify. `clientError.passwordKeychainSaveError` if the initial password rotation attempt was successful, but the new password could not be saved to the Keychain. `clientError.passwordRevertError` if an error was encountered during password rotation and the password was unable to be reverted.
     */
    class func password_change(newPassword: String) throws {
        // Get Configuration Settings
        let security_enabled_user = Determine_secureToken()
        // Pull Local Administrator Record
        guard let local_node = try? ODNode.init(session: ODSession.default(), type: UInt32(kODNodeTypeLocalNodes)) else {
            logger.error("Unable to connect to local node.")
            throw clientError.localNodeConnectionError
        }
        guard let local_admin_record = try? local_node.record(withRecordType: kODRecordTypeUsers, name: adminUsername, attributes: kODAttributeTypeRecordName) else {
            logger.error("Unable to retrieve local administrator record.")
            throw clientError.localAdminRecordError
        }
        // Attempt to load password from System Keychain
        let (old_password, _) = KeychainService.loadPassword(service: "catalyst")
        // Password Changing Function
        if security_enabled_user == true {
            logger.info("User is security enabled")
            // If the attribute is nil then use our first password from config profile to change the password
            if old_password == nil || useFirstPassword == true {
                do {
                    logger.info("Performing first password change using FirstPass key from configuration profile")
                    try local_admin_record.changePassword(firstPassword, toPassword: newPassword)
                } catch {
                    logger.error("Unable to change password for local administrator \(adminUsername) using FirstPassword Key.")
                    logger.info("Attempting password change using hashed serial number.")
                    // compute SHA256 hash of device serial number
                    do {
                        let serialNumber = try? getSerialNumber()
                        let serialHash = SHA256.hash(data: serialNumber!.data(using: .utf8)!)
                        let serialHashString = serialHash.map { String(format: "%02hhx", $0) }.joined()
                        try local_admin_record.changePassword(serialHashString, toPassword: newPassword)
                    } catch {
                        logger.error("Unable to change password for local administrator \(adminUsername) using Serial Number Hash.")
                        throw clientError.firstPasswordChangeError
                    }
                }
            }
            else {
                // Use the System Keychain password to change the old password to the new one and retain secureToken
                do {
                    try local_admin_record.changePassword(old_password, toPassword: newPassword)
                } catch {
                    logger.error("Unable to change password for local administrator \(adminUsername) using password loaded from keychain.")
                    throw clientError.passwordChangeFromKeychainError
                }
            }
        }
        else {
            // Do the standard reset as FileVault and secureToken are not present
            do {
                try local_admin_record.changePassword(nil, toPassword: newPassword)
            } catch {
                logger.warning("Unable to reset password for local administrator \(adminUsername).")
            }
        }
        do {
            // Confirm password change was successful
            try local_admin_record.verifyPassword(newPassword)
        } catch {
            logger.error("Password change failed to complete locally. Please ensure the process is running with enough permissions to perform a rotation.")
            throw clientError.passwordDidNotStickError
        }
        // Write our new password to System Keychain
        let save_status : OSStatus = KeychainService.savePassword(service: "catalyst", secret: newPassword)
        if save_status == noErr {
            logger.info("Password change has been completed locally.")
        } else {
            logger.error("We were unable to save the password to keychain so we will revert the changes.")
            do {
                try local_admin_record.changePassword(newPassword, toPassword: old_password)
                throw clientError.passwordKeychainSaveError
            } catch {
                logger.error("Unable to revert back to the old password, Please reset the local administrator account to the FirstPass key and start again")
                throw clientError.passwordRevertError
            }
        }
        
        // Keychain Removal if enabled
        if removeKeychain == true {
            let local_admin_home = local_admin_record.value(forKeyPath: "dsAttrTypeStandard:NFSHomeDirectory") as! NSMutableArray
            let local_admin_keychain_path = local_admin_home[0] as! String + "/Library/Keychains"
            do {
                if FileManager.default.fileExists(atPath: local_admin_keychain_path) {
                    logger.info("Removing Keychain for local administrator account \(adminUsername)...")
                    try FileManager.default.removeItem(atPath: local_admin_keychain_path)
                }
                else {
                    logger.info("Keychain does not currently exist. This may be due to the fact that the user account has never been logged into and is only used for elevation...")
                }
            } catch {
                logger.warning("Unable to remove \(adminUsername)'s Keychain. If logging in as this user you may be presented with prompts for keychain")
            }
        }
    }
}
