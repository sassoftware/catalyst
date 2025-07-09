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
//  main.swift
//  CloudLAPS
//
//  Created by Henry Kon on 4/17/24.
//

import Foundation
import os

/* Logging */
private let logger = Logger(
    subsystem: Bundle.main.bundleIdentifier!,
    category: String(describing: "Catalyst.main")
)

logger.info("Process invoked at \(getDateString(), privacy: .public) UTC")

/// Determines if the process is running as `root`
let isRoot = verify_root()
if(!isRoot) {
    logger.error("Not running as root!")
    exit(77)
}

/* Variable Validation */
/// The Device ID.
var deviceId = ""
/// The Secret Event Endpoint URI.
var secretUri = ""
/// The Client Event Endpoint URI.
var clientEventUri = ""
/// The Device Identification URI.
var identUri = ""
/// Storage variable for building header tables.
var headerTable = ""
/// The Local Administrator Username.
var adminUsername = ""

do {
    logger.trace("Validating plist variables")
    deviceId = try getAzureADDeviceId()
    secretUri = try getSecretUri()
    clientEventUri = try getClientEventUri()
    identUri = try getIdentUri()
    adminUsername = try getLocalAdminUsername()
} catch catalystError.deviceIdFetchError {
    logger.error("No stored Device ID")
    exit(1)
} catch catalystError.secretUriFetchError {
    logger.error("No stored Secret URI")
    exit(1)
} catch catalystError.clientEventUriFetchError {
    logger.error("No stored Client Event URI")
    exit(1)
} catch catalystError.localAdminUsernameFetchError {
    logger.error("No stored Local Admin Username")
    exit(1)
}
logger.trace("plist variables verification success")

/// The Device Name
let deviceName = getDeviceName()
/// Debug Variable
var skipClientEvent = false
/// Storage Variable for Failure Result
var failureResult = ""
/// Storage Variable for Failure Message
var failureMessage = ""
/// Secret Expiration Date
var expDate = try? LocalTools.getExpirationDate()
/// Date Formatter instantiation.
let formatter = DateFormatter()

if(expDate! < Date()) {
    do {
        /* Construct Secret Event Header Table */
        do {
            logger.trace("Attempting to construct Secret Event Header Table")
            headerTable = try constructSecretHeaderTable(deviceName: deviceName, userName: adminUsername, override: true)!
            logger.trace("Constructor Secret Event Header Table returned success")
        } catch catalystError.secretHeaderTableConstructError(status: 0) {
            logger.error("Received error from libCatalyst: Failed to build Secret Event Header Table")
            exit(1)
        }
        
        // attempt to perform secret event transaction
        var secret = try processEventTransaction(uri: secretUri, header: headerTable)
        if(secret[1] == "412") {
            // no security id exists or current one is expired, (re)establish secure id
            logger.info("Establishing new security id as current one is null or expired")
            let identTable = try constructIdentHeaderTable()!
            let ident = try processEventTransaction(uri: identUri, header: identTable)
            if(ident[1] == "200") {
                // success! re-attempt secret txn
                secret = try processEventTransaction(uri: secretUri, header: headerTable)
                if(secret[0] == "") {
                    logger.error("Secret event transaction failed to return a response")
                    exit(1)
                }
                // return to handle as normal
            } else {
                logger.error("Ident transaction failure")
                exit(1)
            }
        }
        if(secret[0] == "") {
            logger.error("Secret event transaction failed to return a response")
            exit(1)
        }
        logger.trace("Secret event transaction success")
        do {
            try LocalTools.password_change(newPassword: secret[0])
        } catch(clientError.localNodeConnectionError) {
            try sendClientEvent(result: "Failure", message: "Unable to connect to local directory node using the administrator account specified.")
            exit(1)
        } catch(clientError.creationDateUnwrapError) {
            try sendClientEvent(result: "Failure", message: "Unable to unwrap cration date from keychain entry.")
            exit(1)
        } catch(clientError.localAdminRecordError) {
            try sendClientEvent(result: "Failure", message: "Unable to retrieve local administrator record.")
            exit(1)
        } catch(clientError.firstPasswordChangeError) {
            try sendClientEvent(result: "Failure", message: "Unable to change password for local administrator \(adminUsername) using FirstPassword Key.")
            exit(1)
        } catch(clientError.passwordChangeFromKeychainError) {
            try sendClientEvent(result: "Failure", message: "Unable to change password for local administrator \(adminUsername) using password loaded from keychain.")
            exit(1)
        } catch(clientError.passwordRevertError) {
            try sendClientEvent(result: "Failure", message: "Unable to revert back to the old password, Please reset the local administrator account to the FirstPass key and start again")
            exit(1)
        } catch(clientError.passwordKeychainSaveError) {
            try sendClientEvent(result: "Failure", message: "Unable to save the password to keychain.")
            exit(1)
        } catch(clientError.passwordDidNotStickError) {
            try sendClientEvent(result: "Failure", message: "Attempted to rotate password but could not verify that the rotation was successful. Check original password and process privileges.")
            exit(1)
        }
        let newExpDate = try? LocalTools.getExpirationDate()
        logger.info("Password rotation success for account \(adminUsername). New expiration date is \(getDateStringFromDate(date: newExpDate!))")
        try sendClientEvent(result: "Success", message: "Password rotation completed successfully")
    } catch catalystError.webRequestEncodingError {
        logger.error("Secret event web request encoding error")
        exit(1)
    } catch catalystError.webRequestExecutionError {
        logger.error("Secret event web request execution error")
        exit(1)
    }
} else {
    logger.info("Password not rotated for account \(adminUsername) as the current password does not expire until \(getDateStringFromDate(date: expDate!))")
    do {
        try sendClientEvent(result: "Success", message: "Password not rotated as it has not yet expired.")
    }
}

logger.info("Process completed at \(getDateString(), privacy: .public) UTC")
