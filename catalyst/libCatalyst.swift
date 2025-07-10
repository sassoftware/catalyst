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
//  libCatalyst.swift
//  CloudLAPS
//
//  Created by Henry Kon on 4/22/24.
//
/**
 Contains handlers and functions for communicating with the CloudLAPS web backend.
 @author Henry Kon <henry.kon@sas.com>
 */

import Foundation
import CryptoKit
import os
import SystemConfiguration

private let logger = Logger(
    subsystem: Bundle.main.bundleIdentifier!,
    category: String(describing: "Catalyst.libCatalyst")
)

let Defaults = UserDefaults.init()

/* Structs / Enumerators / Extensions */

/**
 Enumerations for thrown errors in this module.
 */
enum catalystError: LocalizedError {
    /// The Device ID private key could not be found.
    case privateKeyNotFound
    /// An unspecified error was encountered.
    case unhandledError(status: Any)
    /// An error occured while attempting to JSON-encode one of the header tables.
    case jsonEncodeError
    /// The Device ID could not be UTF8 encoded for signing.
    case deviceIdEncodeError
    /// A cryptographic error was encountered during Device ID signing.
    case rsaSigningError
    /// The service expected to contain the Device Serial Number could not be found or loaded.
    case serialNumberLocationError
    /// The service expected to contain the Device Serial Number was found but the Serial Number could not be derived.
    case serialNumberCfPropertyError
    /// The Intune MDM Agent certificate could not be found.
    case certificateNotFound
    /// The certificate was found but there was an error while reading the certificate content.
    case certificateFetchError
    /// Could not fetch the Device ID from the preference list.
    case deviceIdFetchError
    /// Could not fetch the First Rotation Password from the preference list.
    case firstPasswordFetchError
    /// One or more of the Client Event header table variables could not be fetched or computed.
    case clientEventHeaderTableConstructError(status: Int)
    /// One or more of the Secret Event header table variables could not be fetched or computed.
    case secretHeaderTableConstructError(status: Int)
    /// One or more of the Device Identification header table variables could not be fetched or computed.
    case identHeaderTableConstructError(status: Int)
    /// The PKCS1v15SHA256 signing algorithm is not supported on this device.
    case signingAlgorithmNotSupportedError
    /// Could not fetch the Secret Event Endpoint URI from the preference list.
    case secretUriFetchError
    /// Could not fetch the Client Event Endpoint URI from the preference list.
    case clientEventUriFetchError
    /// Could not fetch the Device Identification Endpoint URI from the prefrence list.
    case identUriFetchError
    /// Could not fetch the Local Administrator username from the preference list.
    case localAdminUsernameFetchError
    /// An error occurred while encoding HTTP request content for execution.
    case webRequestEncodingError
    /// An error occurred during execution of a HTTP request.
    case webRequestExecutionError
}

/// JSON Header Table for Secret Events.
struct SecretEventHeaderTable: Codable {
    /// The Device Name.
    var DeviceName: String
    /// The Device ID.
    var DeviceID: String
    /// The Device Serial Number.
    var SerialNumber: String
    /// The Device Type (ie. VM or non-VM).
    var `Type`: String
    /// A cryptographic signature derived by base64-encoding the Azure AD device ID and signing using the Intune MDM Agent certificate.
    var Signature: String
    /// The thumbprint of the Intune MDM Agent certificate.
    var Thumbprint: String
    /// The public key of the Intune MDM Agent certificate, derived using cryptography from the certificate private key.
    var PublicKey: String
    /// The username of the Local Administrator account.
    var UserName: String
    /// Whether the secret stored in CloudLAPS can be overwritten.
    var SecretUpdateOverride: Bool
    /// The type of account being escrowed (Local Administrator for now, reserved for future use).
    var ContentType: String
    /// The expiration date of the Intune MDM Agent certificate.
    var ExpirationDate: String
    
    init?(deviceName: String, userName: String, override: Bool) throws {
        logger.info("Device ID: \(deviceId)")
        guard let serialNumber = try? getSerialNumber() else { throw catalystError.clientEventHeaderTableConstructError(status: 1) }
        guard let azureAdDeviceId = try? getAzureADDeviceId() else { throw catalystError.clientEventHeaderTableConstructError(status: 2) }
        guard let intuneDeviceId = try? getIntuneDeviceId() else { throw catalystError.clientEventHeaderTableConstructError(status: 2)}
        let CertIdent = "IntuneMDMAgent-" + intuneDeviceId
        guard let thumbprint = try? getCertificateThumbprint(withIdentifier: CertIdent)?.uppercased() else { throw catalystError.clientEventHeaderTableConstructError(status: 3) }
        guard let privateKey = try? getPrivateKeyForSigning(withIdentifier: CertIdent) else { throw catalystError.clientEventHeaderTableConstructError(status: 4) }
        guard let signature = try? signDeviceId(with: privateKey, deviceId: azureAdDeviceId).base64EncodedString() else { throw catalystError.clientEventHeaderTableConstructError(status: 5) }
        guard let publicKey = try? getPublicKeyFromCertificate(withIdentifier: CertIdent) else { throw catalystError.clientEventHeaderTableConstructError(status: 6) }
        guard let expirationDate = try? getExpirationDateFromCertificate(withIdentifier: CertIdent) else { throw catalystError.clientEventHeaderTableConstructError(status: 7)}
        DeviceName = deviceName
        DeviceID = azureAdDeviceId
        SerialNumber = serialNumber
        `Type` = "NonVM" 
        Signature = signature
        Thumbprint = thumbprint
        PublicKey = publicKey
        UserName = userName
        SecretUpdateOverride = override
        ContentType = "Local Administrator"
        ExpirationDate = getDateOnlyStringFromDate(date: expirationDate)
    }
}

/// JSON Header Table for Device Identification Events.
struct IdentHeaderTable: Codable {
    /// The Device ID.
    var DeviceID: String
    /// The Device Serial Number.
    var SerialNumber: String
    /// A cryptographic signature derived by base64-encoding the Azure AD device ID and signing using the Intune MDM Agent certificate.
    var Signature: String
    /// The thumbprint of the Intune MDM Agent certificate.
    var Thumbprint: String
    /// The expiration date of the newly rotated secret.
    var ExpirationDate: String
    /// The full PEM-encoded content of the Intune MDM Agent certificate.
    var FullPem: String
    
    /**
     Initializes a Client Event Header Table object.
     - Throws: `catalystError.identHeaderTableConstructError` with a non-zero error code corresponding to the variable retrieval that failed, `catalystError.certificateFetchError` if an error is encountered getching the certificate.
     */
    init?() throws {
        logger.info("Device ID: \(deviceId)")
        guard let serialNumber = try? getSerialNumber() else { throw catalystError.identHeaderTableConstructError(status: 1) }
        guard let azureAdDeviceId = try? getAzureADDeviceId() else { throw catalystError.identHeaderTableConstructError(status: 2) }
        guard let intuneDeviceId = try? getIntuneDeviceId() else { throw catalystError.identHeaderTableConstructError(status: 2) }
        let CertIdent = "IntuneMDMAgent-" + intuneDeviceId
        guard let thumbprint = try? getCertificateThumbprint(withIdentifier: CertIdent)?.uppercased() else { throw catalystError.identHeaderTableConstructError(status: 3) }
        guard let privateKey = try? getPrivateKeyForSigning(withIdentifier: CertIdent) else { throw catalystError.identHeaderTableConstructError(status: 4) }
        guard let signature = try? signDeviceId(with: privateKey, deviceId: azureAdDeviceId).base64EncodedString() else { throw catalystError.identHeaderTableConstructError(status: 5) }
        guard let expirationDate = try? getExpirationDateFromCertificate(withIdentifier: CertIdent) else { throw catalystError.identHeaderTableConstructError(status: 7) }
        guard let pemData = try? getPemDataFromCertificate(withIdentifier: CertIdent) else { throw catalystError.certificateFetchError }
        DeviceID = azureAdDeviceId
        SerialNumber = serialNumber
        Signature = signature
        Thumbprint = thumbprint
        ExpirationDate = getDateStringFromDate(date: expirationDate)
        FullPem = pemData
    }
}


/// JSON Header Table for Client Events.
struct ClientEventHeaderTable: Codable {
    /// The Device Name.
    var DeviceName: String
    /// The Device ID.
    var DeviceID: String
    /// The Device Serial Number.
    var SerialNumber: String
    /// A cryptographic signature derived by base64-encoding the Azure AD device ID and signing using the Intune MDM Agent certificate.
    var Signature: String
    /// The thumbprint of the Intune MDM Agent certificate.
    var Thumbprint: String
    /// The public key of the Intune MDM Agent certificate, derived using cryptography from the certificate private key.
    var PublicKey: String
    /// The result of the password rotation event.
    var PasswordRotationResult: String
    /// The date and time of the client event.
    var DateTimeUtc: String
    /// A message describing the client event (ie. a failure description).
    var ClientEventMessage: String
    /// The expiration date of the Intune MDM Agent certificate.
    var ExpirationDate: String
    
    /**
     Initializes a Client Event Header Table object.
     - Parameters:
        - deviceName: The device name.
        - passwordRotationResult: A `String` description of the password rotation result.
        - clientEventMessage: A `String` message describing the result of the client event.
     - Throws: `catalystError.clientEventHeaderTableConstructError` with a non-zero error code corresponding to the variable retrieval that failed.
     */
    init?(deviceName: String, passwordRotationResult: String, clientEventMessage: String) throws {
        guard let serialNumber = try? getSerialNumber() else { throw catalystError.clientEventHeaderTableConstructError(status: 1) }
        guard let azureAdDeviceId = try? getAzureADDeviceId() else { throw catalystError.clientEventHeaderTableConstructError(status: 2) }
        guard let intuneDeviceId = try? getIntuneDeviceId() else { throw catalystError.clientEventHeaderTableConstructError(status: 2)}
        guard let thumbprint = try? getCertificateThumbprint(withIdentifier: "IntuneMDMAgent-" + intuneDeviceId)?.uppercased() else { throw catalystError.clientEventHeaderTableConstructError(status: 3) }
        guard let privateKey = try? getPrivateKeyForSigning(withIdentifier: "IntuneMDMAgent-" + intuneDeviceId) else { throw catalystError.clientEventHeaderTableConstructError(status: 4) }
        guard let signature = try? signDeviceId(with: privateKey, deviceId: azureAdDeviceId).base64EncodedString() else { throw catalystError.clientEventHeaderTableConstructError(status: 5) }
        guard let publicKey = try? getPublicKeyFromCertificate(withIdentifier: "IntuneMDMAgent-" + intuneDeviceId) else { throw catalystError.clientEventHeaderTableConstructError(status: 6) }
        guard let expirationDate = try? getExpirationDateFromCertificate(withIdentifier: "IntuneMDMAgent-" + intuneDeviceId) else { throw catalystError.clientEventHeaderTableConstructError(status: 7)}
        DeviceName = deviceName
        DeviceID = azureAdDeviceId
        SerialNumber = serialNumber
        Signature = signature
        Thumbprint = thumbprint
        PublicKey = publicKey
        PasswordRotationResult = passwordRotationResult
        DateTimeUtc = getDateString()
        ClientEventMessage = clientEventMessage
        ExpirationDate = getDateOnlyStringFromDate(date: expirationDate)
    }
}


/* Helper Functions */

/**
 Retrieves private key matching the given device ID from the Keychain.
 - Parameters:
    - deviceId: The device ID to search for.
 - Returns: The private key as a `SecKey` object.
 */
private func getPrivateKeyForSigning(withIdentifier: String) throws -> SecKey {
    let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                kSecAttrLabel as String: withIdentifier,
                                kSecReturnRef as String: true]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status != errSecItemNotFound else { throw catalystError.privateKeyNotFound }
    guard status == errSecSuccess else { throw catalystError.unhandledError(status: status) }
    let privateKey = item as! SecKey
    return privateKey
}

/**
 Computes SHA1 hash thumprint of a given certificate.
 - Parameters:
    - identifier{String} The device ID to search for.
 - Returns The SHA1 certificate thumbprint as a `String` object.
 */
private func getCertificateThumbprint(withIdentifier identifier: String) throws -> String? {
    let query: [String: Any] = [kSecClass as String: kSecClassCertificate,
                               kSecAttrLabel as String: identifier,
                               kSecReturnRef as String: true,]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status != errSecItemNotFound else {
        throw catalystError.certificateNotFound
    }
    guard status == errSecSuccess else {
        throw catalystError.certificateFetchError
    }
    let der = SecCertificateCopyData(item as! SecCertificate) as Data
    let sha1 = Insecure.SHA1.hash(data: der)
    let sha1hexString = Data(sha1).hexEncodedString()
    return sha1hexString as String
}

/**
 Computes public key from a Keychain certificate.
 - Parameters:
    - identifier: The Device ID to use in querying for the certificate.
 - Returns: The certificate public key as a `String` object.
 */
private func getPublicKeyFromCertificate(withIdentifier identifier: String) throws -> String? {
    let query: [String: Any] = [kSecClass as String: kSecClassCertificate,
                                kSecAttrLabel as String: identifier,
                                kSecReturnRef as String: true,]
    var item: CFTypeRef?
    var error: Unmanaged<CFError>?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status != errSecItemNotFound else {
        throw catalystError.certificateNotFound
    }
    guard status == errSecSuccess else {
        throw catalystError.certificateFetchError
    }
    let keyData = SecKeyCopyExternalRepresentation(SecCertificateCopyKey(item as! SecCertificate)!, &error)
    let data = keyData! as Data
    return data.base64EncodedString()
}

/**
 Returns PEM-encoded representation from a Keychain certificate.
 - Parameters:
    - identifier: the Device ID to use in querying for the certificate.
 - returns: The certificate PEM representation as a `String` object.
*/
private func getPemDataFromCertificate(withIdentifier identifier: String) throws -> String? {
    let query: [String: Any] = [kSecClass as String: kSecClassCertificate,
                                kSecAttrLabel as String: identifier,
                                kSecReturnRef as String: true,]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status != errSecItemNotFound else {
        throw catalystError.certificateNotFound
    }
    guard status == errSecSuccess else {
        throw catalystError.certificateFetchError
    }
    var dataExport: CFData?
    SecItemExport(item as! SecCertificate, .formatPEMSequence, SecItemImportExportFlags.pemArmour, nil, &dataExport)
    let str = String(data: dataExport! as Data, encoding: .utf8)
    return str!.replacingOccurrences(of: "\n", with: "").replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "").replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
}

/**
 Computes certificate expiration date from a Keychain certificate.
 - Parameters:
    - identifier: the certificate identifier to use in querying for the certificate.
 - Returns: the certificate expiration date as a `Date` object.
 */
private func getExpirationDateFromCertificate(withIdentifier identifier: String) throws -> Date? {
    let query: [String: Any] = [kSecClass as String: kSecClassCertificate,
                                kSecAttrLabel as String: identifier,
                                kSecReturnRef as String: true,]
    var item: CFTypeRef?
    var error: Unmanaged<CFError>?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status != errSecItemNotFound else {
        throw catalystError.certificateNotFound
    }
    guard status == errSecSuccess else {
        throw catalystError.certificateFetchError
    }
    let arr = CFStringCreateArrayBySeparatingStrings(kCFAllocatorDefault, kSecOIDInvalidityDate, "\n" as CFString)
    let date = SecCertificateCopyValues(item as! SecCertificate, arr, &error) as CFDictionary?
    //let data = date! as Data
    if let dict = date as? [String: AnyObject] {
        return dict["2.5.29.24"]!["value"] as? Date
    }
    throw catalystError.certificateFetchError
}


/**
 Retrieves the Intune Device ID from the preferences plist.
 - Returns: The device's Intune Device ID.
 */
func getIntuneDeviceId() throws -> String {
    guard let ret = Defaults.string(forKey: "IntuneDeviceId") else {
        throw catalystError.deviceIdFetchError
    }
    return ret
}

/**
 Retrieves the Intune Azure AD Device ID from the preferences plist.
 - Returns: The device's AD Device ID.
 */
func getAzureADDeviceId() throws -> String {
    guard let ret = Defaults.string(forKey: "DeviceId") else {
        throw catalystError.deviceIdFetchError
    }
    return ret
}

/**
 Retrieves the Secret Event Endpoint URI from the preferences plist.
 - Returns: The Secret Event Endpoint URI.
 */
func getSecretUri() throws -> String {
    guard let ret = Defaults.string(forKey: "SetSecretURI") else {
        throw catalystError.secretUriFetchError
    }
    return ret
}

/**
 Retrieves the Client Event Endpoint URI from the preferences plist.
 - Returns: The Client Event Endpoint URI.
 */
func getClientEventUri() throws -> String {
    guard let ret = Defaults.string(forKey: "SendClientEventURI") else {
        throw catalystError.clientEventUriFetchError
    }
    return ret
}

/**
 Retrieves the Client Identification Endpoint URI from the preferences plist.
 - Returns: The Client Identification Endpoint URI.
 */
func getIdentUri() throws -> String {
    guard let ret = Defaults.string(forKey: "IdentUri") else {
        throw catalystError.identUriFetchError
    }
    return ret
}

/**
 Retrieves the local admin username from the preferences plist.
 - Returns: The local admin username.
 */
func getLocalAdminUsername() throws -> String {
    guard let ret = Defaults.string(forKey: "AdminUsername") else {
        throw catalystError.localAdminUsernameFetchError
    }
    return ret
}

/**
 Gets the current device name.
 - Returns: The current device name.
 */
func getDeviceName() -> String {
    let name = SCDynamicStoreCopyComputerName(nil, nil)
    return name! as String
}

/**
 Gets the First Rotation Password from the preferences plist.
 - Returns: The First Rotation Password.
 */
func getFirstPassword() throws -> String {
    guard let ret = Defaults.string(forKey: "FirstPassword") else {
        throw catalystError.firstPasswordFetchError
    }
    return ret
}

/**
 Computes RSA-SHA256 signature of the device ID.
 - Parameters:
    - privateKey: The private key object to use for signature calculation as a `SecKey` object.
    - deviceId: The device ID to encode as a `String` object.
 - Returns The device ID signature as a `Data` object.
 */
func signDeviceId(with privateKey: SecKey, deviceId: String) throws -> Data {
    guard let data = deviceId.data(using: .utf8) else {
        throw catalystError.deviceIdEncodeError
    }
    var error: Unmanaged<CFError>?
    guard SecKeyIsAlgorithmSupported(privateKey, .sign, .rsaSignatureMessagePKCS1v15SHA256) else {
        throw catalystError.signingAlgorithmNotSupportedError
    }
    guard let signature = SecKeyCreateSignature(privateKey, .rsaSignatureMessagePKCS1v15SHA256, data as CFData, &error) else {
        throw error?.takeRetainedValue() ?? catalystError.rsaSigningError
    }
    
    return signature as Data
}

/**
 Retrieves the device serial number.
 - Returns: The device serial number.
 */
func getSerialNumber() throws -> String {
      let platformExpert = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice") )
      guard platformExpert > 0 else {
          throw catalystError.serialNumberLocationError
      }
      guard let serialNumber = (IORegistryEntryCreateCFProperty(platformExpert, kIOPlatformSerialNumberKey as CFString, kCFAllocatorDefault, 0).takeUnretainedValue() as? String)?.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines) else {
          throw catalystError.serialNumberCfPropertyError
      }
      IOObjectRelease(platformExpert)
      return serialNumber
}

/**
 Builds the Secret Event header table.
 - Parameters:
    - deviceName: The device name.
    - userName: The local admin user name.
    - override: A `boolean` value ot `false` if local admin user already exists, `true` otherwise.
 */
func constructSecretHeaderTable(deviceName: String, userName: String, override: Bool) throws -> String? {
    do {
        /* Construct Table */
        let headerTable = try SecretEventHeaderTable(deviceName: deviceName, userName: userName, override: override)
        /* Encode Table */
        let jsonEncoder = JSONEncoder()
        jsonEncoder.outputFormatting = .prettyPrinted
        let encodedHeaderTable = try jsonEncoder.encode(headerTable)
        let encodedStringHeaderTable = String(data: encodedHeaderTable, encoding: .utf8)!
        return encodedStringHeaderTable
    } catch catalystError.secretHeaderTableConstructError(status: 1) {
        logger.error("Failed to construct Secret Event Header Table: Could not retrieve Serial Number")
    } catch catalystError.secretHeaderTableConstructError(status: 2) {
        logger.error("Failed to construct Secret Event Header Table: Could not retrieve Device ID")
    } catch catalystError.secretHeaderTableConstructError(status: 3) {
        logger.error("Failed to construct Secret Event Header Table: Could not retrieve Certificate Thumbprint")
    } catch catalystError.secretHeaderTableConstructError(status: 4) {
        logger.error("Failed to construct Secret Event Header Table: Could not retrieve Certificate Private Key")
    } catch catalystError.secretHeaderTableConstructError(status: 5) {
        logger.error("Failed to construct Secret Event Header Table: Could not retrieve Signature")
    } catch catalystError.secretHeaderTableConstructError(status: 6) {
        logger.error("Failed to construct Secret Event Header Table: Could not retrieve Certificate Public Key")
    } catch {
        logger.error("Failed to encode the Secret Event Header Table: \(error)")
        print(catalystError.jsonEncodeError)
    }
    throw catalystError.secretHeaderTableConstructError(status: 0)
}

/**
 Builds the Client Event header table.
 - Parameters:
    - deviceName: The device name.
    - passwordRotationResult: The password rotation result as a `String` object.
    - clientEventMessage: The client event message as a `String` object.
 - Returns: The JSON-encoded header table as a `String` object.
 - Throws: `catalystError.clientEventHeaderTableConstructError` with a non-zero `status` code if there was an error retrieving or encoding a variable in the header table, zero for any other error.
 */
func constructClientEventHeaderTable(deviceName: String, passwordRotationResult: String, clientEventMessage: String) throws -> String? {
    do {
        /* Construct Table */
        let headerTable = try ClientEventHeaderTable(deviceName: deviceName, passwordRotationResult: passwordRotationResult, clientEventMessage: clientEventMessage)
        /* Encode Table */
        let jsonEncoder = JSONEncoder()
        jsonEncoder.outputFormatting = .prettyPrinted
        let encodedHeaderTable = try jsonEncoder.encode(headerTable)
        let encodedStringHeaderTable = String(data: encodedHeaderTable, encoding: .utf8)!
        return encodedStringHeaderTable
    } catch catalystError.clientEventHeaderTableConstructError(status: 1) {
        logger.error("Failed to construct Client Event Header Table: Could not retrieve Serial Number")
    } catch catalystError.clientEventHeaderTableConstructError(status: 2) {
        logger.error("Failed to construct Client Event Header Table: Could not retrieve Device ID")
    } catch catalystError.clientEventHeaderTableConstructError(status: 3) {
        logger.error("Failed to construct Client Event Header Table: Could not retrieve Certificate Thumbprint")
    } catch catalystError.clientEventHeaderTableConstructError(status: 4) {
        logger.error("Failed to construct Client Event Header Table: Could not retrieve Certificate Private Key")
    } catch catalystError.clientEventHeaderTableConstructError(status: 5) {
        logger.error("Failed to construct Client Event Header Table: Could not retrieve Signature")
    } catch catalystError.clientEventHeaderTableConstructError(status: 6) {
        logger.error("Failed to construct Client Event Header Table: Could not retrieve Certificate Public Key")
    } catch {
        logger.error("Failed to encode the Client Event Header Table: \(error)")
        print(catalystError.jsonEncodeError)
    }
    throw catalystError.clientEventHeaderTableConstructError(status: 0)
}

/**
 Builds the Device Identification header table.
 - Returns: The JSON-encoded header table as a `String` object.
 - Throws: `catalystError.identHeaderTableConstructError` with a non-zero `status` code if there was an error retrieving or encoding a variable in the header table, zero for any other error.
 */
func constructIdentHeaderTable() throws -> String? {
    do {
        /* Construct Table */
        let headerTable = try IdentHeaderTable()
        /* Encode Table */
        let jsonEncoder = JSONEncoder()
        jsonEncoder.outputFormatting = .prettyPrinted
        let encodedHeaderTable = try jsonEncoder.encode(headerTable)
        return String(data: encodedHeaderTable, encoding: .utf8)
    } catch catalystError.identHeaderTableConstructError(status: 1) {
        logger.error("Failed to construct Ident Header Table: Could not retrieve Serial Number")
    } catch catalystError.identHeaderTableConstructError(status: 2) {
        logger.error("Failed to construct Ident Event Header Table: Could not retrieve Device ID")
    } catch catalystError.identHeaderTableConstructError(status: 3) {
        logger.error("Failed to construct Ident Event Header Table: Could not retrieve Certificate Thumbprint")
    } catch catalystError.identHeaderTableConstructError(status: 4) {
        logger.error("Failed to construct Ident Event Header Table: Could not retrieve Certificate Private Key")
    } catch catalystError.identHeaderTableConstructError(status: 5) {
        logger.error("Failed to construct Ident Event Header Table: Could not retrieve Signature")
    } catch catalystError.identHeaderTableConstructError(status: 6) {
        logger.error("Failed to construct Ident Event Header Table: Could not retrieve Certificate Public Key")
    } catch catalystError.identHeaderTableConstructError(status: 7) {
        logger.error("Failed to construct Ident Event Header Table: Could not retrieve Certificate Expiration Date")
    } catch {
        logger.error("Failed to encode the Ident Event Header Table: \(error)")
        print(catalystError.jsonEncodeError)
    }
    throw catalystError.identHeaderTableConstructError(status: 0)
}

/**
 Sends a web request to the CloudLAPS function app API.
 - Parameters:
    - uri: The URI of the CloudLAPS function app Endpoint.
    - header: A `String` object containing the encoded JSON headers to send to the function app.
 - Returns: A 2-element `String` array containing the request response and status code.
 - Throws: `catalystError.webRequestExecutionError` if the server returns an adverse error code or if there is an execution error, `catalystError.newSecretNotYetReady` if the server indicates that a new secret is not available due to policy.
 */
func processEventTransaction(uri: String, header: String) throws -> [String] {
    let postData = header.data(using: .utf8)
    var request = URLRequest(url: URL(string: uri)!)
    request.addValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpMethod = "POST"
    request.httpBody = postData
    let(data, response, error) = URLSession.shared.synchronousDataTask(urlrequest: request)
    if let error = error {
        logger.error("\(error)")
    } else if ((response as! HTTPURLResponse).statusCode == 400) {
        logger.error("Event transaction error 400 Bad Request: \(error)")
        throw catalystError.webRequestExecutionError
    } else if ((response as! HTTPURLResponse).statusCode == 412) {
        var ret = [String]()
        ret.append(String(data: data!, encoding: .utf8) ?? "")
        ret.append((response as! HTTPURLResponse).statusCode.codingKey.stringValue)
        return ret
    } else if ((response as! HTTPURLResponse).statusCode != 200){
        logger.error("Event transaction non-400 error: \(error)")
    } else {
        var ret = [String]()
        ret.append(String(data: data!, encoding: .utf8) ?? "")
        ret.append((response as! HTTPURLResponse).statusCode.codingKey.stringValue)
        return ret
    }
    throw catalystError.webRequestExecutionError
    // catching and rethrowing other HTTP codes is left to the caller
}

/**
 Sends a client event to the CloudLAPS server.
 - Parameters:
    - result: The result field.
    - message: The result message.
 - Throws: `catalystError.webRequestEncodingError` if the message body can't be encoded, `catalystError.webRequestExecutionError` if an issue is encountered while sending the message via HTTP.
 */
func sendClientEvent(result: String, message: String) throws {
    /* Construct and send Client Event Header Table */
    do {
        logger.trace("Attempting to construct Client Event Header Table")
        headerTable = try constructClientEventHeaderTable(deviceName: deviceName, passwordRotationResult: result, clientEventMessage: message)!
        logger.trace("Constructor Client Event Header Table returned success")
    } catch catalystError.clientEventHeaderTableConstructError(status: 0) {
        logger.error("Received error from libCatalyst: Failed to build Client Event Header Table")
        // handled here since its simpler than catching again and rethrowing in main.
        exit(9119)
    }
    do {
        logger.trace("Attempting client event transaction with \(clientEventUri)")
        let result = try processEventTransaction(uri: clientEventUri, header: headerTable)
        logger.trace("Successfully sent client event message. Response: \(result)")
    } catch catalystError.webRequestEncodingError {
        throw catalystError.webRequestEncodingError
    } catch catalystError.webRequestExecutionError {
        throw catalystError.webRequestExecutionError
    }
}
