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
//  common.swift
//  CloudLAPS
//
//  Created by Henry Kon on 4/22/24.
//

import Foundation

/* Extensions */

/**
 Extension to URLSession to allow invocation of synchronous web requests
 > Note: From https://stackoverflow.com/questions/26784315/can-i-somehow-do-a-synchronous-http-request-via-nsurlsession-in-swift
 */
extension URLSession {
    /* Can you believe Apple has neglected to implement this for over a decade? */
    func synchronousDataTask(urlrequest: URLRequest) -> (data: Data?, response: URLResponse?, error: Error?) {
        var data: Data?
        var response: URLResponse?
        var error: Error?

        let semaphore = DispatchSemaphore(value: 0)

        let dataTask = self.dataTask(with: urlrequest) {
            data = $0
            response = $1
            error = $2

            semaphore.signal()
        }
        dataTask.resume()

        _ = semaphore.wait(timeout: .distantFuture)

        return (data, response, error)
    }
}

/// Hex Encoding extension for certificate thumbprints
extension Data {
    struct HexEncodingOptions: OptionSet {
        let rawValue: Int
        static let upperCase = HexEncodingOptions(rawValue: 1 << 0)
    }
    func hexEncodedString(options: HexEncodingOptions = []) -> String {
        let format = options.contains(.upperCase) ? "%02hhX" : "%02hhx"
        return self.map { String(format: format, $0) }.joined()
    }
}

/* Classes and Functions */

/**
 Library class for executing shell commands or other executables
 > Note: From https://stackoverflow.com/questions/26971240/how-do-i-run-an-terminal-command-in-a-swift-script-e-g-xcodebuild
 */
class Shell: NSObject {
    /**
     Directly calls a shell function and returns the standard output/error when finished
     > Warning: **This will execute direct shell commands as root and can cause undefined behaviour, use with care**
     - Parameters:
        - launchPath: the file path of the process to launch
        - arguments: an array of arguments to pass to the process
     - Returns: A `String` containing the process standard output/error after execution completes
     */
    class func run(launchPath: String, arguments: [String]) -> String {
        let task = Process()
        task.launchPath = launchPath
        task.arguments = arguments
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe
        task.launch()
        task.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: String.Encoding.utf8)!
        if output.count > 0 {
            //remove newline character.
            let lastIndex = output.index(before: output.endIndex)
            return String(output[output.startIndex ..< lastIndex])
        }
        return output
    }
}

/**
 Returns the current UTC date and time
 - Returns: A `String` containing the current UTC date and time in the format "MM/dd/yyyy HH:mm:ss a Z"
 */
func getDateString() -> String {
    let now = Date()
    let formatter = DateFormatter()
    formatter.dateFormat = "M/d/yyyy h:mm:ss a"
    formatter.amSymbol = "AM"
    formatter.pmSymbol = "PM"
    formatter.timeZone = TimeZone(identifier: "GMT")
    return formatter.string(from: now)
}

/**
 Creates a `Date` object from a `String` containing a date and time.
 - Parameters:
    - date: A `String` object containing a date and time.
 - Returns: A `Date` object containing the date and time corresponding to the input.
 */
func getDateFromString(date: String) throws -> Date {
    let formatter = DateFormatter()
    formatter.dateFormat = "M/d/yyyy h:mm:ss a"
    formatter.amSymbol = "AM"
    formatter.pmSymbol = "PM"
    formatter.timeZone = TimeZone(identifier: "GMT")
    let ret = formatter.date(from: date)
    if(ret == nil) {
        throw clientError.dateUnwrapError
    }
    return ret!
}

/**
 Creates a `String` containing the date and time from a `Date` object.
 - Parameters:
    - date: A `Date` object containing a date and time
 - Returns: A `String` object containing the date and time corresponding to the input.
 */
func getDateStringFromDate(date: Date) -> String {
    let formatter = DateFormatter()
    formatter.dateFormat = "M/d/yyyy h:mm:ss a"
    formatter.amSymbol = "AM"
    formatter.pmSymbol = "PM"
    formatter.timeZone = TimeZone(identifier: "GMT")
    return formatter.string(from: date)
}

/**
 Creates a `String` containing the date from a `Date` object.
 - Parameters:
    - date: A `Date` object containing a date and (optionally) a time.
 - Returns: A `String` object containing only the date corresponding to the input.
 */
func getDateOnlyStringFromDate(date: Date) -> String {
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd"
    return formatter.string(from: date)
}

/**
 Verifies if the active process is running as `root`
 - Returns: a `Boolean` value of `true` if the process is running as `root`, otherwise `false`
 */
func verify_root() -> Bool {
    // Check if running as root
    let current_running_User = NSUserName()
    if current_running_User != "root" {
        return false
    } else {
        return true
    }
}
