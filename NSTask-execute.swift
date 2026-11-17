//
//  NSTask-execute.swift
//  AppSigner
//
//  Created by Daniel Radtke on 11/3/15.
//  Copyright © 2015 Daniel Radtke. All rights reserved.
//

import Foundation
struct AppSignerTaskOutput {
    var output: String
    var status: Int32
    init(status: Int32, output: String){
        self.status = status
        self.output = output
    }
}
extension Process {
    func launchSynchronous() -> AppSignerTaskOutput {
        self.standardInput = FileHandle.nullDevice
        let pipe = Pipe()
        self.standardOutput = pipe
        self.standardError = pipe
        let pipeFile = pipe.fileHandleForReading
        do {
            try self.run()
        } catch {
            return AppSignerTaskOutput(status: -1, output: error.localizedDescription)
        }

        // Drain to EOF before waiting, retaining output even for very short-lived helpers.
        // Never terminate a task after it has exited (or after its PID has been reused).
        let data = pipeFile.readDataToEndOfFile()
        self.waitUntilExit()
        pipeFile.closeFile()
        
        if let output = String.init(data: data, encoding: String.Encoding.utf8) {
            return AppSignerTaskOutput(status: self.terminationStatus, output: output)
        } else {
            return AppSignerTaskOutput(status: self.terminationStatus, output: "")
        }
        
    }
    
    func execute(_ launchPath: String, workingDirectory: String?, arguments: [String]?)->AppSignerTaskOutput{
        self.executableURL = URL(fileURLWithPath: launchPath)
        if arguments != nil {
            self.arguments = arguments
        }
        if workingDirectory != nil {
            self.currentDirectoryURL = URL(fileURLWithPath: workingDirectory!)
        }
        return self.launchSynchronous()
    }
    
}
