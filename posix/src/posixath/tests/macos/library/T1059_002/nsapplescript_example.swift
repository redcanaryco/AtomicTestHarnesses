import Foundation

// Read the script path from the command-line
let script_path = readLine()

do {
    // Read script contents from the file path provided
    let script_contents = try NSString(contentsOfFile: script_path!, encoding: String.Encoding.ascii.rawValue)

    var error: NSDictionary?
    if let scriptObject = NSAppleScript(source: script_contents as String) {
        // Execute the script contents
        if let outputString = scriptObject.executeAndReturnError(&error).stringValue {
            print(outputString)
        } else if (error != nil) {
            print("error: ", error!)
        }
    }
} catch {
    print(error)
}
