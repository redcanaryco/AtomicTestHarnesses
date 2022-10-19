import Foundation
import OSAKit

// Read the script path from the command-line
let script_path = readLine()

do {
    // Read script contents from the file path provided
    let script_contents = try NSString(contentsOfFile: script_path!, encoding: String.Encoding.ascii.rawValue)
    let scriptObject = OSAScript(source: script_contents as String, language: OSALanguage.init(forName: "JavaScript"))
    
    var compileErr : NSDictionary?
    scriptObject.compileAndReturnError(&compileErr)
    var scriptErr : NSDictionary?
    let myresult = scriptObject.executeAndReturnError(&scriptErr)
    print("\(myresult):\(scriptErr)")
} catch {
    print(error)
}
