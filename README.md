# SiteSurvey
# Site Survey Logger - Burp Suite Extension

A Burp Suite extension to log and analyze web application flows, including screen transitions, parameters, and request/response details.

[Screenshot coming up later]

## Features
- Logs requests/responses with metadata (URL, method, params, status codes)
- Customizable scope and filtering
- Export data to clipboard (tab-delimited for Excel)
- Highlight important requests
- Screen/button tracking for web flows

## Requirements
- Burp Suite Professional/Community (v2022.9+)
- Jython 2.7 Standalone JAR

## Installation

### Step 1: Install Jython
1. Download **Jython 2.7 Standalone** JAR from:  
   https://www.jython.org/download
2. In Burp Suite, go to:  
   `Extender` → `Options` → `Python Environment`  
   → Set path to the downloaded Jython JAR file

### Step 2: Load the Extension
1. Download `akuma.v2.0.py` from this repository
2. In Burp Suite:  
   `Extender` → `Extensions` → `Add`  
   → Select `Python` as type → Choose the downloaded `.py` file

## Usage
1. After loading, a new tab **"Site Survey Pro"** will appear
2. Browse your target application while Burp proxies traffic
3. Use the interface to:
   - Filter requests by scope/extensions
   - Highlight important entries
   - Copy selected data to clipboard
   - Organize screens/flows

## Customization
- **Manage Scope**: Control which URLs are logged  
- **Filter Extensions**: Include/exclude file types (`.js`, `.php`, etc.)  
- **Column Selection**: Right-click → Copy specific columns  

## Troubleshooting
- **Extension not loading?**  
  - Verify Jython is properly configured in Burp  
  - Check Burp's `Extender` → `Errors` tab for debug info  

- **Missing requests?**  
  - Adjust scope rules via `Manage Scope` button  
  - Disable filters if needed  

## License
MIT License - See [LICENSE](LICENSE) file.

---
