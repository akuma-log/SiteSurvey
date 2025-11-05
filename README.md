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
   `Extensions` → `Extensions Settings` → `Python Environment`  
   → Set path to the downloaded Jython JAR file

### Step 2: Load the Extension
1. Download `sitesurvey.v2.py` from this repository
2. In Burp Suite:  
   `Extensions` → `Add`  
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
  - Check Burp's `Extensions` → `Errors` tab for debug info  

- **Missing requests?**  
  - Adjust scope rules via `Manage Scope` button  
  - Disable filters if needed
 
#### Disable Browser Cache for better performance
   - you can disable the cache in Firefox by going to `about:config` and setting `network.http.use-cache` to false, but this can negatively impact performance. A better alternative for most users is to use a keyboard shortcut to bypass the cache when needed, such as `Shift + Click` the Reload button or `Ctrl+F5`, which forces a fresh download for that specific page without permanently disabling caching. For permanent disabling, you can set `network.http.use-cache` to false in `about:config`, or clear the cache automatically when you close Firefox in the settings.

## Design

<img width="1153" height="989" alt="Screenshot 2025-11-05 093034" src="https://github.com/user-attachments/assets/2fd983a5-dd39-4cd7-a4d5-8bda16137df9" />


## License
MIT License - See [LICENSE](LICENSE) file.

---
