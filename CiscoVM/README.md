# Cisco Vulnerability Management (Cisco VM) App
version: 1.0.0

### About the App
The app allows to export endpoints data to Cisco Vulnerability Management.

### Requirements
The App supports:
- ForeScout CounterACT 8.4
- ForeScout eyeExtend Connect 2.0.15
- ForeScout Connect Plugin 1.7.4

### ForeScout Documentation Portal
To access ForeScout documentation, please refer to [https://docs.forescout.com/](https://docs.forescout.com/)

### Licenses
This App includes a license file. Please review the `license.txt` file included in the distribution.

### How it works
Forescout Cisco VM App exports endpoints data to Cisco Vulnerability Management REST API.
The app contains Policy template that controls the export process by applying Export or Reset actions.

#### Export flow
1. By default, the policy export data only for new endpoints or endpoints that were changed from the last export. 
By default, the recheck for the changed endpoints happens every day at 12 AM (Forescout Appliance time zone).  
2. If export for endpoint fails, the app retries an export in 10 minutes. If the export fails again, the app attempts reexport each 2 hours.
3. In case if endpoint doesn't have any changes for the exported properties for 1 month, it's reexported.
4. Endpoints that have Exported and Unchanged state are also following daily recheck schedule. They are not moved to Pending state before the recheck to avoid redundant execution of Reset action.

#### Exported properties mapping
Forescout        | Cisco Vulnerability Management
------------- | -----------------------------
IPv4 Address | IP Address
DHCP Hostname | Hostname
MAC Address | MAC Address
Function | "FS Function" tag
Vendor and Model | "FS Vendor and Model" tag
NIC Vendor | "FS NIC Vendor" tag

#### Properties
Property        | Description
------------- | -----------------------------
Cisco VM Exported State | Defines the state of the latest export (Pending, Failed, Exported, Unchanged)
Cisco VM Exported Hash | Hash of the latest exported payload

### Configuration
Before starting configuration process, Forescout connector must be created in Cisco Vulnerability Management UI.
The connector generates configuration parameters that are required to configure Cisco VM eyeExtend Connect app.

#### Configure App
Parameters required during the configuration process:
* URL - URL of Cisco VM Webhook which saves the exported data to Cisco VM environment
* UID - a unique identifier defined per client per connector
* AUTH Token - Token for Cisco VM REST API

#### Apply policy
Policy must be added manually after the app is imported and configured.
1. Go to ForeScout Policy tab -> Add -> "Cisco VM" policy template group -> "Cisco VM Export" template
2. Follow configuration instructions. The user must set IP range of endpoints that should be exported. Other configuration steps are optional as the template includes default configuration. 