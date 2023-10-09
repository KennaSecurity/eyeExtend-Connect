# Cisco Vulnerability Management (CVM) App
version: 1.0.0

### About the App
The App is written to integrate with Cisco Vulnerability Management

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
Forescout Cisco VM App integrates with Cisco Vulnerability Management via a Rest API.
Required parameters:
* URL
* UID (a unique identifier per client and established connector)
* Bearer Token 

### Apply police
The default policy for the connector will be automatically created as part of APP deployment. The configuration can be found in `policies/nptemplates/kenna_exported.xml`. 

*Apply policies* : ForeScout Policy tab -> Add -> "Cisco VM" policy template group -> "Cisco VM Devices" template 

The user should set IP range to apply policies, the rules for the properties will be taken from conf file by default. 

### Logs
```
ssh <USER>@<FORESCOUT_PLATFORM_IP>
tail -n50 /usr/local/forescout/plugin/connect_module/python_logs/python_server.log
```