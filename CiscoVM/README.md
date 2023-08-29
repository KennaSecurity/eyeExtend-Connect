# Cisco Vulnerability Management (CVM) App
version: 1.0.0

### About the App
The App is written to integrate with Cisco Vulnerability Management

### Requirements
The App supports:
- ForeScout CounterACT 8.4
- ForeScout eyeExtend Connect <???>

### ForeScout Documentation Portal
To access ForeScout documentation, please refer to [https://docs.forescout.com/](https://docs.forescout.com/)

### Licenses
This App includes a license file. Please review the `license.txt` file included in the distribution.

### How it works
TODO

### Properties
TODO

### Apply police
The default policy for the connector will be automatically created as part of APP deployment. The configuration can be found in `policies/nptemplates/kenna_exported.xml`. 

*Apply policies* : ForeScout Policy tab -> Add -> "CiscoVM" policy template group -> "CiscoVM Devices" template 

The user should set IP range to apply policies, the rules for the properties will be taken from conf file by default. 

### Logs
```
ssh <USER>@<FORESCOUT_IP>
tail -n50 /usr/local/forescout/plugin/connect_module/python_logs/python_server.log
```