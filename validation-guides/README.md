# validation-guides

## create_md.py
I think this script to start creation of the yml file for the new rules.\
markdown file will be generate from the yaml.\
Maybe one day it will be put or replaced by the official repository.

### create_md.yml 
It is the database for the markdown information by logsource.\
The key is the `{product}_{category}_{service}` from sigma rules
- `source` is the information where the detection data is (apache log , windows event/channel,...)
- `audit` is how to enable the source 

### use
```bash
usage: create_md.py [-h] [--input INPUT] [--output OUTPUT] [--verbose] [--test] [--author]

Create the yml information file with common information for new rules

optional arguments:
  -h, --help            show this help message and exit
  --input INPUT, -i INPUT
                        Sigma rules directory (default ../sigma/rules)
  --output OUTPUT, -o OUTPUT
                        Output directory (default ./rules)
  --verbose, -v         Display missing keys
  --test, -t            Test only don't save
  --author, -a          Set the author name (default frack113)
```

Use `--test` to deal with remove or rename sigma rule in a first time.

Example :

- `python create_md.py -i c:\FrackSigma\sigma\rules -o .\rules -a "me or not me" `

- `python create_md.py -i ../sigma/rules -o /tmp`

### My todo

- [X] add a output for the missing key
- [X] add a repport of action (creation_md.log)
- [X] update the yml file if create_md.yml is updated
- [X] check if missing or rename sigma rule
- [ ] fix my bugs / issues

### create_md.yml
Some are bad information, Rule have to be fix 

- [ ] None_None_azure.activitylogs is missing and used by 34 rule(s)
- [ ] None_None_azure.auditlogs is missing and used by 1 rule(s)
- [ ] None_None_azure.signinlogs is missing and used by 5 rule(s)
- [ ] None_None_azureactivity is missing and used by 5 rule(s)
- [ ] None_None_cloudtrail is missing and used by 30 rule(s)
- [ ] None_None_gcp.audit is missing and used by 12 rule(s)
- [ ] None_None_google_workspace.admin is missing and used by 6 rule(s)
- [ ] None_None_okta is missing and used by 12 rule(s)
- [ ] None_None_onelogin.events is missing and used by 2 rule(s)
- [ ] None_authentication_None is missing and used by 1 rule(s)
- [ ] None_dns_None is missing and used by 11 rule(s)
- [ ] None_firewall_None is missing and used by 6 rule(s)
- [ ] None_proxy_None is missing and used by 30 rule(s)
- [ ] None_threatdetection_m365 is missing and used by 1 rule(s)
- [ ] None_threatmanagement_m365 is missing and used by 7 rule(s)
- [ ] None_threatmanagement_microsoft365 is missing and used by 3 rule(s)
- [ ] None_threatmanagement_office365 is missing and used by 1 rule(s)
- [ ] None_webserver_None is missing and used by 40 rule(s)
- [ ] apache_None_None is missing and used by 3 rule(s)
- [ ] cisco_accounting_aaa is missing and used by 12 rule(s)
- [ ] django_application_None is missing and used by 1 rule(s)
- [ ] endpoint detection logs_process_creation_None is missing and used by 1 rule(s)
- [ ] linux_None_None is missing and used by 17 rule(s)
- [ ] linux_None_auditd is missing and used by 43 rule(s)
- [ ] linux_None_auth is missing and used by 1 rule(s)
- [ ] linux_None_clamav is missing and used by 1 rule(s)
- [ ] linux_None_guacamole is missing and used by 1 rule(s)
- [ ] linux_None_modsecurity is missing and used by 1 rule(s)
- [ ] linux_None_sshd is missing and used by 2 rule(s)
- [ ] linux_None_syslog is missing and used by 2 rule(s)
- [ ] linux_None_vsftpd is missing and used by 1 rule(s)
- [ ] linux_file_create_None is missing and used by 1 rule(s)
- [ ] linux_network_connection_None is missing and used by 2 rule(s)
- [ ] linux_process_creation_None is missing and used by 24 rule(s)
- [ ] macos_file_event_None is missing and used by 2 rule(s)
- [ ] macos_process_creation_None is missing and used by 27 rule(s)
- [ ] netflow_None_None is missing and used by 1 rule(s)
- [ ] python_application_None is missing and used by 1 rule(s)
- [ ] qualys_None_None is missing and used by 2 rule(s)
- [ ] ruby_on_rails_application_None is missing and used by 1 rule(s)
- [ ] spring_application_None is missing and used by 1 rule(s)
- [ ] sql_application_None is missing and used by 1 rule(s)
- [ ] unix_None_None is missing and used by 1 rule(s)
- [ ] windows_None_dns-server is missing and used by 2 rule(s)
- [ ] windows_None_driver-framework is missing and used by 1 rule(s)
- [ ] windows_None_microsoft-servicebus-client is missing and used by 1 rule(s)
- [ ] windows_None_msexchange-management is missing and used by 7 rule(s)
- [ ] windows_None_ntlm is missing and used by 2 rule(s)
- [X] windows_None_pipe_connected is missing and used by 1 rule(s) #PR
- [ ] windows_None_printservice-admin is missing and used by 1 rule(s)
- [ ] windows_None_printservice-operational is missing and used by 1 rule(s)
- [ ] windows_None_smbclient-security is missing and used by 1 rule(s)
- [ ] windows_defender_None_None is missing and used by 2 rule(s)
- [ ] windows_ldap_query_None is missing and used by 1 rule(s)
- [ ] windows_system_None is missing and used by 1 rule(s)
- [ ] windows_webserver_None is missing and used by 1 rule(s)
- [ ] zoho_manageengine_webserver_None is missing and used by 1 rule(s)

### Thanks
ZikyHD
