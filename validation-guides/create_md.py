# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Project: create_md.py
Date: 03/11/2021
Author: frack113
Version: 1.0
Description: 
    create the md file with commun information for new rules
Requirements:
    python 3.7 min
Todo:
    - check the template
    - add more information 
"""

""" Template beta
Rule: Title
Author
Change History
Required Log Sources
Required Audit Policy / Config
Description
    How to trigger the rule
Code
    Code snippet or complete program code
Example: Expected Event
"""

import yaml
import pathlib
import tqdm
import datetime

Sources_dict = {
    "None_None_None": """
Please complete the file
""",
    "windows_ps_module_None": """
EventID: 4103
Channel: Microsoft-Windows-PowerShell/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx)
""",
    "windows_ps_script_None": """
EventID: 4104
Channel: Microsoft-Windows-PowerShell/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx)
""",
    "windows_ps_classic_start_None":"""
EventID: 400
Channel: Windows PowerShell (%SystemRoot%\System32\Winevt\Logs\Windows PowerShell.evtx)
""",
    "windows_ps_classic_provider_start_None":"""
EventID: 600
Channel: Windows PowerShell (%SystemRoot%\System32\Winevt\Logs\Windows PowerShell.evtx)
""",
    "windows_ps_classic_script_None":"""
EventID: 800
Channel: Windows PowerShell (%SystemRoot%\System32\Winevt\Logs\Windows PowerShell.evtx)
""",
    "windows_process_creation_None":"""
* sysmon
EventID: 1
Channel: Microsoft-Windows-Sysmon/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx)

* windows buildin
EventID: 4688
Channel: Security (%SystemRoot%\System32\Winevt\Logs\Security.evtx)

""",
    "windows_file_change_None":"""
* sysmon
EventID: 2
Channel: Microsoft-Windows-Sysmon/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx)
""",
    "windows_network_connection_None":"""
* sysmon
EventID: 3
Channel: Microsoft-Windows-Sysmon/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx)
""",
    "windows_sysmon_status_None":"""
* sysmon
EventID: 4 or 16
Channel: Microsoft-Windows-Sysmon/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx)
""",
    "windows_process_terminated_None":"""
* sysmon
EventID: 5
Channel: Microsoft-Windows-Sysmon/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx)
""",
    "windows_driver_loaded_None":"""
* sysmon
EventID: 6
Channel: Microsoft-Windows-Sysmon/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx)
""",
    "windows_image_loaded_None":"""
* sysmon
EventID: 7
Channel: Microsoft-Windows-Sysmon/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx)
""",
    "windows_create_remote_thread_None":"""
* sysmon
EventID: 8
Channel: Microsoft-Windows-Sysmon/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx)
""",
    "windows_raw_access_thread_None":"""
* sysmon
EventID: 9
Channel: Microsoft-Windows-Sysmon/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx)
""",
    "windows_process_access_None":"""
* sysmon
EventID: 10
Channel: Microsoft-Windows-Sysmon/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx)
""",
    "windows_file_creation_None":"""
* sysmon
EventID: 11
Channel: Microsoft-Windows-Sysmon/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx)
""",
    "windows_registry_event_None":"""
* sysmon
EventID: 12,13 or 14
Channel: Microsoft-Windows-Sysmon/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx)

* windows buildin
EventID: 4657
Channel: Security (%SystemRoot%\System32\Winevt\Logs\Security.evtx)
""",
    "windows_create_stream_hash_None":"""
* sysmon
EventID: 15
Channel: Microsoft-Windows-Sysmon/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx)
""",
    "windows_pipe_created_None":"""
* sysmon
EventID: 17 or 18
Channel: Microsoft-Windows-Sysmon/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx)
""",
    "windows_wmi_event_None":"""
* sysmon
EventID: 19,20 or 21
Channel: Microsoft-Windows-Sysmon/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx)
""",
    "windows_dns_query_None":"""
* sysmon
EventID: 22
Channel: Microsoft-Windows-Sysmon/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx)
""",
    "windows_file_delete_None":"""
* sysmon
EventID: 23 or 26
Channel: Microsoft-Windows-Sysmon/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx)
""",
    "windows_clipboard_capture_None":"""
* sysmon
EventID: 24
Channel: Microsoft-Windows-Sysmon/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx)
""",
    "windows_process_tampering_None":"""
* sysmon
EventID: 25
Channel: Microsoft-Windows-Sysmon/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx)
""",
    "windows_sysmon_error_None":"""
* sysmon
EventID: 255
Channel: Microsoft-Windows-Sysmon/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx)
""",
    }

Audit_dict = {
    "None_None_None": "Please complete the file\n",
    "windows_ps_module_None": """
To enable module logging:

1. In the Windows PowerShell GPO settings, set Turn on Module Logging to enabled.
2. In the Options pane, click the button to show Module Name.
3. In the Module Names window, enter * to record all modules.
4. Click OK in the Module Names window.
5. Click OK in the Module Logging window.

Alternately you can set the following registry values:
```
HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging → EnableModuleLogging = 1
HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging \ModuleNames → * = *
```
""",
    "windows_ps_script_None":"""
To enable script block logging, go to the Windows PowerShell GPO settings and set Turn on `PowerShell Script Block Logging to enabled.

Alternately, you can set the following registry value:

`HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging → EnableScriptBlockLogging = 1`
""",
    "windows_process_creation_None":"""
* sysmon
Sysmon must be installed on configured.
The basic configuration of sysmon configuration can be found on :
  - https://github.com/SwiftOnSecurity/sysmon-config
  - https://github.com/Neo23x0/sysmon-config
  - https://github.com/olafhartong/sysmon-modular

* buildin
You must enable the Audit Process Creation audit policy so that 4688 events are generated.
You can enable this audit policy from the following Group Policy Object (GPO) container: 
`Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\System Audit Policies\Detailed Tracking`.
You must enable the Include command line in process creation events GPO setting.
You can find this setting in the following GPO container:
`Computer Configuration\Administrative Templates\System\Audit Process Creation`.

Alternatively, you can enable this setting in the local system registry by setting the 
`HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`
""",
    "windows_file_change_None":"""
* sysmon
Sysmon must be installed on configured.
The basic configuration of sysmon configuration can be found on :
- https://github.com/SwiftOnSecurity/sysmon-config
- https://github.com/Neo23x0/sysmon-config
- https://github.com/olafhartong/sysmon-modular
""",
    "windows_network_connection_None":"""
* sysmon
Sysmon must be installed on configured.
The basic configuration of sysmon configuration can be found on :
- https://github.com/SwiftOnSecurity/sysmon-config
- https://github.com/Neo23x0/sysmon-config
- https://github.com/olafhartong/sysmon-modular
""",
    "windows_sysmon_status_None":"""
* sysmon
Sysmon must be installed on configured.
The basic configuration of sysmon configuration can be found on :
- https://github.com/SwiftOnSecurity/sysmon-config
- https://github.com/Neo23x0/sysmon-config
- https://github.com/olafhartong/sysmon-modular
""",
    "windows_process_terminated_None":"""
* sysmon
Sysmon must be installed on configured.
The basic configuration of sysmon configuration can be found on :
- https://github.com/SwiftOnSecurity/sysmon-config
- https://github.com/Neo23x0/sysmon-config
- https://github.com/olafhartong/sysmon-modular
""",
    "windows_driver_loaded_None":"""
* sysmon
Sysmon must be installed on configured.
The basic configuration of sysmon configuration can be found on :
- https://github.com/SwiftOnSecurity/sysmon-config
- https://github.com/Neo23x0/sysmon-config
- https://github.com/olafhartong/sysmon-modular
""",
    "windows_image_loaded_None":"""
* sysmon
Sysmon must be installed on configured.
The basic configuration of sysmon configuration can be found on :
- https://github.com/SwiftOnSecurity/sysmon-config
- https://github.com/Neo23x0/sysmon-config
- https://github.com/olafhartong/sysmon-modular
""",
    "windows_create_remote_thread_None":"""
* sysmon
Sysmon must be installed on configured.
The basic configuration of sysmon configuration can be found on :
- https://github.com/SwiftOnSecurity/sysmon-config
- https://github.com/Neo23x0/sysmon-config
- https://github.com/olafhartong/sysmon-modular
""",
    "windows_raw_access_thread_None":"""
* sysmon
Sysmon must be installed on configured.
The basic configuration of sysmon configuration can be found on :
- https://github.com/SwiftOnSecurity/sysmon-config
- https://github.com/Neo23x0/sysmon-config
- https://github.com/olafhartong/sysmon-modular
""",
    "windows_process_access_None":"""
* sysmon
Sysmon must be installed on configured.
The basic configuration of sysmon configuration can be found on :
- https://github.com/SwiftOnSecurity/sysmon-config
- https://github.com/Neo23x0/sysmon-config
- https://github.com/olafhartong/sysmon-modular
""",
    "windows_file_creation_None":"""
* sysmon
Sysmon must be installed on configured.
The basic configuration of sysmon configuration can be found on :
- https://github.com/SwiftOnSecurity/sysmon-config
- https://github.com/Neo23x0/sysmon-config
- https://github.com/olafhartong/sysmon-modular
""",
    "windows_registry_event_None":"""
* sysmon
Sysmon must be installed on configured.
The basic configuration of sysmon configuration can be found on :
- https://github.com/SwiftOnSecurity/sysmon-config
- https://github.com/Neo23x0/sysmon-config
- https://github.com/olafhartong/sysmon-modular
""",
    "windows_create_stream_hash_None":"""
* sysmon
Sysmon must be installed on configured.
The basic configuration of sysmon configuration can be found on :
- https://github.com/SwiftOnSecurity/sysmon-config
- https://github.com/Neo23x0/sysmon-config
- https://github.com/olafhartong/sysmon-modular
""",
    "windows_pipe_created_None":"""
* sysmon
Sysmon must be installed on configured.
The basic configuration of sysmon configuration can be found on :
- https://github.com/SwiftOnSecurity/sysmon-config
- https://github.com/Neo23x0/sysmon-config
- https://github.com/olafhartong/sysmon-modular
""",
    "windows_wmi_event_None":"""
* sysmon
Sysmon must be installed on configured.
The basic configuration of sysmon configuration can be found on :
- https://github.com/SwiftOnSecurity/sysmon-config
- https://github.com/Neo23x0/sysmon-config
- https://github.com/olafhartong/sysmon-modular
""",
    "windows_dns_query_None":"""
* sysmon
Sysmon must be installed on configured.
The basic configuration of sysmon configuration can be found on :
- https://github.com/SwiftOnSecurity/sysmon-config
- https://github.com/Neo23x0/sysmon-config
- https://github.com/olafhartong/sysmon-modular
""",
    "windows_file_delete_None":"""
* sysmon
Sysmon must be installed on configured.
The basic configuration of sysmon configuration can be found on :
- https://github.com/SwiftOnSecurity/sysmon-config
- https://github.com/Neo23x0/sysmon-config
- https://github.com/olafhartong/sysmon-modular
""",
    "windows_clipboard_capture_None":"""
* sysmon
Sysmon must be installed on configured.
The basic configuration of sysmon configuration can be found on :
- https://github.com/SwiftOnSecurity/sysmon-config
- https://github.com/Neo23x0/sysmon-config
- https://github.com/olafhartong/sysmon-modular
""",
    "windows_process_tampering_None":"""
* sysmon
Sysmon must be installed on configured.
The basic configuration of sysmon configuration can be found on :
- https://github.com/SwiftOnSecurity/sysmon-config
- https://github.com/Neo23x0/sysmon-config
- https://github.com/olafhartong/sysmon-modular
""",
    "windows_sysmon_error_None":"""
* sysmon
Sysmon must be installed on configured.
The basic configuration of sysmon configuration can be found on :
- https://github.com/SwiftOnSecurity/sysmon-config
- https://github.com/Neo23x0/sysmon-config
- https://github.com/olafhartong/sysmon-modular
""",
    }

def get_sigma_logsource(yaml_dict):
    product = yaml_dict["logsource"]["product"] if "product" in yaml_dict["logsource"] else "None"
    category = yaml_dict["logsource"]["category"] if "category" in yaml_dict["logsource"] else "None"
    service = yaml_dict["logsource"]["service"] if "service" in yaml_dict["logsource"] else "None"
    return f"{product}_{category}_{service}"

def get_source(logsource):
    local_logsource =  Sources_dict[logsource] if logsource in Sources_dict else Sources_dict["None_None_None"]
    return local_logsource

def get_audit(logsource):
    local_logsource =  Audit_dict[logsource] if logsource in Audit_dict else Audit_dict["None_None_None"]
    return local_logsource
    
path_rule = '../sigma/rules'
files_list = [yml for yml in pathlib.Path(path_rule).glob('**/*.yml')]
my_bar = tqdm.tqdm(total=len(files_list))

for rule_file in files_list:
    my_bar.update(1)
    directory = str(rule_file.parent).replace('\\','/').replace(path_rule,'.')
    pathlib.Path(directory).mkdir(parents=True, exist_ok=True)
    new_file = f"{directory}/{rule_file.name}".replace('.yml','.md')
    if pathlib.Path(new_file).exists() != True:
        with rule_file.open('r', encoding='UTF-8') as file:
            yaml_dict = yaml.load(file, Loader=yaml.BaseLoader)
            logsource = get_sigma_logsource(yaml_dict)
            source = get_source(logsource)
            audit = get_audit(logsource)
            with pathlib.Path(new_file).open('w', encoding='UTF-8', newline='') as md_file:
                logsource = get_sigma_logsource(yaml_dict)
                md_file.write(f'# Rule: {yaml_dict["title"]}\n\n')
                md_file.write(f'Sigma rule ID : {yaml_dict["id"]}\n\n')
                md_file.write('## Author\n\nFrack113 autogenerator\n\n')
                md_file.write(f'## Change History\n\n- {datetime.date.today()} file creation\n\n')
                md_file.write(f'## Required Log Sources\n{source}\n')
                md_file.write(f'## Required Audit Policy / Config\n{audit}\n')
                md_file.write('## Description\n\nPlease complete the file\n\n')
                md_file.write('## Code\n\nPlease complete the file\n\n')
                md_file.write('## Example\n\nPlease complete the file\n\n')


