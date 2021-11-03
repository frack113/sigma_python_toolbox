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
    "None_None_None": "Please complete the file\n",
    "windows_ps_module_None": """
EventID: 4103
Channel:
- Microsoft-Windows-PowerShell/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx)
""",
    "windows_ps_script_None": """
EventID: 4104
Channel:
- Microsoft-Windows-PowerShell/Operational (%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx)
""",
    "windows_ps_classic_start_None":"""
Eventid: 400
Channel:
- Windows PowerShell (%SystemRoot%\System32\Winevt\Logs\Windows PowerShell.evtx)
"""
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
        with rule_file.open('r',encoding='UTF-8') as file:
            yaml_dict = yaml.load(file, Loader=yaml.BaseLoader)
            logsource = get_sigma_logsource(yaml_dict)
            source = get_source(logsource)
            audit = get_audit(logsource)
            with pathlib.Path(new_file).open('w',encoding='UTF-8') as md_file:
                logsource = get_sigma_logsource(yaml_dict)
                md_file.write(f'# Rule: {yaml_dict["title"]}\n')
                md_file.write(f'Sigma rule ID : {yaml_dict["id"]}\n\n')
                md_file.write('## Author\n Frack113 autogenerator\n\n')
                md_file.write(f'## Change History\n - {datetime.date.today()} file creation\n\n')
                md_file.write(f'## Required Log Sources\n{source}\n')
                md_file.write(f'## Required Audit Policy / Config\n{audit}\n')
                md_file.write('## Description\nPlease complete the file\n\n')
                md_file.write('## Code\nPlease complete the file\n\n')
                md_file.write('## Example\nPlease complete the file\n\n')


