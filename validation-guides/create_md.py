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

def get_sigma_logsource(yaml_dict):
    product = yaml_dict["logsource"]["product"] if "product" in yaml_dict["logsource"] else "None"
    category = yaml_dict["logsource"]["category"] if "category" in yaml_dict["logsource"] else "None"
    service = yaml_dict["logsource"]["service"] if "service" in yaml_dict["logsource"] else "None"
    return f"{product}_{category}_{service}"

def get_source(logsource):
    local_logsource =  full_dict[logsource]["source"] if logsource in full_dict else full_dict["None_None_None"]["source"]
    return local_logsource

def get_audit(logsource):
    local_logsource =  full_dict[logsource]["audit"] if logsource in full_dict else full_dict["None_None_None"]["audit"]
    return local_logsource

with open('create_md.yml','r',encoding='UTF-8') as file:
    full_dict = yaml.load(file, Loader=yaml.BaseLoader)

path_rule = '../sigma/rules'
files_list = [yml for yml in pathlib.Path(path_rule).glob('**/*.yml')]
my_bar = tqdm.tqdm(total=len(files_list))

for rule_file in files_list:
    my_bar.update(1)
    directory = str(rule_file.parent).replace('\\','/').replace(path_rule,'.')
    pathlib.Path(directory).mkdir(parents=True, exist_ok=True)
    new_file = f"{directory}/{rule_file.name}".replace('.yml','.md')
    with rule_file.open('r', encoding='UTF-8') as file:
        yaml_dict = yaml.load(file, Loader=yaml.BaseLoader)
        title = yaml_dict["title"]
        id = yaml_dict["id"]
        logsource = get_sigma_logsource(yaml_dict)
        source = get_source(logsource)
        audit = get_audit(logsource)
    if pathlib.Path(new_file).exists() != True:
        with pathlib.Path(new_file).open('w', encoding='UTF-8', newline='') as md_file:
            md_file.write(f'# Rule: {title}\n\n')
            md_file.write(f'Sigma rule ID : {id}\n\n')
            md_file.write('## Author\n\nFrack113 autogenerator\n\n')
            md_file.write(f'## Change History\n\n- {datetime.date.today()} file creation\n\n')
            md_file.write(f'## Required Log Sources\n\n{source}\n\n')
            md_file.write(f'## Required Audit Policy / Config\n\n{audit}\n\n')
            md_file.write('## Description\n\nPlease complete the file\n\n')
            md_file.write('## Code\n\nPlease complete the file\n\n')
            md_file.write('## Example\n\nPlease complete the file\n\n')
    else:
        pass
        #next check if the source and audit parts need to be update :)

