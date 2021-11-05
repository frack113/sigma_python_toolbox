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
    create the md file with common information for new rules
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

import ruamel.yaml
import pathlib
import tqdm
import datetime
import argparse
from collections import OrderedDict

class knowledge():
    def _init_(self):
        self.ref = {}

    def load(self,filename):
        with open(filename,'r',encoding='UTF-8') as file:
            self.ref = ruamel.yaml.load(file, Loader=ruamel.yaml.RoundTripLoader)    

    def get_source(self,logsource):
        local_logsource =  self.ref[logsource]["source"] if logsource in self.ref else self.ref["None_None_None"]["source"]
        return local_logsource

    def get_audit(self,logsource):
        local_logsource =  self.ref[logsource]["audit"] if logsource in self.ref else self.ref["None_None_None"]["audit"]
        return local_logsource

class information():
    def _init_():
        self.info = {}

    def clean(self):
        self.info = {
            "title": "",
            "id": "",
            "author": "",
            "history": "",
            "source": "",
            "audit": "",
            "description": "",
            "code": "",
            "example": ""
        }

    def new(self):
        mydate = f"{datetime.date.today().strftime('%Y%m%d')}: creation of the file"
        self.info = {
            "title": "sigma title",
            "id": "sigma id",
            "author": "Frack113 autogenerator",
            "history": [mydate],
            "source": "update script database",
            "audit": "update script database",
            "description": "Contribute to the updating of information",
            "code": "Contribute to the updating of information",
            "example": "Contribute to the updating of information"
        }

    def get_sigma_logsource(self,yaml_dict):
        product = yaml_dict["logsource"]["product"].lower() if "product" in yaml_dict["logsource"] else "None"
        category = yaml_dict["logsource"]["category"].lower() if "category" in yaml_dict["logsource"] else "None"
        service = yaml_dict["logsource"]["service"].lower() if "service" in yaml_dict["logsource"] else "None"
        return f"{product}_{category}_{service}"

    def write_md(self,name):
        with pathlib.Path(name).open('w', encoding='UTF-8', newline='') as md_file:
            md_file.write(f'# Rule: {self.info["title"]}\n\n')
            md_file.write(f'Sigma rule ID : {self.info["id"]}\n\n')
            md_file.write(f'## Author\n\n{self.info["author"]}\n\n')
            md_file.write(f'## Change History\n\n- {self.info["history"]} \n\n')
            md_file.write(f'## Required Log Sources\n\n{self.info["source"]}\n\n')
            md_file.write(f'## Required Audit Policy / Config\n\n{self.info["audit"]}\n\n')
            md_file.write(f'## Description\n\n{self.info["description"]}\n\n')
            md_file.write(f'## Code\n\n{self.info["code"]}\n\n')
            md_file.write(f'## Example\n\n{self.info["example"]}\n\n')

    def save(self,name):
        with pathlib.Path(name).open('w', encoding='UTF-8', newline='') as yaml_file:
            ruamel.yaml.dump(self.info, yaml_file, Dumper=ruamel.yaml.RoundTripDumper)

    def load(self,filename):
        with open(filename,'r',encoding='UTF-8') as file:
            self.info = ruamel.yaml.load(file, Loader=ruamel.yaml.RoundTripLoader)   

class sigma_info():
    def _init_():
        self.info = {}
    
    def load(self,filename):
        with open(filename,'r',encoding='UTF-8') as file:
            self.info = ruamel.yaml.load(file, Loader=ruamel.yaml.RoundTripLoader)

    def get_section(self,name):
        data = self.info[name] if name in self.info else None
        return data
    
#Main
data = knowledge()
data.load('create_md.yml')

parser = argparse.ArgumentParser(description='Create the md file with common information for new rules')
parser.add_argument("--input", '-i', help="Sigma rules directory", type=str, default="../sigma/rules")
parser.add_argument("--output", '-o', help="Output directory", default=".", type=str)
parser.add_argument("--verbose", '-v', help="Display missing keys", default=False, action='store_true')
args = parser.parse_args()

path_rule = args.input
output_dir = args.output
sigma_list = [yml for yml in pathlib.Path(path_rule).glob('**/*.yml')]
info_list = [yml for yml in pathlib.Path(output_dir).glob('**/*.yml')]

print("Get sigma ID")
sigma_id = {}
sigma_bar = tqdm.tqdm(total=len(sigma_list))
sigma_data = sigma_info()
for rule_file in sigma_list:
    sigma_bar.update(1)
    sigma_data.load(rule_file)
    sigma_id[rule_file.name] = sigma_data.get_section("id")


print("Get info ID")
info_id = {}
if len(info_list)>0:
    info_bar = tqdm.tqdm(total=len(info_list))
    for rule_file in sigma_list:
        info_bar.update(1)
        with rule_file.open('r', encoding='UTF-8') as file:
            yaml_dict = ruamel.yaml.load(file, Loader=ruamel.yaml.RoundTripLoader)
            info_id[rule_file.name] = yaml_dict["id"]

print("Generate the file") 
missing_keys = {}
yml_info = information()

my_bar = tqdm.tqdm(total=len(sigma_list))
for rule_file in sigma_list:
    yml_info.new()
    my_bar.update(1)
    directory = str(rule_file.parent).replace('\\','/').replace(path_rule,output_dir)
    pathlib.Path(directory).mkdir(parents=True, exist_ok=True)
    new_file = f"{directory}/{rule_file.name}"
    with rule_file.open('r', encoding='UTF-8') as file:
        yaml_dict = ruamel.yaml.load(file, Loader=ruamel.yaml.RoundTripLoader)
        yml_info.info["title"] = yaml_dict["title"]
        yml_info.info["id"] = yaml_dict["id"]
        logsource = yml_info.get_sigma_logsource(yaml_dict)
        if logsource not in data.ref:
            if logsource in missing_keys:
                missing_keys[logsource]["count"] = missing_keys[logsource]["count"] + 1
                missing_keys[logsource]["rules"].append(rule_file)
            else:
                missing_keys[logsource] = { "count": 1, "rules": [rule_file] }
        yml_info.info["source"] = data.get_source(logsource)
        yml_info.info["audit"] = data.get_audit(logsource)
    if pathlib.Path(new_file).exists() != True:
        yml_info.save(new_file)
        yml_info.write_md(new_file.replace('.yml','.md'))
    else:
        pass
        #next check if the source and audit parts need to be update :)
if missing_keys != {} and args.verbose:
    missing_keys = OrderedDict(x for x in sorted(missing_keys.items()))
    print("Missing {} keys in template:".format(len(missing_keys)))
    print("-------------------------")
    for k,v in missing_keys.items():
        print("Key {} is missing and used by {} rule(s)".format(k,v["count"]))
