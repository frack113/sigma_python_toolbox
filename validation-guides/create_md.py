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

    def get_section(self,logsource,section):
        local_logsource =  self.ref[logsource][section] if logsource in self.ref else self.ref["None_None_None"][section]
        return local_logsource

    def is_updated(self,logsource,section,data):
        if logsource in self.ref:
            if self.ref[logsource][section] == data:
                return False
            else:
                return True
        else:
            return False

class information():
    def _init_():
        self.info = {}

    def clean(self):
        self.info = {
            "title": "",
            "id": "",
            "authors": [],
            "history": [],
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
            "authors": ["Frack113"],
            "history": [mydate],
            "source": "update script database",
            "audit": "update script database",
            "description": "Contribute to the updating of information",
            "code": "Contribute to the updating of information",
            "example": "Contribute to the updating of information"
        }

    def write_md(self,name):
        with pathlib.Path(name).open('w', encoding='UTF-8', newline='') as md_file:
            md_file.write(f'# Rule: {self.info["title"]}\n\n')
            md_file.write(f'Sigma rule ID : {self.info["id"]}\n\n')
            md_file.write(f'## authors\n\n{self.info["authors"]}\n\n')
            md_file.write(f'## Change History\n\n- {self.info["history"]} \n\n')
            md_file.write(f'## Required Log Sources\n\n{self.info["source"]}\n\n')
            md_file.write(f'## Required Audit Policy / Config\n\n{self.info["audit"]}\n\n')
            md_file.write(f'## Description\n\n{self.info["description"]}\n\n')
            md_file.write(f'## Code\n\n{self.info["code"]}\n\n')
            md_file.write(f'## Example\n\n{self.info["example"]}\n\n')

    def save(self,name):
        with pathlib.Path(name).open('w', encoding='UTF-8', newline='') as yaml_file:
            ruamel.yaml.dump(self.info, yaml_file, Dumper=ruamel.yaml.RoundTripDumper,indent=2,block_seq_indent=2)

    def load(self,filename):
        with open(filename,'r',encoding='UTF-8') as file:
            self.info = ruamel.yaml.load(file, Loader=ruamel.yaml.RoundTripLoader)   
 
    def get_section(self,name):
        data = self.info[name] if name in self.info else None
        return data
    
    def set_section(self,name,data):
        self.info[name] = data

    def update_history(self,msg):
        mydate = f"{datetime.date.today().strftime('%Y%m%d')}: {msg}"
        self.info["history"].insert(0,mydate)

class sigma_info():
    def _init_():
        self.info = {}
    
    def load(self,filename):
        with open(filename,'r',encoding='UTF-8') as file:
            self.info = ruamel.yaml.load(file, Loader=ruamel.yaml.RoundTripLoader)

    def get_section(self,name):
        data = self.info[name] if name in self.info else None
        return data

    def calcul_logsource_id(self):
        product = self.info["logsource"]["product"].lower() if "product" in self.info["logsource"] else "None"
        category = self.info["logsource"]["category"].lower() if "category" in self.info["logsource"] else "None"
        service = self.info["logsource"]["service"].lower() if "service" in self.info["logsource"] else "None"
        return f"{product}_{category}_{service}"
    
    def is_updated(self,section,data):
        if self.info[section] == data:
            return False
        else:
            return True

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

print("\nGet sigma ID")
sigma_id = {}
sigma_bar = tqdm.tqdm(total=len(sigma_list))
sigma_data = sigma_info()
for rule_file in sigma_list:
    sigma_bar.update(1)
    sigma_data.load(rule_file)
    sigma_id[rule_file.name] = sigma_data.get_section("id")


print("\nGet info ID")
info_id = {}
info_data = information()
if len(info_list)>0:
    info_bar = tqdm.tqdm(total=len(info_list))
    for rule_file in sigma_list:
        info_bar.update(1)
        info_data.load(rule_file)
        info_id[rule_file.name] = info_data.get_section("id")

print("\nGenerate the file") 
missing_keys = {}


my_bar = tqdm.tqdm(total=len(sigma_list))
for rule_file in sigma_list:
    sigma_data.load(rule_file)
    logsource = sigma_data.calcul_logsource_id()
    if logsource not in data.ref:
        if logsource in missing_keys:
            missing_keys[logsource]["count"] = missing_keys[logsource]["count"] + 1
            missing_keys[logsource]["rules"].append(rule_file)
        else:
            missing_keys[logsource] = { "count": 1, "rules": [rule_file] }

    info_directory = str(rule_file.parent).replace('\\','/').replace(path_rule,output_dir)
    pathlib.Path(info_directory).mkdir(parents=True, exist_ok=True)
    info_file = f"{info_directory}/{rule_file.name}"

    if pathlib.Path(info_file).exists() != True:
        info_data.new()
        info_data.set_section("title",sigma_data.get_section("title"))
        info_data.set_section("id",sigma_data.get_section("id"))
        info_data.set_section("source",data.get_section(logsource,"source"))
        info_data.set_section("audit",data.get_section(logsource,"audit"))
        info_data.save(info_file)
    else:
        info_data.load(info_file)
        updated = False
        if sigma_data.is_updated("title",info_data.get_section("title")):
            info_data.set_section("title",sigma_data.get_section("title"))
            updated = True
        if sigma_data.is_updated("id",info_data.get_section("id")):
            info_data.set_section("id",sigma_data.get_section("id"))
            updated = True
        if data.is_updated(logsource,"source",info_data.get_section("source")):
            info_data.set_section("source",data.get_section(logsource,"source"))
            updated = True  
        if data.is_updated(logsource,"audit",info_data.get_section("audit")):
            info_data.set_section("audit",data.get_section(logsource,"audit"))
            updated = True
        if updated:
            info_data.update_history("auto update by frack113 script")
            info_data.save(info_file)

    my_bar.update(1)

if missing_keys != {} and args.verbose:
    missing_keys = OrderedDict(x for x in sorted(missing_keys.items()))
    print("Missing {} keys in template:".format(len(missing_keys)))
    print("-------------------------")
    for k,v in missing_keys.items():
        print("Key {} is missing and used by {} rule(s)".format(k,v["count"]))
