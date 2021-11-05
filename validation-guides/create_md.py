# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Project: create_md.py
Date: 05/11/2021
Author: frack113
Version: 1.2
Description: 
    create the yml file with common information for new sigma rules
"""

import ruamel.yaml
import pathlib
import tqdm
import datetime
import argparse
from collections import OrderedDict
import logging

class knowledge():
    def __init__(self):
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
    def __init__(self,author):
        self.info = {}
        self.author = author

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
            "authors": [self.author],
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

    def save(self,name,ondisk):
        if ondisk:
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
    def __init__(self):
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
logging.basicConfig(filename='create_md.log',filemode='w',level=logging.INFO)
logging.info("Wellcome into the log world")
data = knowledge()
data.load('create_md.yml')

parser = argparse.ArgumentParser(description='Create the yml informationfile with common information for new rules')
parser.add_argument("--input", '-i', help="Sigma rules directory", type=str, default="../sigma/rules")
parser.add_argument("--output", '-o', help="Output directory", default="./rules", type=str)
parser.add_argument("--verbose", '-v', help="Display missing keys", default=False, action='store_true')
parser.add_argument("--test", '-t', help="Test only don't save",default=False, action='store_true')
parser.add_argument("--author", '-a', help="Set the author", default="frack113", type=str)
args = parser.parse_args()

save_output = not args.test
path_rule = args.input
if not pathlib.Path(path_rule).is_dir():
    print ("input must be a directory with sigma rule")
    logging.fatal("input must be a directory with sigma rule")
    exit(2)

output_dir = args.output
if not pathlib.Path(output_dir).is_dir():
    print ("output must be a directory for the sigma information file")
    logging.fatal("output must be a directory for the sigma information file")
    exit(2)

sigma_list = [yml for yml in pathlib.Path(path_rule).glob('**/*.yml')]
info_list = [yml for yml in pathlib.Path(output_dir).glob('**/*.yml')]

logging.info(f"Find {len(sigma_list)} sigma rule(s)")
sigma_id = {}
sigma_bar = tqdm.tqdm(total=len(sigma_list),desc="Get sigma ID")
sigma_data = sigma_info()
for rule_file in sigma_list:
    sigma_bar.update(1)
    sigma_data.load(rule_file)
    sigma_id[rule_file.name] = sigma_data.get_section("id")
sigma_bar.close()

logging.info(f"Find {len(info_list)} sigma information file(s)")
info_id = {}
info_data = information(args.author)
if len(info_list)>0:
    info_bar = tqdm.tqdm(total=len(info_list),desc="Get info ID")
    for info_file in info_list:
        info_bar.update(1)
        info_data.load(info_file)
        info_id[info_file.name] = info_data.get_section("id")
    info_bar.close()

    check_name_bar = tqdm.tqdm(total=len(info_list),desc="Check diff")
    id_sigma = {v:k for k,v in sigma_id.items()}
    for key,val_id in info_id.items():
        check_name_bar.update(1)
        if not key in sigma_id:
            logging.error(f"{key} information file have no sigma rule")
        elif val_id != sigma_id[key]:
            logging.error(f"{key} information file have not the same ID than the sigma rule")
        elif key != id_sigma[val_id]:
            logging.error(f"{key} information file have the same ID than {id_sigma[val_id]} rule")
    check_name_bar.close()


missing_keys = {}

my_bar = tqdm.tqdm(total=len(sigma_list),desc="Generate the file")
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

    if pathlib.Path(info_file).exists():
        info_data.load(info_file)
        updated = False
        if sigma_data.is_updated("title",info_data.get_section("title")):
            info_data.set_section("title",sigma_data.get_section("title"))
            updated = True
            logging.warning(f"Update title in {info_file}")
        if sigma_data.is_updated("id",info_data.get_section("id")):
            info_data.set_section("id",sigma_data.get_section("id"))
            updated = True
            logging.critical(f"Update id in {info_file}")
        if data.is_updated(logsource,"source",info_data.get_section("source")):
            info_data.set_section("source",data.get_section(logsource,"source"))
            updated = True
            logging.warning(f"Update source in {info_file}")
        if data.is_updated(logsource,"audit",info_data.get_section("audit")):
            info_data.set_section("audit",data.get_section(logsource,"audit"))
            updated = True
            logging.warning(f"Update audit in {info_file}")
        if updated:
            info_data.update_history("auto update by frack113 script")
            info_data.save(info_file,save_output)
    else:
        info_data.new()
        info_data.set_section("title",sigma_data.get_section("title"))
        info_data.set_section("id",sigma_data.get_section("id"))
        info_data.set_section("source",data.get_section(logsource,"source"))
        info_data.set_section("audit",data.get_section(logsource,"audit"))
        info_data.save(info_file,save_output)
        logging.warning(f"Adding new file {info_file}")
    my_bar.update(1)
my_bar.close()

if missing_keys != {} and args.verbose:
    missing_keys = OrderedDict(x for x in sorted(missing_keys.items()))
    print("Missing {} keys in template:".format(len(missing_keys)))
    print("-------------------------")
    for k,v in missing_keys.items():
        print("Key {} is missing and used by {} rule(s)".format(k,v["count"]))
