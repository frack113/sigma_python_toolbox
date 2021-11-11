# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Project: check_field.py
Date: 2021/11/10
Author: frack113
Version: 1.0
Description: 
    Check field name use in sigma rule
    Add fields from sysmon 13.30 schemas 4.81
Requirements:
    python :)
Todo:

"""

import ruamel.yaml
import pathlib
import tqdm
import datetime
import argparse
from collections import OrderedDict
import logging

class DataBase():

    def __init__(self,filename):
        self.filename = filename
        if pathlib.Path(filename).exists():
            with pathlib.Path(filename).open('r',encoding='UTF-8') as file:
                yml_rule = ruamel.yaml.load(file, Loader=ruamel.yaml.RoundTripLoader)
            self.data = yml_rule
            for index in self.data.keys():
                self.data[index]["rule"] = []
        else:
            self.data = {}

    def check(self,index,value):
        if index in self.data:
            if value in self.data[index]["valid"]:
                return True
            else:
                if not value in self.data[index]["rule"]:
                    self.data[index]["rule"].append(value)
                return False
        else:
            self.data[index] = {
                "valid": [],
                "rule":  [value]
                }
            return False

    def update_default(self):
        for index in self.data:
            if index[:8]=="windows_":
                if not "EventID" in self.data[index]["valid"]:
                    self.data[index]["valid"].append("EventID")
                if not "Provider_Name" in self.data[index]["valid"]:
                    self.data[index]["valid"].append("Provider_Name")                   

    def save(self):
        out_dict ={}
        for k in sorted(self.data):
            out_dict[k] = {
                "valid":sorted(self.data[k]["valid"]),
                "rule":sorted(self.data[k]["rule"])               
            }
        with pathlib.Path(self.filename).open('w',encoding='UTF-8') as file:
            ruamel.yaml.dump(out_dict, file, Dumper=ruamel.yaml.RoundTripDumper,indent=2,block_seq_indent=2)

class MySigma():

    def __init__(self):
        self.logsource = {
            "product":  "None",
            "category": "None",
            "service":  "None"
            }
        self.index = "None_None_None"
        self.subindex = None  
        self.field = []

    def load(self,filename):
        with filename.open('r',encoding='UTF-8') as file:
            yml_rule = ruamel.yaml.load(file, Loader=ruamel.yaml.RoundTripLoader)
            self.logsource= {
                "product":  "None",
                "category": "None",
                "service":  "None"
                }
            self.subindex = None
            self.field = []
            logsource = yml_rule["logsource"]
            if "product" in logsource:
                self.logsource["product"] = logsource["product"]
            if "category" in logsource:
                self.logsource["category"] = logsource["category"]
            if "service" in logsource:
                self.logsource["service"] = logsource["service"]
            
            self.index = f'{self.logsource["product"]}_{self.logsource["category"]}_{self.logsource["service"]}'

            detection = yml_rule["detection"]
            for item in detection:
                if item == "condition":
                    continue
                elif item == "timeframe":
                    continue
                else:
                    if isinstance(detection[item],OrderedDict):
                        for sub_item in detection[item]:
                            if "|" in sub_item:
                                name = sub_item.split("|")[0]
                            else:
                                name = sub_item
                            self.field.append(name)
                            if name == "EventID":
                                eventid = detection[item]["EventID"]
                                if isinstance(eventid,str):
                                    self.subindex = eventid
                                elif isinstance(eventid,int):
                                    self.subindex = str(eventid)
            if self.subindex != None:
                self.index = f"{self.index}_{self.subindex}"

parser = argparse.ArgumentParser(description='Create the md file with common information for new rules')
parser.add_argument("--input", '-i', help="Sigma rules directory", type=str, default="../sigma")
parser.add_argument("--output", '-o', help="Output rapport yml name", default="rule_rapport.yml", type=str)
args = parser.parse_args()

path_sigma = args.input
output_yml = args.output

print ("Load database")
info = DataBase("check_field.yml")

print("Update default field")
info.update_default()

print("Processing :")
invalid = {}
rule = MySigma()
sigma_list = [yml for yml in pathlib.Path(f"{path_sigma}/rules").glob('**/*.yml')]
sigma_bar = tqdm.tqdm(total=len(sigma_list),unit='file',desc="Parse sigma rule")
for sigma_file in sigma_list:
    sigma_bar.update(1)
    rule.load(sigma_file)
    for item in rule.field:
        if info.check(rule.index,item) != True:
            if  sigma_file.name in invalid:
                if not item in invalid[sigma_file.name]["field"]:
                    invalid[sigma_file.name]["field"].append(item)
            else:
                invalid[sigma_file.name] = {
                                            "logsource": rule.index,
                                            "field": [item]
                }

sigma_bar.close()


print("Save database")
info.save()
print(f"find {len(invalid)} elements to be considered")
if len(invalid)>0:
    with pathlib.Path(output_yml).open('w',encoding='UTF-8') as file:
        ruamel.yaml.dump(invalid, file, Dumper=ruamel.yaml.RoundTripDumper,indent=2,block_seq_indent=2)
    
    invalid_log = {}
    for rule_name,rule_info in invalid.items():
        if rule_info["logsource"] in invalid_log:
            invalid_log[rule_info["logsource"]].append({rule_name:rule_info["field"]})
        else:
            invalid_log[rule_info["logsource"]] = [{rule_name:rule_info["field"]}]
    with pathlib.Path(f"log_{output_yml}").open('w',encoding='UTF-8') as file:
        ruamel.yaml.dump(invalid_log, file, Dumper=ruamel.yaml.RoundTripDumper,indent=2,block_seq_indent=2)

print("Bye")