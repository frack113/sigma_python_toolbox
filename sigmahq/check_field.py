# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Project: check_field.py
Date: 2021/11/13
Author: frack113
Version: 1.1
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
        else:
            self.data = {}
    
    def update(self,product,category,service,eventid,state,value):
        if eventid == None:
            order_list = self.data[product][category][service][state]
            order_list.append(value)
            order_list = sorted(set(order_list))
            self.data[product][category][service][state] = order_list
        else:
            order_list = self.data[product][category][service][eventid][state]
            order_list.append(value)
            order_list = sorted(set(order_list))
            self.data[product][category][service][eventid][state] = order_list           
    
    def create(self,product,category,service,eventid = None):
        if product not in self.data.keys():
            self.data[product] = {}
        if category not in self.data[product].keys():
            self.data[product][category] = {}
        if service not in self.data[product][category].keys():
            self.data[product][category][service] = {}
        if eventid == None:
            self.data[product][category][service] = {"valid":[],"rule":[]}
        else:
            if eventid not in self.data[product][category][service].keys():
                self.data[product][category][service][eventid] = {"valid":[],"rule":[]}


    def check(self,logsource,value):
        product = logsource["product"]
        if product in self.data.keys():
            category = logsource["category"]
            if category in self.data[product].keys():
                service = logsource["service"]
                if service in self.data[product][category].keys():
                    eventid = logsource["eventid"]
                    if eventid == None:
                        if value in self.data[product][category][service]["valid"]:
                            return True
                        else:
                            self.update(product,category,service,None,"rule",value)
                    else:
                        if eventid in self.data[product][category][service].keys():
                            if value in self.data[product][category][service][eventid]["valid"]:
                                return True
                            else:
                              self.update(product,category,service,eventid,"rule",value)
                        else:
                            self.create(product,category,service,eventid)
                else: #service
                    if product == "windows" and category == "None" :
                        self.create(product,category,service,"any")
                    else:
                        self.create(product,category,service)         
            else: # category
                self.create(product,category,"None")
        else: # product
            self.create(product,"None","None")
        return False

    def update_default(self):
        if "windows" in self.data.keys():  #error 1st lanch with with data empty 
            if "None" in self.data["windows"]:
                if "None" in self.data["windows"]["None"].keys():
                    self.data["windows"]["None"].pop("None",None)

                for service in self.data["windows"]["None"]:
                    if not "any" in self.data["windows"]["None"][service].keys():
                        self.create("windows","None",service,"any")
                        self.update("windows","None",service,"any","valid","EventID")
                        self.update("windows","None",service,"any","valid","Provider_Name")
                    if len(self.data["windows"]["None"][service])>1:
                        valid =[]
                        for eventid in self.data["windows"]["None"][service]:
                            valid.extend(self.data["windows"]["None"][service][eventid]["valid"])
                        self.data["windows"]["None"][service]["any"]["valid"] = sorted(set(valid))

    def save(self):
        with pathlib.Path(self.filename).open('w',encoding='UTF-8') as file:
            ruamel.yaml.dump(self.data, file, Dumper=ruamel.yaml.RoundTripDumper,indent=4,block_seq_indent=4)

class MySigma():

    def __init__(self):
        self.logsource = {
            "product":  "None",
            "category": "None",
            "service":  "None",
            "eventid": None
            }
        self.field = []
        self.index = ""

    def load(self,filename):
        with filename.open('r',encoding='UTF-8') as file:
            yml_rule = ruamel.yaml.load(file, Loader=ruamel.yaml.RoundTripLoader)
            self.logsource= {
                "product":  "None",
                "category": "None",
                "service":  "None",
                "eventid": None
                }
            self.field = []
            logsource = yml_rule["logsource"]
            if "product" in logsource:
                self.logsource["product"] = logsource["product"]
            if "category" in logsource:
                self.logsource["category"] = logsource["category"]
            if "service" in logsource:
                self.logsource["service"] = logsource["service"]
            
            detection = yml_rule["detection"]
            unique = True
            event_id = None
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
                            if name == "EventID" and unique:
                                if event_id!= None:
                                    unique = False
                                else:
                                    detection_event_id = detection[item]["EventID"]
                                    if isinstance(detection_event_id,str):
                                        event_id = detection_event_id
                                    elif isinstance(detection_event_id,int):
                                        event_id = str(detection_event_id)
            self.index = f'{self.logsource["product"]}_{self.logsource["category"]}_{self.logsource["service"]}'
            if self.logsource["product"] == "windows" and self.logsource["category"] == "None":
                if unique:
                    if event_id == None:
                        self.logsource["eventid"] = "any"
                    else:
                        self.logsource["eventid"] = event_id
                else:
                    self.logsource["eventid"] = "any"
                self.index = f'{self.index}_{self.logsource["eventid"]}'

class OSSEM_DD():
    def __init__(self,path,database):
        self.path = path
        self.database = database
    
    def update_zeek(self):
        zeek_list = [yml for yml in pathlib.Path(f"{self.path}/zeek").glob('**/events/*.yml')]
        zeek_bar = tqdm.tqdm(total=len(zeek_list),unit='file',desc="zeek ")
        for zeek in zeek_list:
            zeek_bar.update(1)
            with zeek.open('r',encoding='UTF-8') as file:
                yml_zeek = ruamel.yaml.load(file, Loader=ruamel.yaml.RoundTripLoader)
                service = yml_zeek["event_code"]
                self.database.create("zeek","None",service)
                for field in yml_zeek["event_fields"]:
                    self.database.update("zeek","None",service,None,"valid",str(field["name"]))
        zeek_bar.close()

    def update_windows(self,rep,product,category,service):
        win_list = [yml for yml in pathlib.Path(f"{self.path}/windows/etw-providers/{rep}").glob('**/events/*.yml')]
        win_bar = tqdm.tqdm(total=len(win_list),unit='file',desc=f"{rep} ")
        for win_file in win_list:
            win_bar.update(1)
            with win_file.open('r',encoding='UTF-8') as file:
                yml_win = ruamel.yaml.load(file, Loader=ruamel.yaml.RoundTripLoader)
                eventid = yml_win["event_code"]
               # etw = yml_win["log_source"]
                self.database.create(product,category,service,eventid)
                for field in yml_win["event_fields"]:
                    self.database.update(product,category,service,eventid,"valid",str(field["name"]).replace(" ","_"))
        win_bar.close()

    def update_cloud(self,rep):
        cloud_list = [yml for yml in pathlib.Path(f"{self.path}/{rep}").glob('**/events/*.yml')]
        cloud_bar = tqdm.tqdm(total=len(cloud_list),unit='file',desc=f"{rep} ")
        for cloud_file in cloud_list:
            cloud_bar.update(1)
            with cloud_file.open('r',encoding='UTF-8') as file:
                try:
                    yml_cloud = ruamel.yaml.load(file, Loader=ruamel.yaml.RoundTripLoader)
                except:
                    continue
                product = yml_cloud["platform"]
                category = "None"
                service = yml_cloud["event_code"]
                self.database.create(product,category,service)
                for field in yml_cloud["event_fields"]:
                    self.database.update(product,category,service,None,"valid",str(field["name"]).replace(" ","_").replace(":","_"))
        cloud_bar.close()

def order_dict(mydict):
    out_dict ={}
    for k in sorted(mydict.keys()):
        value = mydict[k]
        if isinstance(value,dict):
            value = order_dict(value)
        out_dict[k] = value
    return out_dict

parser = argparse.ArgumentParser(description='Create the md file with common information for new rules')
parser.add_argument("--sigma", '-s', help="Sigma base directory", type=str, default="../sigma")
parser.add_argument("--ossemdb", '-o', help="Ossem-db base directory", type=str, default="../OSSEM-DD")
parser.add_argument("--rapport", '-r', help="Output rapport yml name", default="rule_rapport.yml", type=str)
args = parser.parse_args()

path_sigma = args.sigma
path_ossemdb = args.ossemdb
output_yml = args.rapport


print ("Load database")
info = DataBase("check_field.yml")

print ("Load OSSEM-DB")
ossem = OSSEM_DD(path_ossemdb,info)
ossem.update_zeek()
ossem.update_cloud("aws")
ossem.update_cloud("azure")
ossem.update_windows("Microsoft-Windows-Security-Auditing","windows","None","security")
ossem.update_windows("Microsoft-Windows-AppLocker","windows","None","applocker")
ossem.update_windows("Microsoft-Windows-SMBClient","windows","None","smbclient-security")


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
        if info.check(rule.logsource,item) != True:
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
info.data = order_dict(info.data)
info.save()

print(f"find {len(invalid)} elements to be considered")
if len(invalid)>0:
    order_invalid = order_dict(invalid)
    with pathlib.Path(output_yml).open('w',encoding='UTF-8') as file:
        ruamel.yaml.dump(order_invalid, file, Dumper=ruamel.yaml.RoundTripDumper,indent=2,block_seq_indent=2)
    
    invalid_log = {}
    for rule_name,rule_info in invalid.items():
        if rule_info["logsource"] in invalid_log:
            invalid_log[rule_info["logsource"]].append({rule_name:rule_info["field"]})
        else:
            invalid_log[rule_info["logsource"]] = [{rule_name:rule_info["field"]}]
    order_invalid_log ={}
    for index in sorted(invalid_log):
        order_invalid_log[index]=invalid_log[index]

    with pathlib.Path(f"log_{output_yml}").open('w',encoding='UTF-8') as file:
        ruamel.yaml.dump(order_invalid_log, file, Dumper=ruamel.yaml.RoundTripDumper,indent=2,block_seq_indent=2)

print("Bye")
