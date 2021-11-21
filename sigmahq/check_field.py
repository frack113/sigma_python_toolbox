# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Project: check_field.py
Date: 2021/11/21
Author: frack113
Version: 1.2
Description: 
    Check field name use in sigma rule
Requirements:
    python :)
change:
    next challange 
        - rebuild how manage eventid
        - remove empty eventid
        - create custom OSSEM-DB
    1.2
        - add ask_me
        - fix sigma extract field name (deeper)
    1.1
        - if no EventID look into all etw from service
        - Update some win field name
    1.x 
        - Add fields from sysmon 13.30 schemas 4.81
        - And many bugs
"""

import ruamel.yaml
import pathlib
import tqdm
from collections import OrderedDict

class DataBase():

    def __init__(self,filename_dft,filename_win):
        self.filename_dft = filename_dft
        if pathlib.Path(filename_dft).exists():
            with pathlib.Path(filename_dft).open('r',encoding='UTF-8') as file:
                yml_rule = ruamel.yaml.load(file, Loader=ruamel.yaml.RoundTripLoader)
            self.data_dft = yml_rule
        else:
            self.data_dft = {}
        self.filename_win =filename_win
        if pathlib.Path(filename_win).exists():
            with pathlib.Path(filename_win).open('r',encoding='UTF-8') as file:
                yml_rule = ruamel.yaml.load(file, Loader=ruamel.yaml.RoundTripLoader)
            self.data_win = yml_rule
        else:
            self.data_win = {}
    
    def update_dft(self,state,value,product,category,service):
        order_list = self.data_dft[product][category][service][state]
        order_list.append(value)
        order_list = sorted(set(order_list))
        self.data_dft[product][category][service][state] = order_list

    def update_win(self,state,value,product,category,service,etw,eventid):
        order_list = self.data_win[product][category][service][etw][eventid][state]
        order_list.append(value)
        order_list = sorted(set(order_list))
        self.data_win[product][category][service][etw][eventid][state] = order_list

    def update(self,state,value,product,category,service,etw=None,eventid=None):
        if eventid == None:
            self.update_dft(state,value,product,category,service)
        else:
            self.update_win(state,value,product,category,service,etw,eventid)
 
    def create_dft(self,product,category,service):
        if product not in self.data_dft.keys():
            self.data_dft[product] = {}
        if category not in self.data_dft[product].keys():
            self.data_dft[product][category] = {}
        if service not in self.data_dft[product][category].keys():
            self.data_dft[product][category][service] = {"valid":[],"rule":[]}

    def create_win(self,product,category,service,etw,eventid):
        if product not in self.data_win.keys():
            self.data_win[product] = {}
        if category not in self.data_win[product].keys():
            self.data_win[product][category] = {}
        if service not in self.data_win[product][category].keys():
            self.data_win[product][category][service] = {}
        if etw not in self.data_win[product][category][service].keys():
            self.data_win[product][category][service][etw] = {}
        if eventid not in self.data_win[product][category][service][etw].keys():
            self.data_win[product][category][service][etw][eventid] = {"valid":[],"rule":[]}

    def create(self,product,category,service,etw = None,eventid = None):
        if eventid == None:
            self.create_dft(product,category,service)
        else:
            self.create_win(product,category,service,etw,eventid)

    def check_dft(self,logsource,value):
        product = logsource["product"]
        category = logsource["category"]
        service = logsource["service"]
        if product in self.data_dft.keys():
            if category in self.data_dft[product].keys():
                if service in self.data_dft[product][category].keys():
                    if value in self.data_dft[product][category][service]["valid"]:
                        return True
                    else:
                        self.update("rule",value,product,category,service)
                else: #service
                    self.create(product,category,service)         
            else: # category
                self.create(product,category,service)
        else: # product
            self.create(product,category,service)
        return False

    def check_win(self,logsource,value):
        product = logsource["product"]
        category = logsource["category"]
        service = logsource["service"]
        eventid = logsource["eventid"]
        if product in self.data_win.keys():
            if category in self.data_win[product].keys():
                if service in self.data_win[product][category].keys():
                    valid = False
                    for etw in self.data_win[product][category][service]:
                        if eventid in self.data_win[product][category][service][etw].keys():
                            if value in self.data_win[product][category][service][etw][eventid]["valid"]:
                                valid = True
                        elif eventid == '0':
                            for local_id in self.data_win[product][category][service][etw].keys():
                                if value in self.data_win[product][category][service][etw][local_id]["valid"]:
                                    valid = True
                    if not valid:
                       if value in self.data_win[product][category][service]["default"]["0"]["valid"]:
                            valid = True
                    
                    if valid:
                        return True
                    else:
                        self.create(product,category,service,"default",eventid) 
                        self.update("rule",value,product,category,service,"default",eventid)
                else: #service
                    self.create(product,category,service,"default",eventid)         
            else: # category
                self.create(product,category,service,"default",eventid)
        else: # product
            self.create(product,category,service,"default",eventid)
        return False

    def check(self,logsource,value):
        if logsource["product"] == "windows":
            return self.check_win(logsource,value)
        else:
            return self.check_dft(logsource,value)

    def clean_rule(self,mydict):
        for k in mydict.keys():
            value = mydict[k]
            if isinstance(value,dict):
                if "rule" in value.keys():
                    mydict[k]["rule"] = []
                else:
                    value = self.clean_rule(value)
    
    def init_win_default(self):
        for category in self.data_win["windows"]:
            for service in self.data_win["windows"][category]:
                self.create_win("windows",category,service,"default","0")
                self.update("valid","EventID","windows",category,service,"default","0")
                self.update("valid","Provider_Name","windows",category,service,"default","0")

    def save(self):
        with pathlib.Path(self.filename_dft).open('w',encoding='UTF-8') as file:
            ruamel.yaml.dump(self.data_dft, file, Dumper=ruamel.yaml.RoundTripDumper,indent=4,block_seq_indent=4)
        with pathlib.Path(self.filename_win).open('w',encoding='UTF-8') as file:
            ruamel.yaml.dump(self.data_win, file, Dumper=ruamel.yaml.RoundTripDumper,indent=4,block_seq_indent=4)

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
        def extract_field(the_dict,unique,event_id=None):
            for sub_item in the_dict:
                if "|" in sub_item:
                    name = sub_item.split("|")[0]
                else:
                    name = sub_item
                self.field.append(name)
                if name == "EventID" and unique:
                    if event_id!= None:
                        unique = False
                    else:
                        detection_event_id = the_dict["EventID"]
                        if isinstance(detection_event_id,str):
                            event_id = detection_event_id
                        elif isinstance(detection_event_id,int):
                            event_id = str(detection_event_id)
            return unique, event_id

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
                    if isinstance(detection[item],dict):
                        unique, event_id = extract_field(detection[item],unique, event_id)
                    elif isinstance(detection[item],list):
                        if not isinstance(detection[item][0], str): #Keywords search
                            for list_or in detection[item]:
                                unique, event_id = extract_field(list_or,unique, event_id)

            self.index = f'{self.logsource["product"]}_{self.logsource["category"]}_{self.logsource["service"]}'
            if self.logsource["product"] == "windows":
                if unique:
                    if event_id == None:
                        self.logsource["eventid"] = "0"
                    else:
                        self.logsource["eventid"] = event_id
                else:
                    self.logsource["eventid"] = "0"
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
                    self.database.update("valid",str(field["name"]),"zeek","None",service)
        zeek_bar.close()

    def update_windows(self,rep,product,category,service):
        win_list = [yml for yml in pathlib.Path(f"{self.path}/windows/etw-providers/{rep}").glob('**/events/*.yml')]
        win_bar = tqdm.tqdm(total=len(win_list),unit='file',desc=f"{rep} ")
        for win_file in win_list:
            win_bar.update(1)
            with win_file.open('r',encoding='UTF-8') as file:
                yml_win = ruamel.yaml.load(file, Loader=ruamel.yaml.RoundTripLoader)
                eventid = yml_win["event_code"]
                etw = yml_win["log_source"]
                self.database.create(product,category,service,etw,eventid)
                for field in yml_win["event_fields"]:
                    self.database.update("valid",str(field["name"]).replace(" ","_"),product,category,service,etw,eventid)
        win_bar.close()

    def update_cloud(self,rep):
        cloud_list = [yml for yml in pathlib.Path(f"{self.path}/{rep}").glob('**/events/*.yml')]
        cloud_bar = tqdm.tqdm(total=len(cloud_list),unit='file',desc=f"{rep} ")
        for cloud_file in cloud_list:
            cloud_bar.update(1)
            with cloud_file.open('r',encoding='UTF-8') as file:
                #try:
                yml_cloud = ruamel.yaml.load(file, Loader=ruamel.yaml.RoundTripLoader)
                #except:
                #    continue
                product = yml_cloud["platform"]
                category = "None"
                service = yml_cloud["event_code"]
                self.database.create(product,category,service)
                for field in yml_cloud["event_fields"]:
                    self.database.update("valid",str(field["name"]).replace(" ","_").replace(":","_"),product,category,service)
        cloud_bar.close()

def order_dict(mydict):
    out_dict ={}
    for k in sorted(mydict.keys()):
        value = mydict[k]
        if isinstance(value,dict):
            value = order_dict(value)
        elif isinstance(value,list):
            value = sorted(set(value))
        out_dict[k] = value
    return out_dict

def ask_me(question,default,valid= None):
    get_rep = False
    while get_rep == False:
        rep = input(f"{question} ? (empty = {default}) :")
        if rep == '':
            rep = default
            get_rep = True
        elif valid == None:
            get_rep = True
        else:
            if rep in valid:
                get_rep = True
    return rep

print("Hello ready to check some sigma rule")
path_sigma = ask_me("Sigma base directory","../sigma")

print("Load database")
info = DataBase("check_field_dft.yml","check_field_win.yml")
print("Clean old bad rule field name")
info.clean_rule(info.data_dft)
info.clean_rule(info.data_win)


update_ossem = ask_me("Update database from OSSEM_DB","n",["y","n"])
if update_ossem == "y":
    path_ossemdb = ask_me("Ossem-db base directory","../OSSEM-DD")
    print ("Works with OSSEM-DB")
    ossem = OSSEM_DD(path_ossemdb,info)
    ossem.update_zeek()
    ossem.update_cloud("aws")
    ossem.update_cloud("azure")
    ossem.update_windows("Microsoft-Windows-Security-Auditing","windows","None","security")
    ossem.update_windows("Microsoft-Windows-Eventlog","windows","None","security")
    ossem.update_windows("Microsoft-Windows-AppLocker","windows","None","applocker")
    ossem.update_windows("Microsoft-Windows-SMBClient","windows","None","smbclient-security")
    ossem.update_windows("Microsoft-Windows-NTLM","windows","None","ntlm")
    ossem.update_windows("Microsoft-Windows-Dhcp-Client","windows","None","dhcp")
    ossem.update_windows("Microsoft-Windows-DriverFrameworks-UserMode","windows","None","driver-framework")
    ossem.update_windows("Microsoft-Windows-PrintService","windows","None","printservice-admin")  # ?
    ossem.update_windows("Microsoft-Windows-PrintService","windows","None","printservice-operational") # ?
    ossem.update_windows("Microsoft-Windows-SMBClient","windows","None","smbclient-security") # ?

print("Create missing windows 'default' etw")
info.init_win_default()

print("Processing rules :")
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
info.data_dft = order_dict(info.data_dft)
info.data_win = order_dict(info.data_win)
info.save()

print(f"find {len(invalid)} elements to be considered")
if len(invalid)>0:
    output_yml = ask_me("Output rapport yml name","rule_rapport.yml")
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

print("Have a nice day :)")