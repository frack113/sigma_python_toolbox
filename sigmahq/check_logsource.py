# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Project: check-logsource.py
Date: 03/11/2021
Author: frack113
Version: 0.1
Description: 
    
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
def deep(liste,name,level):
    info = []
    if level > 2:
        return info
    for item in liste:
        if item == name:
            info.append(liste[item])
        elif isinstance(liste[item],OrderedDict):
            info.extend(deep(liste[item],name,level+1))
    return info

parser = argparse.ArgumentParser(description='Create the md file with common information for new rules')
parser.add_argument("--input", '-i', help="Sigma rules directory", type=str, default="../sigma")
parser.add_argument("--output", '-o', help="Output rapport yml name", default="rapport.yml", type=str)
args = parser.parse_args()

path_sigma = args.input
output_yml = args.output
config_list = [yml for yml in pathlib.Path(f"{path_sigma}/tools/config").glob('**/*.yml')]

config_bar = tqdm.tqdm(total=len(config_list),unit='file',desc="Parse config yml")
product_list = []
category_list = []
service_list = []
for config in config_list:
    config_bar.update(1)
    with config.open('r',encoding='UTF-8') as file:
        info = ruamel.yaml.load(file, Loader=ruamel.yaml.RoundTripLoader)
        for section in info:
            if section == 'logsources':
                product_list.extend(deep(info[section],"product",0))
                category_list.extend(deep(info[section],"category",0))
                service_list.extend(deep(info[section],"service",0))
config_bar.close()

product_list = list(set(product_list))
category_list = list(set(category_list))
service_list = list(set(service_list))

print(f"Find {len(product_list)} product")
print(f"Find {len(category_list)} category")
print(f"Find {len(service_list)} service")

sigma_list = [yml for yml in pathlib.Path(f"{path_sigma}/rules").glob('**/*.yml')]
sigma_bar = tqdm.tqdm(total=len(sigma_list),unit='file',desc="Parse sigma rule")
invalid = {}
for sigma in sigma_list:
    sigma_bar.update(1)
    with sigma.open('r',encoding='UTF-8') as file:
        rule = ruamel.yaml.load(file, Loader=ruamel.yaml.RoundTripLoader)
        logsource = rule["logsource"]
        valid = True
        msg = {
            "path": str(sigma.parent),
            "product":  "-",
            "category": "-",
            "service":  "-"
            }
        if "product" in logsource:
            if not logsource["product"] in product_list:
                if logsource["product"].lower() in product_list:
                    msg["product"] = f"Case error for {logsource['product']}"
                else:
                    msg["product"] = f"No found {logsource['product']}"
                valid = False
            else:
                msg["product"] = f"{logsource['product']} ok"
        if "category" in logsource:
            if not logsource["category"] in category_list:
                if logsource["category"].lower() in category_list:
                    msg["category"] = f"Case error for {logsource['category']}"
                else:
                    msg["category"] = f"No found {logsource['category']}"            
                valid = False
            else:
                msg["category"] = f"{logsource['category']} ok"
        if "service" in logsource:
            if not logsource["service"] in service_list:
                if logsource["service"].lower() in service_list:
                    msg["service"] = f"Case error for {logsource['service']}"
                else:
                    msg["service"] = f"No found {logsource['service']}"   
                valid = False        
            else:
                msg["service"] = f"{logsource['service']} ok"
        if not valid:
            invalid[sigma.name] = msg

sigma_bar.close()

print(f"find {len(invalid)} elements to be considered")
if len(invalid)>0:
    with pathlib.Path(output_yml).open('w',encoding='UTF-8') as file:
        ruamel.yaml.dump(invalid, file, Dumper=ruamel.yaml.RoundTripDumper,indent=2,block_seq_indent=2)
