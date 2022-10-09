from ruamel.yaml import YAML
import tqdm
import pathlib
import datetime
from collections import OrderedDict
import copy

''' SigmaHQ ref
title
id [optional]
related [optional]
   - type {type-identifier}
     id {rule-id}
status [optional]
description [optional]
author [optional]
references [optional]
date + modified
logsource
   category [optional]
   product [optional]
   service [optional]
   definition [optional]
   ...
detection
   {search-identifier} [optional]
      {string-list} [optional]
      {field: value} [optional]
   ...
   timeframe [optional]
   condition
fields [optional]
falsepositives [optional]
level [optional]
tags [optional]
'''

def order(yml):
    old_yml = copy.deepcopy(yml)
    new_yml = {}
    
    new_yml['title'] = old_yml['title']
    del old_yml['title']
    
    new_yml['id'] = old_yml['id']
    del old_yml['id']
    
    if 'related' in old_yml:
        new_yml['related'] = old_yml['related']
        del old_yml['related']
        
    new_yml['status'] = old_yml['status']
    del old_yml['status']
    
    if 'description' in old_yml:
        new_yml['description'] = old_yml['description']
        del old_yml['description']

    if 'references' in old_yml:
        new_yml['references'] = old_yml['references']
        del old_yml['references']
        
    if 'author' in old_yml:
        new_yml['author'] = old_yml['author']
        del old_yml['author'] 

    new_yml['date'] = old_yml['date']
    del old_yml['date']
    new_yml['modified'] = "2021/12/02"
    if 'modified' in old_yml:
        new_yml['modified'] = old_yml['modified']
        del old_yml['modified']

    if 'tags' in old_yml:
        new_yml['tags'] = old_yml['tags']
        del old_yml['tags']

    new_yml['logsource'] = old_yml['logsource']
    del old_yml['logsource']
    
    new_yml['detection'] = old_yml['detection']
    del old_yml['detection']
   

    if 'falsepositives' in old_yml:
        new_yml['falsepositives'] = old_yml['falsepositives']
        del old_yml['falsepositives']

    if 'level' in old_yml:
        new_yml['level'] = old_yml['level']
        del old_yml['level']               

    if 'fields' in old_yml:
        new_yml['fields'] = old_yml['fields']
        del old_yml['fields']

    for key in old_yml.keys():
        new_yml[key] = old_yml[key]
        print(f"Found custom key {key}")
        del old_yml[key]

    if len(old_yml)>0:
        print(f"There is a BIG Problem here: {old_yml}")
    return new_yml
        

yaml = YAML()
yaml.preserve_quotes = True
yaml.explicit_start = False
yaml.preserve_quotes =True
yaml.width = 2000

yaml.indent(mapping=4, sequence=4, offset=4)

path_sigma = '../../sigma'
sigma_list = [yml for yml in pathlib.Path(f"{path_sigma}/rules").glob('**/*.yml')]
#sigma_bar = tqdm.tqdm(total=len(sigma_list),unit='file',desc="Parse sigma rule")

today_date = datetime.datetime.now()
today_date_str = datetime.datetime.strftime(today_date,'%Y/%m/%d')
print (f"Today is {today_date_str}")

for sigma_file in sigma_list:
    #sigma_bar.update(1)
    local_path = str(sigma_file.parent).replace('..','./temp')
    with sigma_file.open('r',encoding='UTF-8',newline='') as file:
        yml_sigma = yaml.load(file)
        if not 'status' in yml_sigma:
            print(sigma_file.name)
            continue
        if yml_sigma['status'] in ["experimental"]:
            update_str = yml_sigma['modified'] if 'modified' in yml_sigma else yml_sigma['date']
            update_date = datetime.datetime.strptime(update_str,'%Y/%m/%d')
            delta = today_date - update_date
            if delta.days >365:
                print (f"Update : {sigma_file.name} last change {update_str} get {delta.days} days")
                val = order(yml_sigma)
                val['status'] = 'stable' if val['status']=='test' else 'test'
                val['modified'] = today_date_str
                filepath = pathlib.Path(f"{local_path}/{sigma_file.name}")
                filepath.parent.mkdir(parents=True, exist_ok=True)
                with filepath.open('w',encoding='UTF-8',newline='') as file_out:
                    yaml.dump(val,file_out)

#sigma_bar.close()
