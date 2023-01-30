import requests
import pathlib
import json
import time
from ruamel.yaml import YAML

def get_hijacklibs_json(path, delta=3600):
    need_to_download = False

    if pathlib.Path(path).exists():
        epoch_now = time.time()
        file_lstat = pathlib.Path(path).lstat()
        delta_time = epoch_now - file_lstat.st_mtime

        if delta_time > delta:
            need_to_download = True
            pathlib.Path(path).unlink()

    else:
        need_to_download = True

    if need_to_download:
        my_file = requests.get(
            "https://hijacklibs.net/api/hijacklibs.json"
        )

        with pathlib.Path(path).open("w", encoding="UTF-8", newline="\n") as file:
            file.write(my_file.content.decode())
    
    
    with pathlib.Path(path).open("r", encoding="UTF-8", newline="\n") as file:
        data= json.load(file)

    return data

def get_sigma_info():
    data = {}

    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.explicit_start = False
    yaml.preserve_quotes = True
    yaml.width = 5000

    yaml.indent(mapping=4, sequence=4, offset=4)

    path_sigma = '../../sigma'
    sigma_list = [yml for yml in pathlib.Path(f"{path_sigma}/rules").glob('**/*.yml')]

    for sigma_file in sigma_list:
        with sigma_file.open('r',encoding='UTF-8',newline='') as file:
            yml_sigma = yaml.load(file)
            data[sigma_file.name] = yml_sigma

    return data

print("Load hijacklibs.json")
hijacklibs = get_hijacklibs_json('hijacklibs.json')

print("Load all sigma rules")
sigma = get_sigma_info()

print("Let's rock...")
nofound= []
for dll_record in hijacklibs:
    print (f'Search for {dll_record["Name"]}')
    found =  False
    
    for rule in sigma:
        if dll_record["Name"] in str(sigma[rule]['detection']):
            #print (f'Found in {rule}')
            found = True
   
    if not found:
        nofound.append(dll_record)

if len(nofound) > 0:
    print(f'Found {len(nofound)} missing dll')
    with pathlib.Path('dll_missing.json').open("w", encoding="UTF-8", newline="\n") as file:
        for element in nofound:
            json.dump(element,file)
            file.write(',\n')
        
