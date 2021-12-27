import json
import csv
import pathlib
import re

print('Hello me :)')

csv_list = [['technique','nmr','Rule_Path','Rule_Id','Match_Strings']]

file_json_list = pathlib.Path('.').glob('*_aurora.json')
for file_json in file_json_list:
    print (f'Open {file_json.name}')
    technique, nmr = re.findall(r'(\S+)_test_(\d+)_aurora', file_json.name)[0]
    
    with file_json.open('r',encoding='UTF8') as file:
        json_lines = file.readlines()
    
    for line in json_lines:
        json_data = json.loads(line)
        if 'Module' in json_data and  json_data['Module'] == 'Sigma':
            csv_list.append([technique,nmr,json_data['Rule_Path'],json_data['Rule_Id'],json_data['Match_Strings']])

with pathlib.Path('result.csv').open('w',encoding='UTF-8', newline='') as file:
    csv_writer = csv.writer(file, delimiter=';', quotechar='|')
    csv_writer.writerows(csv_list)
