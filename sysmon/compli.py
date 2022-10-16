import xml.etree.ElementTree as ETree
import csv

list_file = {'9.00':'sysmon_9.xml',
             '10.00': 'sysmon_10.xml',
             '11.00': 'sysmon_11.xml',
             '12.03': 'sysmon_12_03.xml',
             '13.01': 'sysmon_13_01.xml',
             '13.30': 'sysmon_13_30.xml',
             '14.01': 'sysmon_14_01.xml',
            }

list_all = [['Eventid','Name','Sysmon']]

for version in list_file:

    print (f"Open file {list_file[version]}")
    parser = ETree.XMLParser(encoding="utf-8")
    tree = ETree.parse(list_file[version], parser=parser)

    for event in tree.iter('event'):
        line = []
        line.append(event.get('value'))
        line.append(event.get('name'))
        line.append(version)
        for field in event:
            line.append(field.get('name'))
        list_all.append(line)

with open('Sysmon.csv', mode='w',encoding="utf-8",newline='') as csv_file:
    write = csv.writer(csv_file)
    write.writerows(list_all) 