# validation-guides

## create_md.py
I think this script to start creation of the md file for the new rules.\
Maybe one day it will be put or replaced by the official repository.

### create_md.yml 
It is the database for the markdown information by logsource.\
The key is the `{product}_{category}_{service}` from sigma rules
- `source` is the information where the detection data is (apache log , windows event/channel,...)
- `audit` is how to enable the source 

### My todo

- [ ] add a output for the missing key
- [ ] add a repport of action
- [ ] update create_md.yml
- [ ] update the md file if create_md.yml is updated
- [ ] change the md file name if the sigma filename change (check by id)
- [ ] fix my bugs / issues

### Evolution

It is not decided yet but the management in yaml and automatic generation of a md as on other project seems a relevant and perennial approach


### Thanks
ZikyHD  

## update_from_evtx.py
to do on free time on day \
Update file with evtx malware references when possible (only for file without)
