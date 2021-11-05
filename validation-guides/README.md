# validation-guides

## create_md.py
I think this script to start creation of the yml file for the new rules.\
markdown file will be generate from the yaml.\
Maybe one day it will be put or replaced by the official repository.

### create_md.yml 
It is the database for the markdown information by logsource.\
The key is the `{product}_{category}_{service}` from sigma rules
- `source` is the information where the detection data is (apache log , windows event/channel,...)
- `audit` is how to enable the source 

### use
```bash
usage: create_md.py [-h] [--input INPUT] [--output OUTPUT] [--verbose]

Create the md file with common information for new rules

optional arguments:
  -h, --help            show this help message and exit
  --input INPUT, -i INPUT
                        Sigma rules directory
  --output OUTPUT, -o OUTPUT
                        Output directory
  --verbose, -v         Display missing keys
```
### My todo

- [X] add a output for the missing key
- [X] add a repport of action (creation_md.log)
- [X] update the yml file if create_md.yml is updated
- [ ] manage if the sigma filename change (check by id)
- [ ] fix my bugs / issues

### Evolution

- [ ] update create_md.yml
- [ ] add a pretty local md output

### Thanks
ZikyHD
