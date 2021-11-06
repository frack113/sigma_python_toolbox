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
usage: create_md.py [-h] [--input INPUT] [--output OUTPUT] [--verbose] [--test] [--author]

Create the yml information file with common information for new rules

optional arguments:
  -h, --help            show this help message and exit
  --input INPUT, -i INPUT
                        Sigma rules directory (default ../sigma/rules)
  --output OUTPUT, -o OUTPUT
                        Output directory (default ./rules)
  --verbose, -v         Display missing keys
  --test, -t            Test only don't save
  --author, -a          Set the author name (default frack113)
```

Use `--test` to deal with remove or rename sigma rule in a first time.

Example :

- `python create_md.py -i c:\FrackSigma\sigma\rules -o .\rules -a "me or not me" `

- `python create_md.py -i ../sigma/rules -o /tmp`

### My todo

- [X] add a output for the missing key
- [X] add a repport of action (creation_md.log)
- [X] update the yml file if create_md.yml is updated
- [X] check if missing or rename sigma rule
- [ ] fix my bugs / issues

### Evolution

- [ ] update create_md.yml
- [ ] add a pretty local md output ?

### Thanks
ZikyHD
