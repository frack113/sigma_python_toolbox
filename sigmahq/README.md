# sigmahq

## check_logsource.py
Try to find errors in logsource
Find : 
 - not exist in the config yml
 - exist but another case in the config yml


### use

### My todo

### Evolution

### Thanks

## check_field.py
Try to find errors in fields use in SigmaHQ rule

### Prerequisites
local repro of :
- [sigmaHQ](https://github.com/SigmaHQ/sigma)
- [OSSEM-DB](https://github.com/OTRF/OSSEM-DD)

### use
run it (should run)
check:
- check_field.yml for new name find in rule
- rule_rapport for information by rule
- log_rule_rapport for information by logsource

Update or fix check_field.yml
fix sigma rule and make a PR 

### My todo
- add more data from OSSEM-DB
- remove the "any" in yaml

### Evolution
- be more cool to use

### Thanks
https://github.com/OTRF/OSSEM-DD

## rule_history.yml
Keep track of remove rule from SigmaHQ

### use

### My todo

### Evolution

### Thanks
