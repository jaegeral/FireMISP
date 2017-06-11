firemisp 0.9.1 (2017-06-11)
===========================
- code cleanup

firemisp 0.8.4 (2017-02-27)
===========================

- make it python3
- tested with all three example files
- introduced test cases


firemisp 0.8.4 (2016-10-13)
===========================

- introduced root_infection
- lot of correlations added
- more correlation
- fixed some C2 stuff
- introducing Whitelist config param, e.g. for your proxy ip or other ips you want to whitelist to be reported as destination ip

firemisp 0.8.3 (2016-10-12)
===========================

- first version to get real files from fireeye
- for debuggiung purposes writing the json files to a directory as a output
- catching some typo of Fireeye
- lots of improvements
- started with unit tests


firemisp 0.8.2 (2016-05-04)
===========================

- first version of C2 connection parsing and adding it to MISP is working
- config.example.cfg updated to the latest needs
- code cleanup

firemisp 0.8.2 (2016-05-04)
===========================

- add alert url as another criteria to not generate a new misp event but attach it to the previous
- add firemisp webserver params to the config

firemisp 0.8.1 (2016-05-03)
===========================

- introduced pyFireEyeAlert class
- adding attributes to events that already exist
- creating new events if not already in MISP
- auto comment for MISP attributes
- auto tags for Source --> veris:action:social:vector (MAIL / WEB)
- auto tags for severity --> veris:impact:overall_rating, csirt_case_classification:criticality-classification
- auto tags for severity --> Threat Rating within MISP

- objects being parsed:
-- ['alert']['id']
-- ['alert']['product']
-- ['appliance']
-- ['appliance-id']
-- ['alert']['src']['mac']
-- ['alert']['vlan']
-- ['alert']['dst']['smtpTo']
-- ['alert']['src']['smtpMailFrom']
-- ['alert']['smtpMessage']['subject']
-- ['alert']['severity']
-- ['alert']['src']['ip']
-- ['alert']['src']['host']
-- ['alert']['explanation']

firemisp 0.0.1 (2016-05-02)
===========================

init


