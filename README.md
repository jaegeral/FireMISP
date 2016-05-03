python script for interacting with misp

Inspired by: https://github.com/spcampbell/FireStic

Installation
============

update the values to your needs

modify the API Key:
```
cp key.py.sample key.py
vi key.py
#change the values
```

API key can be requested at Sebastian / Alexander

Running
=======

run the script:

Testing
=======

To test with real data put your *.json files in testing/real (they will be ignored by git)

```
    python testing/fmtest.py -d testing/real
```

To test with sample data:#

```
    python testing/fmtest.py -f testing/alert_details_fireeye_reducted.json
```

Example:
========
