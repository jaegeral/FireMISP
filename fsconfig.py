# ---------------------------------------------
# --- firestic.py configuration

# Elasticsearch index to use - YYYY.MM.DD will be appended
esIndex = 'firestic'

# Geoip database for external (internet) addresses
extGeoipDatabase = 'geoip/GeoLiteCity.dat'

# Geoip database for internal (LAN) addresses (see README)
intGeoipDatabase = 'geoip/GeoLiteCity.dat'

# Geoip database for external address ASN info
ASNGeoipDatabase = 'geoip/GeoIPASNum.dat'

# ASN for internal addresses
localASN = 'your_org_name'

# IP for http server to listen on
httpServerIP = '127.0.0.1'

# Port for http server to listen on
httpServerPort = 8080

# File for logging errors
logFile = 'firestic_error.log'

# Send email/SMS alerts - see firestic_alert.py
sendAlerts = False

# ---------------------------------------------
# --- firestic_alert.py configuration

# email server FQDN or ip address
smtpServer = "your.relay.server.org"
smtpPort = 25

# From address
fromEmail = "FireMisp@basf.com"

# Email Recipients
# Comma delimited string of email addresses
toEmail = "cert@basf.com"

# Possible types: ips-event, malware-callback, malware-object, infection-match, domain-match, web-infection
emailTypeAlertOn = ['ips-event', 'malware-callback', 'malware-object', 'infection-match', 'domain-match', 'web-infection']

# SMS Recipients
# Comma delimted string. Format depends on carrier. You'll have to look it up.
toSMS = "aphonenumber@vtext.com"

# Possible types: ips-event, malware-callback, malware-object, infection-match, domain-match, web-infection
smsTypeAlertOn = ['malware-callback', 'malware-object', 'infection-match', 'domain-match', 'web-infection']

# Possible actions: blocked, notified, alert.
# Make this an empty array [] to not alert on anything.
smsActionAlertOn = ['notified', 'alert']

# Local timezone for conversion (@timestamp is UTC) - see pytz.all_timezones
# http://stackoverflow.com/questions/13866926/python-pytz-list-of-timezones
# Common US TZ: US/Central US/Eastern US/Mountain US/Pacific - see link above for more
myTimezone = 'US/Eastern'
