# FireStic - Python script for indexing FireEye json alerts
# into Elasticsearch over http...and some alerting too
#
# Please see: https://github.com/spcampbell/firestic
#
from datetime import datetime
#from elasticsearch import Elasticsearch
from BaseHTTPServer import HTTPServer
from BaseHTTPServer import BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import threading
import json
import logging
import socket
import firestic_alert
import fsconfig
import socket
import ConfigParser


config = ConfigParser.RawConfigParser()
config.read('config.cfg')

#init logger
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')



class MyRequestHandler(BaseHTTPRequestHandler):

    # ---------- GET handler to check if httpserver up ----------
    def do_GET(self):
        pingresponse = {"name": "Firestic is up"}
        if self.path == "/ping":
            self.send_response(200)
            self.send_header("Content-type:", "text/html")
            self.wfile.write("\n")
            json.dump(pingresponse, self.wfile)

    # -------------- POST handler: where the magic happens --------------
    def do_POST(self):
        # get the posted data and remove newlines
        data = self.rfile.read(int(self.headers.getheader('Content-Length')))
        clean = data.replace('\n', '')
        theJson = json.loads(clean)

        self.send_response(200)
        self.end_headers()

        # deal with multiple alerts embedded as an array
        if isinstance(theJson['alert'], list):
#            alertJson = theJson
#            del alertJson['alert']
            for element in theJson['alert']:
                alertJson = {}  # added for Issue #4
                alertJson['alert'] = element
                logger.info("Processing FireEye Alert: " + str(alertJson['alert']['id']))
                processAlert(alertJson)
        else:
            print "Processing FireEye Alert: " + str(theJson['alert']['id'])
            processAlert(theJson)

# ---------------- end class MyRequestHandler ----------------


# ---------------- Class handles requests in a separate thread. ----------------

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
	pass

# ---------------- end class ThreadedHTTPServer ----------------

def processAlert(theJson):
    # ---------- add geoip information ----------
    alertInfo = {}
    alertInfo['srcIp'] = theJson['alert'].setdefault('src', {}).setdefault(u'ip', u'0.0.0.0')
    alertInfo['dstIp'] = theJson['alert'].setdefault('dst', {}).setdefault(u'ip', u'0.0.0.0')

    alertInfo['type'] = theJson['alert']['name']
    if alertInfo['type'] == 'ips-event':
        alertInfo['mode'] = theJson['alert']['explanation']['ips-detected']['attack-mode']

    logger.debug(alertInfo)

    geoInfo = queryGeoip(alertInfo)

    theJson['alert']['src']['geoip'] = geoInfo['src']
    theJson['alert']['dst']['geoip'] = geoInfo['dst']

    # ---------- add @timestamp ----------
    # use alert.occurred for timestamp. It is different for IPS vs other alerts
    # ips-event alert.occurred format: 2014-12-11T03:28:08Z
    # all other alert.occurred format: 2014-12-11 03:28:33+00
    if theJson['alert']['name'] == 'ips-event':
        timeFormat = '%Y-%m-%dT%H:%M:%SZ'
    else:
        timeFormat = '%Y-%m-%d %H:%M:%S+00'

    oc = datetime.strptime(theJson['alert']['occurred'], timeFormat)
    # Append YYYY.MM.DD to indexname like Logstash
    esIndexStamped = fsconfig.esIndex + oc.strftime('-%Y.%m.%d')
    # Put the formatted time into @timestamp
    theJson['@timestamp'] = oc.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    # ---------- Remove alert.explanation.os-changes ----------
    # TODO: figure out a way to incorporate this info.
    # Doing this is complicated. Will require creative
    # Elasticsearch mapping (template?). Need to gather more json examples.
    # UPDATE -- For now, we will extract a few key bits of information from
    #           os-changes: Operating system(s) targeted, application(s) targeted,
    #           malicious activity found and listed in 'malicious-alert'.
    if 'os-changes' in theJson['alert']['explanation']:
        # Go extract some useful data to include in alert
        theJson['alert']['explanation']['summaryinfo'] = getSummaryInfo(theJson['alert']['explanation']['os-changes'])
        # DEV: save the os-changes field to file for later review
        with open('oschanges.json', 'a') as outfile:
            fileData = 'TIMESTAMP: ' + theJson['@timestamp'] + ' - '
            fileData += theJson['alert']['name'] + ' - '
            fileData += theJson['alert']['id'] + '\n'
            fileData += json.dumps(theJson['alert']['explanation']['os-changes'])
            fileData += '\n--------------------\n\n'
            outfile.write(fileData)
        del theJson['alert']['explanation']['os-changes']
        print "[os-changes] deleted"

    # ---------- Index data into Elasticsearch ----------
    try:
        #TODO: here is the real upload of the stuff
        logger.debug(json.dumps(theJson, sort_keys=True,indent=4, separators=(',', ': ')))
        '''
        es.index(index=esIndexStamped,
                 doc_type=theJson['alert']['name'], body=theJson)
                 '''
    except:
        logText = "\n-----------\nES POST ERROR\n-----------\nJSON: "
        logText += json.dumps(theJson) + "\n"
        # logText += "TIME: " + datetime.utcnow() + "\n"
        logging.exception(logText)



    # ---------- send email alerts ----------
    if fsconfig.sendAlerts is True:
        try:
            firestic_alert.sendAlert(theJson, fsconfig)
        except:
            logText = "\n-----------\nEMAIL ERROR\n-----------\nJSON: "
            logText += json.dumps(theJson) + "\n"
            # logText += "TIME: " + datetime.utcnow() + "\n"
            logging.exception(logText)


def queryGeoip(alertInfo):
    geoipInfo = {}

    if (alertInfo['type'] == 'ips-event') and (alertInfo['mode'] == 'server'):
        # ips-event mode is server so src = external, dest = internal
        geoipInfo['dst'] = getGeoipRecord(alertInfo['dstIp'], fsconfig.intGeoipDatabase, 'city')
        if geoipInfo['dst'] is not None:
            geoipInfo['dst']['asn'] = fsconfig.localASN
            geoipInfo['dst']['hostname'] = getHostname(alertInfo['dstIp'])
        geoipInfo['src'] = getGeoipRecord(alertInfo['srcIp'], fsconfig.extGeoipDatabase, 'city')
        if geoipInfo['src'] is not None:
            geoipInfo['src']['asn'] = getGeoipRecord(alertInfo['srcIp'], fsconfig.ASNGeoipDatabase, 'asn')
            geoipInfo['src']['hostname'] = getHostname(alertInfo['srcIp'])
    else:
        # treat all others as src = internal, dest = external
        geoipInfo['dst'] = getGeoipRecord(alertInfo['dstIp'], fsconfig.extGeoipDatabase, 'city')
        if geoipInfo['dst'] is not None:
            geoipInfo['dst']['asn'] = getGeoipRecord(alertInfo['dstIp'], fsconfig.ASNGeoipDatabase, 'asn')
            geoipInfo['dst']['hostname'] = getHostname(alertInfo['dstIp'])
        geoipInfo['src'] = getGeoipRecord(alertInfo['srcIp'], fsconfig.intGeoipDatabase, 'city')
        if geoipInfo['src'] is not None:
            geoipInfo['src']['asn'] = fsconfig.localASN
            geoipInfo['src']['hostname'] = getHostname(alertInfo['srcIp'])

    # add long,lat coordinate field...Kibana needs a field [long,lat] for "bettermap"
    if geoipInfo['dst'] is not None:
        geoipInfo['dst']['coordinates'] = [geoipInfo['dst']['longitude'], geoipInfo['dst']['latitude']]
    if geoipInfo['src'] is not None:
        geoipInfo['src']['coordinates'] = [geoipInfo['src']['longitude'], geoipInfo['src']['latitude']]

    return geoipInfo

def getSummaryInfo(oschanges):
    summaryInfo = []
    if isinstance(oschanges,list):
        for instance in oschanges:
            thisInfo = {}
            thisInfo['osinfo'] = instance['osinfo']
            thisInfo['app-name'] = instance['application']['app-name']
            thisInfo['malicious-alert'] = []
            if ('malicious-alert' in instance):
                for eachma in instance['malicious-alert']:
                    thisInfo['malicious-alert'].append(eachma)
            summaryInfo.append(thisInfo)
    else:
        thisInfo = {}
        thisInfo['osinfo'] = oschanges['osinfo']
        thisInfo['app-name'] = oschanges['application']['app-name']
        thisInfo['malicious-alert'] = []
        if ('malicious-alert' in oschanges):
            for eachma in oschanges['malicious-alert']:
                thisInfo['malicious-alert'].append(eachma)
        summaryInfo.append(thisInfo)

    return summaryInfo

def getHostname(ipaddress):
    try:
        lu = socket.gethostbyaddr(ipaddress)
        return lu[0]
    except:
        return None


def getGeoipRecord(ipAddress, database, queryType):  # queryType = asn or city
    #TODO: check if that can be removed
    '''
    gi = pygeoip.GeoIP(database)
    if queryType == 'city':
        return gi.record_by_addr(ipAddress)
    elif queryType == 'asn':
        return gi.org_by_addr(ipAddress)
    else:

        return None
          '''
    return None


def main():
    server = ThreadedHTTPServer((fsconfig.httpServerIP, fsconfig.httpServerPort), \
									MyRequestHandler)

    logger.info("Starting HTTP server %s %s",fsconfig.httpServerIP,fsconfig.httpServerPort)
    print "\nStarting HTTP server %s %s...\n" % (fsconfig.httpServerIP,fsconfig.httpServerPort)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("HTTP Server stopped")
        print "\n\nHTTP server stopped.\n"


if __name__ == "__main__":
    #es = Elasticsearch()
    logging.basicConfig(level=logging.WARNING,
                        filename=fsconfig.logFile,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    main()
