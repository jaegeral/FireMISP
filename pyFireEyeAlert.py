#!/usr/bin/env python

# pyFireEyeAlert - Python class for parsing FireEye json alerts
#
# Alexander Jaeger (deralexxx)
#
# The MIT License (MIT) see https://github.com/deralexxx/FireMISP/blob/master/LICENSE
#
# Based on the idea of:
#

import re

from datetime import datetime
import simplejson as json
import logging


#init logger
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')



class pyFireEyeAlert (object):
    def __init__(self, a_alert_json):
        """

        :param a_alert_json:
        :type a_alert_json:
        :rtype: object
        """
        self.alert = a_alert_json
        self.alert_id = None
        self.alert_ma_id = None
        self.product = None
        self.alert_url = None
        self.victim_email = None
        self.attacker_email = None
        self.mail_subject = None
        self.alert_src_ip = None
        self.alert_src_host = None
        self.alert_severity = None
        self.malware_http_header = None
        self.src_mac = None
        self.product_version = None
        self.src_vlan = None
        self.product_appliance = None
        self.product_appliance_id = None
        self.malware_md5 = None
        self.malware_av_name = None
        self.malware_type= None
        self.malware_file_type = None
        self.malware_http_post = None
        self.malware_file_name = None
        self.occured = None

        #TODO:
        self.c2_protocoll = None
        self.c2_port = None
        self.c2_channel = None
        self.c2 = None
        self.c2services = None
        self.c2_address = None

        # important: parse after initiate, otherwise values will be overwritten
        self._parse_json(a_alert_json)

    #'tcp','1234','1.2.3.4'):
    def add_cnc_service(self,protocoll,port,ip):
        self.c2services = True
        self.c2_address = "1.2.3.4"
        self.c2_port = "1234"
        self.c2_protocoll = "tcp"
        logger.debug("add cnc service called %s %s %s",protocoll,port,ip)



    def _parse_json(self, p_alert_json):
        # Print out the Json given to the method
        #logger.debug(json.dumps(theJson, sort_keys=True, indent=2, separators=(',', ': ')))

        """

        :param p_alert_json:
        :type p_alert_json:
        """
        if not p_alert_json:
            raise ValueError('No Json given')


        #parsing magic will happen here

        if 'id' in p_alert_json['alert']:
            self.alert_id = str(p_alert_json['alert']['id'])

        if 'alert-url' in p_alert_json['alert']:
            self.alert_url = str(p_alert_json['alert']['alert-url'])
            # and split it to get the ma_id "alert-url": "https://fireeye.foo.bar/event_stream/events_for_bot?ma_id=12345678",
            self.alert_ma_id = (self.alert_url.split("="))[1]

        # TYPE of APPLIANCE

        if 'product' in p_alert_json['alert']:
            self.product = p_alert_json['alert']['product']
            logger.debug(self.product)

        elif 'product' in p_alert_json:
            self.product = p_alert_json['product']

        if 'version' in p_alert_json:
            self.product_version = p_alert_json['version']

        if 'appliance' in p_alert_json:
            self.product_appliance = p_alert_json['appliance']

        if 'appliance-id' in p_alert_json:
            self.product_appliance_id = p_alert_json['appliance-id']

        if 'mac' in p_alert_json['alert']:
            self.src_mac = p_alert_json['alert']['src']['mac']
            logger.debug("mac %s",self.src_mac)

        if 'vlan' in p_alert_json['alert']:
            self.src_vlan = p_alert_json['alert']['vlan']

        if 'dst' in p_alert_json['alert']:
        # to
            if 'smtpTo' in p_alert_json['alert']['dst']:
                self.victim_email = p_alert_json['alert']['dst']['smtpTo']

        # from
        if 'smtpMailFrom' in p_alert_json['alert']['src']:
            attacker_email_temp = p_alert_json['alert']['src']['smtpMailFrom']

            #HACK if Source is: "John Doe" <joen@doe.com> --> john@doe.com
            match = re.search(r'[\w\.-]+@[\w\.-]+', attacker_email_temp)
            self.attacker_email =  match.group(0)

        # subject
        if 'smtpMessage' in p_alert_json['alert']:
            self.mail_subject = p_alert_json['alert']['smtpMessage']['subject']
            #misp.add_email_subject(event, subject)

        #severity (majr minr, ...)
        if 'severity' in p_alert_json['alert']:
            self.alert_severity = p_alert_json['alert']['severity']

        # alert - src
        if 'ip' in p_alert_json['alert']['src']:
            self.alert_src_ip = p_alert_json['alert']['src']['ip']

        if 'host' in p_alert_json['alert']['src']:
            self.alert_src_host = p_alert_json['alert']['src']['host']


        # occured
        # ---------- add @timestamp ----------
        # use alert.occurred for timestamp. It is different for IPS vs other alerts
        # ips-event alert.occurred format: 2014-12-11T03:28:08Z
        # all other alert.occurred format: 2014-12-11 03:28:33+00
        if p_alert_json['alert']['name'] == 'ips-event':
            timeFormat = '%Y-%m-%dT%H:%M:%SZ'
        else:
            timeFormat = '%Y-%m-%d %H:%M:%S+00'

        oc = datetime.strptime(p_alert_json['alert']['occurred'], timeFormat)
        self.occured = oc.isoformat()
        logger.debug("date: %s",oc.isoformat())
        # Put the formatted time into @timestamp
        # theJson['@timestamp'] = oc.strftime('%Y-%m-%dT%H:%M:%S.%fZ')




        #TODO: multiple malware
        if 'explanation' in p_alert_json['alert']:
            self.parse_explanation(p_alert_json['alert']['explanation'])


        '''
        ...
        "cnc-services": {
          "cnc-service": [
            {
              "protocol": "tcp",
              "port": "4143",
              "channel": "\\\\026\\\\003\\\\001",
              "address": "1.2.3.4"
            },
            {
              "protocol": "tcp",
              "port": "9943",
              "channel": "\\\\026\\\\003\\\\001",
              "address": "8.8.8.8"
            },
            {
              "protocol": "tcp",
              "port": "4493",
              "channel": "\\\\026\\\\003\\\\001",
              "address": "1.1.1.1"
            }
          ]
        '''
        if self.parse_explanation:
            if 'cnc-services' in p_alert_json['alert']['explanation']:
                self.add_cnc_service('tcp', '1234', '1.2.3.4')

                for element in p_alert_json['alert']['explanation']['cnc-services']['cnc-service']:
                    logger.debug("c2 detected")
                    self.add_cnc_service('tcp','1234','1.2.3.4')
                    #self.c2_channel = str(element['md5Sum'])
                    #self.malware_av_name = str(element['name'])


        logger.debug("Parsing finished")


    def parse_explanation(self, theJson_explanation):
        #logger.debug("only expl: %s",json.dumps(theJson_explanation))


        if 'malwareDetected' in theJson_explanation:
            # iterate
            for element in theJson_explanation['malwareDetected']['malware']:
                self.malware_md5 = str(element['md5Sum'])
                self.malware_av_name = str(element['name'])
        ## different writing of FireEye
        elif 'malware-detected' in theJson_explanation:
            if 'md5sum' in theJson_explanation['malware-detected']['malware']:
                self.malware_md5 = theJson_explanation['malware-detected']['malware']['md5sum']
            if 'name' in theJson_explanation['malware-detected']['malware']:
                self.malware_av_name = theJson_explanation['malware-detected']['malware']['name']
            if 'original' in theJson_explanation['malware-detected']['malware']:
                self.malware_file_name = theJson_explanation['malware-detected']['malware']['original']

            if 'http-header' in theJson_explanation['malware-detected']['malware']:
                self.malware_http_header = theJson_explanation['malware-detected']['malware']['http-header']
