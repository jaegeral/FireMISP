import configparser
import logging

HAVE_PYMISP = True
try:
    from pymisp import PyMISP
except:
    HAVE_PYMISP = False

from pyFireEyeAlert import pyFireEyeAlert

config = configparser.RawConfigParser()
config.read('config.cfg')

# set config values
misp_url = config.get('MISP', 'misp_url')
misp_key = config.get('MISP', 'misp_key')
misp_verifycert = config.getboolean('MISP', 'misp_verifycert')

firemisp_ip = config.get('FireMisp', 'httpServerIP')
firemisp_port = config.getint('FireMisp', 'httpServerPort')
firemisp_logfile = config.get('FireMisp', 'logFile')


#init logger
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

urllib3_logger = logging.getLogger('urllib3')
urllib3_logger.setLevel(logging.CRITICAL)

whitelist = config.get('FireMisp', 'whitelist').split(',')
