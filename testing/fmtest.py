'''
Script to send FireEye alerts saved as json files to FireStic for testing.

Option to send a single file or to read a directory and send all .json files.
'''

import requests
import json
import sys
import getopt
import glob
import time

from pymisp import PyMISP


# parameters
# -f --file = a specific json file to send
# -d --dir = all the json files in a directory
# -t --timeout = delay in seconds between sends. Default 1 second
# -u --url = url/ip address of MISP server
# -p --port = port server is listening on

def processFile(inputfile,serverurl):
    headers = {'content-type': 'application/json'}
    try:
        with open(inputfile) as json_file:
            file_data = json_file.read()
            try:
                r = requests.post(serverurl, data=file_data, headers=headers, timeout=5)
            except Exception, e:
                print " "
                print "COMMUNICATION ERROR : " + str(e)
                print " "
                sys.exit(2)
    except Exception, e:
        print " "
        print "FILE ERROR : " + str(e)
        print " "

    print inputfile + " sent to " + serverurl + ". Status code: " + str(r.status_code) + "."

    return

def printopts():
    print '''
    USAGE:
    -f --file       a specific json file to send
    -d --dir        directory of json files to send. Use ./ for current directory
        ** must include either -f or -d but not both **
    -t --timeout    (optional) seconds delay between multiple sends. Default = 1
    -u --url        url/ip address to send to
    -p --port       port server is listening on

    EXAMPLES:
    fstest.py -f ./testalert.json -u localhost -p 8080
    fstest.py -d ./alerts -t 2 -u 192.168.1.2 -p 8080
    fstest.py -d ./ -u localhost -p 8888
    '''

def main(argv):
    inputfile = ''
    inputdir = ''
    timeout = 1
    url = ''
    port = ''
    mode = ''

    try:
        opts, args = getopt.getopt(argv,"hf:d:t:u:p:",["help=","file=","dir=","timeout=","url=","port="])
    except getopt.GetoptError:
        printopts()
        sys.exit(2)

    if not len(opts):
        print 'No options specified:'
        printopts()
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h","--help"):
            printopts()
            sys.exit()
        elif opt in ("-f", "--file"):
            inputfile = arg
            mode = 'file'
        elif opt in ("-d", "--dir"):
            inputdir = arg
            mode = 'directory'
        elif opt in ("-t", "--timeout"):
            timeout = arg
        elif opt in ("-u", "--url"):
            url = arg
        elif opt in ("-p", "--port"):
            port = arg

    # if no url or port --> error
    if (url == '') or (port == ''):
        print "ERROR: url and port are required"
        printopts()
        sys.exit(2)

    serverurl = 'http://' + url + ':' + port

    # go try to read file and send
    if (mode == 'file'):
        processFile(inputfile,serverurl)
    elif (mode == 'directory'):
        filelist = glob.glob(inputdir + '*.json')
        if len(filelist):
            for afile in filelist:
                processFile(afile,serverurl)
                time.sleep(float(timeout))
        else:
            print "No files of type .json found in directory: " + inputdir
    else:
        print "unknown mode"

if __name__ == "__main__":
   main(sys.argv[1:])