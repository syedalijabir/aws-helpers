#!/usr/bin/env python
# vim: set syntax=python:
#
# Owner: Ali Jabir
# Email: syedalijabir@gmail.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import boto3
import botocore
import json
import logging
from optparse import OptionParser
import os
import sys
import pdb
import platform
import pprint
import time

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.FileHandler("python.log")
handler.setLevel(logging.INFO)
logger.addHandler(handler)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

usage = """python """ + os.path.basename(__file__) + """ [params]
    --help               Display help menu"""

class col:
    HEADER = '\033[95m'
    if (platform.system() != "Linux"):
        BLUE = '\033[36m'
    else:
        BLUE = '\033[94m'
    GREEN = '\033[92m'
    INFO = '\033[93m'
    ERROR = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def params_check(parser=None):
    if not parser:
        parser = OptionParser(description='Base python script')

    parser.add_option("-p", "--profile", dest='profile', type="string",
                      default="", help='AWS Profile')
    parser.add_option("-q", "--quiet", action="store_false", dest="verbose", default=True,
                      help="Do not log on console.")
    (options, args) = parser.parse_args()
    if len(args) != 0:
        print (usage)
        sys.exit(2)
    return (options, args)

def read_options(options):
    global g_profile, g_search, globalHelp, globalVerbose

    if options:
        if options.profile == "":
            print(col.ERROR + "ERR: AWS Profile not defined" + col.END)
            print (usage)
            sys.exit(2)
        g_profile = options.profile
        globalVerbose = options.verbose

def get_file_handler(fileName):
    if isAccessible(fileName):
        try:
            fileHandler = open(fileName, 'r')
            return fileHandler
        except IOError as err:
            logger.error('I/O error({0}): {1}'.format(err.errno, err.strerror))
            sys.exit(1)
        except:
            logger.error("Unexpected error:", sys.exc_info()[0])
            sys.exit(1)

def get_all_from_profile():
    aws_session = boto3.Session(
        profile_name=g_profile)
    ssm = aws_session.client('ssm')
    try:
        resp = ssm.describe_parameters()
    except botocore.exceptions.ClientError as e:
        print('request failed: {}'.format(e.response['Error']['Message']))
        raise AwsError(e.response['Error']['Code'])
    except botocore.exceptions.EndpointConnectionError as e:
        logger.debug('DBG: {}'.format(e))
        logger.debug('DBG: {}'.format(dir(e)))
        print('request failed: {}'.format(e.response['Error']['Message']))

    params = resp["Parameters"]
    for item in params:
        print(col.INFO + item["Name"] + ":" + col.END)
        print("Description: {}".format(item["Description"]).ljust(30))
        print("Version:     {}".format(item["Version"]).ljust(30))
        value = ssm.get_parameter(Name=item["Name"], WithDecryption=False)
        print("Value:       {}".format(value['Parameter']['Value']).ljust(30))
        print("")

def main():
    get_all_from_profile()

(options, args) = params_check()
read_options(options)

if globalVerbose == True:
    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(formatter)
    logger.addHandler(consoleHandler)

if __name__ == '__main__':
    sys.exit(main())

