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

dir_path = os.path.dirname(os.path.realpath(__file__))
base_path = os.path.split(os.path.split(dir_path)[0])[0]

log_file = base_path + "/aws-helpers/ec2/python.log"

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.FileHandler(log_file)
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
    parser.add_option("-s", "--search", dest='search', type="string",
                      default="", help='Search string for name')
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
        g_search = options.search
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

def main():
    #logger.info("Starting main function")
    retries = 5
    aws_session = boto3.Session(
        profile_name=g_profile)
    ec2 = aws_session.client('ec2')
    while retries >= 0:
        try:
            resp = ec2.describe_instances()
            break
        except botocore.exceptions.ClientError as e:
            print('request failed: {}'.format(e))
            retries -= 1
            if retries == 0:
                print(col.ERROR + "Max. retries reached, try again." + col.END)
                sys.exit(1)
            print("Retries left: {}".format(retries))
            time.sleep(2)
    profile_insts = {}
    if resp["Reservations"]:
        for group in resp["Reservations"]:
            if group["Instances"]:
                inst = group["Instances"]
                if inst[0]["State"]["Name"] != "terminated":
                    if "Tags" in inst[0]:
                        for item in inst[0]["Tags"]:
                            if item["Key"] == "Name":
                                name = item["Value"]
                                break
                        if name in profile_insts:
                            profile_insts[name] = "{}, {}    ({})".format(profile_insts[name], inst[0]["PrivateIpAddress"], inst[0]["InstanceId"])
                        else:
                            profile_insts.update({ name : "{}    ({})".format(inst[0]["PrivateIpAddress"], inst[0]["InstanceId"]) })
    print(col.INFO + "All available instances" + col.END)
    print(json.dumps(profile_insts, sort_keys=True, indent=4))

    if g_search != "":
        for key, value in profile_insts.items():
            if key.find(g_search) >= 0:
                print(col.GREEN + "{}".format(key).ljust(30) + col.END +  " {}".format(value.split(",")))

(options, args) = params_check()
read_options(options)

if globalVerbose == True:
    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(formatter)
    logger.addHandler(consoleHandler)

if __name__ == '__main__':
    sys.exit(main())

