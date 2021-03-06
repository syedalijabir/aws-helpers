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
from botocore.exceptions import ClientError
import json
import logging
from optparse import OptionParser
import os
import sys
import pdb
import platform
import pprint
import time
import yaml

dir_path = os.path.dirname(os.path.realpath(__file__))
base_path = os.path.split(os.path.split(dir_path)[0])[0]

log_file = base_path + "/aws-helpers/ssm/python.log"

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
    parser.add_option("-f", "--file", dest="yaml_file", type="string",
                      default="", help="Path to yaml file with SSM parameter config")
    parser.add_option("-n", "--name", dest="name", type="string",
                      default="", help="Name of SSM parameter")
    parser.add_option("-c", "--create", action="store_true", dest="create", default=False,
                      help="Create an SSM parameter")
    parser.add_option("-d", "--delete", action="store_true", dest="delete", default=False,
                      help="Delete an SSM parameter")
    parser.add_option("-q", "--quiet", action="store_false", dest="verbose", default=True,
                      help="Do not log on console.")
    (options, args) = parser.parse_args()
    if len(args) != 0:
        print (usage)
        sys.exit(2)
    return (options, args)

def read_options(options):
    global g_profile, g_create, g_delete, g_file, g_name, globalVerbose

    if options:
        # Troubleshooting for profile param
        if options.profile == "":
            print(col.ERROR + "ERR: AWS Profile not defined" + col.END)
            print (usage)
            sys.exit(2)

        # Troubleshooting for create & file param
        if options.create != None and options.create == True:
            if options.yaml_file is None or options.yaml_file == "":
                print(col.ERROR + "ERR: Must specify a file for CREATE feature" + col.END)
                print (usage)
                sys.exit(2)
            if not isAccessible(options.yaml_file):
                print(col.ERROR + "ERR: File [{}] is not accessible".format(options.yaml_file) + col.END)
                sys.exit(2)
        elif options.create == None and options.yaml_file != "":
            print(col.ERROR + "ERR: -f/--file parameter also requires an explicit -c/--create flag" + col.END)
            sys.exit(2)

        if options.delete != None and options.delete == True:
            if options.name is None or options.name == "":
                print(col.ERROR + "ERR: Parameter Name must be set for DELETE feature" + col.END)
                print (usage)
                sys.exit(2)

        g_profile = options.profile
        g_create  = options.create
        g_file    = options.yaml_file
        g_delete  = options.delete
        g_name    = options.name
        globalVerbose = options.verbose

def isAccessible(path, mode="r"):
    """
    Check if the file/directory at 'path' is accessible
    """
    try:
        file = open(path, mode)
        file.close()
    except OSError as e:
        logger.error(e)
        return False
    except IOError as e:
        logger.error(e)
        return False
    return True

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

def get_all_from_profile(ssm):
    try:
        resp = ssm.describe_parameters()
    except ClientError as e:
        logger.error(e)
        sys.exit(1)

    params = resp["Parameters"]
    for item in params:
        print(col.INFO + item["Name"] + ":" + col.END)
        print("Description: {}".format(item["Description"]).ljust(30))
        print("Version:     {}".format(item["Version"]).ljust(30))
        value = ssm.get_parameter(Name=item["Name"], WithDecryption=False)
        print("Value:       {}".format(value['Parameter']['Value']).ljust(30))
        print("")

def create_parameter(ssm):
    param_yaml = yaml.load(open(g_file), Loader=yaml.FullLoader)

    # Check if YAML format is correct
    if not "Name" in param_yaml:
        logger.error("YAML file must contain parameter [Name]")
    if not "Description" in param_yaml:
        logger.error("YAML file must contain parameter [Description]")
    if not "Type" in param_yaml:
        logger.error("YAML file must contain parameter [Type]")
    if not "Overwrite" in param_yaml:
        logger.error("YAML file must contain parameter [Overwrite]")
#    if not "Tags" in param_yaml:
#        logger.error("YAML file must contain parameter [Tags]")

    try:
        response = ssm.put_parameter(
        Name=param_yaml["Name"],
        Description=param_yaml["Description"],
        Value=param_yaml["Value"],
        Type=param_yaml["Type"],
        Overwrite=param_yaml["Overwrite"])
#        Tags=param_yaml["Tags"])
    except ClientError as e:
        logger.error(e)
        sys.exit(1)
    logger.info("SSM parameter [ {} ] created/updated in profile {}".format(param_yaml["Name"], g_profile))

def delete_parameter(ssm):
    # check if parameter exists
    delete_flag = False
    try:
        resp = ssm.describe_parameters()
    except ClientError as e:
        logger.error(e)
        sys.exit(1)

    params = resp["Parameters"]
    for item in params:
        if item["Name"] == g_name:
            delete_flag = True

    # delete parameter
    if delete_flag:
        try:
            response = ssm.delete_parameter(
            Name=g_name)
        except ClientError as e:
            logger.error(e)
            sys.exit(1)
        logger.info("Deleted parameter [ {} ] in profile {}".format(g_name, g_profile))
    else:
        logger.info("Parameter [ {} ] not found in profile {}".format(g_name, g_profile))

def main():
    aws_session = boto3.Session(
        profile_name=g_profile)
    ssm = aws_session.client('ssm')

    if g_create == True:
        create_parameter(ssm)
    elif g_delete == True:
        delete_parameter(ssm)
    else:
        get_all_from_profile(ssm)

(options, args) = params_check()
read_options(options)

if globalVerbose == True:
    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(formatter)
    logger.addHandler(consoleHandler)

if __name__ == '__main__':
    sys.exit(main())

