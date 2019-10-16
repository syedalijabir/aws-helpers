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

import argparse
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

log_file = base_path + "/aws-helpers/es/python.log"

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.FileHandler(log_file)
handler.setLevel(logging.INFO)
logger.addHandler(handler)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

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

class BadNoneValue(Exception):
    """Raise an error if an argument is None"""
    def __init__(self, argument):
        self.argument = argument

    def __str__(self):
        return 'argument {}: can not be None'.format(self.argument)

def argument_parser():
    parser = argparse.ArgumentParser(
        description='Find RDS domains in an AWS profile')
    parser.add_argument(
        '-p', '--profile',
        help='AWS Profile')
    parser.add_argument(
        '-s', '--search',
        help='Search string for name')
    parser.add_argument(
        '-q', '--quiet',
        action="store_true",
        help='Do not log on console')
    return parser

def validate_parameters(namespace, parser):
    if namespace.profile is None:
        parser.print_usage()
        raise BadNoneValue('-p/--profile')
    return

def parse_parameters(arguments):
    parser = argument_parser()
    namespace = parser.parse_args(arguments)
    validate_parameters(namespace, parser)

    return vars(namespace)

def get_file_handler(fileName):
    if isAccessible(fileName):
        try:
            fileHandler = open(fileName, 'r')
            return fileHandler
        except IOError as err:
            logger.error('I/O error({0}): {1}'.format(err.errno, err.strerror))
            exit(1)
        except:
            logger.error("Unexpected error:", sys.exc_info()[0])
            exit(1)

def main(cli_arguments):

    # Parse parameters
    parameters = parse_parameters(cli_arguments)

    if parameters["quiet"] is False:
        consoleHandler = logging.StreamHandler()
        consoleHandler.setFormatter(formatter)
        logger.addHandler(consoleHandler)

    retries = 5
    aws_session = boto3.Session(
        profile_name = parameters["profile"])
    es = aws_session.client('es')
    while retries > 0:
        try:
            resp = es.list_domain_names()
            break
        except botocore.exceptions.ClientError as e:
            print('request failed: {}'.format(e))
            retries -= 1
            if retries == 0:
                print(col.ERROR + "Max. retries reached, try again." + col.END)
                exit(1)
            print("Retries left: {}".format(retries))
            time.sleep(2)
    if not resp["DomainNames"]:
        logger.error("No Elastic Search domains found in profile {}".format(parameters["profile"]))
        exit()

    logger.info("Number of Elastic search domains found: {}".format(len(resp["DomainNames"])))
    
    domains = []
    found_names = []
    for domain_name in resp["DomainNames"]:
        domain = {}
        try:
            domain_details = es.describe_elasticsearch_domain(
                DomainName = domain_name["DomainName"]
            )
        except botocore.exceptions.ClientError as e:
            print('describe_elasticsearch_domain request failed for {}: {}'.format(domain_name["DomainName"], e))
        found_names.append(domain_details["DomainStatus"]["DomainName"])
        domain["DomainId"] = domain_details["DomainStatus"]["DomainId"]
        domain["Endpoint"] = domain_details["DomainStatus"]["Endpoints"]["vpc"]
        domain["ElasticsearchVersion"] = domain_details["DomainStatus"]["ElasticsearchVersion"]
        domain["InstanceType"] = domain_details["DomainStatus"]["ElasticsearchClusterConfig"]["InstanceType"]
        domains.append(domain)

    print(col.INFO + "All available domains" + col.END)
    print(json.dumps(found_names, indent=4, sort_keys=True, default=str))

    for domain_name in domains:
        print(col.GREEN + "{}".format(domain_name["DomainId"]) + col.END)
        print(json.dumps(domain_name, indent=4, sort_keys=True, default=str))

if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        LOG.error('\nInterrupted by keyboard')
    except BadNoneValue as e:
        LOG.error("{}: error: {}".format(sys.argv[0], e))
