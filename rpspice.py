#!/usr/bin/python3
# -*- coding: utf-8 -*-
# now  with GPG-signed commits
"""rpspice - a Proxmox PVE SPICE wrapper for Remmina

Uses SSH tunneling to connect to SPICE-enabled VMs, which are
running inside Proxmox PVE.
Requirements: remmina, remmina-plugin-spice, python3,
              python3-crypto, subprocess, tempfile

Credits:
--------
Initial shell script:
https://forum.proxmox.com/threads/remote-spice-access-without-using-web-manager.16561/page-3#post-238210
Remmina password encryption:
https://github.com/kvaps/keepass-url-overrides/blob/master/remmina/remmina-encode-password.py

"""

import os
from os.path import expanduser
import getpass
import re
import time
import base64
import subprocess
import tempfile
from argparse import ArgumentParser
import requests
from Crypto.Cipher import DES3

# CONSTANTS
DEBUG = True

# TODO: Explain this
# /sbin/iptables -F
# /sbin/iptables -t nat -F
# /sbin/iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8006
PVE_PORT = ''

def main():

    # Get the arguments object
    arguments = parse_arguments()

    # https://<arguments.fqdn>:[8006]/api2/json/
    pve_api_url = 'https://' + arguments.fqdn + ':' + PVE_PORT + '/api2/json/'

    # TODO: Add node name generation code
    # TODO: this needs to be calculated dynamically!

    pve_node_fqdn = arguments.fqdn
    pve_node_name = arguments.fqdn.split('.')[0]


    # TODO: Separate in a function
    # 2) Cluster resources URL
    pve_cluster_status_url = pve_api_url + 'cluster/resources'

    # 3) API link for SPICE config
    # Needs refactoring
    pve_spice_url = pve_api_url + 'nodes/' + pve_node_name + '/qemu/' +\
                    arguments.vmid + '/spiceproxy'

    # Get credential parameters
    (pve_cookie, pve_header) = get_pve_cookies(api_url=pve_api_url,
                                               username=arguments.username,
                                               password=arguments.password)

    pve_resource = requests.get(pve_cluster_status_url,
                                headers=pve_header,
                                cookies=pve_cookie)

    pve_spice = requests.post(pve_spice_url,
                              headers=pve_header,
                              cookies=pve_cookie)

    #DEBUG
    if DEBUG:
        print(pve_resource.status_code)
        print(pve_resource.text)
        print('Collecting VM info')

    remmina_password = encrypt_remmina(pve_spice.json()['data']['password'])
    remmina_port = pve_spice.json()['data']['tls-port']

    # Generating Remmina CA file
    remmina_ca_file = open(expanduser("~") + '/ca.crt', 'w')
    # TODO: Refactor to function here
    generate_ca_file()
    remmina_ca_file.write(pve_spice.json()['data']['ca'].replace('\\n', '\n'))
    # TODO: Safely remove CA file
    remmina_ca_file.close()

    # Generating connection file
    remmina_connection_file = open(tempfile.NamedTemporaryFile(dir=expanduser("~"),
                                                               suffix='.remmina').name, 'w')
    # TODO: This looks like a mess, needs tyding up
    remmina_connection_parameters = '''[remmina]
    sharesmartcard=0
    postcommand=
    enableaudio=0
    resizeguest=0
    group=
    name=spice@VM
    ssh_username=root
    ssh_auth=3
    ssh_server = ''' + str(pve_node_fqdn) + '''
    ssh_enabled=1
    ssh_loopback=1
    ssh_charset=UTF-8
    usetls=1
    cacert= ''' + str(remmina_ca_file.name) + '''
    precommand=
    viewonly=0
    protocol=SPICE
    sharefolder=
    disablepasswordstoring=0
    server=localhost:'''+ str(remmina_port) + '''
    disableclipboard=0
    window_maximize=0
    viewmode=1
    window_height = 925
    window_width = 1563
    ''' + 'password = ' + remmina_password + '''
    '''
    remmina_connection_file.write(remmina_connection_parameters)
    remmina_connection_file.close()


    devnull = open(os.devnull, 'w')
    subprocess.run(["remmina", '--name', 'remmina_spiced', '-c', remmina_connection_file.name],
                   stdout=devnull, stderr=devnull)


    # DEBUG: Sometime file could not be deleted immeadiately
    time.sleep(5)
    devnull.close()
    os.remove(remmina_connection_file.name)
    print('Bye!!\n')

def parse_arguments():
    '''Argument parser for Proxmox API

    Minimal set of arguments: username, password, cluster address
    and <node name (or ID)> <- [TO BE IMPLEMENTED]
    '''
    arg_parser = ArgumentParser()

    arg_parser.add_argument("-u", '--user', dest='username', required=True,
                            help="Proxmox PVE username (example: johndoe@pve)")

    arg_parser.add_argument("-c", "--cluster", dest='fqdn', required=True,
                            help="Proxmox cluster FQDN (example: foo.example.com)")

    arg_parser.add_argument("-p", "--password", dest='password', required=False,
                            help="User password in clear text")

    # VM ID/name selection
    vmid_group = arg_parser.add_mutually_exclusive_group(required=True)
    # Not supported yet
    vmid_group.add_argument("-n", '--name', dest='vmname', help="VM name in PVE cluster")
    # Not supported yet
    vmid_group.add_argument("-i", '--id', dest='vmid', help="VM ID in PVE cluster")

    # We parse here to determine if user had entered password
    arg_output = arg_parser.parse_args()

    # If -p is not specified, ask for password safely
    if not arg_output.password:
        arg_output.password = getpass.getpass()

    return arg_output

def encrypt_remmina(password):
    '''Encrypts a string to the Remmina format

    Extracts a unique key from the users's home
    directory and uses it to encrypt input.
    Returns encrypted string.
    '''
    home = expanduser("~")
    remmina_dir = home + '/' + '.remmina/'
    remmina_pref = 'remmina.pref'

    remmina_pref_file = open(remmina_dir + remmina_pref)
    file_lines = remmina_pref_file.readlines()
    remmina_pref_file.close()

    for i in file_lines:
        if re.findall(r'secret=', i):
            remmina_pref_secret_b64 = i[len(r'secret='):][:-1]

    plaintext = password.encode('utf-8')
    secret = base64.b64decode(remmina_pref_secret_b64)

    key = secret[:24]
    salt = secret[24:]
    plaintext = plaintext + b"\0" * (8 - len(plaintext) % 8)
    cipher = DES3.new(key, DES3.MODE_CBC, salt)

    result = base64.b64encode(cipher.encrypt(plaintext))
    result = result.decode('utf-8')

    return result

def get_pve_cookies(api_url, username, password):
    '''Gets credential tokens

    Uses Proxmox API call to get Authentication Cookie
    and CSRF prevention token. This data is then used
    to further authentificated API calls.

    Arguments:
        api_url {string} -- URL of the Proxmox VE cluster API
        username {string} -- Proxmox VE user name
        password {string} -- User password

    Returns:
        [tuple] -- [Returns tuple of dictionaries
                    in format ({'PVEAuthCookie':'<data>'},{'CSRFPreventionToken':'<data>'})]

    Raises:
        ConnectionError -- [Raises connection error if the cluster's
                            answer is anything except 200 OK]
    '''

    # Sending ticket request
    pve_ticket_response = requests.post(url=api_url + 'access/ticket',
                                        data={'username':username,'password':password})
    # Checking server response
    if not pve_ticket_response.ok:
        raise ConnectionError('PVE proxy returned HTTP code ' +
                              str(pve_ticket_response.status_code))

    pve_cookie = {
        'PVEAuthCookie': pve_ticket_response.json()['data']['ticket'],
    }

    pve_header = {
        'CSRFPreventionToken': pve_ticket_response.json()['data']['CSRFPreventionToken'],
    }

    # Returns a tuple of dictionariese
    return pve_cookie, pve_header

# A placeholder
def get_node_info():
    # Input - a json object (API call result)
    # output - a dictionary with node parameters
    return None

# A placeholder
def generate_ca_file():
    # Input - a json object (API call result)
    # output - certificate file name
    print('Im doing nothing for now!')

# A placeholder
def generate_rc_file():
    # Input - json object (API call result)
    # Output - configuration file name
    # and generate a correct connection file
    return None # Must return file name

if __name__ == '__main__':
    main()
