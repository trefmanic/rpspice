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
DEBUG = False

def main():

    # Get the arguments object
    arguments = parse_arguments()

    # Determine if the cluster web interface
    # is running on default 8006 port,
    # or default SSL port (443)
    pve_port = determine_port(arguments.fqdn)


    # 1) PVE API URL
    # https://<arguments.fqdn>:[port]/api2/json/
    pve_api_url = 'https://' + arguments.fqdn + ':' + pve_port + '/api2/json/'

    # 2) Get credential parameters
    (pve_cookie, pve_header) = get_pve_cookies(api_url=pve_api_url,
                                               username=arguments.username,
                                               password=arguments.password)
    # 3) Get VM status dictionary
    # If VM name is provided, use it, else use VM ID
    vminfo = get_node_info(api_url=pve_api_url,
                           pve_cookie=pve_cookie,
                           pve_header=pve_header,
                           vmname=arguments.vmname,
                           vmid=arguments.vmid)

    # 3) Get API link for SPICE config
    # Needs refactoring
    pve_spice_url = pve_api_url + 'nodes/' + vminfo['node'] + '/' + vminfo['type'] + '/' + vminfo['id'] + '/spiceproxy'

    pve_spice = requests.post(pve_spice_url,
                              headers=pve_header,
                              cookies=pve_cookie)

    if DEBUG:
        print(pve_spice.status_code)
        print(pve_spice.text)

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
    node_fqdn = vminfo['node'] + arguments.fqdn.partition('.')[1] +\
                                 arguments.fqdn.partition('.')[2]

    remmina_connection_parameters = '''[remmina]
    name=spice@'''+ vminfo['name'] + '''
    ssh_username=root
    ssh_auth=3
    ssh_server = ''' + node_fqdn + '''
    ssh_enabled=1
    ssh_loopback=1
    ssh_charset=UTF-8
    usetls=1
    cacert= ''' + str(remmina_ca_file.name) + '''
    protocol=SPICE
    disablepasswordstoring=0
    server=localhost:'''+ str(remmina_port) + '''
    viewmode=1
    window_height = 600
    window_width = 800
    ''' + 'password = ' + remmina_password
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
    vmid_group.add_argument("-n", '--name', dest='vmname', help="VM name in PVE cluster")
    vmid_group.add_argument("-i", '--id', dest='vmid', help="VM ID in PVE cluster")

    # We parse here to determine if user had entered password
    arg_output = arg_parser.parse_args()

    # If -p is not specified, ask for password safely
    if not arg_output.password:
        arg_output.password = getpass.getpass()

    return arg_output

def encrypt_remmina(password):
    '''Generates encrypted passwords for Remmina

    Uses unique key from the user's home directory
    to encrypt provided string (password) to the format,
    which Remmina understands.
    Credits: kvaps @github.com

    Arguments:
        password {string} -- A password in plaintext

    Returns:
        string -- Encrypted password
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

def determine_port(fqdn):
    try:
        request = requests.get('https://' + fqdn + ':443')
        request.raise_for_status()
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        return '8006'
    else:
        return '443'

def get_pve_cookies(api_url, username, password):
    '''Gets credential tokens

    Uses Proxmox API call to get Authentication Cookie
    and CSRF prevention token. That data is then used
    to make authentificated API calls.

    Arguments:
        api_url {string} -- URL of the Proxmox VE cluster API
        username {string} -- Proxmox VE user name
        password {string} -- User password

    Returns:
        tuple -- Returns tuple of dictionaries
                    in format ({'PVEAuthCookie':'<data>'},{'CSRFPreventionToken':'<data>'})

    Raises:
        ConnectionError -- Raises connection error if the cluster's
                            answer is anything except 200 OK
    '''

    # Sending ticket request
    pve_ticket_response = requests.post(url=api_url + 'access/ticket',
                                        data={'username':username, 'password':password})
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


def get_node_info(api_url, pve_header, pve_cookie, vmname=None, vmid=None):
    '''Generates Proxmox VM info

    Uses Proxmox PVE API call to determine VM parameters
    Searches by VM ID or name, raises exception if both
    are empty or VM with ID/name not found in cluster.

    Arguments:
        url {strind} -- Proxmox cluster API URL
        pve_header {dictionary} -- Authentication: CSRF prevention token
        pve_cookie {dictionary} -- Authentication: PVEAuth cookie

    Keyword Arguments:
        vmname {string} -- optional VM name (default: {None})
        vmid {string} -- optional VM ID (default: {None})

    Returns:
        dictionary -- VM parameters, such as name, type, id, etc.

    Raises:
        ValueError -- when either ID or name are not provided.
        BaseException -- when search for VM is unsuccessfull.
    '''
    # If no values provided:
    if not vmname and not vmid:
        raise ValueError("Neither Name nor ID provided")

    vminfo = dict({})

    # https://<arguments.fqdn>:[port]/api2/json/cluster/resources
    url = api_url + 'cluster/resources'

    pve_resource = requests.get(url, headers=pve_header, cookies=pve_cookie).json()['data']

    # Search for the VM data
    for item in pve_resource:

        # VM's only
        if item['type'] == 'lxc' or item['type'] == 'qemu':
            # if either name or id matches:
            # may cause collisions?
            true_id = item['id'].split('/')[1] # lxc|qemu/xxx -> xxx
            if item['name'] == vmname or true_id == vmid:
                vminfo['name'] = item['name']
                vminfo['type'] = item['type']
                vminfo['id'] = true_id
                vminfo['node'] = item['node']
    if not vminfo:
        # Not name nor id foud
        raise BaseException("VM not found in cluster")
    return vminfo

# A placeholder
def generate_ca_file():
    # Input - a json object (API call result)
    # output - certificate file name
    pass
# A placeholder
def generate_rc_file():
    # Input - json object (API call result)
    # Output - configuration file name
    # and generate a correct connection file
    return None # Must return file name

if __name__ == '__main__':
    main()
