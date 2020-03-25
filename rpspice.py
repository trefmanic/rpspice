#!/usr/bin/python3
'''rpspice - a Proxmox PVE SPICE wrapper for Remmina

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

'''
# -*- coding: utf-8 -*-
# now  with GPG-signed commits

import os
from os.path import expanduser
import getpass
import re
import time
import base64
import subprocess
import tempfile
from argparse import ArgumentParser
from Crypto.Cipher import DES3
import requests

'''
TODO:
* Document everything
* Separate SPICE API call into a function
* Create a way to use different SSH username (now root)
* Develop a method for guaranteed removal of temp files
'''


# CONSTANTS
DEBUG = False

def main():
    '''Main worker

    '''
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
                           vmname=arguments.vmname,
                           vmid=arguments.vmid)

    # 4) Get SPICE parameters
    pve_spice = get_spice_info(api_url=pve_api_url,
                               pve_cookie=pve_cookie,
                               pve_header=pve_header,
                               vmnode=vminfo['node'],
                               vmtype=vminfo['type'],
                               vmid=vminfo['id'])

    remmina_port = pve_spice.json()['data']['tls-port']
    remmina_password = encrypt_remmina(pve_spice.json()['data']['password'])
    node_fqdn = vminfo['node'] + arguments.fqdn.partition('.')[1] +\
                                 arguments.fqdn.partition('.')[2] + '\n'

    # 4) Generating CA file for TLS connection
    remmina_ca_file_name = generate_ca_file(pve_spice.json()['data']['ca'])


    # 5) Generate connection file
    remmina_connection_file_name = generate_rc_file(vminfo['name'], node_fqdn,
                                                    remmina_ca_file_name, remmina_port,
                                                    remmina_password)

    # 6) Starting Remmina subprocess
    devnull = open(os.devnull, 'w')
    subprocess.run(["remmina", '--name', 'remmina_spiced', '-c', remmina_connection_file_name],
                   stdout=devnull, stderr=devnull)


    # DEBUG: Sometime file could not be deleted immeadiately
    time.sleep(5)
    devnull.close()
    os.remove(remmina_connection_file_name)
    os.remove(remmina_ca_file_name)

    print('All done and thanks for all the fish.')

def parse_arguments():
    '''Argument parser for Proxmox API

    Minimal set of arguments: username, password, cluster address
    and node name or ID
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
    '''Determines Proxmox VE port

    Test if Proxmox VE web API is running on
    the default HTTPS port (443), if not, falls
    back to the PVE default port (8006)

    Arguments:
        fqdn {string} -- FQDN of a Proxmox VE cluster.

    Returns:
        string -- Valid port (443 or 8006)
    '''
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


def get_node_info(api_url, pve_cookie, vmname=None, vmid=None):
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

    pve_resource = requests.get(url, cookies=pve_cookie).json()['data']

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

def get_spice_info(api_url, pve_cookie, pve_header, vmnode, vmtype, vmid):
    '''Gets VM information

    '''
    pve_spice_url = api_url + 'nodes/' + vmnode + '/' + vmtype + '/' + vmid + '/spiceproxy'
    pve_spice = requests.post(pve_spice_url, headers=pve_header, cookies=pve_cookie)

    if not pve_spice.ok:
        raise ConnectionError('Could not get SPICE params, got answer {status}'.format(
            status=pve_spice.status_code))
    return pve_spice


def generate_ca_file(ca_raw):
    '''Generates CA file from raw input

    Takes input as a raw string from JSON API
    call result and writes it into a temporary file

    Arguments:
        ca_raw {string} -- Raw string from JSON

    Returns:
        string -- CA file name
    '''
    ca_file = open(tempfile.NamedTemporaryFile(dir=expanduser("~"),
                                               suffix='.crt').name, 'w')

    ca_file.write(ca_raw.replace('\\n', '\n'))
    ca_file.close()

    return ca_file.name


def generate_rc_file(node_name, node_fqdn, ca_file_name, port, password):
    '''Makes connection file for Remmina

    Generates and returns file name of a temporary
    Remmina connection file.

    Arguments:
        node_name {string} -- A name of a node, which runs selected VM
        node_fqdn {string} -- Fully Qualified Domain Name of a node
        ca_file_name {string} -- A name of generated CA file
        port {string} -- Port of a SPICE interface in a node
        password (string) -- Password, ecnrypted for Remmina

    Returns:
        string -- Connection file name
    '''
    # Generating connection file
    connection_file = open(tempfile.NamedTemporaryFile(dir=expanduser("~"),
                                                       suffix='.remmina').name, 'w')
    # Creating a list for Remmina settings
    conn_param = []
    # Filling in parameters...
    # Common settings
    conn_param.append('[remmina]' + '\n')
    conn_param.append('name=spice@' + node_name + '\n')
    # SSH parameters
    conn_param.append('ssh_username=root' + '\n')
    conn_param.append('ssh_auth=3' + '\n')

    conn_param.append('ssh_server=' + node_fqdn + '\n')
    conn_param.append('ssh_enabled=1' + '\n')
    conn_param.append('ssh_loopback=1' + '\n')
    # Testing
    # conn_param.append('ssh_charset=UTF-8' + '\n')
    # TLS parameters
    conn_param.append('usetls=1' + '\n')
    conn_param.append('cacert=' + ca_file_name + '\n')
    # Protocol and connection parameters
    conn_param.append('protocol=SPICE' + '\n')
    conn_param.append('disablepasswordstoring=0' + '\n')
    conn_param.append('server=localhost:' + str(port) + '\n')
    # Testing
    # conn_param.append('viewmode=1' + '\n')
    # Window parameters
    conn_param.append('window_height=720' + '\n')
    conn_param.append('window_width=1280' + '\n')
    # Password
    conn_param.append('password=' + password + '\n')

    # We have collected all settings, writing out:
    connection_file.writelines(conn_param)
    connection_file.close()

    return connection_file.name

if __name__ == '__main__':
    main()
