#!/usr/bin/python3
# -*- coding: utf-8 -*-
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

# TODO: get this from the commandline!
PVE_VM_ID = '100'

def main():

    # Парсим аргументы сценария:
    arguments = parse_arguments()

    # TODO: this needs to be calculated dynamically!
    pve_node_fqdn = arguments.fqdn
    pve_node_name = arguments.fqdn.split('.')[0]

    # API link for getting tickets (https://<arguments.fqdn>:8006/api2/json/access/ticket)
    pve_ticket_url = 'https://' + arguments.fqdn + ':8006/api2/json/access/ticket'

    # API link for SPICE config
    # (https://<arguments.fqdn>:8006/api2/json/nodes/origin/qemu/103/spiceproxy)
    pve_spice_url = str('https://' + arguments.fqdn + ':8006/api2/json/nodes/' + pve_node_name
                        + '/qemu/' + PVE_VM_ID + '/spiceproxy')

    # Получаем состояние ресурсов кластера
    pve_status_url = 'https://' + arguments.fqdn + ':8006/api2/json/cluster/resources'

    # DEBUG
    if DEBUG:
        print(pve_ticket_url)
        print(pve_spice_url)
    # END DEBUG

    # Sending ticket requests
    pve_ticket_response = requests.post(url=pve_ticket_url, data={'username':arguments.username,
                                                                  'password':arguments.password})

    # TODO: pve_ticket_response.ok <- TRUE
    # Проверяем ответ сервера
    if not pve_ticket_response.ok:
        raise ConnectionError('PVE proxy returned HTTP code ' +
                              str(pve_ticket_response.status_code))

    # Parsing server response

    pve_ticket = pve_ticket_response.json()['data']['ticket']
    pve_csrf = pve_ticket_response.json()['data']['CSRFPreventionToken']

    # DEBUG
    if DEBUG:
        print(pve_ticket_response.text)
        print("PVE Ticket: ", pve_ticket, "\n")
        print("PVE CSRFPreventionToken: ", pve_csrf, "\n")

    # Getting SPICE configuration

    pve_cookies = {
        'PVEAuthCookie': pve_ticket,
    }
    pve_header = {
        'CSRFPreventionToken': pve_csrf,
    }

    pve_spice = requests.post(pve_spice_url, headers=pve_header, cookies=pve_cookies)

    # DEBUG
    if DEBUG:
        print(pve_spice.status_code)
        print(pve_spice.text)

        # DATA
        print(pve_spice.json()['data']['password'])
        print(pve_spice.json()['data']['tls-port'])


    pve_resource = requests.get(pve_status_url, headers=pve_header, cookies=pve_cookies)

    #DEBUG
    if DEBUG:
        print(pve_resource.status_code)
        print(pve_resource.text)
        print('Collecting VM info')

    remmina_password = encrypt_remmina(pve_spice.json()['data']['password'])
    remmina_port = pve_spice.json()['data']['tls-port']


    # Generating connection file

    def generate_ca_file():
        print('Im doing nothing for now!')

    remmina_connection_file = open(tempfile.NamedTemporaryFile(dir=expanduser("~"),
                                                               suffix='.remmina').name, 'w')
    remmina_ca_file = open(expanduser("~") + '/ca.crt', 'w')

    # TODO: Refactor to function here
    generate_ca_file()

    remmina_ca_file.write(pve_spice.json()['data']['ca'].replace('\\n', '\n'))

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

    # TODO: Safely remove CA file
    remmina_ca_file.close()

    #remmina_options = '-c ' + remmina_connection_file.name

    devnull = open(os.devnull, 'w')
    subprocess.run(["remmina", '--name', 'remmina_spiced', '-c', remmina_connection_file.name],
                  stdout=devnull, stderr=devnull)


    # DEBUG: Sometime file could not be deleted immeadiately
    time.sleep(5)
    devnull.close()
    os.remove(remmina_connection_file.name)
    print('Bye!!\n')

def parse_arguments():
    '''Парсер аргументов

    Тут мы обрабатываем аргументы сценария
    '''
    arg_parser = ArgumentParser()
    arg_parser.add_argument("-u", '--user', dest='username', required=True,
                            help="Proxmox PVE username (example: johndoe@pve)")
    arg_parser.add_argument("-p", "--password", dest='password', required=True,
                            help="User password")
    arg_parser.add_argument("-c", "--cluster", dest='fqdn', required=True,
                            help="Proxmox cluster FQDN (example: foo.example.com)")
    return arg_parser.parse_args()

def encrypt_remmina(password):
    '''Шифрует пароль для Remmina

    Извлекает из домашнего каталога пользователя
    ключ шифрования и шифрует и пароль, возвращает
    пароль в формате, который Remmina понимает.
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

if __name__ == '__main__':
    main()