# rpspice
A Python wrapper for Remmina to connect to SPICE-enabled VM's running in Proxmox PVE

## About
This wrapper uses Proxmox VE API to generate connection parameters for Remmina, then initiates a connection with the temporary configuration.
It uses SSH tunneling to connect.

Based on the shell script, provided by [der-brumm-baer](https://forum.proxmox.com/members/der-brumm-baer.60239/) from [Proxmox VE Community forum](https://forum.proxmox.com/threads/remote-spice-access-without-using-web-manager.16561/page-3).

## Dependencies
Remmina and SPICE plugin (obviously), Python3.
Python3 modules:
* requests
* cryptography

install with:

    pip3 install requests cryptography

## Usage
**Please, remember, that this is a prototype. It may not work and could be a subject to major changes in the future.**

As of now you need to have SSH access to the Proxmox VE cluster. The user (root) and the authentification method (RSA key) are still hardcoded in.

Run this script with the **--help** argument to get a full list of options:

    ./rpspice.py --help

[//]: # (Now with GPG commit signatures.)
