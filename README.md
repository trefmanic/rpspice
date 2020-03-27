# Important notice!
This project is now discontinued in favour of the new remote-viewer wrapper. Check it out [in trefmanic/rwrap](https://github.com/trefmanic/rwrap) repo.

Why did I do that? Because, basically, remote-viewer does the same thing, but it's much easier to wrap it in a script. Additionally, I've ran into numerous
compatability issues with the Remmina's SPICE plugin, especially when used with Proxmox VE.

# rpspice
A Python wrapper for Remmina to connect to SPICE-enabled VM's, running in a Proxmox VE

## About
This wrapper uses Proxmox VE API to generate connection parameters for Remmina, then initiates a connection with the temporary configuration.
It uses SSH tunneling to connect.

Based on the shell script, provided by [der-brumm-baer](https://forum.proxmox.com/members/der-brumm-baer.60239/) from [Proxmox VE Community forum](https://forum.proxmox.com/threads/remote-spice-access-without-using-web-manager.16561/page-3).

## Dependencies
Remmina and SPICE plugin, Python3.
Python3 modules:
* requests
* cryptography

install with:

    pip3 install requests cryptography

## Usage

As of now you need to have SSH access to the node of a Proxmox cluster, which is running VM. The user (root) and the authentification method (RSA key) are still hardcoded in.

Run this script with the **--help** argument to get a full list of options:

    ./rpspice.py --help

[//]: # (Version 0.1 released!)
