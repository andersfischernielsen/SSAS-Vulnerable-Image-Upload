Getting the image to work:


1. Download and import the box
https://mega.nz/#!McZQSSBC!RQPPisX9jk6tmpydQ-ZTTrIHgkHgIniTTRo7IMsi4WE


2. Setup Host-only network
Go to the Virtual Box Manager and Preferences/Network/Host-only network. If there is no network already, press the add symbol to create a new one. Set the IPv4 address to 192.168.100.3 and mask to 255.255.255.0.

Now navigate to Settings/Network/Adapter3 in the imported box and select the Host-only network you just created under 'name'

The host-only adapter means that you can access the box from your host machine by the ip https://192.168.100.5

