Program Description:
===

This application is used to protect the smart home IoT environment. It consists basically of three engines. The
system works in two different modes of operations: The Inline mode where the system is installed inline with
the traffic in a device such as a Raspberry Pi or a Router. In this mode, the system works as an intrusion 
prevention system (IPS) where it detects and blocks thrats and alerts the user at the same time. The other mode 
is a Passive mode where the system is not installed inline with the traffic and thus can work as an intrusion 
detection system (IDS) and can only detects attacks and alerts the user. The user can receive alerts via a GUI
interface. The GUI also allows the user to view, verify and delete/block suspect devices.

 
Technical Specification:
===

* Linux OS.
* Python 3
* No other dependencies or third-party library needed.



System Features:
===

This version include the following features:
* System ability to work both as IPS or IDS depending on the type of installation whether inline with the traffic or not.
* Detection and/or Prevention of threats regardless of IoT device securing the entire smart home network.
* Privacy monitoring and detection of unencrypted cleartext and alerting the user at the same time.
* Device management via regular device scanning and providing list of devices for a the user to verify and remove/block
  suspect devices.


Usage:
===
This program can be configured to run automatically as a systemctl service when the machine boots. However, it can
also be run from a Linux terminal.

Below is a sample command from a Raspberry Pi 4 terminal, just type the following and press enter.

root@raspberrypi:/home/pi/Software/IoT-HASS# python3 iot_hass_service.py 

To run the GUI interface the user can simply double click on the file to open the GUI window. However, alternatively
the GUI can be run from the terminal as follows:

root@raspberrypi:/home/pi/Software/IoT-HASS# python3 iot_hass_gui.py

Note: All IoT-HASS files must be included under the IoT-HASS folder in the above example.
 

