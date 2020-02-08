#!/usr/bin/python3

################################################################
#                                                              #
# IoT-HASS GUI Interface                                       #
# =====================================                        #
#                                                              #
# This GUI represents the a user interface for the homeowner   #
# The homeowner receives alerts both from the intrusion        # 
# detection engine and the privacy monitoring engine. The user #
# also can view, verify, delete/block IoT devices via the GUI. #
################################################################

from tkinter import *
import tkinter.messagebox as MessageBox
import sqlite3
import os

root = Tk()
root.geometry("800x600")
root.title("IoT-HASS Realtime Monitor")

# function to show the last intrusion date and time 
def show_last_intrusion_datetime():

	conn = sqlite3.connect('IoT_Hass.db')
	c = conn.cursor()

	c.execute('select * from IDS_Alerts')

	rows = c.fetchall()

	for row in rows:
		getLastIntrusion = str(row[0]) + '			' + str(row[1]) + '			' + str(row[2])
		listbox2.insert(list.size()+1, getLastIntrusion)

	conn.commit()
	c.close()
	conn.close()

# function to show the last privacy leak date and time 
def show_last_privacy_leak_datetime():

	conn = sqlite3.connect('IoT_Hass.db')
	c = conn.cursor()

	c.execute('select * from Privacy_Alerts')

	rows = c.fetchall()

	for row in rows:
		getLastPrivacyLeak = str(row[0]) + '			' + str(row[1]) + '			' + str(row[2])
		listbox3.insert(list.size()+1, getLastPrivacyLeak)

	conn.commit()
	c.close()
	conn.close()

# function to block suspect devices
def delete_device():
	if(e_device_ip.get() == ""):
		MessageBox.showinfo("Block Status", "Device IP is required for Deletion")
	else:
		# Delete the device from the Sqlite3 table
		conn = sqlite3.connect('IoT_Hass.db')
		c = conn.cursor()
		c.execute("delete from Home_IoT_Devices where device_ip = '"+ e_device_ip.get() +"'")
		conn.commit()		
    
        # Block the source IP of the suspect device
		os.system("echo $MY_SUDO_PASS | sudo -S iptables -A INPUT -s " + e_device_ip.get() + " -j DROP")
    

		e_device_ip.delete(0, 'end')
		show_devices()
		MessageBox.showinfo("Delete Status", "Deleted Successfully")
		c.close()
		conn.close()

# function to show the user all active connected IoT devices 
def show_devices():

	conn = sqlite3.connect('IoT_Hass.db')
	c = conn.cursor()

	c.execute('select * from Home_IoT_Devices')

	rows = c.fetchall()

	for row in rows:
		getDevices = str(row[0]) + '			' + str(row[1]) + '			' + str(row[2])
		list.insert(list.size()+1, getDevices)

	conn.commit()
	c.close()
	conn.close()

# title for intrusion detection alerts
ids_engine = Label(root, text='Intrusion Detection Alerts', font=('bold', 12))
ids_engine.place(x=250, y=10);

# Showing last intrusion record
listbox2 = Listbox(root)
listbox2.place(x=50, y=40, width=600, height=35)

# title for the privacy leak alerts
privacy_engine = Label(root, text='Privacy Leak Alerts', font=('bold', 12))
privacy_engine.place(x=270, y=100);

# Showing last intrusion record
listbox3 = Listbox(root)
listbox3.place(x=50, y=130, width=600, height=35)

# title for the identity access and management for IoT devices
iam_engine = Label(root, text='IoT Device Manager', font=('bold', 12))
iam_engine.place(x=270, y=200);

# label for deleting/blocking suspect device
device_ip = Label(root, text='Device IP', font=('bold', 9))
device_ip.place(x=50, y=510);

# textbox for entering the device IP we like to delete
e_device_ip = Entry()
e_device_ip.place(x=130, y=505)

# button to click to delete/block the device IP
btn_device_ip = Button(root, text='Delete Device', font=("italic", 9), bg="white", command=delete_device)
btn_device_ip.place(x=330, y=505)

# label for deleting/blocking suspect device
device_disconnect = Label(root, text='Note: After deleting disconnect device physically to remove it entirely from home network', font=('bold', 9))
device_disconnect.place(x=50, y=535);

list = Listbox(root)
list.place(x=50, y=230, width=600, height=250)

show_last_intrusion_datetime()

show_last_privacy_leak_datetime()

show_devices()

root.mainloop()
