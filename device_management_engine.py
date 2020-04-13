##############################################################
#                                                            #
# Device Management Engine                                   #
# =====================================                      #
#                                                            #
# This engine uses arp-scan command to scan IoT devices in   #
# the network and display them via a GUI to the homeowner    #
# so she can validate them and diconnect any suspect device. #
##############################################################

## For Device Management Engine
from subprocess import Popen, PIPE
import re
import sqlite3

class DM_Engine:
      
      
    def dm_engine():          
        stdout = Popen('arp-scan --interface=eth0 --localnet', shell=True, stdout=PIPE).stdout
        for line in stdout:
            try:
                #the real code does filtering here
                line_str = str(line.rstrip(), 'utf-8')
                ip, mac, *vendor = line_str.split()
                vendor_str = str(vendor)
                vendor_str = ((((vendor_str.replace("[","")).replace("]","")).replace("'","")).replace(")","")).replace("(","")
            
                # validate IP address
                if(DM_Engine.is_valid_ip(ip) == True):
                    ip = ip
                else:
                    ip = ""
            
                #validate mac
                if(DM_Engine.is_valid_mac_address(mac) == True):
                    mac = mac
                else:
                    mac = None
            
                #validate vendor
                if(vendor_str == "datalink, type:, EN10MB, Ethernet" or vendor_str == "1.9, with, 256, hosts, http://www.nta-monitor.com/tools/arp-scan/"):
                    vendor_str = ""
                else:
                    vendor_str = vendor_str
            
                conn = sqlite3.connect('IoT_Hass.db')
                c = conn.cursor()

                c.execute('CREATE TABLE IF NOT EXISTS Home_IoT_Devices(Device_IP TEXT, Device_MAC TEXT NOT NULL UNIQUE, Device_Vendor TEXT)')

                c.execute('INSERT OR IGNORE INTO Home_IoT_Devices(Device_IP, Device_MAC, Device_Vendor) VALUES(?,?,?)',(ip, mac, vendor_str))
                
                c.execute('DELETE FROM Home_IoT_Devices WHERE Device_MAC IS NULL')

                conn.commit()
                c.close()
                conn.close()
 
            except ValueError:
                print("")


    # Function to validate MAC address
    def is_valid_mac_address(value):
        allowed = re.compile(r"""
                         (
                             ^([0-9A-F]{2}[-]){5}([0-9A-F]{2})$
                            |^([0-9A-F]{2}[:]){5}([0-9A-F]{2})$
                         )
                         """,
                         re.VERBOSE|re.IGNORECASE)

        if allowed.match(value) is None:
            return False
        else:
            return True

    # Function to validate IP address
    def is_valid_ip(address):
        try:
            host_bytes = address.split('.')
            valid = [int(b) for b in host_bytes]
            valid = [b for b in valid if b >= 0 and b<=255]
            return len(host_bytes) == 4 and len(valid) == 4
        except:
            return False
            
    # Function that tries to block all IP addresses by default
    # if successful it mark environment as Inline otherwise it
    # mark it as passive.
    def block_all_ips():
        
        conn = sqlite3.connect('IoT_Hass.db')
        c = conn.cursor()

        c.execute('select * from Home_IoT_Devices')
        
        c2 = conn.cursor()
        
        c2.execute('CREATE TABLE IF NOT EXISTS Home_IoT_Environment(Environment TEXT)')

        rows = c.fetchall()

        for row in rows:
            device_ip = str(row[0])
		    # Try to block all IP addresses
            if not os.system("echo $MY_SUDO_PASS | sudo -S iptables -A INPUT -s " + device_ip + " -j DROP"):
                c2.execute('UPDATE Home_IoT_Environment SET Environment = ? WHERE Environment != ?', ('Passive','Passive'))
                conn.commit()
            else:
                c2.execute('UPDATE Home_IoT_Environment SET Environment = ? WHERE Environment != ?', ('Inline','Inline'))
                conn.commit()

        c.close()
        c2.close()
        conn.close()
        


            
        
        
