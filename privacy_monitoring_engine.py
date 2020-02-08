############################################################################
#                                                                          #
#           Privacy Monitoring Engine                                      #
#           =========================                                      #
#                                                                          #
#  This engine monitors the smart home environment for 24/7 and detect any #
#  clear text or private information leaked by the IoT devics. When a leak #
#  is detected the user is alerted via a GUI interface.                    #                                                        #
#                                                                          #
############################################################################

from scapy.all import *
from scapy.utils import hexdump
import sqlite3
import logger as lg
import datetime

class Privacy_Engine:
    
    def privacy_monitoring_engine(dest_mac, src_mac, raw_data, src, target):
    
        pkt = Packet(raw_data)
        raw = pkt.lastlayer()

        Source_IP = src
        Destination_IP = target
        Source_MAC = src_mac
        Destination_MAC = dest_mac


        # Call the Shannon entropy Test here and pass the hexdump(raw)
        if(Privacy_Engine.entropy(str(hexdump(raw))) >= 3.5):
            lg.privacy_logger.info(str(datetime.datetime.now()) + ' Encrypted payload')
            lg.privacy_logger.info(str(datetime.datetime.now()) + ' Source IP: ' + str(Source_IP))
            lg.privacy_logger.info(str(datetime.datetime.now()) + ' Destination IP: ' + str(Destination_IP))
            lg.privacy_logger.info(str(datetime.datetime.now()) + ' Source MAC: ' + str(Source_MAC))
            lg.privacy_logger.info(str(datetime.datetime.now()) + ' Destination MAC: ' + str(Destination_MAC))
        else:
            lg.privacy_logger.info(str(datetime.datetime.now()) + ' Plain text found')
            lg.privacy_logger.info(str(datetime.datetime.now()) + ' Source IP: ' + str(Source_IP))
            lg.privacy_logger.info(str(datetime.datetime.now()) + ' Destination IP: ' + str(Destination_IP))
            lg.privacy_logger.info(str(datetime.datetime.now()) + ' Source MAC: ' + str(Source_MAC))
            lg.privacy_logger.info(str(datetime.datetime.now()) + ' Destination MAC: ' + str(Destination_MAC))
            Privacy_Engine.user_privacy_alerts(str(datetime.datetime.now()), str(Source_IP), str(Source_MAC))


    # Function to calculate the Shannon entropy test for a string
    def entropy(string):
        "Calculates the Shannon entropy of a string"

        # find probability of chararacters in a specified string
        prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]

        # calculate the Shannon entropy
        entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])

        return entropy
        
    # Function to alert the user/homeowner about private information leak
    def user_privacy_alerts(Last_privacy_leak_datetime, source_ip, source_mac):

        conn = sqlite3.connect('IoT_Hass.db')
        c = conn.cursor()

        c.execute('CREATE TABLE IF NOT EXISTS Privacy_Alerts(Last_privacy_leak_datetime TEXT, Action_Taken TEXT, Recommendation TEXT)')

        c.execute('UPDATE Privacy_Alerts SET Last_privacy_leak_datetime = ?, Recommendation = ? ', (Last_privacy_leak_datetime, 'Disconnect device with IP ' + source_ip + ' and MAC ' + source_mac))

        conn.commit()
        c.close()
        conn.close()
