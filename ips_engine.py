############################################################################
#                                                                          #
#           Intrusion Detection and Prevention Engine                      #
#           =========================================                      #
#                                                                          #
#  This engine monitors the smart home environment 24/7 and detect and     #
#  prevent malicious attacks. When an intrusion is detected the user is    #
#  alerted via a GUI interface.                                            #
#                                                                          #
############################################################################

import pandas as pd
import logger as lg
import datetime
from datetime import timedelta
import sqlite3
LOG = lg.IoT_HASS_Logger

class IPS_Engine:
    
    def ips_engine(mean_biat, std_biat, max_biat, pkt_len_varience, std_idle, src, target, classifier):

        ######## Extract Five Selected Features from Live Packets #####

        # creating an empty data frame to hold live features
        dfLiveFeatures = pd.DataFrame(columns=['Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Packet Length Variance', 'Idle Std'])
    
        # appending rows to the columns
        dfLiveFeatures = dfLiveFeatures.append({'Bwd IAT Mean': mean_biat, 'Bwd IAT Std': std_biat, 'Bwd IAT Max': max_biat, 'Packet Length Variance': pkt_len_varience, 'Idle Std': std_idle}, ignore_index=True)
    
        Prod_dataset = dfLiveFeatures

        y_prod_pred = classifier.predict(Prod_dataset)

        Src_IP = src
        Dst_IP = target

        IPS_Engine.block_and_alert(Src_IP, Dst_IP, y_prod_pred)


    # A function to block malicious packets and alerts the user
    def block_and_alert(Src_IP, Dst_IP, y_prod_pred):

        Source_IP = []
        Destination_IP = []

        Id = []
        counter = 0
        for x in (y_prod_pred.astype(str)):
            Id.append(str(counter))
            counter = counter + 1

        # Add the Id column to y_prod_pred dataset and
        # then convert it to a DataFrame
        y_prod_pred_df = pd.DataFrame(data=y_prod_pred)
        #print(y_prod_pred_df)
        y_prod_pred_df["Id"] = Id

        # Add the Id column to y_prod_pred dataset and
        # then convert it to a DataFrame
        Source_IP.append(Src_IP)
        Src_IP_df = pd.DataFrame(data=Source_IP)
        Src_IP_df["Id"] = Id
    
        Destination_IP.append(Dst_IP)
        Dst_IP_df = pd.DataFrame(data=Destination_IP)
        Dst_IP_df["Id"] = Id

        Combined_df = pd.merge(y_prod_pred_df, Src_IP_df, on='Id', how='inner')
    
        #print(Combined_df)

        Combined_df = Combined_df.rename(columns={'0_x':'Label','0_y':'SourceIP'})

        Combined_df2 = pd.merge(y_prod_pred_df, Dst_IP_df, on='Id', how='inner')
    
        #print(Combined_df2)
        Combined_df2 = Combined_df2.rename(columns={'0_x':'Label','0_y':'DestinationIP'})

        Combined_df3 = pd.merge(Combined_df, Combined_df2, on='Id', how='inner')

        del Combined_df3['Label_y']

        Combined_df3 = Combined_df3.rename(columns={'Label_x':'Label'})

        #print(Combined_df3)

        for row in Combined_df3.itertuples():
            if(str(row.Label) == '1'):
                lg.ids_logger.info(str(datetime.datetime.now().isoformat(' ','seconds')) + ' Attack: ' + str(row.Label) + ' Source IP: '+ str(row.SourceIP) + ' Destination IP: '+ str(row.DestinationIP))
                IPS_Engine.block_source_ip(row.SourceIP)
                IPS_Engine.user_ids_alerts(str(datetime.datetime.now().isoformat(' ','seconds')))
            else:
                lg.ids_logger.info(str(datetime.datetime.now().isoformat(' ','seconds')) + ' Normal: ' + str(row.Label) + ' Source IP: '+ str(row.SourceIP) + ' Destination IP: '+ str(row.DestinationIP))


    # Function to block the source IP for 10 hours and alert the user
    def block_source_ip(SourceIP):
     
        block_time_hh = (datetime.datetime.now()).hour
        block_time_mm = (datetime.datetime.now()).minute
        block_time = str(block_time_hh)+":"+str(block_time_mm)

        unblock_time = datetime.datetime.now() + timedelta(hours=10)
        unblock_time_hh = (unblock_time).hour
        unblock_time_mm = (unblock_time).minute

        unblock_time = str(unblock_time_hh)+":"+str(unblock_time_mm)
    
        # Block the source IP of the attack for 10 hours
        os.system("echo $MY_SUDO_PASS | sudo -S iptables -A INPUT -s " + str(SourceIP) + " -m time --timestart "+ block_time + " --timestop " + unblock_time + " -j DROP")
    
        ids_logger = LOG.setup_logger('ids_logger', lg.IOT_HASS_IDS_LOG)
        ids_logger.info(str(datetime.datetime.now()) + ' Block Time: ' + block_time)
        ids_logger.info(str(datetime.datetime.now()) + ' Unblock Time: ' + unblock_time)
    
    
    # Function to record IDS alerts for the user/homeowner
    def user_ids_alerts(Intrusion_DateTime):

        conn = sqlite3.connect('IoT_Hass.db')
        c = conn.cursor()

        c.execute('CREATE TABLE IF NOT EXISTS IDS_Alerts(Last_Intrusion_DateTime TEXT, Action_Taken TEXT, Recommendation TEXT)')

        c.execute('UPDATE IDS_Alerts SET Last_Intrusion_DateTime = ? ', (Intrusion_DateTime,))
        
        conn.commit()
        c.close()
        conn.close()
