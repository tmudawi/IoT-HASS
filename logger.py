####################################################################
#                                                                  #
# IoT-HASS Logger                                                  #
# =====================================                            #
#                                                                  #
# This logging functionality is used to log all traffic whether    #
# it is normal or attack packets. There are two types of log files # 
# one for IDS and another for privacy monitoring.                  #
#                                                                  #
####################################################################

IOT_HASS_IDS_LOG = "/home/pi/Software/IoT-HASS/iot_hass_ids.log"
IOT_HASS_PRIVACY_LOG = "/home/pi/Software/IoT-HASS/iot_hass_privacy.log"

import logging
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')

class IoT_HASS_Logger:
    
    def setup_logger(name, log_file, level=logging.INFO):
        """Function setup as many loggers as you want"""

        handler = logging.FileHandler(log_file)        
        handler.setFormatter(formatter)

        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.addHandler(handler)

        return logger

# Call the setup_logger function for both log files
ids_logger = IoT_HASS_Logger.setup_logger('ids_logger', IOT_HASS_IDS_LOG)
privacy_logger = IoT_HASS_Logger.setup_logger('privacy_logger', IOT_HASS_PRIVACY_LOG)
