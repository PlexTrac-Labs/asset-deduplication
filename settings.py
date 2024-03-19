import logging


# LOGGING
console_log_level = logging.INFO
file_log_level = logging.INFO
save_logs_to_file = True

# REQUESTS
# if the Plextrac instance is running on https without valid certs, requests will respond with cert error
# change this to false to override verification of certs
verify_ssl = True
# number of times to rety a request before throwing an error. will only throw the last error encountered if
# number of retries is exceeded. set to 0 to disable retrying requests
retries = 0

# description of script that will be print line by line when the script is run
script_info = ["====================================================================",
               "= Asset De-duplication                                             =",
               "=------------------------------------------------------------------=",
               "= This script is designed to de-duplicate client assets using      =",
               "= the Plextrac API. It identifies duplicate assets within a        =",
               "= specific Plextrac client and updates associated findings to      =",
               "= reference a primary asset for each group of duplicate assets.    =",
               "=                                                                  =",
               "===================================================================="
            ]
