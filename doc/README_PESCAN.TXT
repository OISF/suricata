Suricata PEScan v1.0

This file details the changes made to the Suricata baseline for integrating the PEScan v1.0 service. The service involves creating a detection engine keyword 'pescan' that matches when a PE file is detected via a byte scanner, or when the file has an anomaly score that meets certain condition criteria.  In addition, when PE files are detected, their header and anomaly flag information is logged to a separate file (pescan.log) using the logging module.

The directory structure begins with the Suricata baseline as structured in its GIT repository (git://phalanx.openinfosecfoundation.org/oisf.git).  The PEScan integration changes have been made as noted below.

Files modified in the baseline:

/oisf/configure.in			Added 'libpescan' dependency
/oisf/Makefile.am			Added 'libpescan' sub-directory dependency
/oisf/suricata.yaml.in			Added 'pescan-log' logging module
/oisf/rules/files.rules			Added rules that reference 'pescan'
/oisf/src/Makefile.am			Added 'detect-pescan.*, log-pescan.*, and util-pescan.*' references
/oisf/src/flow.h			Added FLOW_FILE_NO_PESCAN_TS and _TC values
/oisf/src/tm-threads-common.h		Added TMM_PESCANLOG value
/oisf/src/detect.h			Added DETECT_PESCAN value and SigGroup flags
/oisf/src/detect.c			Added call to DetectPescanRegister() and SigGroup functions
/oisf/src/detect-engine-siggroup.h	Added 'SigGroupHeadSetPEScanFlag() function prototype
/oisf/src/detect-engine-siggroup.c	Added 'SigGroupHeadSetPEScanFlag() function implementation
/oisf/src/suricata.c			Added call to TmModuleLogPescanLogRegister() function
/oisf/src/detect-engine-file.c		Added ability to wait for enough file data before processing
/oisf/src/util-file.h			Added PE-related flags to 'File' structure
/oisf/src/util-file.c			Added PE-related cleanup to FileFree() function
/oisf/src/app-layer-htp-file.c		Added references to FILE_NOPESCAN flag

Files added to the baseline:

/oisf/src/detect-pescan.h	Detect 'pescan' keyword header file
/oisf/src/detect-pescan.c	Detect 'pescan' keyword implementation code
/oisf/src/log-pescanlog.h	Log to 'pescan-log' module header file
/oisf/src/log-pescan.c		Log to 'pescan-log' module implementation code
/oisf/src/util-pescan.h		PEScan function prototype and size constants
/oisf/src/util-pescan.c		PEScan function implementation
/oisf/libpescan/*               Source and build scripts for 'libpescan' dependency

Files modified locally to enable PEScan:

/oisf/suricata.yaml		Set 'pescan-log.enabled' to Yes
/oisf/rules/files.rules		Uncomment PEScan rules

Installation:

This release is available as a GIT patch. Installing it should be self-explanatory if you have already installed a GIT patch created using the OISF contribution instructions page.
