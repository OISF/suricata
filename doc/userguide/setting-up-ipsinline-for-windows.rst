Setting up IPS/inline for Windows
=================================

This guide explains how to work with Suricata in layer 4 inline mode using
WinDivert on Windows.

First start by compiling Suricata with WinDivert support. For instructions, see
`Windows Installation
<https://redmine.openinfosecfoundation.org/attachments/download/1175/SuricataWinInstallationGuide_v1.4.3.pdf>`_.
This documentation has not yet been updated with WinDivert information, so make
sure to add the following flags to `configure`:

::
  
  --enable-windivert --with-windivert-include=<include-dir> --with-windivert-libraries=<libraries-dir>

WinDivert.dll and WinDivert.sys must be in the same directory as the Suricata
executable. WinDivert automatically installs the driver when it is run. For more
information about WinDivert, see https://www.reqrypt.org/windivert-doc.html.

To check if you have WinDivert enabled in your Suricata, enter the following
command in an elevated command prompt or terminal:

::
  
  suricata -c suricata.yaml --windivert [filter string]

For information on the WinDivert filter language, see
https://www.reqrypt.org/windivert-doc.html#filter_language

If Suricata is running on a gateway and is meant to protect the computers behind
that gateway, you need to run WinDivert at the NETWORK_FORWARD layer. This can
be achieved using the following command:

::

  suricata -c suricata.yaml --windivert-forward [filter string]

A quick start is to examine all traffic, in which case you can use the following
command:

::
  
  suricata -c suricata.yaml --windivert[-forward] true

The filter is automatically stopped and normal traffic resumes when Suricata is
stopped.