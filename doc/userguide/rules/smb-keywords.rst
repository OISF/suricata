SMB Keywords
==============

SMB keywords used in both SMB1 and SMB2 protocols.

smb_filename
--------------

SMB filename is an sticky buffer to match the filename in SMB Create requests.

.. note:: Remember that SMB2 filenames are Unicode encoded.

If you want to match traffic that access to file "a.txt", you could use the following rule::

  alert smb any any -> any any (msg: "SMB file match";smb.filename; content:"a|00|.|00|t|00|x|00|t|00|";sid:1;)
  
