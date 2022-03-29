SMB Keywords
==============

SMB keywords used in both SMB1 and SMB2 protocols.

smb.filename
--------------

SMB filename is a sticky buffer to match the filename in SMB Create requests.

.. note:: Remember that SMB2 filenames are Unicode encoded.

If you want to match traffic that access to file "a.txt", you could use the following rule::

  alert smb any any -> any any (msg: "SMB file match";smb.filename; content:"a|00|.|00|t|00|x|00|t|00|";sid:1;)
  

.. topic:: Difference between smb.filename and filename keyword

   They were made for different purposes. *filename* keyword (and *file.name* sticky buffer) were made to match the name of the file extracted/transferred from different protocols, that includes SMB, whereas **smb.filename will match in any SMB create request**.

   This means that *smb.filename* will match for files that were opened for read or write, that will be matched by *filename* also. But *smb.filename* will also match files opened to read files attributes, which won't be matched by *filename*.

   Other difference is that *smb.filename* will match for directories that are open with SMB create.

   Therefore:

   - **filename**: Name of tranferred files over many protocols, including SMB.
   - **smb.filename**: SMB create file request filename field, so files and directories opened for any purpose (transfer, query, list, etc).
