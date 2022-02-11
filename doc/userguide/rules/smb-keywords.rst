SMB Keywords
==============

SMB keywords used in both SMB1 and SMB2 protocols.

smb.cmd
---------

Used to match SMB command. Decimal, Hexadecimal or command names values are admitted.


The following signature are equivalent::

  alert smb any any -> any any (msg: "Smb command rule"; smb.cmd: 10; sid: 1;)
  alert smb any any -> any any (msg: "Smb command rule"; smb.cmd: 0xa; sid: 1;)
  alert smb any any -> any any (msg: "Smb command rule"; smb.cmd: lock; sid: 1;)


You can also specify several commands separated by comma::

  alert smb any any -> any any (msg: "Smb command rule"; smb.cmd: 10,create,0x4; sid: 1;)


Commands will match with both versions of SMB, so very careful using this rule.
For example, the following rule::

  alert smb any any -> any any (msg: "Smb command rule"; smb.cmd: 1; sid: 1;)


It will match with the ``SMB2 Session Setup`` and ``SMB1 Delete Directory`` commands.

Moreover, some commands names are shared by both SMB1 and SMB2, so they will match both.
That can be useful in certain situations but lead to false positives in others, be aware.
For example this rule::

  alert smb any any -> any any (msg: "Smb command rule"; smb.cmd: create; sid: 1;)

It will match with SMB2 0x05 and SMB1 0x03 commands codes.

SMB2 command names:

================== ========================
SMB2 Command Name  Code
================== ========================
negotiate          0x00
session_setup      0x01
logoff             0x02
tree_connect       0x03
tree_disconnect    0x04
create             0x05
close              0x06
flush              0x07
read               0x08
write              0x09
lock               0x0A
ioctl              0x0B
cancel             0x0C
echo               0x0D
query_directory    0x0E
change_notify      0x0F
query_info         0x10
set_info           0x11
oplock_break       0x12
================== ========================


SMB1 command names:

======================= ========================
SMB1 Command Name       Code
======================= ========================
create_directory        0x00
delete_directory        0x01
open                    0x02
create                  0x03
close                   0x04
flush                   0x05
delete                  0x06
rename                  0x07
query_information       0x08
set_information         0x09
read                    0x0A
write                   0x0B
lock_byte_range         0x0C
unlock_byte_range       0x0D
create_temporary        0x0E
create_new              0x0F
check_directory         0x10
process_exit            0x11
seek                    0x12
lock_and_read           0x13
write_and_unlock        0x14
read_raw                0x1A
read_mpx                0x1B
read_mpx_secondary      0x1C
write_raw               0x1D
write_mpx               0x1E
write_mpx_secondary     0x1F
write_complete          0x20
query_server            0x21
set_information2        0x22
query_information2      0x23
locking_andx            0x24
transaction             0x25
transaction_secondary   0x26
ioctl                   0x27
ioctl_secondary         0x28
copy                    0x29
move                    0x2A
echo                    0x2B
write_and_close         0x2C
open_andx               0x2D
read_andx               0x2E
write_andx              0x2F
new_file_size           0x30
close_and_tree_disc     0x31
transaction2            0x32
transaction2_secondary  0x33
find_close2             0x34
find_notify_close       0x35
tree_connect            0x70
tree_disconnect         0x71
negotiate               0x72
session_setup_andx      0x73
logoff_andx             0x74
tree_connect_andx       0x75
security_package_andx   0x7E
query_information_disk  0x80
search                  0x81
find                    0x82
find_unique             0x83
find_close              0x84
nt_transact             0xA0
nt_transact_secondary   0xA1
nt_create_andx          0xA2
nt_cancel               0xA4
nt_rename               0xA5
open_print_file         0xC0
write_print_file        0xC1
close_print_file        0xC2
get_print_queue         0xC3
read_bulk               0xD8
write_bulk              0xD9
write_bulk_data         0xDA
invalid                 0xFE
no_andx_command         0xFF
======================= ========================

