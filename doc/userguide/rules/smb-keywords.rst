SMB Keywords
==============

SMB keywords used in both SMB1 and SMB2 protocols.

smb.cmd
---------

Used to match SMB command. Decimal, Hexadecimal or command names (case
insensitive) values are admitted.


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

================================ ========================
SMB2 Command Name                Code
================================ ========================
SMB2_COMMAND_NEGOTIATE_PROTOCOL  0x00
negotiate                        0x00
SMB2_COMMAND_SESSION_SETUP       0x01
session_setup                    0x01
SMB2_COMMAND_SESSION_LOGOFF      0x02
logoff                           0x02
SMB2_COMMAND_TREE_CONNECT        0x03
tree_connect                     0x03
SMB2_COMMAND_TREE_DISCONNECT     0x04
tree_disconnect                  0x04
SMB2_COMMAND_CREATE              0x05
create                           0x05
SMB2_COMMAND_CLOSE               0x06
close                            0x06
SMB2_COMMAND_FLUSH               0x07
flush                            0x07
SMB2_COMMAND_READ                0x08
read                             0x08
SMB2_COMMAND_WRITE               0x09
write                            0x09
SMB2_COMMAND_LOCK                0x0A
lock                             0x0A
SMB2_COMMAND_IOCTL               0x0B
ioctl                            0x0B
SMB2_COMMAND_CANCEL              0x0C
cancel                           0x0C
SMB2_COMMAND_KEEPALIVE           0x0D
echo                             0x0D
keep_alive                       0x0D
SMB2_COMMAND_FIND                0x0E
query_directory                  0x0E
find                             0x0E
SMB2_COMMAND_CHANGE_NOTIFY       0x0F
change_notify                    0x0F
SMB2_COMMAND_GET_INFO            0x10
get_info                         0x10
query_info                       0x10
SMB2_COMMAND_SET_INFO            0x11
set_info                         0x11
SMB2_COMMAND_OPLOCK_BREAK        0x12
oplock_break                     0x12
================================ ========================


SMB1 command names:

================================== ========================
SMB1 Command Name                  Code
================================== ========================
SMB1_COMMAND_CREATE_DIRECTORY      0x00
create_directory                   0x00
SMB1_COMMAND_DELETE_DIRECTORY      0x01
delete_directory                   0x01
SMB1_COMMAND_OPEN                  0x02
open                               0x02
SMB1_COMMAND_CREATE                0x03
create                             0x03
SMB1_COMMAND_CLOSE                 0x04
close                              0x04
SMB1_COMMAND_FLUSH                 0x05
flush                              0x05
SMB1_COMMAND_DELETE                0x06
delete                             0x06
SMB1_COMMAND_RENAME                0x07
rename                             0x07
SMB1_COMMAND_QUERY_INFORMATION     0x08
query_information                  0x08
SMB1_COMMAND_SET_INFORMATION       0x09
set_information                    0x09
SMB1_COMMAND_READ                  0x0A
read                               0x0A
SMB1_COMMAND_WRITE                 0x0B
write                              0x0B
SMB1_COMMAND_LOCK_BYTE_RANGE       0x0C
lock_byte_range                    0x0C
SMB1_COMMAND_UNLOCK_BYTE_RANGE     0x0D
unlock_byte_range                  0x0D
SMB1_COMMAND_CREATE_TEMPORARY      0x0E
create_temporary                   0x0E
SMB1_COMMAND_CREATE_NEW            0x0F
create_new                         0x0F
SMB1_COMMAND_CHECK_DIRECTORY       0x10
check_directory                    0x10
SMB1_COMMAND_PROCESS_EXIT          0x11
process_exit                       0x11
SMB1_COMMAND_SEEK                  0x12
seek                               0x12
SMB1_COMMAND_LOCK_AND_READ         0x13
lock_and_read                      0x13
SMB1_COMMAND_WRITE_AND_UNLOCK      0x14
write_and_unlock                   0x14
SMB1_COMMAND_READ_RAW              0x1A
read_raw                           0x1A
SMB1_COMMAND_READ_MPX              0x1B
read_mpx                           0x1B
SMB1_COMMAND_READ_MPX_SECONDARY    0x1C
read_mpx_secondary                 0x1C
SMB1_COMMAND_WRITE_RAW             0x1D
write_raw                          0x1D
SMB1_COMMAND_WRITE_MPX             0x1E
write_mpx                          0x1E
SMB1_COMMAND_WRITE_MPX_SECONDARY   0x1F
write_mpx_secondary                0x1F
SMB1_COMMAND_WRITE_COMPLETE        0x20
write_complete                     0x20
SMB1_COMMAND_QUERY_SERVER          0x21
query_server                       0x21
SMB1_COMMAND_SET_INFORMATION2      0x22
set_information2                   0x22
SMB1_COMMAND_QUERY_INFORMATION2    0x23
query_information2                 0x23
SMB1_COMMAND_LOCKING_ANDX          0x24
locking_andx                       0x24
SMB1_COMMAND_TRANS                 0x25
transaction                        0x25
SMB1_COMMAND_TRANS_SECONDARY       0x26
transaction_secondary              0x26
SMB1_COMMAND_IOCTL                 0x27
ioctl                              0x27
SMB1_COMMAND_IOCTL_SECONDARY       0x28
ioctl_secondary                    0x28
SMB1_COMMAND_COPY                  0x29
copy                               0x29
SMB1_COMMAND_MOVE                  0x2A
move                               0x2A
SMB1_COMMAND_ECHO                  0x2B
echo                               0x2B
SMB1_COMMAND_WRITE_AND_CLOSE       0x2C
write_and_close                    0x2C
SMB1_COMMAND_OPEN_ANDX             0x2D
open_andx                          0x2D
SMB1_COMMAND_READ_ANDX             0x2E
read_andx                          0x2E
SMB1_COMMAND_WRITE_ANDX            0x2F
write_andx                         0x2F
SMB1_COMMAND_NEW_FILE_SIZE         0x30
new_file_size                      0x30
SMB1_COMMAND_CLOSE_AND_TREE_DISC   0x31
close_and_tree_disc                0x31
SMB1_COMMAND_TRANS2                0x32
transaction2                       0x32
SMB1_COMMAND_TRANS2_SECONDARY      0x33
transaction2_secondary             0x33
SMB1_COMMAND_FIND_CLOSE2           0x34
find_close2                        0x34
SMB1_COMMAND_FIND_NOTIFY_CLOSE     0x35
find_notify_close                  0x35
SMB1_COMMAND_TREE_CONNECT          0x70
tree_connect                       0x70
SMB1_COMMAND_TREE_DISCONNECT       0x71
tree_disconnect                    0x71
SMB1_COMMAND_NEGOTIATE_PROTOCOL    0x72
negotiate                          0x72
SMB1_COMMAND_SESSION_SETUP_ANDX    0x73
session_setup_andx                 0x73
SMB1_COMMAND_LOGOFF_ANDX           0x74
logoff_andx                        0x74
SMB1_COMMAND_TREE_CONNECT_ANDX     0x75
tree_connect_andx                  0x75
SMB1_COMMAND_SECURITY_PACKAGE_ANDX 0x7E
security_package_andx              0x7E
SMB1_COMMAND_QUERY_INFO_DISK       0x80
query_information_disk             0x80
SMB1_COMMAND_SEARCH                0x81
search                             0x81
SMB1_COMMAND_FIND                  0x82
find                               0x82
SMB1_COMMAND_FIND_UNIQUE           0x83
find_unique                        0x83
SMB1_COMMAND_FIND_CLOSE            0x84
find_close                         0x84
SMB1_COMMAND_NT_TRANS              0xA0
nt_transact                        0xA0
SMB1_COMMAND_NT_TRANS_SECONDARY    0xA1
nt_transact_secondary              0xA1
SMB1_COMMAND_NT_CREATE_ANDX        0xA2
nt_create_andx                     0xA2
SMB1_COMMAND_NT_CANCEL             0xA4
nt_cancel                          0xA4
SMB1_COMMAND_NT_RENAME             0xA5
nt_rename                          0xA5
SMB1_COMMAND_OPEN_PRINT_FILE       0xC0
open_print_file                    0xC0
SMB1_COMMAND_WRITE_PRINT_FILE      0xC1
write_print_file                   0xC1
SMB1_COMMAND_CLOSE_PRINT_FILE      0xC2
close_print_file                   0xC2
SMB1_COMMAND_GET_PRINT_QUEUE       0xC3
get_print_queue                    0xC3
SMB1_COMMAND_READ_BULK             0xD8
read_bulk                          0xD8
SMB1_COMMAND_WRITE_BULK            0xD9
write_bulk                         0xD9
SMB1_COMMAND_WRITE_BULK_DATA       0xDA
write_bulk_data                    0xDA
SMB1_COMMAND_INVALID               0xFE
invalid                            0xFE
SMB1_COMMAND_NONE                  0xFF
no_andx_command                    0xFF
================================== ========================
