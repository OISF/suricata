/* Copyright (C) 2017 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/* RFC 1094, section '2.2 Server Procedures' */
#[repr(u32)]
#[derive(EnumStringU32)]
#[allow(non_camel_case_types)]
pub enum NfsProc2 {
    NULL = 0,
    GETATTR = 1,
    SETATTR = 2,
    ROOT = 3,
    LOOKUP = 4,
    READLINK = 5,
    READ = 6,
    WRITECACHE = 7,
    WRITE = 8,
    CREATE = 9,
    REMOVE = 10,
    RENAME = 11,
    LINK = 12,
    SYMLINK = 13,
    MKDIR = 14,
    RMDIR = 15,
    READDIR = 16,
    STATFS = 17,
}

/* RFC 1094, section '2.2 Server Procedures' -- note the v2 opcode
 * space differs from v3 (e.g. LOOKUP is 4 in v2, 3 in v3; WRITE is 8
 * in v2, 7 in v3). The v2 state machine must match these, not the
 * NFSPROC3_* values. */
pub const NFSPROC2_NULL: u32 = 0;
pub const NFSPROC2_GETATTR: u32 = 1;
pub const NFSPROC2_SETATTR: u32 = 2;
pub const NFSPROC2_ROOT: u32 = 3;
pub const NFSPROC2_LOOKUP: u32 = 4;
pub const NFSPROC2_READLINK: u32 = 5;
pub const NFSPROC2_READ: u32 = 6;
pub const NFSPROC2_WRITECACHE: u32 = 7;
pub const NFSPROC2_WRITE: u32 = 8;
pub const NFSPROC2_CREATE: u32 = 9;
pub const NFSPROC2_REMOVE: u32 = 10;
pub const NFSPROC2_RENAME: u32 = 11;
pub const NFSPROC2_LINK: u32 = 12;
pub const NFSPROC2_SYMLINK: u32 = 13;
pub const NFSPROC2_MKDIR: u32 = 14;
pub const NFSPROC2_RMDIR: u32 = 15;
pub const NFSPROC2_READDIR: u32 = 16;
pub const NFSPROC2_STATFS: u32 = 17;

/* RFC 1813, section '3. Server Procedures' */
pub const NFSPROC3_NULL: u32 = 0;
pub const NFSPROC3_GETATTR: u32 = 1;
pub const NFSPROC3_SETATTR: u32 = 2;
pub const NFSPROC3_LOOKUP: u32 = 3;
pub const NFSPROC3_ACCESS: u32 = 4;
pub const NFSPROC3_READLINK: u32 = 5;
pub const NFSPROC3_READ: u32 = 6;
pub const NFSPROC3_WRITE: u32 = 7;
pub const NFSPROC3_CREATE: u32 = 8;
pub const NFSPROC3_MKDIR: u32 = 9;
pub const NFSPROC3_SYMLINK: u32 = 10;
pub const NFSPROC3_MKNOD: u32 = 11;
pub const NFSPROC3_REMOVE: u32 = 12;
pub const NFSPROC3_RMDIR: u32 = 13;
pub const NFSPROC3_RENAME: u32 = 14;
pub const NFSPROC3_LINK: u32 = 15;
pub const NFSPROC3_READDIR: u32 = 16;
pub const NFSPROC3_READDIRPLUS: u32 = 17;
pub const NFSPROC3_FSSTAT: u32 = 18;
pub const NFSPROC3_FSINFO: u32 = 19;
pub const NFSPROC3_PATHCONF: u32 = 20;
pub const NFSPROC3_COMMIT: u32 = 21;

#[repr(u32)]
#[derive(EnumStringU32)]
#[allow(non_camel_case_types)]
pub enum NfsProc3 {
    NULL = 0,
    GETATTR = 1,
    SETATTR = 2,
    LOOKUP = 3,
    ACCESS = 4,
    READLINK = 5,
    READ = 6,
    WRITE = 7,
    CREATE = 8,
    MKDIR = 9,
    SYMLINK = 10,
    MKNOD = 11,
    REMOVE = 12,
    RMDIR = 13,
    RENAME = 14,
    LINK = 15,
    READDIR = 16,
    READDIRPLUS = 17,
    FSSTAT = 18,
    FSINFO = 19,
    PATHCONF = 20,
    COMMIT = 21,
}

/* RFC 1813, section '2.6 Defined Error Numbers' */
pub const NFS3_OK: u32 = 0;
pub const NFS3ERR_PERM: u32 = 1;
pub const NFS3ERR_NOENT: u32 = 2;
pub const NFS3ERR_IO: u32 = 5;
pub const NFS3ERR_NXIO: u32 = 6;
pub const NFS3ERR_ACCES: u32 = 13;
pub const NFS3ERR_EXIST: u32 = 17;
pub const NFS3ERR_XDEV: u32 = 18;
pub const NFS3ERR_NODEV: u32 = 19;
pub const NFS3ERR_NOTDIR: u32 = 20;
pub const NFS3ERR_ISDIR: u32 = 21;
pub const NFS3ERR_INVAL: u32 = 22;
pub const NFS3ERR_FBIG: u32 = 27;
pub const NFS3ERR_NOSPC: u32 = 28;
pub const NFS3ERR_ROFS: u32 = 30;
pub const NFS3ERR_MLINK: u32 = 31;
pub const NFS3ERR_NAMETOOLONG: u32 = 63;
pub const NFS3ERR_NOTEMPTY: u32 = 66;
pub const NFS3ERR_DQUOT: u32 = 69;
pub const NFS3ERR_STALE: u32 = 70;
pub const NFS3ERR_REMOTE: u32 = 71;
pub const NFS3ERR_BADHANDLE: u32 = 10001;
pub const NFS3ERR_NOT_SYNC: u32 = 10002;
pub const NFS3ERR_BAD_COOKIE: u32 = 10003;
pub const NFS3ERR_NOTSUPP: u32 = 10004;
pub const NFS3ERR_TOOSMALL: u32 = 10005;
pub const NFS3ERR_SERVERFAULT: u32 = 10006;
pub const NFS3ERR_BADTYPE: u32 = 10007;
pub const NFS3ERR_JUKEBOX: u32 = 10008;

pub fn nfs3_status_string(status: u32) -> String {
    match status {
        NFS3_OK => "OK",
        NFS3ERR_PERM => "ERR_PERM",
        NFS3ERR_NOENT => "ERR_NOENT",
        NFS3ERR_IO => "ERR_IO",
        NFS3ERR_NXIO => "ERR_NXIO",
        NFS3ERR_ACCES => "ERR_ACCES",
        NFS3ERR_EXIST => "ERR_EXIST",
        NFS3ERR_XDEV => "ERR_XDEV",
        NFS3ERR_NODEV => "ERR_NODEV",
        NFS3ERR_NOTDIR => "ERR_NOTDIR",
        NFS3ERR_ISDIR => "ERR_ISDIR",
        NFS3ERR_INVAL => "ERR_INVAL",
        NFS3ERR_FBIG => "ERR_FBIG",
        NFS3ERR_NOSPC => "ERR_NOSPC",
        NFS3ERR_ROFS => "ERR_ROFS",
        NFS3ERR_MLINK => "ERR_MLINK",
        NFS3ERR_NAMETOOLONG => "ERR_NAMETOOLONG",
        NFS3ERR_NOTEMPTY => "ERR_NOTEMPTY",
        NFS3ERR_DQUOT => "ERR_DQUOT",
        NFS3ERR_STALE => "ERR_STALE",
        NFS3ERR_REMOTE => "ERR_REMOTE",
        NFS3ERR_BADHANDLE => "ERR_BADHANDLE",
        NFS3ERR_NOT_SYNC => "ERR_NOT_SYNC",
        NFS3ERR_BAD_COOKIE => "ERR_BAD_COOKIE",
        NFS3ERR_NOTSUPP => "ERR_NOTSUPP",
        NFS3ERR_TOOSMALL => "ERR_TOOSMALL",
        NFS3ERR_SERVERFAULT => "ERR_SERVERFAULT",
        NFS3ERR_BADTYPE => "ERR_BADTYPE",
        NFS3ERR_JUKEBOX => "ERR_JUKEBOX",
        _ => {
            return (status).to_string();
        }
    }
    .to_string()
}

// NFSv4 (RFC 7530, section 13.1 "Error Definitions") defines its own
// error number space. It reuses the NFSv3 values for the common errors
// but diverges in the 10000s (e.g. 10008 is DELAY in v4 but JUKEBOX in
// v3, and v4 adds SAME/DENIED/EXPIRED/... down to 10048). A v4 status
// must therefore not be named from the v3 table.
pub fn nfs4_status_string(status: u32) -> String {
    match status {
        0 => "OK",
        1 => "ERR_PERM",
        2 => "ERR_NOENT",
        5 => "ERR_IO",
        6 => "ERR_NXIO",
        13 => "ERR_ACCESS",
        17 => "ERR_EXIST",
        18 => "ERR_XDEV",
        20 => "ERR_NOTDIR",
        21 => "ERR_ISDIR",
        22 => "ERR_INVAL",
        27 => "ERR_FBIG",
        28 => "ERR_NOSPC",
        30 => "ERR_ROFS",
        31 => "ERR_MLINK",
        63 => "ERR_NAMETOOLONG",
        66 => "ERR_NOTEMPTY",
        69 => "ERR_DQUOT",
        70 => "ERR_STALE",
        10001 => "ERR_BADHANDLE",
        10003 => "ERR_BAD_COOKIE",
        10004 => "ERR_NOTSUPP",
        10005 => "ERR_TOOSMALL",
        10006 => "ERR_SERVERFAULT",
        10007 => "ERR_BADTYPE",
        10008 => "ERR_DELAY",
        10009 => "ERR_SAME",
        10010 => "ERR_DENIED",
        10011 => "ERR_EXPIRED",
        10012 => "ERR_LOCKED",
        10013 => "ERR_GRACE",
        10014 => "ERR_FHEXPIRED",
        10015 => "ERR_SHARE_DENIED",
        10016 => "ERR_WRONGSEC",
        10017 => "ERR_CLID_INUSE",
        10018 => "ERR_RESOURCE",
        10019 => "ERR_MOVED",
        10020 => "ERR_NOFILEHANDLE",
        10021 => "ERR_MINOR_VERS_MISMATCH",
        10022 => "ERR_STALE_CLIENTID",
        10023 => "ERR_STALE_STATEID",
        10024 => "ERR_OLD_STATEID",
        10025 => "ERR_BAD_STATEID",
        10026 => "ERR_BAD_SEQID",
        10027 => "ERR_NOT_SAME",
        10028 => "ERR_LOCK_RANGE",
        10029 => "ERR_SYMLINK",
        10030 => "ERR_RESTOREFH",
        10031 => "ERR_LEASE_MOVED",
        10032 => "ERR_ATTRNOTSUPP",
        10033 => "ERR_NO_GRACE",
        10034 => "ERR_RECLAIM_BAD",
        10035 => "ERR_RECLAIM_CONFLICT",
        10036 => "ERR_BADXDR",
        10037 => "ERR_LOCKS_HELD",
        10038 => "ERR_OPENMODE",
        10039 => "ERR_BADOWNER",
        10040 => "ERR_BADCHAR",
        10041 => "ERR_BADNAME",
        10042 => "ERR_BAD_RANGE",
        10043 => "ERR_LOCK_NOTSUPP",
        10044 => "ERR_OP_ILLEGAL",
        10045 => "ERR_DEADLOCK",
        10046 => "ERR_FILE_OPEN",
        10047 => "ERR_ADMIN_REVOKED",
        10048 => "ERR_CB_PATH_DOWN",
        _ => {
            return (status).to_string();
        }
    }
    .to_string()
}

pub const RPCMSG_ACCEPTED: u32 = 0;
pub const RPCMSG_DENIED: u32 = 1;

pub fn rpc_status_string(status: u32) -> String {
    match status {
        RPCMSG_ACCEPTED => "ACCEPTED",
        RPCMSG_DENIED => "DENIED",
        _ => {
            return (status).to_string();
        }
    }
    .to_string()
}

/* http://www.iana.org/assignments/rpc-authentication-numbers/rpc-authentication-numbers.xhtml */
/* RFC 1057 Section 7.2 */
/* RFC 2203 Section 3 */

pub const RPCAUTH_NULL: u32 = 0;
pub const RPCAUTH_UNIX: u32 = 1;
pub const RPCAUTH_SHORT: u32 = 2;
pub const RPCAUTH_DH: u32 = 3;
pub const RPCAUTH_KERB: u32 = 4;
pub const RPCAUTH_RSA: u32 = 5;
pub const RPCAUTH_GSS: u32 = 6;

pub fn rpc_auth_type_string(auth_type: u32) -> String {
    match auth_type {
        RPCAUTH_NULL => "NULL",
        RPCAUTH_UNIX => "UNIX",
        RPCAUTH_SHORT => "SHORT",
        RPCAUTH_DH => "DH",
        RPCAUTH_KERB => "KERB",
        RPCAUTH_RSA => "RSA",
        RPCAUTH_GSS => "GSS",
        _ => {
            return (auth_type).to_string();
        }
    }
    .to_string()
}

pub fn rpc_auth_type_known(auth_type: u32) -> i8 {
    // RPCAUTH_GSS is the maximum
    if auth_type <= RPCAUTH_GSS {
        return 1;
    }
    return -1;
}

pub const NFSPROC4_NULL: u32 = 0;
pub const NFSPROC4_COMPOUND: u32 = 1;
/* ops */
pub const NFSPROC4_ACCESS: u32 = 3;
pub const NFSPROC4_CLOSE: u32 = 4;
pub const NFSPROC4_COMMIT: u32 = 5;
pub const NFSPROC4_CREATE: u32 = 6;
pub const NFSPROC4_DELEGPURGE: u32 = 7;
pub const NFSPROC4_DELEGRETURN: u32 = 8;
pub const NFSPROC4_GETATTR: u32 = 9;
pub const NFSPROC4_GETFH: u32 = 10;
pub const NFSPROC4_LINK: u32 = 11;
pub const NFSPROC4_LOCK: u32 = 12;
pub const NFSPROC4_LOCKT: u32 = 13;
pub const NFSPROC4_LOCKU: u32 = 14;
pub const NFSPROC4_LOOKUP: u32 = 15;
pub const NFSPROC4_LOOKUPP: u32 = 16;
pub const NFSPROC4_NVERIFY: u32 = 17;
pub const NFSPROC4_OPEN: u32 = 18;
pub const NFSPROC4_OPENATTR: u32 = 19;
pub const NFSPROC4_OPEN_CONFIRM: u32 = 20;
pub const NFSPROC4_OPEN_DOWNGRADE: u32 = 21;
pub const NFSPROC4_PUTFH: u32 = 22;
pub const NFSPROC4_PUTPUBFH: u32 = 23;
pub const NFSPROC4_PUTROOTFH: u32 = 24;
pub const NFSPROC4_READ: u32 = 25;
pub const NFSPROC4_READDIR: u32 = 26;
pub const NFSPROC4_READLINK: u32 = 27;
pub const NFSPROC4_REMOVE: u32 = 28;
pub const NFSPROC4_RENAME: u32 = 29;
pub const NFSPROC4_RENEW: u32 = 30;
pub const NFSPROC4_RESTOREFH: u32 = 31;
pub const NFSPROC4_SAVEFH: u32 = 32;
pub const NFSPROC4_SECINFO: u32 = 33;
pub const NFSPROC4_SETATTR: u32 = 34;
pub const NFSPROC4_SETCLIENTID: u32 = 35;
pub const NFSPROC4_SETCLIENTID_CONFIRM: u32 = 36;
pub const NFSPROC4_VERIFY: u32 = 37;
pub const NFSPROC4_WRITE: u32 = 38;
pub const NFSPROC4_RELEASE_LOCKOWNER: u32 = 39;
pub const NFSPROC4_EXCHANGE_ID: u32 = 42;
pub const NFSPROC4_CREATE_SESSION: u32 = 43;
pub const NFSPROC4_DESTROY_SESSION: u32 = 44;
pub const NFSPROC4_GETDEVINFO: u32 = 47;
pub const NFSPROC4_LAYOUTGET: u32 = 50;
pub const NFSPROC4_LAYOUTRETURN: u32 = 51;
pub const NFSPROC4_SECINFO_NO_NAME: u32 = 52;
pub const NFSPROC4_SEQUENCE: u32 = 53;
pub const NFSPROC4_DESTROY_CLIENTID: u32 = 57;
pub const NFSPROC4_RECLAIM_COMPLETE: u32 = 58;

pub const NFSPROC4_ILLEGAL: u32 = 10044;

#[repr(u32)]
#[derive(EnumStringU32)]
#[allow(non_camel_case_types)]
pub enum NfsProc4 {
    NULL = 0,
    COMPOUND = 1,
    ACCESS = 3,
    CLOSE = 4,
    COMMIT = 5,
    CREATE = 6,
    DELEGPURGE = 7,
    DELEGRETURN = 8,
    GETATTR = 9,
    GETFH = 10,
    LINK = 11,
    LOCK = 12,
    LOCKT = 13,
    LOCKU = 14,
    LOOKUP = 15,
    LOOKUPP = 16,
    NVERIFY = 17,
    OPEN = 18,
    OPENATTR = 19,
    OPEN_CONFIRM = 20,
    OPEN_DOWNGRADE = 21,
    PUTFH = 22,
    PUTPUBFH = 23,
    PUTROOTFH = 24,
    READ = 25,
    READDIR = 26,
    READLINK = 27,
    REMOVE = 28,
    RENAME = 29,
    RENEW = 30,
    RESTOREFH = 31,
    SAVEFH = 32,
    SECINFO = 33,
    SETATTR = 34,
    SETCLIENTID = 35,
    SETCLIENTID_CONFIRM = 36,
    VERIFY = 37,
    WRITE = 38,
    RELEASE_LOCKOWNER = 39,
    EXCHANGE_ID = 42,
    CREATE_SESSION = 43,
    DESTROY_SESSION = 44,
    GETDEVINFO = 47,
    LAYOUTGET = 50,
    LAYOUTRETURN = 51,
    SECINFO_NO_NAME = 52,
    SEQUENCE = 53,
    DESTROY_CLIENTID = 57,
    RECLAIM_COMPLETE = 58,
    ILLEGAL = 10044,
}

pub const NFS4_OK: u32 = 0;

pub(super) fn nfs_is_read(version: u16, proc: u32) -> bool {
    match version {
        2 => proc == (NfsProc2::READ as u32),
        3 => proc == (NfsProc3::READ as u32),
        4 => proc == (NfsProc4::READ as u32),
        _ => false,
    }
}

pub(super) fn nfs_is_write(version: u16, proc: u32) -> bool {
    match version {
        2 => proc == (NfsProc2::WRITE as u32),
        3 => proc == (NfsProc3::WRITE as u32),
        4 => proc == (NfsProc4::WRITE as u32),
        _ => false,
    }
}

pub(super) fn nfs_is_rename(version: u16, proc: u32) -> bool {
    match version {
        2 => proc == (NfsProc2::RENAME as u32),
        3 => proc == (NfsProc3::RENAME as u32),
        4 => proc == (NfsProc4::RENAME as u32),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nfs4_status_string() {
        assert_eq!(nfs4_status_string(0), "OK");
        assert_eq!(nfs4_status_string(1), "ERR_PERM");
        assert_eq!(nfs4_status_string(70), "ERR_STALE");
        // the v3/v4 divergence: 10008 is DELAY in v4, JUKEBOX in v3
        assert_eq!(nfs4_status_string(10008), "ERR_DELAY");
        assert_eq!(nfs3_status_string(10008), "ERR_JUKEBOX");
        assert_eq!(nfs4_status_string(10048), "ERR_CB_PATH_DOWN");
        // undefined value falls back to the numeric string
        assert_eq!(nfs4_status_string(10049), "10049");
    }
}
