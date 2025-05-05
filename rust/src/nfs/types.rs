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

pub fn nfs3_procedure_string(procedure: u32) -> String {
    match procedure {
        NFSPROC3_NULL => "NULL",
        NFSPROC3_GETATTR => "GETATTR",
        NFSPROC3_SETATTR => "SETATTR",
        NFSPROC3_LOOKUP => "LOOKUP",
        NFSPROC3_ACCESS => "ACCESS",
        NFSPROC3_READLINK => "READLINK",
        NFSPROC3_READ => "READ",
        NFSPROC3_WRITE => "WRITE",
        NFSPROC3_CREATE => "CREATE",
        NFSPROC3_MKDIR => "MKDIR",
        NFSPROC3_SYMLINK => "SYMLINK",
        NFSPROC3_MKNOD => "MKNOD",
        NFSPROC3_REMOVE => "REMOVE",
        NFSPROC3_RMDIR => "RMDIR",
        NFSPROC3_RENAME => "RENAME",
        NFSPROC3_LINK => "LINK",
        NFSPROC3_READDIR => "READDIR",
        NFSPROC3_READDIRPLUS => "READDIRPLUS",
        NFSPROC3_FSSTAT => "FSSTAT",
        NFSPROC3_FSINFO => "FSINFO",
        NFSPROC3_PATHCONF => "PATHCONF",
        NFSPROC3_COMMIT => "COMMIT",
        _ => {
            return (procedure).to_string();
        }
    }
    .to_string()
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

pub fn nfs4_procedure_string(procedure: u32) -> String {
    match procedure {
        NFSPROC4_COMPOUND => "COMPOUND",
        NFSPROC4_NULL => "NULL",
        // ops
        NFSPROC4_ACCESS => "ACCESS",
        NFSPROC4_CLOSE => "CLOSE",
        NFSPROC4_COMMIT => "COMMIT",
        NFSPROC4_CREATE => "CREATE",
        NFSPROC4_DELEGPURGE => "DELEGPURGE",
        NFSPROC4_DELEGRETURN => "DELEGRETURN",
        NFSPROC4_GETATTR => "GETATTR",
        NFSPROC4_GETFH => "GETFH",
        NFSPROC4_LINK => "LINK",
        NFSPROC4_LOCK => "LOCK",
        NFSPROC4_LOCKT => "LOCKT",
        NFSPROC4_LOCKU => "LOCKU",
        NFSPROC4_LOOKUP => "LOOKUP",
        NFSPROC4_LOOKUPP => "LOOKUPP",
        NFSPROC4_NVERIFY => "NVERIFY",
        NFSPROC4_OPEN => "OPEN",
        NFSPROC4_OPENATTR => "OPENATTR",
        NFSPROC4_OPEN_CONFIRM => "OPEN_CONFIRM",
        NFSPROC4_OPEN_DOWNGRADE => "OPEN_DOWNGRADE",
        NFSPROC4_PUTFH => "PUTFH",
        NFSPROC4_PUTPUBFH => "PUTPUBFH",
        NFSPROC4_PUTROOTFH => "PUTROOTFH",
        NFSPROC4_READ => "READ",
        NFSPROC4_READDIR => "READDIR",
        NFSPROC4_READLINK => "READLINK",
        NFSPROC4_REMOVE => "REMOVE",
        NFSPROC4_RENAME => "RENAME",
        NFSPROC4_RENEW => "RENEW",
        NFSPROC4_RESTOREFH => "RESTOREFH",
        NFSPROC4_SAVEFH => "SAVEFH",
        NFSPROC4_SECINFO => "SECINFO",
        NFSPROC4_SETATTR => "SETATTR",
        NFSPROC4_SETCLIENTID => "SETCLIENTID",
        NFSPROC4_SETCLIENTID_CONFIRM => "SETCLIENTID_CONFIRM",
        NFSPROC4_VERIFY => "VERIFY",
        NFSPROC4_WRITE => "WRITE",
        NFSPROC4_RELEASE_LOCKOWNER => "RELEASE_LOCKOWNER",
        NFSPROC4_ILLEGAL => "ILLEGAL",
        _ => {
            return (procedure).to_string();
        }
    }
    .to_string()
}

pub const NFS4_OK: u32 = 0;
