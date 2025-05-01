/* Copyright (C) 2025 Open Information Security Foundation
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

// FTP state progress values
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum FtpStateValues {
    FTP_STATE_IN_PROGRESS,
    FTP_STATE_FINISHED,
}
// FTP Data progress values
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum FtpDataStateValues {
    FTPDATA_STATE_IN_PROGRESS,
    FTPDATA_STATE_FINISHED,
}

// FTP request command values
#[repr(u8)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
pub enum FtpRequestCommand {
    FTP_COMMAND_UNKNOWN,
    FTP_COMMAND_ABOR,
    FTP_COMMAND_ACCT,
    FTP_COMMAND_ALLO,
    FTP_COMMAND_APPE,
    FTP_COMMAND_AUTH_TLS,
    FTP_COMMAND_CDUP,
    FTP_COMMAND_CHMOD,
    FTP_COMMAND_CWD,
    FTP_COMMAND_DELE,
    FTP_COMMAND_EPSV,
    FTP_COMMAND_HELP,
    FTP_COMMAND_IDLE,
    FTP_COMMAND_LIST,
    FTP_COMMAND_MAIL,
    FTP_COMMAND_MDTM,
    FTP_COMMAND_MKD,
    FTP_COMMAND_MLFL,
    FTP_COMMAND_MODE,
    FTP_COMMAND_MRCP,
    FTP_COMMAND_MRSQ,
    FTP_COMMAND_MSAM,
    FTP_COMMAND_MSND,
    FTP_COMMAND_MSOM,
    FTP_COMMAND_NLST,
    FTP_COMMAND_NOOP,
    FTP_COMMAND_PASS,
    FTP_COMMAND_PASV,
    FTP_COMMAND_PORT,
    FTP_COMMAND_PWD,
    FTP_COMMAND_QUIT,
    FTP_COMMAND_REIN,
    FTP_COMMAND_REST,
    FTP_COMMAND_RETR,
    FTP_COMMAND_RMD,
    FTP_COMMAND_RNFR,
    FTP_COMMAND_RNTO,
    FTP_COMMAND_SITE,
    FTP_COMMAND_SIZE,
    FTP_COMMAND_SMNT,
    FTP_COMMAND_STAT,
    FTP_COMMAND_STOR,
    FTP_COMMAND_STOU,
    FTP_COMMAND_STRU,
    FTP_COMMAND_SYST,
    FTP_COMMAND_TYPE,
    FTP_COMMAND_UMASK,
    FTP_COMMAND_USER,
    FTP_COMMAND_EPRT,
}
