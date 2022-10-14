/* Copyright (C) 2018-2020 Open Information Security Foundation
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

use crate::smb::smb::*;

impl SMBState {
    #[cfg(not(feature = "debug"))]
    pub fn _debug_tx_stats(&self) { }

    #[cfg(feature = "debug")]
    pub fn _debug_tx_stats(&self) {
        if self.transactions.len() > 1 {
            let txf = self.transactions.first().unwrap();
            let txl = self.transactions.last().unwrap();

            SCLogDebug!("TXs {} MIN {} MAX {}", self.transactions.len(), txf.id, txl.id);
            SCLogDebug!("- OLD tx.id {}: {:?}", txf.id, txf);
            SCLogDebug!("- NEW tx.id {}: {:?}", txl.id, txl);
            self._dump_txs();
        }
    }

    #[cfg(not(feature = "debug"))]
    pub fn _dump_txs(&self) { }
    #[cfg(feature = "debug")]
    pub fn _dump_txs(&self) {
        let len = self.transactions.len();
        for i in 0..len {
            let tx = &self.transactions[i];
            let ver = tx.vercmd.get_version();
            let _smbcmd = if ver == 2 {
                let (_, cmd) = tx.vercmd.get_smb2_cmd();
                cmd
            } else {
                let (_, cmd) = tx.vercmd.get_smb1_cmd();
                cmd as u16
            };

            match tx.type_data {
                Some(SMBTransactionTypeData::FILE(ref d)) => {
                    SCLogDebug!("idx {} tx id {} progress {}/{} filename {} type_data {:?}",
                            i, tx.id, tx.request_done, tx.response_done,
                            String::from_utf8_lossy(&d.file_name), tx.type_data);
                },
                _ => {
                    SCLogDebug!("idx {} tx id {} ver:{} cmd:{} progress {}/{} type_data {:?} tx {:?}",
                            i, tx.id, ver, _smbcmd, tx.request_done, tx.response_done, tx.type_data, tx);
                },
            }
        }
    }

    #[cfg(not(feature = "debug"))]
    pub fn _debug_state_stats(&self) { }

    #[cfg(feature = "debug")]
    pub fn _debug_state_stats(&self) {
        SCLogDebug!("ssn2vec_map {} guid2name_map {} ssn2vecoffset_map {} ssn2tree_map {} ssnguid2vec_map {} file_ts_guid {} file_tc_guid {} transactions {}", self.ssn2vec_map.len(), self.guid2name_map.len(), self.ssn2vecoffset_map.len(), self.ssn2tree_map.len(), self.ssnguid2vec_map.len(), self.file_ts_guid.len(), self.file_tc_guid.len(), self.transactions.len());
    }
}
