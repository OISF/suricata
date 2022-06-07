// Copyright (C) 2022 Open Information Security Foundation
//
// You can copy, redistribute or modify this Program under the terms of
// the GNU General Public License version 2 as published by the Free
// Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// version 2 along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
// 02110-1301, USA.

use suricata_config::loader::load_from_file;
use suricata_config::loader::LoaderError;
use suricata_config::printer::print_node;

fn main() {
    let filename = std::env::args().nth(1).unwrap();
    match load_from_file(&filename) {
        Ok(docs) => {
            for doc in docs {
                print_node(&doc, vec![]);
            }
        }
        Err(err) => match err {
            LoaderError::YamlScanError { filename, source } => {
                println!("yaml parse error in file {:?}: {}", filename, source);
                std::process::exit(1);
            }
            _ => {
                panic!("Failed to load file: {:?}", err);
            }
        },
    }
}
