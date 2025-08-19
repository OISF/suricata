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

// Author: Shivani Bhardwaj <shivani@oisf.net>

use itertools::iproduct;
use petgraph::algo::is_cyclic_directed;
use petgraph::graph::{DiGraph, IndexType, NodeIndex};
use petgraph::visit::Bfs;
use petgraph::{Direction, Graph};
use std::collections::HashMap;
use std::os::raw::c_void;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
struct SCGNode {
    iid: u32,        /* signature iid or flowbits iid */
    ntype: bool,     /* node type: Signature (0), Flowbit (1) */
    cmd: bool,       /* only used by flowbits; 0: READ, 1: WRITE */
    nidx: NodeIndex, /*  */
}

#[no_mangle]
pub unsafe extern "C" fn SCCreateDirectedGraph() -> *mut c_void {
    let graph: DiGraph<SCGNode, ()> = Graph::new();
    let boxed_graph = Box::new(graph);
    return Box::into_raw(boxed_graph) as *mut c_void;
}

#[no_mangle]
pub unsafe extern "C" fn SCCreateNodeEdgeDirectedGraph(
    graph: *mut c_void, iid: u32, ntype: bool, cmd: bool, sig_gid: u32,
) -> u32 {
    let graph = graph as *mut DiGraph<SCGNode, ()>;
    let mut g = (*graph).clone();
    let mut nd = SCGNode {
        iid: iid,
        ntype: ntype,
        cmd: cmd,
        nidx: NodeIndex::new(sig_gid as usize),
    };
    let nidx = g.add_node(nd);
    nd.nidx = nidx;

    let sidx = NodeIndex::new(sig_gid as usize);
    if ntype == true {
        /* It's a flowbit type node */
        if cmd == true {
            /* WRITE command */
            g.add_edge(sidx, nd.nidx, ()); /* edge from signature to flowbit */
        } else {
            g.add_edge(nd.nidx, sidx, ()); /* edge from flowbit to signature */
        }
    }
    nd.nidx.index() as u32
}

#[no_mangle]
pub unsafe extern "C" fn SCResolveFlowbitDependencies(
    graph: *mut std::os::raw::c_void, sorted_sid_list: *mut u32, sorted_sid_list_len: u32,
) {
    let graph = graph as *mut DiGraph<SCGNode, ()>;
    let mut g = (*graph).clone();
    normalize_graph(&mut g);
    if is_cyclic_directed(&g) {
        return;
    }
    let sorted_sid_list =
        std::slice::from_raw_parts_mut(&mut *sorted_sid_list, sorted_sid_list_len as usize);
    bfs_tree_dag(&mut g, sorted_sid_list);
}

fn normalize_graph(g: &mut Graph<SCGNode, ()>) {
    let mut map_new_edges: Vec<(NodeIndex, NodeIndex)> = Vec::new();
    let mut fb_nodes_list: Vec<SCGNode> = Vec::new();

    for nd in g.node_weights() {
        println!("Node: iid={}, ntype:{}, cmd={}", nd.iid, nd.ntype, nd.cmd);
        if nd.ntype == true {
            let in_edges: Vec<NodeIndex> =
                g.neighbors_directed(nd.nidx, Direction::Incoming).collect();

            let out_edges: Vec<NodeIndex> =
                g.neighbors_directed(nd.nidx, Direction::Outgoing).collect();

            let map_edges_curnode: Vec<(NodeIndex, NodeIndex)> =
                iproduct!(in_edges, out_edges).collect();
            map_new_edges.extend(map_edges_curnode);
        }
        fb_nodes_list.push(*nd);
    }

    for (from, to) in map_new_edges {
        if !g.find_edge(from, to).is_some() {
            g.add_edge(from, to, ());
        }
    }

    for node in fb_nodes_list {
        g.remove_node(node.nidx);
    }
}

fn calculate_in_degree_nodes(
    g: &mut Graph<SCGNode, ()>, in_degrees: &mut HashMap<NodeIndex, usize>,
) {
    for node_idx in g.node_indices() {
        let in_degree = g.neighbors_directed(node_idx, Direction::Incoming).count();
        in_degrees.insert(node_idx, in_degree);
    }
}

fn bfs_tree_dag(g: &mut Graph<SCGNode, ()>, sorted_sid_list: &mut [u32]) {
    let mut dummy = SCGNode {
        iid: u32::MAX,
        ntype: false,
        cmd: false,
        nidx: NodeIndex::new(IndexType::max()),
    };

    let nidx = g.add_node(dummy);
    dummy.nidx = nidx;

    let mut in_degrees: HashMap<NodeIndex, usize> = HashMap::new();

    calculate_in_degree_nodes(g, &mut in_degrees);
    for (node_idx, in_degree) in in_degrees {
        if in_degree == 0 {
            //            let mut node = &g[node_idx];
            //            debug_validate_bug_on!(node.ntype == true);
            g.add_edge(dummy.nidx, node_idx, ());
        }
    }

    let mut bfs = Bfs::new(&*g, dummy.nidx);
    let mut i = 0;

    while let Some(nidx) = bfs.next(&*g) {
        sorted_sid_list[i] = g[nidx].iid;
        i += 1;
    }
}
