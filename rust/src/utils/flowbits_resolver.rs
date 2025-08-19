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
use petgraph::graph::{GraphError, NodeIndex};
use petgraph::stable_graph::StableDiGraph;
use petgraph::visit::Bfs;
use petgraph::Direction;
use std::collections::HashMap;
use std::os::raw::c_void;

#[derive(Debug, Copy, Clone)]
struct SCGNode {
    iid: u32,        /* signature iid or flowbits iid */
    ntype: bool,     /* node type: Signature (0), Flowbit (1) */
    nidx: NodeIndex, /* Graph's internal node index */
}

#[no_mangle]
pub unsafe extern "C" fn SCCreateDirectedGraph() -> *mut c_void {
    let graph: StableDiGraph<SCGNode, ()> = StableDiGraph::new();
    let boxed_graph = Box::new(graph);
    println!(
        "sizeof(StableDiGraph): {:?}",
        std::mem::size_of::<StableDiGraph<SCGNode, ()>>()
    );
    /* Make an opaque pointer for C as nothing is changed there */
    return Box::into_raw(boxed_graph) as *mut c_void;
}

#[no_mangle]
pub unsafe extern "C" fn SCFreeDirectedGraph(graph: *mut c_void) {
    let _ = Box::from_raw(graph as *mut StableDiGraph<SCGNode, ()>);
}

#[no_mangle]
pub unsafe extern "C" fn SCCreateNodeEdgeDirectedGraph(
    graph: *mut c_void, iid: u32, ntype: bool, cmd: bool, sig_gid: u32,
) -> i64 {
    let g = &mut *(graph as *mut StableDiGraph<SCGNode, ()>);

    let node_idx;
    if let Some(nidx) = get_or_create_node(g, iid, ntype) {
        node_idx = nidx;
    } else {
        SCLogError!("Error adding node; Graph is at full capacity");
        return -2;
    }

    let sidx = NodeIndex::from(sig_gid);

    if ntype {
        /* flowbit type node */
        if cmd {
            /* WRITE command */
            match g.try_update_edge(sidx, node_idx, ()) {
                /* edge from signature to flowbit */
                Ok(_) => {
                    println!("Created an edge from {:?} -> {:?}", sidx, node_idx);
                }
                Err(GraphError::EdgeIxLimit) => {
                    SCLogError!("Error adding edge; Graph is at full capacity");
                    return -2;
                }
                Err(GraphError::NodeOutBounds) => {
                    SCLogError!("Error adding edge; node does not exist");
                    return -2;
                }
                Err(_) => {
                    SCLogError!("Error adding edge to the Graph");
                    return -2;
                }
            }
        } else {
            match g.try_update_edge(node_idx, sidx, ()) {
                /* edge from flowbit to signature */
                Ok(_) => {
                    println!("Created an edge from {:?} -> {:?}", sidx, node_idx);
                }
                Err(GraphError::EdgeIxLimit) => {
                    SCLogError!("Error adding edge; Graph is at full capacity");
                    return -2;
                }
                Err(GraphError::NodeOutBounds) => {
                    SCLogError!("Error adding edge; node does not exist");
                    return -2;
                }
                Err(_) => {
                    SCLogError!("Error adding edge to the Graph");
                    return -2;
                }
            }
        }
    }

    println!("node count: {:?}", g.node_count());
    node_idx.index() as i64
}

#[no_mangle]
pub unsafe extern "C" fn SCResolveFlowbitDependencies(
    graph: *mut c_void, sorted_sid_list: *mut u32, sorted_sid_list_len: u32,
) {
    let g = &mut *(graph as *mut StableDiGraph<SCGNode, ()>);

    println!("Indices in the graph:");
    for i in g.node_indices() {
        println!("idx: {:?}", i);
    }
    for nd in g.node_weights() {
        println!("The beginning node: {:?}", nd);
    }

    debug_validate_bug_on!(g.node_count() == 0);

    let sorted_sid_list =
        std::slice::from_raw_parts_mut(&mut *sorted_sid_list, sorted_sid_list_len as usize);

    // No need for all the extra work if there's just one node
    if g.node_count() == 1 {
        debug_validate_bug_on!(sorted_sid_list_len != 1);
        sorted_sid_list[0] = g[NodeIndex::from(0)].iid;
        return;
    }

    normalize_graph(g);
    if is_cyclic_directed(&g.clone()) {
        return;
    }
    bfs_tree_dag(g, sorted_sid_list);
}

fn get_or_create_node(
    g: &mut StableDiGraph<SCGNode, ()>, iid: u32, ntype: bool,
) -> Option<NodeIndex> {
    for node in g.node_weights() {
        if node.iid == iid && node.ntype == ntype {
            return Some(node.nidx);
        }
    }
    let nd = SCGNode {
        iid,
        ntype,
        nidx: NodeIndex::from(u32::MAX),
    };
    if let Ok(idx) = g.try_add_node(nd) {
        g[idx].nidx = idx;
        println!("Created node: {:?}", g[idx]);
        return Some(idx);
    }

    None
}

fn normalize_graph(g: &mut StableDiGraph<SCGNode, ()>) {
    let mut map_new_edges: Vec<(NodeIndex, NodeIndex)> = Vec::new();
    let mut fb_nodes_list: Vec<SCGNode> = Vec::new();

    for nd in g.node_weights() {
        println!("Pre normalized node: {:?}", nd);
    }

    for nd in g.node_weights() {
        if nd.ntype {
            let in_edges: Vec<NodeIndex> =
                g.neighbors_directed(nd.nidx, Direction::Incoming).collect();

            let out_edges: Vec<NodeIndex> =
                g.neighbors_directed(nd.nidx, Direction::Outgoing).collect();

            let map_edges_curnode: Vec<(NodeIndex, NodeIndex)> =
                iproduct!(in_edges, out_edges).collect();
            map_new_edges.extend(map_edges_curnode);
            fb_nodes_list.push(*nd);
        }
    }

    for (from, to) in map_new_edges {
        if g.find_edge(from, to).is_none() {
            println!("map_new_edges -- from: {:?}; to: {:?}", from, to);
            g.add_edge(from, to, ());
        }
    }

    for node in fb_nodes_list {
        println!("Removing node {:?}", node);
        g.remove_node(node.nidx);
    }
}

fn calculate_in_degree_nodes(
    g: &mut StableDiGraph<SCGNode, ()>, in_degrees: &mut HashMap<NodeIndex, usize>,
) {
    for node_idx in g.node_indices() {
        let in_degree = g.neighbors_directed(node_idx, Direction::Incoming).count();
        println!("in_degree for node {:?}: {:?}", g[node_idx], in_degree);
        in_degrees.insert(node_idx, in_degree);
    }
}

fn bfs_tree_dag(g: &mut StableDiGraph<SCGNode, ()>, sorted_sid_list: &mut [u32]) {
    let mut in_degrees: HashMap<NodeIndex, usize> = HashMap::new();
    calculate_in_degree_nodes(g, &mut in_degrees);

    let nidx;
    if let Some(idx) = get_or_create_node(g, u32::MAX, false) {
        nidx = idx;
    } else {
        SCLogError!("Error adding node; Graph is at full capacity");
        return;
    }

    println!("node count: {:?}", g.node_count());
    for node in g.node_weights() {
        // There shouldn't be any flowbit nodes left at this point
        debug_validate_bug_on!(node.ntype != false);
        println!("FIN Node: {:?}", node);
    }

    for (node_idx, in_degree) in in_degrees {
        if in_degree == 0 {
            println!("added edge from {:?} -> {:?}", nidx, node_idx);
            g.add_edge(nidx, node_idx, ());
        }
    }

    let mut bfs = Bfs::new(&*g, nidx);
    let mut i = 0;

    println!("BFS of the graph:");
    while let Some(idx) = bfs.next(&*g) {
        if idx != nidx {
            println!("[{:?}]: {:?}", i, g[idx]);
            sorted_sid_list[i] = g[idx].iid;
            i += 1;
        }
    }
}
