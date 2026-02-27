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
use petgraph::algo::{is_cyclic_directed, tarjan_scc};
use petgraph::graph::{GraphError, NodeIndex};
use petgraph::stable_graph::StableDiGraph;
use petgraph::visit::Bfs;
use petgraph::Direction;
use std::collections::HashMap;
use std::os::raw::c_void;


/// Special Graph Node storing flowbit or signature
#[derive(Debug, Copy, Clone)]
struct SCGNode {
    iid: u32,        /* signature iid or flowbits iid (in VarNameStore) */
    ntype: bool,     /* node type: Signature (0), Flowbit (1) */
    nidx: NodeIndex, /* Graph's internal node index */
}

/// Function to create an empty directed Graph
#[no_mangle]
pub unsafe extern "C" fn SCCreateDirectedGraph() -> *mut c_void {
    // StableDiGraph is the ideal choice here for there is removal of
    // nodes in the line later and this type of graph guarantees to
    // not re-use any existing node indices
    let graph: StableDiGraph<SCGNode, u8> = StableDiGraph::new();
    let boxed_graph = Box::new(graph);

    /* Make an opaque pointer for C as nothing is changed there */
    return Box::into_raw(boxed_graph) as *mut c_void;
}

/// Drop the directed Graph. Called from C.
#[no_mangle]
pub unsafe extern "C" fn SCFreeDirectedGraph(graph: *mut c_void) {
    let _ = Box::from_raw(graph as *mut StableDiGraph<SCGNode, u8>);
}

/// Function to get or create a node and add an appropriate directed
/// edge based on its type
#[no_mangle]
pub unsafe extern "C" fn SCCreateNodeEdgeDirectedGraph(
    graph: *mut c_void, iid: u32, ntype: bool, write_cmd: bool, cmd: u8, sig_gid: u32,
) -> i64 {
    let g = &mut *(graph as *mut StableDiGraph<SCGNode, u8>);

    let node_idx;
    if let Some(nidx) = get_or_create_node(g, iid, ntype) {
        node_idx = nidx;
    } else {
        SCLogError!("Error adding node; Graph is at full capacity");
        return -2;
    }

    let sidx = NodeIndex::from(sig_gid);

    if !ntype {
        SCLogNotice!("Node type is not flowbit");
        return node_idx.index() as i64;
    }

    /* flowbit type node */
    if write_cmd {
        /* WRITE command */
        match g.try_update_edge(sidx, node_idx, cmd) {
            /* edge from signature to flowbit */
            Ok(_) => {
                SCLogNotice!("Created an edge from {:?} -> {:?}", sidx, node_idx);
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
        match g.try_update_edge(node_idx, sidx, cmd) {
            /* edge from flowbit to signature */
            Ok(_) => {
                SCLogNotice!("Created an edge from {:?} -> {:?}", sidx, node_idx);
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

    SCLogNotice!("node count: {:?}", g.node_count());
    node_idx.index() as i64
}

/// Recursive fn to find a valid cycle and update the graph
/// STODO what is the time complexity of this entire algorithm now with so
/// much of fluff?
fn check_cycle_update_graph(graph: &mut StableDiGraph<SCGNode, u8>) -> i8
{
    let mut nodes: Vec<Vec<NodeIndex>> = Vec::new();
    /* Check graph for any cycles */
    if !is_cyclic_directed(&graph.clone()) {
        SCLogNotice!("no cycles");
        return 0;
    } else {
        SCLogNotice!("Found a cycle. Checking if its valid..");
        let sccs = tarjan_scc(&*graph);
        // find all strongly connected components of the graph
        for scc in sccs.iter().filter(|scc| scc.len() > 1) {
            SCLogNotice!("Cycle nodes: {:?}", scc);
            nodes.push(scc.to_vec());
            // STODO what if it's a big cycle? can that happen?
        }
    }
    for scc in nodes {
        for np in scc.windows(2) { // STODO make a test with cycle formed b/w 5 nodes
            if let [a, b] = np {
                // STODO BEWARE, this is only correct for cycle b/w two nodes
                if let Some(e1) = graph.find_edge(*a, *b) {
                    if let Some(e2) = graph.find_edge(*b, *a) {
                        let w1 = graph.edge_weight(e1).unwrap(); // STODO is this safe?
                        let w2 = graph.edge_weight(e2).unwrap(); // STODO is this safe?
                        if w1 == w2 {
                            debug_validate_bug_on!(*w1 == (1 << 7));
                            // It's a cycle of same commands and must be rejected
                            return -1;
                        } else {
                            // Remove the edge with higher weight (so lower priority)
                            if *w1 > *w2 {
                                graph.remove_edge(e1);
                            } else {
                                graph.remove_edge(e2);
                            }
                        }
                    }
                }

            }
        }
    }

    // Call the fn again for multiple cycles STODO add tests
    check_cycle_update_graph(graph)
}


/// Wrapper function to resolve flowbit dependencies
#[no_mangle]
pub unsafe extern "C" fn SCResolveFlowbitDependencies(
    graph: *mut c_void, sorted_sid_list: *mut u32, sorted_sid_list_len: u32,
) -> i8 {
    let g = &mut *(graph as *mut StableDiGraph<SCGNode, u8>);

    debug_validate_bug_on!(g.node_count() == 0);

    /* Create a signature only directed graph */
    normalize_graph(g);

    let sorted_sid_list =
        std::slice::from_raw_parts_mut(&mut *sorted_sid_list, sorted_sid_list_len as usize);

    /* No need for all the extra work if there's just one node */
    if g.node_count() == 1 {
        debug_validate_bug_on!(sorted_sid_list_len != 1);
        sorted_sid_list[0] = g[NodeIndex::from(0)].iid;
        /* Given that first a signature is added, it is guaranteed
         * that 0th node must always be a signature node */
        debug_validate_bug_on!(g[NodeIndex::from(0)].ntype);
        return 0;
    }

    if check_cycle_update_graph(g) == -1 {
        // Couldn't do anything to fix the graph, it's a legit cycle
        return -1;
    }

    /* At this point, it must be a DAG, so perform a BFS on the tree to find
     * out the correct order of signatures */
    return bfs_tree_dag(g, sorted_sid_list);
}

fn get_or_create_node(
    g: &mut StableDiGraph<SCGNode, u8>, iid: u32, ntype: bool,
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
        SCLogNotice!("Created node: {:?}", g[idx]);
        return Some(idx);
    }

    None
}

/// Function to create a dependency graph among signatures
/// A map of all the edges is created and then flowbit nodes
/// are eliminated while creating a direct directed edge between
/// the signature nodes connected by the flowbit node
fn normalize_graph(g: &mut StableDiGraph<SCGNode, u8>) {
    let mut map_new_edges: Vec<(NodeIndex, Vec<(NodeIndex, NodeIndex)>)> = Vec::new();
    let mut fb_nodes_list: Vec<SCGNode> = Vec::new();

    for nd in g.node_weights() {
        if nd.ntype {
            let in_edges: Vec<NodeIndex> =
                g.neighbors_directed(nd.nidx, Direction::Incoming).collect();

            let out_edges: Vec<NodeIndex> =
                g.neighbors_directed(nd.nidx, Direction::Outgoing).collect();

            let map_edges_curnode: Vec<(NodeIndex, NodeIndex)> =
                iproduct!(in_edges, out_edges).collect();
            map_new_edges.push((nd.nidx, map_edges_curnode));
            fb_nodes_list.push(*nd);
        }
    }

    for (fb_nd, sig_nds) in map_new_edges {
        SCLogNotice!("map_new_edges -- from: {:?}; to: {:?}", fb_nd, sig_nds);
        for nd in sig_nds {
            let mut nweight = 0;
            if let Some(ei) = g.find_edge(fb_nd, nd.0) {
                if let Some(w) = g.edge_weight(ei) {
                    nweight |= 1 << w;
                }
            }
            if let Some(ei) = g.find_edge(fb_nd, nd.1) {
                if let Some(w) = g.edge_weight(ei) {
                    nweight |= 1 << w;
                }
            }
            debug_validate_bug_on!(nweight == 0);
            g.add_edge(nd.0, nd.1, nweight);
        }
    }

    for node in fb_nodes_list {
        SCLogNotice!("Removing node {:?}", node);
        /* Only flowbit nodes must be removed from the graph */
        debug_validate_bug_on!(!node.ntype);
        g.remove_node(node.nidx);
    }
}

fn calculate_in_degree_nodes(
    g: &mut StableDiGraph<SCGNode, u8>, in_degrees: &mut HashMap<NodeIndex, usize>,
) {
    for node_idx in g.node_indices() {
        let in_degree = g.neighbors_directed(node_idx, Direction::Incoming).count();
        SCLogNotice!("in_degree for node {:?}: {:?}", g[node_idx], in_degree);
        in_degrees.insert(node_idx, in_degree);
    }
}

/// Perform a BFS (Breadth First Search) of the DAG (Directed Acyclic Graph)
fn bfs_tree_dag(g: &mut StableDiGraph<SCGNode, u8>, sorted_sid_list: &mut [u32]) -> i8 {
    let mut in_degrees: HashMap<NodeIndex, usize> = HashMap::new();
    calculate_in_degree_nodes(g, &mut in_degrees);

    let nidx;
    if let Some(idx) = get_or_create_node(g, u32::MAX, false) {
        nidx = idx;
    } else {
        SCLogError!("Error adding node; Graph is at full capacity");
        return -1;
    }

    /* Connect all the loner nodes to the dummy node so as to create a discoverable
     * path and a connected tree to perform a BFS */
    for (node_idx, in_degree) in in_degrees {
        if in_degree == 0 {
            SCLogNotice!("added edge from {:?} -> {:?}", nidx, node_idx);
            g.add_edge(nidx, node_idx, 1 << 7);
        }
    }

    let mut bfs = Bfs::new(&*g, nidx);
    let mut i = 0;

    SCLogNotice!("BFS of the graph:");
    while let Some(idx) = bfs.next(&*g) {
        /* Don't add dummy node to the graph */
        if idx != nidx {
            SCLogNotice!("[{:?}]: {:?}", i, g[idx]);
            sorted_sid_list[i] = g[idx].iid;
            i += 1;
        }
    }
    0
}
