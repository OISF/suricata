/* Copyright (C) 2026 Open Information Security Foundation
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

use petgraph::algo::{is_cyclic_directed, tarjan_scc};
use petgraph::graph::{GraphError, NodeIndex, EdgeIndex};
use petgraph::stable_graph::StableDiGraph;
use petgraph::visit::{Bfs, EdgeRef};
use petgraph::Direction;
use std::collections::{HashMap, HashSet};
use std::os::raw::c_void;
use crate::jsonbuilder::*;

/// Special Graph Node storing flowbit or signature
#[derive(Debug, Copy, Clone)]
struct SCGNode {
    sid: u32,
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

#[no_mangle]
pub unsafe extern "C" fn SCGetOrCreateNodeGraph(graph: *mut c_void, sid: u32) -> i64 {
    let g = &mut *(graph as *mut StableDiGraph<SCGNode, u8>);

    let node_idx;
    if let Some(nidx) = get_or_create_node(g, sid) {
        node_idx = nidx;
    } else {
        SCLogError!("Error adding node; Graph is at full capacity");
        return -2;
    }

    node_idx.index() as i64
}

/// Function to get or create a node and add an appropriate directed
/// edge based on its type
#[no_mangle]
pub unsafe extern "C" fn SCCreateNodeEdgeDirectedGraph(
    graph: *mut c_void, from: u32, to: u32, cmd: u8,
) -> i64 {
    let g = &mut *(graph as *mut StableDiGraph<SCGNode, u8>);

    let from_idx = NodeIndex::from(from);
    let to_idx = NodeIndex::from(to);

    match g.try_update_edge(from_idx, to_idx, cmd) {
        /* edge from signature to flowbit */
        Ok(e) => {
            SCLogDebug!("Created an edge from {:?} -> {:?} with weight: {:?}", from, to, cmd);
            let g = &mut *(graph as *mut StableDiGraph<SCGNode, u8>);
            if check_cycle_update_graph(g, e) == -1 {
                SCLogError!("Couldn't do anything to fix the graph. Retreating..");
                return -1;
            }
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

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCDebugLogFlowbitGraph(
    jsb: &mut JsonBuilder, graph: *mut c_void
) -> bool {
    let g = &mut *(graph as *mut StableDiGraph<SCGNode, u8>);
    log_graph(jsb, g).is_ok()
}

fn check_cycle_update_graph(graph: &mut StableDiGraph<SCGNode, u8>, cur_e: EdgeIndex) -> i8
{
    /* Check graph for any cycles */
    if !is_cyclic_directed(&graph.clone()) { /* O(V+E) */ //STODO is this clone ok?
        SCLogDebug!("no cycles");
        return 0;
    }

    SCLogDebug!("Found a cycle. Checking if its valid..");
    let sccs = tarjan_scc(&*graph); /* O(V+E) */
//    SCLogDebug!("All SCCs: {:?}", sccs);
    let mut edge_wts = Vec::new();
    // find all strongly connected components of the graph
    // Walk through each SCC
    let mut scc_set: HashSet<_> = HashSet::new();
    for scc in sccs {
        if scc.len() == 1 {
            // Skip single SCCs
            continue;
        }
        SCLogDebug!("Current scc: {:?}", scc);
        scc_set = scc.iter().copied().collect();
        for edge_idx in graph.edge_indices() {
            if let Some((src, tgt)) = graph.edge_endpoints(edge_idx) {
                if scc_set.contains(&src) && scc_set.contains(&tgt) {
                    let in_degree_src = graph.neighbors_directed(src, Direction::Incoming).count();
                    let in_degree_dst = graph.neighbors_directed(tgt, Direction::Incoming).count();
                    if in_degree_src > 1 { // there's another dependency to the cycle, remove the opposite edge
                        if let Some(ei) = graph.find_edge(tgt, src) {
                            graph.remove_edge(ei);
                            return 0;
                        }
                    } else if in_degree_dst > 1 {
                        if let Some(ei) = graph.find_edge(src, tgt) {
                            graph.remove_edge(ei);
                            return 0;
                        }
                    }
                    if let Some(weight) = graph.edge_weight(edge_idx) {
                        edge_wts.push(*weight);
                        SCLogDebug!("edge_wts updated to: {:?}", edge_wts);
                    }
                }
            }
        }
        /* break at the first cycle */
        break;
    }

    let mut seen = HashSet::new();
    let deduped_wts: Vec<u8> = edge_wts.into_iter().filter(|x| seen.insert(*x)).collect();
    SCLogDebug!("deduped_wts: {:?}", deduped_wts);

    debug_validate_bug_on!(deduped_wts.is_empty());
    /* This means that the cycle was created by edges of varying weights */
    if deduped_wts.len() > 1 {
        graph.remove_edge(cur_e);
        return 0;
    }

    /* all weights must exactly be the same for a valid cycle */
    debug_validate_bug_on!(deduped_wts.len() != 1);

    let sids: Vec<_> = scc_set.into_iter().map(|a| (graph[a].sid)).collect();
    SCLogError!("Cyclic dependency found between flowbits from signatures: {:?}", sids);
    return -1;
}


/// Wrapper function to resolve flowbit dependencies
#[no_mangle]
pub unsafe extern "C" fn SCResolveFlowbitDependencies(
    graph: *mut c_void, sorted_sid_list: *mut u32, sorted_sid_list_len: u32,
) -> i8 {
    let g = &mut *(graph as *mut StableDiGraph<SCGNode, u8>);

    debug_validate_bug_on!(g.node_count() == 0);

    let sorted_sid_list =
        std::slice::from_raw_parts_mut(&mut *sorted_sid_list, sorted_sid_list_len as usize);

    /* No need for all the extra work if there's just one node */
    if g.node_count() == 1 {
        debug_validate_bug_on!(sorted_sid_list_len != 1);
        sorted_sid_list[0] = g[NodeIndex::from(0)].sid;
        return 0;
    }

    /* At this point, it must be a DAG, so perform a BFS on the tree to find
     * out the correct order of signatures */
    return bfs_tree_dag(g, sorted_sid_list);
}

fn get_or_create_node(
    g: &mut StableDiGraph<SCGNode, u8>, sid: u32,
) -> Option<NodeIndex> {
    for node in g.node_weights() {
        if node.sid == sid {
            return Some(node.nidx);
        }
    }
    let nd = SCGNode {
        sid,
        nidx: NodeIndex::from(u32::MAX),
    };
    if let Ok(idx) = g.try_add_node(nd) { /* O(1) */
        g[idx].nidx = idx;
        SCLogDebug!("Created node: {:?}", g[idx]);
        return Some(idx);
    }

    None
}

fn calculate_in_degree_nodes(
    g: &mut StableDiGraph<SCGNode, u8>, in_degrees: &mut HashMap<NodeIndex, usize>,
) {
    for node_idx in g.node_indices() {
        let in_degree = g.neighbors_directed(node_idx, Direction::Incoming).count();
        SCLogDebug!("in_degree for node {:?}: {:?}", g[node_idx], in_degree);
        in_degrees.insert(node_idx, in_degree);
    }
}

fn log_graph(js: &mut JsonBuilder, graph: &mut StableDiGraph<SCGNode, u8>) -> Result<(), JsonError>
{
    SCLogNotice!("Starting the logging..");
    for node in graph.node_weights() {
        SCLogNotice!("{:?}", node.nidx.index());
        js.open_object(&node.sid.to_string())?;
        js.open_array("in")?;
        for edge in graph.edges_directed(node.nidx, Direction::Incoming) {
            js.start_object()?;
            js.set_uint("id", edge.source().index() as u64)?;
            js.set_uint("weight", *edge.weight() as u64)?;
            js.set_uint("sid",  graph[edge.source()].sid as u64)?;
            js.close()?;
        }
        js.close()?;
        js.open_array("out")?;
        for edge in graph.edges_directed(node.nidx, Direction::Outgoing) {
            js.start_object()?;
            js.set_uint("id", edge.target().index() as u64)?;
            js.set_uint("weight", *edge.weight() as u64)?;
            js.set_uint("sid", graph[edge.target()].sid as u64)?;
            js.close()?;
        }
        js.close()?;
        js.close()?;
    }
    Ok(())
}

/// Perform a BFS (Breadth First Search) of the DAG (Directed Acyclic Graph)
fn bfs_tree_dag(g: &mut StableDiGraph<SCGNode, u8>, sorted_sid_list: &mut [u32]) -> i8 {
    let mut in_degrees: HashMap<NodeIndex, usize> = HashMap::new();
    calculate_in_degree_nodes(g, &mut in_degrees);

    let nidx;
    if let Some(idx) = get_or_create_node(g, u32::MAX) {
        nidx = idx;
    } else {
        SCLogError!("Error adding node; Graph is at full capacity");
        return -1;
    }

    /* Connect all the loner nodes to the dummy node so as to create a discoverable
     * path and a connected tree to perform a BFS */
    for (node_idx, in_degree) in in_degrees {
        if in_degree == 0 {
            SCLogDebug!("added edge from {:?} -> {:?}", nidx, node_idx);
            g.add_edge(nidx, node_idx, u8::MAX);
        }
    }

    let mut bfs = Bfs::new(&*g, nidx);
    let mut i = 0;

    SCLogDebug!("BFS of the graph:");
    while let Some(idx) = bfs.next(&*g) {
        /* Don't add dummy node to the graph */
        if idx != nidx {
            SCLogDebug!("[{:?}]: {:?}", i, g[idx]);
            sorted_sid_list[i] = g[idx].sid;
            i += 1;
        }
    }
    0
}
