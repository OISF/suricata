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

use crate::conf::*;
use crate::jsonbuilder::*;
use petgraph::algo::{is_cyclic_directed, tarjan_scc, toposort};
use petgraph::graph::{GraphError, NodeIndex};
use petgraph::stable_graph::StableDiGraph;
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use std::collections::{HashMap, HashSet};
use std::os::raw::c_void;

/// Special Graph Node storing flowbit or signature
#[derive(Debug, Copy, Clone)]
struct SCGNode {
    iid: u32,
    sid: u32,
    nidx: NodeIndex, /* Graph's internal node index */
}

#[derive(Debug)]
struct FlowbitSidStore {
    graph: StableDiGraph<SCGNode, u8>,
    iid_map: HashMap<u32, NodeIndex>,
}

/// Function to create an empty directed Graph
#[no_mangle]
pub unsafe extern "C" fn SCCreateDirectedGraph() -> *mut c_void {
    // StableDiGraph is the ideal choice here for there is removal of
    // nodes in the line later and this type of graph guarantees to
    // not re-use any existing node indices
    let fb_sid_store = FlowbitSidStore {
        graph: StableDiGraph::new(),
        iid_map: HashMap::new(),
    };

    /* Make an opaque pointer for C as nothing is changed there */
    return Box::into_raw(Box::new(fb_sid_store)) as *mut c_void;
}

/// Drop the directed Graph. Called from C.
#[no_mangle]
pub unsafe extern "C" fn SCFreeDirectedGraph(store: *mut c_void) {
    let _ = Box::from_raw(store as *mut FlowbitSidStore);
}

#[no_mangle]
pub unsafe extern "C" fn SCGetOrCreateNodeGraph(graph: *mut c_void, iid: u32, sid: u32) -> i64 {
    let g = &mut *(graph as *mut FlowbitSidStore);

    let Some(node_idx) = get_or_create_node(g, iid, sid) else {
        SCLogError!("Error adding node; Graph is at full capacity");
        return -2;
    };

    node_idx.index() as i64
}

/// Function to get or create a node and add an appropriate directed
/// edge based on its type
#[no_mangle]
pub unsafe extern "C" fn SCCreateNodeEdgeDirectedGraph(
    fss_void: *mut c_void, from: u32, to: u32, cmd: u8,
) -> i64 {
    let fss = &mut *(fss_void as *mut FlowbitSidStore);

    let from_idx = NodeIndex::from(from);
    let to_idx = NodeIndex::from(to);

    match fss.graph.try_update_edge(from_idx, to_idx, cmd) {
        /* edge from signature to flowbit */
        Ok(_) => {
            SCLogDebug!(
                "Created an edge from {:?} -> {:?} with weight: {:?}",
                from,
                to,
                cmd
            );
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

fn log_graph(
    js: &mut JsonBuilder, graph: &mut StableDiGraph<SCGNode, u8>,
) -> Result<(), JsonError> {
    SCLogDebug!("Starting the logging..");
    for node in graph.node_weights() {
        SCLogDebug!("{:?}", node.nidx.index());
        js.open_object(&node.sid.to_string())?;
        js.open_array("in")?;
        for edge in graph.edges_directed(node.nidx, Direction::Incoming) {
            js.start_object()?;
            js.set_uint("id", edge.source().index() as u64)?;
            js.set_uint("weight", *edge.weight() as u64)?;
            js.set_uint("sid", graph[edge.source()].sid as u64)?;
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

#[no_mangle]
pub unsafe extern "C" fn SCDebugLogFlowbitGraph(
    jsb: &mut JsonBuilder, fss_void: *mut c_void,
) -> bool {
    let fss = &mut *(fss_void as *mut FlowbitSidStore);
    log_graph(jsb, &mut fss.graph).is_ok()
}

fn check_cycle_update_graph(graph: &mut StableDiGraph<SCGNode, u8>) -> i8 {
    let mut max_stack_size: usize = 100;
    if let Some(val) = conf_get("detect.flowbits.max-cycle-resolution") {
        if let Ok(v) = val.parse::<usize>() {
            if v > u8::MAX as usize {
                SCLogError!("Invalid value for max-cycle-resolution");
            } else {
                max_stack_size = v;
            }
        } else {
            SCLogError!("Invalid value for max-cycle-resolution");
        }
    }

    for i in 0..=max_stack_size {
        /* Check graph for any cycles */
        if !is_cyclic_directed(&*graph) {
            SCLogDebug!("no cycles after {} tries", i);
            return 0;
        }

        SCLogDebug!("Found a cycle in i {}. Checking if it's valid..", i);
        if i == max_stack_size {
            break;
        }

        if !try_resolve_one_cycle(graph) {
            /* If we can't resolve any cycle, we're stuck */
            SCLogError!("Unable to resolve cycles after {} tries", i);
            return -1;
        }
    }

    SCLogError!(
        "Maximum tries ({}) reached while trying to resolve cycles",
        max_stack_size
    );
    return -1;
}

fn try_resolve_one_cycle(graph: &mut StableDiGraph<SCGNode, u8>) -> bool {
    let sccs = tarjan_scc(&*graph);
    let mut edge_map: HashMap<petgraph::graph::EdgeIndex, u8> = HashMap::new();

    /* Find the first multi-node SCC */
    for scc in sccs {
        if scc.len() == 1 {
            let self_loop_edges: Vec<_> = graph
                .edges(scc[0])
                .filter(|edge| edge.target() == scc[0])
                .map(|edge| edge.id())
                .collect();

            if let Some(edge) = self_loop_edges.into_iter().next() {
                graph.remove_edge(edge);
                return true;
            }
            continue;
        }

        SCLogDebug!("Current scc: {:?}", scc);
        let scc_set: HashSet<_> = scc.iter().copied().collect();
        let edge_indices: Vec<_> = graph.edge_indices().collect();

        for edge_idx in edge_indices {
            if let Some((src, tgt)) = graph.edge_endpoints(edge_idx) {
                if scc_set.contains(&src) && scc_set.contains(&tgt) {
                    let in_degree_src = graph.neighbors_directed(src, Direction::Incoming).count();
                    let in_degree_dst = graph.neighbors_directed(tgt, Direction::Incoming).count();
                    if in_degree_src > 1 {
                        /* looks like a cycle but there's a cycle breaker, so remove the edge */
                        if let Some(ei) = graph.find_edge(tgt, src) {
                            graph.remove_edge(ei);
                            return true;
                        }
                    } else if in_degree_dst > 1 {
                        /* looks like a cycle but there's a cycle breaker, so remove the edge */
                        if let Some(ei) = graph.find_edge(src, tgt) {
                            graph.remove_edge(ei);
                            return true;
                        }
                    }
                    /* store all edges involved in the cycle to check their weights later */
                    if let Some(weight) = graph.edge_weight(edge_idx) {
                        edge_map.insert(edge_idx, *weight);
                    }
                }
            }
        }
        /* Find if the cycle causing edges are made up of differing weights */
        let distinct_weights = edge_map.values().copied().collect::<HashSet<u8>>().len();
        debug_validate_bug_on!(distinct_weights == 0);
        if distinct_weights > 1 {
            /* Find and remove the edge with highest weight (lowest priority) */
            if let Some((cur_e, _)) = edge_map.iter().max_by_key(|(_, &weight)| weight) {
                graph.remove_edge(*cur_e);
                return true;
            }
        } else {
            /* Valid cycle with same weights -- can't resolve */
            let sids: Vec<_> = scc_set.into_iter().map(|a| graph[a].sid).collect();
            SCLogError!(
                "Cyclic dependency found between flowbits from signatures: {:?}",
                sids
            );
            return false;
        }
        break;
    }

    /* couldn't resolve */
    false
}

/// Wrapper function to resolve flowbit dependencies
#[no_mangle]
pub unsafe extern "C" fn SCResolveFlowbitDependencies(
    fss_void: *mut c_void, sorted_iid_list: *mut u32, sorted_iid_list_len: u32,
) -> i8 {
    SCLogDebug!("Attempting to resolve flowbit dependencies");
    let fss = &mut *(fss_void as *mut FlowbitSidStore);
    let r = check_cycle_update_graph(&mut fss.graph);
    if r == -1 {
        SCLogError!("Couldn't do anything to fix the graph. Retreating..");
        return -1;
    }

    debug_validate_bug_on!(fss.graph.node_count() == 0);

    let sorted_iid_list =
        std::slice::from_raw_parts_mut(&mut *sorted_iid_list, sorted_iid_list_len as usize);

    /* No need for all the extra work if there's just one node */
    if fss.graph.node_count() == 1 {
        debug_validate_bug_on!(sorted_iid_list_len != 1);
        sorted_iid_list[0] = fss.graph[NodeIndex::from(0)].iid;
        return 0;
    }

    /* At this point, it must be a DAG, so perform a topological sort to find
     * out the correct order of signatures */
    return toposort_dag(&fss.graph, sorted_iid_list);
}

fn get_or_create_node(fss: &mut FlowbitSidStore, iid: u32, sid: u32) -> Option<NodeIndex> {
    if let Some(&nidx) = fss.iid_map.get(&iid) {
        return Some(nidx); /* O(1) */
    }
    let nd = SCGNode {
        iid,
        sid,
        nidx: NodeIndex::from(u32::MAX),
    };
    if let Ok(idx) = fss.graph.try_add_node(nd) {
        /* O(1) */
        fss.graph[idx].nidx = idx;
        fss.iid_map.insert(iid, idx);
        SCLogDebug!("Created node: {:?}", fss.graph[idx]);
        return Some(idx);
    }

    None
}

/// Produce a topological ordering of the DAG
fn toposort_dag(graph: &StableDiGraph<SCGNode, u8>, sorted_iid_list: &mut [u32]) -> i8 {
    match toposort(graph, None) {
        Ok(order) => {
            debug_validate_bug_on!(order.len() != sorted_iid_list.len());
            for (i, idx) in order.into_iter().enumerate() {
                SCLogDebug!("[{:?}]: {:?}", i, graph[idx]);
                sorted_iid_list[i] = graph[idx].iid;
            }
            0
        }
        Err(_) => {
            /* Unreachable in practice: cycles are resolved before this point */
            SCLogError!("Graph still contains a cycle; cannot produce an order");
            -1
        }
    }
}
