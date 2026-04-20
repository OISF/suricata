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

/// Edge object to determine a genuine cycle breaker
#[derive(Debug, Copy, Clone)]
struct SCGEdge {
    cmd: u8,
    fb_id: u32,
}

#[derive(Debug)]
struct FlowbitSidStore {
    graph: StableDiGraph<SCGNode, SCGEdge>,
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
    fss_void: *mut c_void, from: u32, to: u32, cmd: u8, fb_id: u32,
) -> i64 {
    let fss = &mut *(fss_void as *mut FlowbitSidStore);

    let from_idx = NodeIndex::from(from);
    let to_idx = NodeIndex::from(to);

    match fss
        .graph
        .try_update_edge(from_idx, to_idx, SCGEdge { cmd, fb_id })
    {
        /* edge from a flowbit setter to a flowbit reader */
        Ok(_) => {
            SCLogDebug!(
                "Created an edge from {:?} -> {:?} for flowbit {:?} with command: {:?}",
                from,
                to,
                fb_id,
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
    js: &mut JsonBuilder, graph: &mut StableDiGraph<SCGNode, SCGEdge>,
) -> Result<(), JsonError> {
    SCLogDebug!("Starting the logging..");
    for node in graph.node_weights() {
        SCLogDebug!("{:?}", node.nidx.index());
        js.open_object(&node.sid.to_string())?;
        js.open_array("in")?;
        for edge in graph.edges_directed(node.nidx, Direction::Incoming) {
            js.start_object()?;
            js.set_uint("id", edge.source().index() as u64)?;
            js.set_uint("weight", edge.weight().cmd as u64)?;
            js.set_uint("sid", graph[edge.source()].sid as u64)?;
            js.close()?;
        }
        js.close()?;
        js.open_array("out")?;
        for edge in graph.edges_directed(node.nidx, Direction::Outgoing) {
            js.start_object()?;
            js.set_uint("id", edge.target().index() as u64)?;
            js.set_uint("weight", edge.weight().cmd as u64)?;
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

fn check_cycle_update_graph(graph: &mut StableDiGraph<SCGNode, SCGEdge>) -> i8 {
    let MAX_STACK_SIZE: usize = 100;

    for i in 0..MAX_STACK_SIZE {
        /* Check graph for any cycles */
        if !is_cyclic_directed(&*graph) {
            SCLogDebug!("no cycles after {} tries", i);
            return 0;
        }

        SCLogDebug!("Found a cycle in i {}. Checking if it's valid..", i);

        if !try_resolve_one_cycle(graph) {
            /* If we can't resolve any cycle, we're stuck */
            SCLogError!("Unable to resolve cycles after {} tries", i);
            return -1;
        }
    }

    SCLogError!(
        "Maximum tries ({}) reached while trying to resolve cycles",
        MAX_STACK_SIZE
    );
    return -1;
}

fn try_resolve_one_cycle(graph: &mut StableDiGraph<SCGNode, SCGEdge>) -> bool {
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
            let Some((_src, tgt)) = graph.edge_endpoints(edge_idx) else {
                continue;
            };
            if !(scc_set.contains(&_src) && scc_set.contains(&tgt)) {
                continue;
            }
            let SCGEdge { cmd, fb_id } = graph[edge_idx];
            let same_bit_setters = graph
                .edges_directed(tgt, Direction::Incoming)
                .filter(|e| e.weight().fb_id == fb_id)
                .count();
            if same_bit_setters > 1 {
                graph.remove_edge(edge_idx);
                return true;
            }
            /* store cycle edges to inspect their commands (weights) later */
            edge_map.insert(edge_idx, cmd);
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
fn toposort_dag(graph: &StableDiGraph<SCGNode, SCGEdge>, sorted_iid_list: &mut [u32]) -> i8 {
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
