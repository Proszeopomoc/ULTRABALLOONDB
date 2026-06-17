use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::ffi::c_void;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::time::Instant;

const NODE_BYTES: usize = 24;
const EDGE_BYTES: usize = 24;

#[derive(Clone, Debug, PartialEq)]
struct Edge {
    src: u64,
    dst: u64,
    edge_type: u32,
    attenuation_class: u32,
    weight: f64,
}

#[derive(Clone, Debug, PartialEq)]
struct WaveRow {
    node_id: u64,
    energy: f64,
    predecessor: i64,
    edge_type: u32,
}

#[derive(Default, Clone, Debug)]
struct Counters {
    slice_lookups: u64,
    node_rows_read: u64,
    edge_records_read: u64,
    full_scan_counter: u64,
}

#[cfg(unix)]
mod osmap {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::ptr;
    use std::slice;

    const PROT_READ: i32 = 0x1;
    const MAP_PRIVATE: i32 = 0x02;

    extern "C" {
        fn mmap(
            addr: *mut c_void,
            length: usize,
            prot: i32,
            flags: i32,
            fd: i32,
            offset: i64,
        ) -> *mut c_void;
        fn munmap(addr: *mut c_void, length: usize) -> i32;
    }

    pub struct MmapFile {
        _file: File,
        ptr: *mut c_void,
        len: usize,
    }

    impl MmapFile {
        pub fn open(path: &Path) -> Result<Self, String> {
            let file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
            let len = file
                .metadata()
                .map_err(|e| format!("metadata {}: {e}", path.display()))?
                .len() as usize;
            if len == 0 {
                return Err(format!("cannot mmap empty file: {}", path.display()));
            }
            let ptr = unsafe {
                mmap(
                    ptr::null_mut(),
                    len,
                    PROT_READ,
                    MAP_PRIVATE,
                    file.as_raw_fd(),
                    0,
                )
            };
            if ptr as isize == -1 {
                return Err(format!("mmap failed: {}", path.display()));
            }
            Ok(Self { _file: file, ptr, len })
        }

        pub fn as_slice(&self) -> &[u8] {
            unsafe { slice::from_raw_parts(self.ptr as *const u8, self.len) }
        }
    }

    impl Drop for MmapFile {
        fn drop(&mut self) {
            unsafe {
                let _ = munmap(self.ptr, self.len);
            }
        }
    }
}

#[cfg(windows)]
mod osmap {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use std::slice;

    type Handle = *mut c_void;
    const PAGE_READONLY: u32 = 0x02;
    const FILE_MAP_READ: u32 = 0x0004;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileMappingW(
            h_file: Handle,
            attributes: *mut c_void,
            protect: u32,
            max_size_high: u32,
            max_size_low: u32,
            name: *const u16,
        ) -> Handle;
        fn MapViewOfFile(
            mapping: Handle,
            desired_access: u32,
            offset_high: u32,
            offset_low: u32,
            bytes_to_map: usize,
        ) -> *mut c_void;
        fn UnmapViewOfFile(base_address: *const c_void) -> i32;
        fn CloseHandle(object: Handle) -> i32;
    }

    pub struct MmapFile {
        _file: File,
        mapping: Handle,
        ptr: *mut c_void,
        len: usize,
    }

    impl MmapFile {
        pub fn open(path: &Path) -> Result<Self, String> {
            let file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
            let len = file
                .metadata()
                .map_err(|e| format!("metadata {}: {e}", path.display()))?
                .len() as usize;
            if len == 0 {
                return Err(format!("cannot mmap empty file: {}", path.display()));
            }
            let mapping = unsafe {
                CreateFileMappingW(
                    file.as_raw_handle() as Handle,
                    ptr::null_mut(),
                    PAGE_READONLY,
                    0,
                    0,
                    ptr::null(),
                )
            };
            if mapping.is_null() {
                return Err(format!("CreateFileMappingW failed: {}", path.display()));
            }
            let ptr = unsafe { MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0) };
            if ptr.is_null() {
                unsafe {
                    let _ = CloseHandle(mapping);
                }
                return Err(format!("MapViewOfFile failed: {}", path.display()));
            }
            Ok(Self { _file: file, mapping, ptr, len })
        }

        pub fn as_slice(&self) -> &[u8] {
            unsafe { slice::from_raw_parts(self.ptr as *const u8, self.len) }
        }
    }

    impl Drop for MmapFile {
        fn drop(&mut self) {
            unsafe {
                let _ = UnmapViewOfFile(self.ptr as *const c_void);
                let _ = CloseHandle(self.mapping);
            }
        }
    }
}

use osmap::MmapFile;

struct Graph {
    nodes: MmapFile,
    edges: MmapFile,
    node_count: u64,
    edge_count: u64,
    counters: Counters,
}

impl Graph {
    fn open(layout: &Path) -> Result<Self, String> {
        let nodes_path = layout.join("csr_nodes.bin");
        let edges_path = layout.join("csr_edges.bin");
        let nodes_len = fs::metadata(&nodes_path)
            .map_err(|e| format!("metadata {}: {e}", nodes_path.display()))?
            .len() as usize;
        let edges_len = fs::metadata(&edges_path)
            .map_err(|e| format!("metadata {}: {e}", edges_path.display()))?
            .len() as usize;
        if nodes_len % NODE_BYTES != 0 || edges_len % EDGE_BYTES != 0 {
            return Err("CSR file size is not aligned to fixed record width".to_string());
        }
        Ok(Self {
            nodes: MmapFile::open(&nodes_path)?,
            edges: MmapFile::open(&edges_path)?,
            node_count: (nodes_len / NODE_BYTES) as u64,
            edge_count: (edges_len / EDGE_BYTES) as u64,
            counters: Counters::default(),
        })
    }

    fn read_u64(bytes: &[u8], offset: usize) -> u64 {
        let mut raw = [0_u8; 8];
        raw.copy_from_slice(&bytes[offset..offset + 8]);
        u64::from_le_bytes(raw)
    }

    fn read_u32(bytes: &[u8], offset: usize) -> u32 {
        let mut raw = [0_u8; 4];
        raw.copy_from_slice(&bytes[offset..offset + 4]);
        u32::from_le_bytes(raw)
    }

    fn read_f64(bytes: &[u8], offset: usize) -> f64 {
        let mut raw = [0_u8; 8];
        raw.copy_from_slice(&bytes[offset..offset + 8]);
        f64::from_le_bytes(raw)
    }

    fn node_row(&mut self, index: u64) -> (u64, u64, u64) {
        self.counters.node_rows_read += 1;
        let offset = index as usize * NODE_BYTES;
        let bytes = self.nodes.as_slice();
        (
            Self::read_u64(bytes, offset),
            Self::read_u64(bytes, offset + 8),
            Self::read_u64(bytes, offset + 16),
        )
    }

    fn find_range(&mut self, node_id: u64) -> Option<(u64, u64)> {
        self.counters.slice_lookups += 1;
        let mut lo = 0_u64;
        let mut hi = self.node_count;
        while lo < hi {
            let mid = (lo + hi) / 2;
            let (row_node, first, count) = self.node_row(mid);
            if row_node < node_id {
                lo = mid + 1;
            } else if row_node > node_id {
                hi = mid;
            } else {
                return Some((first, count));
            }
        }
        None
    }

    fn get_edges(&mut self, node_id: u64) -> Vec<Edge> {
        let Some((first, count)) = self.find_range(node_id) else {
            return Vec::new();
        };
        let bytes = self.edges.as_slice();
        let mut result = Vec::with_capacity(count as usize);
        for index in first..first + count {
            let offset = index as usize * EDGE_BYTES;
            let dst = Self::read_u64(bytes, offset);
            let edge_type = Self::read_u32(bytes, offset + 8);
            let attenuation_class = Self::read_u32(bytes, offset + 12);
            let weight = Self::read_f64(bytes, offset + 16);
            self.counters.edge_records_read += 1;
            result.push(Edge {
                src: node_id,
                dst,
                edge_type,
                attenuation_class,
                weight,
            });
        }
        result
    }

    fn wave_activation(
        &mut self,
        seeds: &[u64],
        max_steps: usize,
        energy_threshold: f64,
        top_k: usize,
        edge_mask: u32,
    ) -> Vec<WaveRow> {
        let mut frontier: BTreeMap<u64, f64> = BTreeMap::new();
        let mut best: HashMap<u64, f64> = HashMap::new();
        let mut pred: HashMap<u64, (i64, u32)> = HashMap::new();
        for &seed in seeds {
            frontier.insert(seed, 1.0);
            best.insert(seed, 1.0);
            pred.insert(seed, (-1, 0));
        }
        for _ in 0..max_steps {
            let mut next: BTreeMap<u64, f64> = BTreeMap::new();
            for (&src, &energy) in frontier.iter() {
                for edge in self.get_edges(src) {
                    let bit = 1_u32 << (edge.edge_type % 31);
                    if bit & edge_mask == 0 {
                        continue;
                    }
                    let out = energy * edge.weight;
                    if out < energy_threshold {
                        continue;
                    }
                    let next_entry = next.entry(edge.dst).or_insert(-1.0);
                    if out > *next_entry {
                        *next_entry = out;
                    }
                    let best_value = best.get(&edge.dst).copied().unwrap_or(-1.0);
                    if out > best_value {
                        best.insert(edge.dst, out);
                        pred.insert(edge.dst, (src as i64, edge.edge_type));
                    }
                }
            }
            frontier = next;
            if frontier.is_empty() {
                break;
            }
        }
        let mut rows: Vec<WaveRow> = best
            .into_iter()
            .filter(|(_, energy)| *energy >= energy_threshold)
            .map(|(node_id, energy)| {
                let (predecessor, edge_type) = pred.get(&node_id).copied().unwrap_or((-1, 0));
                WaveRow { node_id, energy, predecessor, edge_type }
            })
            .collect();
        rows.sort_by(|a, b| {
            b.energy
                .partial_cmp(&a.energy)
                .unwrap_or(Ordering::Equal)
                .then_with(|| a.node_id.cmp(&b.node_id))
        });
        rows.truncate(top_k);
        rows
    }

    fn export_subgraph(&mut self, selected: &[u64]) -> (Vec<u64>, Vec<(u64, u64, u32)>) {
        let mut nodes = selected.to_vec();
        nodes.sort_unstable();
        nodes.dedup();
        let node_set: HashSet<u64> = nodes.iter().copied().collect();
        let mut edges = Vec::new();
        for &src in &nodes {
            for edge in self.get_edges(src) {
                if node_set.contains(&edge.dst) {
                    edges.push((edge.src, edge.dst, edge.edge_type));
                }
            }
        }
        (nodes, edges)
    }
}

fn synthetic_edges(node_id: u64, event_count: u64) -> [(u64, u32, u32, f64); 3] {
    let i = node_id - 1;
    [
        (((i + 1) % event_count) + 1, 1, 1, 0.91),
        (((i + 7) % event_count) + 1, 2, 1, 0.73),
        (((i * 17 + 11) % event_count) + 1, 3, 2, 0.61),
    ]
}

fn build_synthetic(layout: &Path, event_count: u64) -> Result<f64, String> {
    if event_count == 0 {
        return Err("event_count must be positive".to_string());
    }
    fs::create_dir_all(layout).map_err(|e| format!("mkdir {}: {e}", layout.display()))?;
    let nodes_path = layout.join("csr_nodes.bin");
    let edges_path = layout.join("csr_edges.bin");
    let started = Instant::now();
    let nodes_file = File::create(&nodes_path).map_err(|e| format!("create {}: {e}", nodes_path.display()))?;
    let edges_file = File::create(&edges_path).map_err(|e| format!("create {}: {e}", edges_path.display()))?;
    let mut nodes = BufWriter::with_capacity(1024 * 1024, nodes_file);
    let mut edges = BufWriter::with_capacity(1024 * 1024, edges_file);
    for node_id in 1..=event_count {
        let first = (node_id - 1) * 3;
        nodes.write_all(&node_id.to_le_bytes()).map_err(|e| e.to_string())?;
        nodes.write_all(&first.to_le_bytes()).map_err(|e| e.to_string())?;
        nodes.write_all(&3_u64.to_le_bytes()).map_err(|e| e.to_string())?;
        for (dst, edge_type, attenuation_class, weight) in synthetic_edges(node_id, event_count) {
            edges.write_all(&dst.to_le_bytes()).map_err(|e| e.to_string())?;
            edges.write_all(&edge_type.to_le_bytes()).map_err(|e| e.to_string())?;
            edges.write_all(&attenuation_class.to_le_bytes()).map_err(|e| e.to_string())?;
            edges.write_all(&weight.to_le_bytes()).map_err(|e| e.to_string())?;
        }
    }
    nodes.flush().map_err(|e| e.to_string())?;
    edges.flush().map_err(|e| e.to_string())?;
    let elapsed = started.elapsed().as_secs_f64();
    let manifest = format!(
        "{{\n  \"version\": \"V00R1\",\n  \"role\": \"RUST_NATIVE_CSR_MMAP_CORE_CANDIDATE\",\n  \"node_count\": {},\n  \"edge_count\": {},\n  \"node_record_bytes\": {},\n  \"edge_record_bytes\": {},\n  \"canonical_graph_mutated\": false,\n  \"third_party_rust_crates\": 0\n}}\n",
        event_count,
        event_count * 3,
        NODE_BYTES,
        EDGE_BYTES
    );
    fs::write(layout.join("csr_manifest.json"), manifest).map_err(|e| e.to_string())?;
    Ok(elapsed)
}

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn wave_json(rows: &[WaveRow]) -> String {
    let body = rows
        .iter()
        .map(|row| {
            format!(
                "{{\"node_id\":{},\"energy\":{:.12},\"predecessor\":{},\"edge_type\":{}}}",
                row.node_id, row.energy, row.predecessor, row.edge_type
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("[{body}]")
}

fn subgraph_json(nodes: &[u64], edges: &[(u64, u64, u32)]) -> String {
    let node_text = nodes.iter().map(u64::to_string).collect::<Vec<_>>().join(",");
    let edge_text = edges
        .iter()
        .map(|(src, dst, edge_type)| format!("[{src},{dst},{edge_type}]"))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"nodes\":[{node_text}],\"edges\":[{edge_text}]}}")
}

fn parse_args() -> (String, HashMap<String, String>) {
    let mut values = env::args().skip(1);
    let command = values.next().unwrap_or_else(|| "help".to_string());
    let mut args = HashMap::new();
    while let Some(key) = values.next() {
        if !key.starts_with("--") {
            eprintln!("Unexpected positional argument: {key}");
            process::exit(2);
        }
        let value = values.next().unwrap_or_else(|| {
            eprintln!("Missing value for {key}");
            process::exit(2);
        });
        args.insert(key.trim_start_matches("--").to_string(), value);
    }
    (command, args)
}

fn required<'a>(args: &'a HashMap<String, String>, key: &str) -> &'a str {
    args.get(key).map(String::as_str).unwrap_or_else(|| {
        eprintln!("Missing --{key}");
        process::exit(2);
    })
}

fn parse_u64(args: &HashMap<String, String>, key: &str, default: u64) -> u64 {
    args.get(key)
        .map(|v| v.parse::<u64>().unwrap_or_else(|_| {
            eprintln!("Invalid --{key}: {v}");
            process::exit(2);
        }))
        .unwrap_or(default)
}

fn parse_usize(args: &HashMap<String, String>, key: &str, default: usize) -> usize {
    args.get(key)
        .map(|v| v.parse::<usize>().unwrap_or_else(|_| {
            eprintln!("Invalid --{key}: {v}");
            process::exit(2);
        }))
        .unwrap_or(default)
}

fn parse_f64(args: &HashMap<String, String>, key: &str, default: f64) -> f64 {
    args.get(key)
        .map(|v| v.parse::<f64>().unwrap_or_else(|_| {
            eprintln!("Invalid --{key}: {v}");
            process::exit(2);
        }))
        .unwrap_or(default)
}

fn parse_seeds(text: &str) -> Vec<u64> {
    text.split(',')
        .filter(|v| !v.trim().is_empty())
        .map(|v| v.trim().parse::<u64>().unwrap_or_else(|_| {
            eprintln!("Invalid seed: {v}");
            process::exit(2);
        }))
        .collect()
}

fn write_output(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(path, content).map_err(|e| format!("write {}: {e}", path.display()))
}

fn command_build(args: &HashMap<String, String>) -> Result<(), String> {
    let layout = PathBuf::from(required(args, "layout-dir"));
    let event_count = parse_u64(args, "event-count", 100_000);
    let output = PathBuf::from(required(args, "output"));
    let seconds = build_synthetic(&layout, event_count)?;
    let json = format!(
        "{{\"pass\":true,\"command\":\"build-synthetic\",\"event_count\":{},\"edge_count\":{},\"build_seconds\":{:.9},\"nodes_file_bytes\":{},\"edges_file_bytes\":{},\"third_party_rust_crates\":0}}\n",
        event_count,
        event_count * 3,
        seconds,
        event_count * NODE_BYTES as u64,
        event_count * 3 * EDGE_BYTES as u64
    );
    write_output(&output, &json)?;
    println!("PASS_ULTRABALLOONDB_V00R1_RUST_BUILD");
    println!("OUTPUT={}", output.display());
    Ok(())
}

fn command_query(args: &HashMap<String, String>) -> Result<(), String> {
    let layout = PathBuf::from(required(args, "layout-dir"));
    let output = PathBuf::from(required(args, "output"));
    let seeds = parse_seeds(required(args, "seeds"));
    let max_steps = parse_usize(args, "max-steps", 2);
    let top_k = parse_usize(args, "top-k", 64);
    let threshold = parse_f64(args, "energy-threshold", 0.10);
    let export_limit = parse_usize(args, "export-limit", 128);
    let mut graph = Graph::open(&layout)?;
    let started = Instant::now();
    let rows = graph.wave_activation(&seeds, max_steps, threshold, top_k, u32::MAX);
    let query_seconds = started.elapsed().as_secs_f64();
    let selected: Vec<u64> = rows.iter().take(export_limit).map(|row| row.node_id).collect();
    let (nodes, edges) = graph.export_subgraph(&selected);
    let json = format!(
        "{{\"pass\":true,\"command\":\"query\",\"mmap_active\":true,\"node_count\":{},\"edge_count\":{},\"query_seconds\":{:.9},\"full_scan_counter\":{},\"slice_lookups\":{},\"node_rows_read\":{},\"edge_records_read\":{},\"wave\":{},\"subgraph\":{}}}\n",
        graph.node_count,
        graph.edge_count,
        query_seconds,
        graph.counters.full_scan_counter,
        graph.counters.slice_lookups,
        graph.counters.node_rows_read,
        graph.counters.edge_records_read,
        wave_json(&rows),
        subgraph_json(&nodes, &edges)
    );
    write_output(&output, &json)?;
    println!("PASS_ULTRABALLOONDB_V00R1_RUST_QUERY");
    println!("OUTPUT={}", output.display());
    Ok(())
}

fn percentile_us(values: &mut [f64], percentile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    let rank = ((values.len() - 1) as f64 * percentile).round() as usize;
    values[rank] * 1_000_000.0
}

fn command_bench(args: &HashMap<String, String>) -> Result<(), String> {
    let layout = PathBuf::from(required(args, "layout-dir"));
    let output = PathBuf::from(required(args, "output"));
    let event_count = parse_u64(args, "event-count", 1_000_000);
    let query_samples = parse_usize(args, "query-samples", 5_000);
    let max_steps = parse_usize(args, "max-steps", 2);
    let top_k = parse_usize(args, "top-k", 64);
    let threshold = parse_f64(args, "energy-threshold", 0.10);
    let build_seconds = build_synthetic(&layout, event_count)?;
    let mut graph = Graph::open(&layout)?;
    let mut durations = Vec::with_capacity(query_samples);
    let batch_started = Instant::now();
    let mut row_count = 0_usize;
    for i in 0..query_samples {
        let seed = (i as u64 % event_count) + 1;
        let started = Instant::now();
        let rows = graph.wave_activation(&[seed], max_steps, threshold, top_k, u32::MAX);
        durations.push(started.elapsed().as_secs_f64());
        row_count += rows.len();
    }
    let batch_seconds = batch_started.elapsed().as_secs_f64();
    let p50_us = percentile_us(&mut durations.clone(), 0.50);
    let p95_us = percentile_us(&mut durations.clone(), 0.95);
    let p99_us = percentile_us(&mut durations, 0.99);
    let json = format!(
        "{{\"pass\":true,\"command\":\"bench\",\"event_count\":{},\"edge_count\":{},\"query_samples\":{},\"wave_rows\":{},\"build_seconds\":{:.9},\"batch_query_seconds\":{:.9},\"queries_per_second\":{:.3},\"query_p50_us\":{:.6},\"query_p95_us\":{:.6},\"query_p99_us\":{:.6},\"mmap_active\":true,\"full_scan_counter\":{},\"slice_lookups\":{},\"node_rows_read\":{},\"edge_records_read\":{},\"third_party_rust_crates\":0}}\n",
        event_count,
        event_count * 3,
        query_samples,
        row_count,
        build_seconds,
        batch_seconds,
        query_samples as f64 / batch_seconds.max(f64::MIN_POSITIVE),
        p50_us,
        p95_us,
        p99_us,
        graph.counters.full_scan_counter,
        graph.counters.slice_lookups,
        graph.counters.node_rows_read,
        graph.counters.edge_records_read
    );
    write_output(&output, &json)?;
    println!("PASS_ULTRABALLOONDB_V00R1_RUST_BENCH");
    println!("OUTPUT={}", output.display());
    Ok(())
}

fn print_help() {
    println!("UltraBalloonDB Rust native core candidate V00R1");
    println!("commands:");
    println!("  build-synthetic --layout-dir PATH --event-count N --output FILE");
    println!("  query --layout-dir PATH --seeds 1,2 --max-steps N --top-k N --energy-threshold F --output FILE");
    println!("  bench --layout-dir PATH --event-count N --query-samples N --max-steps N --top-k N --energy-threshold F --output FILE");
}

fn main() {
    let (command, args) = parse_args();
    let result = match command.as_str() {
        "build-synthetic" => command_build(&args),
        "query" => command_query(&args),
        "bench" => command_bench(&args),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => Err(format!("unknown command: {}", json_escape(other))),
    };
    if let Err(error) = result {
        eprintln!("NO_GO_ULTRABALLOONDB_V00R1_RUST_NATIVE_CORE");
        eprintln!("ERROR={error}");
        process::exit(2);
    }
}
