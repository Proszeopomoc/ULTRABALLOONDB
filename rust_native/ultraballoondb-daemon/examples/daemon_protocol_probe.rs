use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use ultraballoondb_daemon::{
    bind_listener, encode_hello, read_frame, serve_one, validate_bind_address, write_frame,
    BackendHealth, DaemonBackend, DaemonSession, Frame, FrameKind, ProtocolConfig,
};

const PASS: &str = "PASS_ULTRABALLOONDB_V00R3D2_DAEMON_AND_PROTOCOL_CORE_PROBE";
const TRANSCRIPT_MAGIC: [u8; 8] = *b"UBDTR01\0";

struct ProbeBackend { generation: u64 }
impl DaemonBackend for ProbeBackend {
    fn health(&self) -> BackendHealth { BackendHealth { healthy: true, read_only: false, generation: self.generation } }
    fn execute_read(&mut self, request: &[u8]) -> Result<Vec<u8>, String> { let mut out=b"READ:".to_vec(); out.extend_from_slice(request); Ok(out) }
    fn execute_write(&mut self, request: &[u8]) -> Result<Vec<u8>, String> { self.generation += 1; let mut out=b"WRITE:".to_vec(); out.extend_from_slice(request); Ok(out) }
}

fn record(records: &mut Vec<(u8, Vec<u8>)>, direction: u8, frame: &Frame, max: u32) {
    records.push((direction, frame.encode(max).expect("encode transcript frame")));
}
fn send(stream: &mut TcpStream, records: &mut Vec<(u8, Vec<u8>)>, frame: Frame, max: u32) -> Frame {
    record(records, 0, &frame, max); write_frame(stream, &frame, max).expect("write request"); let response=read_frame(stream,max).expect("read response"); record(records,1,&response,max); response
}
fn write_transcript(path: &PathBuf, records: &[(u8, Vec<u8>)]) {
    let mut out=Vec::new(); out.extend_from_slice(&TRANSCRIPT_MAGIC); out.extend_from_slice(&(records.len() as u32).to_le_bytes());
    for (direction, frame) in records { out.push(*direction); out.extend_from_slice(&(frame.len() as u32).to_le_bytes()); out.extend_from_slice(frame); }
    fs::write(path,out).expect("write transcript");
}
fn json_escape(value: &str) -> String { value.replace('\\', "\\\\").replace('"', "\\\"") }

fn main() {
    let root=PathBuf::from(std::env::args().nth(1).expect("probe root argument")); fs::create_dir_all(&root).expect("create probe root");
    let config=ProtocolConfig{max_frame_bytes:64*1024,max_requests_per_connection:64,max_read_payload_bytes:32*1024,max_write_payload_bytes:32*1024,io_timeout_millis:10_000,loopback_only:true};
    let listener=bind_listener("127.0.0.1:0".parse::<SocketAddr>().unwrap(),&config).expect("bind loopback"); let address=listener.local_addr().unwrap();
    let server_config=config.clone(); let handle=thread::spawn(move||serve_one(&listener,ProbeBackend{generation:41},server_config,0xAABBCCDD).expect("serve one"));
    thread::sleep(Duration::from_millis(25)); let mut stream=TcpStream::connect(address).expect("connect loopback"); stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap(); stream.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut records=Vec::new();
    let hello=send(&mut stream,&mut records,Frame::new(FrameKind::Hello,1,encode_hello(1,1,64*1024,0x11223344)),config.max_frame_bytes);
    let pong=send(&mut stream,&mut records,Frame::new(FrameKind::Ping,2,b"probe".to_vec()),config.max_frame_bytes);
    let health=send(&mut stream,&mut records,Frame::new(FrameKind::Health,3,vec![]),config.max_frame_bytes);
    let capabilities=send(&mut stream,&mut records,Frame::new(FrameKind::Capabilities,4,vec![]),config.max_frame_bytes);
    let read=send(&mut stream,&mut records,Frame::new(FrameKind::Read,5,b"alpha".to_vec()),config.max_frame_bytes);
    let write=send(&mut stream,&mut records,Frame::new(FrameKind::Write,6,b"beta".to_vec()),config.max_frame_bytes);
    let close=send(&mut stream,&mut records,Frame::new(FrameKind::Close,7,vec![]),config.max_frame_bytes);
    let served=handle.join().expect("server thread");

    let mut prehello=DaemonSession::new(config.clone(),ProbeBackend{generation:0},7).unwrap();
    let prehello_response=prehello.handle(Frame::new(FrameKind::Ping,1,vec![])).unwrap();
    let prehello_rejected=prehello_response.kind==FrameKind::Error && prehello.is_closed();
    let mut duplicate=DaemonSession::new(config.clone(),ProbeBackend{generation:0},8).unwrap();
    duplicate.handle(Frame::new(FrameKind::Hello,1,encode_hello(1,1,64*1024,5))).unwrap();
    let duplicate_response=duplicate.handle(Frame::new(FrameKind::Ping,1,vec![])).unwrap();
    let duplicate_followup=duplicate.handle(Frame::new(FrameKind::Ping,2,vec![])).unwrap();
    let duplicate_request_id_rejected=duplicate_response.kind==FrameKind::Error && duplicate_followup.kind==FrameKind::Pong && !duplicate.is_closed();
    let non_loopback_bind_rejected=validate_bind_address("0.0.0.0:0".parse().unwrap(),true).is_err();
    let mut tampered=Frame::new(FrameKind::Ping,9,b"tamper".to_vec()).encode(config.max_frame_bytes).unwrap(); let last=tampered.len()-1; tampered[last]^=1;
    let tamper_rejected=Frame::decode(&tampered,config.max_frame_bytes).is_err();
    let oversized_rejected=Frame::new(FrameKind::Read,10,vec![0u8;70*1024]).encode(config.max_frame_bytes).is_err();
    let protocol_sequence_ok=hello.kind==FrameKind::HelloAck && pong.kind==FrameKind::Pong && health.kind==FrameKind::HealthResult && capabilities.kind==FrameKind::CapabilitiesResult && read.kind==FrameKind::Result && read.payload==b"READ:alpha" && write.kind==FrameKind::Result && write.payload==b"WRITE:beta" && close.kind==FrameKind::CloseAck;
    let pass=protocol_sequence_ok && served.peer_loopback && served.closed_cleanly && served.request_count==7 && served.read_count==1 && served.write_count==1 && prehello_rejected && duplicate_request_id_rejected && non_loopback_bind_rejected && tamper_rejected && oversized_rejected;
    let transcript=root.join("daemon-protocol-transcript.ubdtr"); write_transcript(&transcript,&records);
    let report=root.join("daemon_protocol_probe_report.json");
    let body=format!("{{\n  \"pass\": {},\n  \"protocol_version\": 1,\n  \"loopback_only\": true,\n  \"loopback_connection_succeeded\": {},\n  \"production_service_installed\": false,\n  \"active_runtime_changed\": false,\n  \"protocol_sequence_ok\": {},\n  \"strict_request_id_monotonicity\": {},\n  \"hello_required\": {},\n  \"tamper_rejected\": {},\n  \"oversized_frame_rejected\": {},\n  \"non_loopback_bind_rejected\": {},\n  \"request_count\": {},\n  \"read_count\": {},\n  \"write_count\": {},\n  \"transcript_file\": \"{}\"\n}}\n",pass,served.peer_loopback,protocol_sequence_ok,duplicate_request_id_rejected,prehello_rejected,tamper_rejected,oversized_rejected,non_loopback_bind_rejected,served.request_count,served.read_count,served.write_count,json_escape(&transcript.to_string_lossy()));
    fs::write(&report,body).expect("write report");
    if !pass { std::process::exit(1); }
    let _=std::io::stdout().write_all(format!("{PASS}\nREPORT={}\nTRANSCRIPT={}\n",report.display(),transcript.display()).as_bytes());
}
