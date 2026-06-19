from typing import Protocol, Tuple

VERSION: str
ABI_VERSION: int
PROTOCOL_VERSION: int
KIND_HELLO: int
KIND_PING: int
KIND_HEALTH: int
KIND_CAPABILITIES: int
KIND_READ: int
KIND_WRITE: int
KIND_CLOSE: int
KIND_HELLO_ACK: int
KIND_PONG: int
KIND_HEALTH_RESULT: int
KIND_CAPABILITIES_RESULT: int
KIND_RESULT: int
KIND_ERROR: int
KIND_CLOSE_ACK: int

class Backend(Protocol):
    def health(self) -> Tuple[bool, bool, int]: ...
    def execute_read(self, request: bytes) -> bytes: ...
    def execute_write(self, request: bytes) -> bytes: ...

class Session:
    def __init__(
        self,
        backend: Backend,
        server_nonce: int = ...,
        max_frame_bytes: int = ...,
        max_requests_per_connection: int = ...,
        max_read_payload_bytes: int = ...,
        max_write_payload_bytes: int = ...,
        io_timeout_millis: int = ...,
        loopback_only: bool = ...,
    ) -> None: ...
    @property
    def max_frame_bytes(self) -> int: ...
    @property
    def destroyed(self) -> bool: ...
    def process_frame(self, request: bytes) -> bytes: ...
    def destroy(self) -> None: ...

def abi_version() -> int: ...
def protocol_version() -> int: ...
def encode_frame(kind: int, request_id: int, payload: bytes, max_frame_bytes: int = ...) -> bytes: ...
def decode_frame(frame: bytes, max_frame_bytes: int = ...) -> tuple[int, int, int, bytes]: ...
def encode_hello_payload(min_version: int, max_version: int, client_max_frame_bytes: int, client_nonce: int) -> bytes: ...
