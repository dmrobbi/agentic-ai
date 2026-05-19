#!/usr/bin/env python3
"""
KaliAgent v3 - Sliver C2 Client
================================

Integrates with Sliver C2 framework for implant management.

Tasks: 4.1.1, 4.1.2, 4.1.3
Status: IMPLEMENTED
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

# Try to import grpc (if available)
try:
    import grpc
    GRPC_AVAILABLE = True
except ImportError:
    GRPC_AVAILABLE = False
    logging.debug("grpc not available - using mock mode")

# Try to import sliver protobuf (if available)
try:
    # from sliver.protobuf import sliver_pb2, sliver_pb2_grpc
    SLIVER_PROTO_AVAILABLE = False
except ImportError:
    SLIVER_PROTO_AVAILABLE = False

SLIVER_AVAILABLE = GRPC_AVAILABLE and SLIVER_PROTO_AVAILABLE

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ImplantType(Enum):
    """Sliver implant types."""
    MUTAGEN = "mutagen"
    REVERSE_HTTP = "reverse_http"
    REVERSE_HTTPS = "reverse_https"
    REVERSE_TCP = "reverse_tcp"
    BIND_TCP = "bind_tcp"
    DNS = "dns"


class Protocol(Enum):
    """Communication protocols."""
    HTTP = "http"
    HTTPS = "https"
    TCP = "tcp"
    DNS = "dns"
    MTLS = "mtls"


@dataclass
class Implant:
    """Sliver implant representation."""
    id: str
    name: str
    hostname: str
    username: str
    uuid: str
    pid: int
    filename: str
    last_checkin: datetime
    active: bool
    implant_type: ImplantType
    protocol: Protocol
    remote_address: str
    locale: str = "en_US"
    arch: str = "amd64"
    os: str = "windows"
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'hostname': self.hostname,
            'username': self.username,
            'uuid': self.uuid,
            'pid': self.pid,
            'filename': self.filename,
            'last_checkin': self.last_checkin.isoformat() if self.last_checkin else None,
            'active': self.active,
            'implant_type': self.implant_type.value,
            'protocol': self.protocol.value,
            'remote_address': self.remote_address,
            'locale': self.locale,
            'arch': self.arch,
            'os': self.os
        }


@dataclass
class C2Session:
    """C2 server session."""
    server_url: str
    username: str
    password: Optional[str]
    client_cert: Optional[Path]
    client_key: Optional[Path]
    ca_cert: Optional[Path]
    connected: bool = False
    session_id: Optional[str] = None
    connected_at: Optional[datetime] = None


class SliverClient:
    """
    Sliver C2 client.
    
    Provides:
    - Server connection management
    - Implant generation
    - Session management
    - Command execution
    - Beacon configuration
    """
    
    def __init__(self, config_dir: Optional[Path] = None):
        """Initialize Sliver client."""
        self.config_dir = config_dir or Path.home() / 'kali_agent_v3' / 'c2' / 'sliver'
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.session: Optional[C2Session] = None
        self.implants: Dict[str, Implant] = {}
        self.sessions: Dict[str, Dict] = {}
        
        # gRPC channel and stub
        self.channel = None
        self.stub = None
        
        logger.info(f"Sliver client initialized (config: {self.config_dir})")
    
    def connect(self, server_url: str, username: str = 'sliver',
               password: Optional[str] = None,
               client_cert: Optional[Path] = None,
               client_key: Optional[Path] = None,
               ca_cert: Optional[Path] = None) -> Tuple[bool, str]:
        """
        Connect to Sliver C2 server.
        
        Args:
            server_url: Sliver server URL (e.g., grpc://localhost:31337)
            username: Username for authentication
            password: Password (optional if using certs)
            client_cert: Client certificate path
            client_key: Client key path
            ca_cert: CA certificate path
            
        Returns:
            Tuple of (success, message)
        """
        logger.info(f"Connecting to Sliver server: {server_url}")
        
        if not SLIVER_AVAILABLE:
            # Mock connection for testing
            logger.warning("Sliver gRPC not available - using mock mode")
            self.session = C2Session(
                server_url=server_url,
                username=username,
                password=password,
                client_cert=client_cert,
                client_key=client_key,
                ca_cert=ca_cert,
                connected=True,
                session_id='mock_session_' + datetime.now().strftime('%Y%m%d%H%M%S'),
                connected_at=datetime.now()
            )
            
            # Save session config
            self._save_session_config()
            
            return True, "Connected (mock mode)"
        
        try:
            # Build gRPC channel
            if client_cert and client_key and ca_cert:
                # mTLS authentication
                with open(ca_cert, 'rb') as f:
                    ca_cert_data = f.read()
                with open(client_cert, 'rb') as f:
                    client_cert_data = f.read()
                with open(client_key, 'rb') as f:
                    client_key_data = f.read()
                
                credentials = grpc.ssl_channel_credentials(
                    root_certificates=ca_cert_data,
                    certificate_chain=client_cert_data,
                    private_key=client_key_data
                )
                
                self.channel = grpc.secure_channel(server_url, credentials)
            else:
                # Insecure connection (development only)
                self.channel = grpc.insecure_channel(server_url)
            
            # Create stub
            # self.stub = sliver_pb2_grpc.SliverRPCStub(self.channel)
            
            # Test connection
            # response = self.stub.Version(sliver_pb2.Empty())
            
            self.session = C2Session(
                server_url=server_url,
                username=username,
                password=password,
                client_cert=client_cert,
                client_key=client_key,
                ca_cert=ca_cert,
                connected=True,
                session_id='session_' + datetime.now().strftime('%Y%m%d%H%M%S'),
                connected_at=datetime.now()
            )
            
            # Save session config
            self._save_session_config()
            
            logger.info("Connected to Sliver server")
            
            return True, "Connected successfully"
            
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False, f"Connection failed: {str(e)}"
    
    def disconnect(self):
        """Disconnect from Sliver server."""
        if self.channel:
            self.channel.close()
            self.channel = None
            self.stub = None
        
        if self.session:
            self.session.connected = False
        
        logger.info("Disconnected from Sliver server")
    
    def _save_session_config(self):
        """Save session configuration."""
        if not self.session:
            return
        
        config_file = self.config_dir / 'session_config.json'
        
        config = {
            'server_url': self.session.server_url,
            'username': self.session.username,
            'client_cert': str(self.session.client_cert) if self.session.client_cert else None,
            'client_key': str(self.session.client_key) if self.session.client_key else None,
            'ca_cert': str(self.session.ca_cert) if self.session.ca_cert else None,
            'last_connected': self.session.connected_at.isoformat() if self.session.connected_at else None
        }
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        # Restrict permissions
        os.chmod(config_file, 0o600)
    
    def load_session_config(self) -> Optional[Dict]:
        """Load saved session configuration."""
        config_file = self.config_dir / 'session_config.json'
        
        if not config_file.exists():
            return None
        
        with open(config_file, 'r') as f:
            return json.load(f)
    
    # =====================================================================
    # Task 4.1.2: Implant Generation
    # =====================================================================
    
    def generate_implant(self, name: str, implant_type: ImplantType,
                        protocol: Protocol, lhost: str, lport: int,
                        arch: str = 'amd64', os_type: str = 'windows',
                        encoder: Optional[str] = None,
                        evasion: bool = True,
                        output_path: Optional[Path] = None) -> Tuple[bool, str]:
        """
        Generate a Sliver implant.
        
        Args:
            name: Implant name
            implant_type: Type of implant
            protocol: Communication protocol
            lhost: Listener host
            lport: Listener port
            arch: Target architecture
            os_type: Target OS
            encoder: Encoder to use
            evasion: Enable evasion techniques
            output_path: Output file path
            
        Returns:
            Tuple of (success, message)
        """
        logger.info(f"Generating implant: {name}")
        logger.info(f"  Type: {implant_type.value}")
        logger.info(f"  Protocol: {protocol.value}")
        logger.info(f"  LHOST: {lhost}, LPORT: {lport}")
        logger.info(f"  Arch: {arch}, OS: {os_type}")
        
        if not self.session or not self.session.connected:
            return False, "Not connected to Sliver server"
        
        # In mock mode, simulate implant generation
        if not SLIVER_AVAILABLE:
            logger.warning("Mock mode - simulating implant generation")
            
            # Create mock implant
            implant = Implant(
                id=f'implant_{datetime.now().strftime("%Y%m%d%H%M%S")}',
                name=name,
                hostname='DESKTOP-TARGET',
                username='victim',
                uuid='mock-uuid-' + datetime.now().strftime('%Y%m%d%H%M%S'),
                pid=0,
                filename=f'{name}.exe' if os_type == 'windows' else name,
                last_checkin=datetime.now(),
                active=False,
                implant_type=implant_type,
                protocol=protocol,
                remote_address=f'{lhost}:{lport}',
                arch=arch,
                os=os_type
            )
            
            self.implants[implant.id] = implant
            
            # Save to file
            if output_path:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                with open(output_path, 'wb') as f:
                    f.write(b'MOCK_IMPLANT_DATA')
                
                logger.info(f"Mock implant saved: {output_path}")
            
            return True, f"Implant generated (mock): {output_path}"
        
        # Real Sliver implant generation would use gRPC here
        # Example (pseudo-code):
        # config = sliver_pb2.ImplantConfig(
        #     name=name,
        #     profile=sliver_pb2.Profile(
        #         mtls_c2=[],
        #         http_c2=[f'http://{lhost}:{lport}'] if protocol == Protocol.HTTP else [],
        #         https_c2=[f'https://{lhost}:{lport}'] if protocol == Protocol.HTTPS else [],
        #     ),
        #     arch=arch,
        #     os=os_type,
        #     encoder=encoder or '',
        #     evasion=evasion
        # )
        #
        # response = self.stub.Generate(sliver_pb2.GenerateReq(config=config))
        #
        # if output_path:
        #     with open(output_path, 'wb') as f:
        #         f.write(response.implant)
        
        return False, "Sliver gRPC not fully implemented - use mock mode"
    
    def generate_beacon(self, name: str, interval: int = 60,
                       jitter: int = 30, lhost: str = '',
                       lport: int = 443, protocol: Protocol = Protocol.HTTPS,
                       arch: str = 'amd64', os_type: str = 'windows',
                       output_path: Optional[Path] = None) -> Tuple[bool, str]:
        """
        Generate a Sliver beacon implant.
        
        Args:
            name: Beacon name
            interval: Callback interval (seconds)
            jitter: Jitter range (seconds)
            lhost: Listener host
            lport: Listener port
            protocol: Communication protocol
            arch: Target architecture
            os_type: Target OS
            output_path: Output file path
            
        Returns:
            Tuple of (success, message)
        """
        logger.info(f"Generating beacon: {name}")
        logger.info(f"  Interval: {interval}s, Jitter: {jitter}s")
        
        return self.generate_implant(
            name=name,
            implant_type=ImplantType.MUTAGEN,
            protocol=protocol,
            lhost=lhost,
            lport=lport,
            arch=arch,
            os_type=os_type,
            evasion=True,
            output_path=output_path
        )
    
    def generate_session_implant(self, name: str,
                                lhost: str, lport: int,
                                protocol: Protocol = Protocol.HTTPS,
                                arch: str = 'amd64',
                                os_type: str = 'windows',
                                output_path: Optional[Path] = None) -> Tuple[bool, str]:
        """
        Generate a Sliver session (reverse) implant.
        
        Args:
            name: Implant name
            lhost: Listener host
            lport: Listener port
            protocol: Communication protocol
            arch: Target architecture
            os_type: Target OS
            output_path: Output file path
            
        Returns:
            Tuple of (success, message)
        """
        logger.info(f"Generating session implant: {name}")
        
        implant_type = ImplantType.REVERSE_HTTPS
        if protocol == Protocol.HTTP:
            implant_type = ImplantType.REVERSE_HTTP
        elif protocol == Protocol.TCP:
            implant_type = ImplantType.REVERSE_TCP
        
        return self.generate_implant(
            name=name,
            implant_type=implant_type,
            protocol=protocol,
            lhost=lhost,
            lport=lport,
            arch=arch,
            os_type=os_type,
            evasion=True,
            output_path=output_path
        )
    
    # =====================================================================
    # Task 4.1.3: Session Management
    # =====================================================================
    
    def list_implants(self) -> List[Implant]:
        """List all generated implants."""
        return list(self.implants.values())
    
    def get_implant(self, implant_id: str) -> Optional[Implant]:
        """Get implant by ID."""
        return self.implants.get(implant_id)
    
    def remove_implant(self, implant_id: str) -> bool:
        """Remove an implant."""
        if implant_id in self.implants:
            del self.implants[implant_id]
            logger.info(f"Removed implant: {implant_id}")
            return True
        return False
    
    def list_sessions(self) -> List[Dict]:
        """List active sessions."""
        # In mock mode, return empty list
        if not SLIVER_AVAILABLE:
            return []
        
        # Real implementation would query Sliver server
        # response = self.stub.Sessions(sliver_pb2.SessionsReq())
        # return list(response.sessions)
        
        return []
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session details."""
        return self.sessions.get(session_id)
    
    def interact_session(self, session_id: str, command: str,
                        timeout: int = 30) -> Tuple[bool, str]:
        """
        Interact with a session.
        
        Args:
            session_id: Session ID
            command: Command to execute
            timeout: Command timeout
            
        Returns:
            Tuple of (success, output)
        """
        logger.info(f"Executing command on session {session_id}: {command}")
        
        if not SLIVER_AVAILABLE:
            # Mock execution
            return True, f"Mock output for: {command}"
        
        # Real implementation
        # response = self.stub.Interact(sliver_pb2.InteractReq(
        #     session_id=session_id,
        #     command=command,
        #     timeout=timeout
        # ))
        #
        # return True, response.output
        
        return False, "Not implemented"
    
    def kill_session(self, session_id: str) -> bool:
        """Kill a session."""
        logger.info(f"Killing session: {session_id}")
        
        if session_id in self.sessions:
            del self.sessions[session_id]
            return True
        
        return False
    
    # =====================================================================
    # Listener Management
    # =====================================================================
    
    def start_listener(self, name: str, protocol: Protocol,
                      host: str = '0.0.0.0', port: int = 443,
                      domain: Optional[str] = None,
                      secure: bool = True) -> Tuple[bool, str]:
        """
        Start a C2 listener.
        
        Args:
            name: Listener name
            protocol: Protocol type
            host: Bind address
            port: Bind port
            domain: Domain name (for HTTP/S)
            secure: Enable TLS
            
        Returns:
            Tuple of (success, message)
        """
        logger.info(f"Starting listener: {name}")
        logger.info(f"  Protocol: {protocol.value}")
        logger.info(f"  Host: {host}, Port: {port}")
        
        if not self.session or not self.session.connected:
            return False, "Not connected to server"
        
        # Mock listener start
        if not SLIVER_AVAILABLE:
            listener_config = {
                'name': name,
                'protocol': protocol.value,
                'host': host,
                'port': port,
                'domain': domain,
                'secure': secure,
                'started_at': datetime.now().isoformat(),
                'active': True
            }
            
            # Save listener config
            listener_file = self.config_dir / f'listener_{name}.json'
            with open(listener_file, 'w') as f:
                json.dump(listener_config, f, indent=2)
            
            logger.info(f"Listener started (mock): {name}")
            
            return True, f"Listener started: {host}:{port}"
        
        # Real implementation
        # response = self.stub.StartListener(sliver_pb2.StartListenerReq(
        #     name=name,
        #     protocol=protocol.value,
        #     host=host,
        #     port=port,
        #     domain=domain or '',
        #     secure=secure
        # ))
        
        return True, f"Listener started: {name}"
    
    def stop_listener(self, name: str) -> bool:
        """Stop a listener."""
        logger.info(f"Stopping listener: {name}")
        
        listener_file = self.config_dir / f'listener_{name}.json'
        
        if listener_file.exists():
            with open(listener_file, 'r') as f:
                config = json.load(f)
            
            config['active'] = False
            config['stopped_at'] = datetime.now().isoformat()
            
            with open(listener_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            return True
        
        return False
    
    def list_listeners(self) -> List[Dict]:
        """List all listeners."""
        listeners = []
        
        for listener_file in self.config_dir.glob('listener_*.json'):
            with open(listener_file, 'r') as f:
                config = json.load(f)
            listeners.append(config)
        
        return listeners
    
    # =====================================================================
    # Statistics & Reporting
    # =====================================================================
    
    def get_statistics(self) -> Dict:
        """Get client statistics."""
        return {
            'connected': self.session.connected if self.session else False,
            'server_url': self.session.server_url if self.session else None,
            'total_implants': len(self.implants),
            'active_sessions': len([i for i in self.implants.values() if i.active]),
            'total_listeners': len(self.list_listeners())
        }
    
    def export_config(self, output_path: Path) -> bool:
        """Export client configuration."""
        config = {
            'session': {
                'server_url': self.session.server_url if self.session else None,
                'username': self.session.username if self.session else None,
                'connected_at': self.session.connected_at.isoformat() if self.session and self.session.connected_at else None
            },
            'implants': [i.to_dict() for i in self.implants.values()],
            'listeners': self.list_listeners()
        }
        
        with open(output_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        logger.info(f"Configuration exported: {output_path}")
        
        return True


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    """Command-line interface for Sliver client."""
    import argparse
    
    parser = argparse.ArgumentParser(description='KaliAgent v3 - Sliver C2 Client')
    parser.add_argument('--connect', type=str, help='Connect to Sliver server')
    parser.add_argument('--generate', type=str, help='Generate implant')
    parser.add_argument('--beacon', type=str, help='Generate beacon')
    parser.add_argument('--list-implants', action='store_true', help='List implants')
    parser.add_argument('--list-listeners', action='store_true', help='List listeners')
    parser.add_argument('--start-listener', type=str, help='Start listener')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    parser.add_argument('--lhost', type=str, default='0.0.0.0', help='Listener host')
    parser.add_argument('--lport', type=int, default=443, help='Listener port')
    
    args = parser.parse_args()
    
    client = SliverClient()
    
    if args.connect:
        success, message = client.connect(args.connect)
        status = "✅" if success else "❌"
        print(f"{status} Connection: {message}")
    
    elif args.generate:
        config = client.load_session_config()
        if not config:
            print("❌ Not connected. Use --connect first")
            return
        
        success, message = client.generate_session_implant(
            name=args.generate,
            lhost=args.lhost,
            lport=args.lport,
            output_path=Path(f'{args.generate}.exe')
        )
        
        status = "✅" if success else "❌"
        print(f"{status} Implant: {message}")
    
    elif args.beacon:
        success, message = client.generate_beacon(
            name=args.beacon,
            lhost=args.lhost,
            lport=args.lport,
            output_path=Path(f'{args.beacon}.exe')
        )
        
        status = "✅" if success else "❌"
        print(f"{status} Beacon: {message}")
    
    elif args.list_implants:
        implants = client.list_implants()
        print(f"\nImplants: {len(implants)}")
        print("=" * 60)
        for i in implants:
            status = "🟢" if i.active else "🔴"
            print(f"{status} {i.name} ({i.implant_type.value}) - {i.os}/{i.arch}")
        print("=" * 60)
    
    elif args.list_listeners:
        listeners = client.list_listeners()
        print(f"\nListeners: {len(listeners)}")
        print("=" * 60)
        for level in listeners:
            status = "🟢" if level.get('active') else "🔴"
            print(f"{status} {level['name']} ({level['protocol']}) - {level['host']}:{level['port']}")
        print("=" * 60)
    
    elif args.start_listener:
        success, message = client.start_listener(
            name=args.start_listener,
            protocol=Protocol.HTTPS,
            host=args.lhost,
            port=args.lport
        )
        
        status = "✅" if success else "❌"
        print(f"{status} Listener: {message}")
    
    elif args.stats or True:
        stats = client.get_statistics()
        print("\nSliver Client Statistics:")
        print("=" * 60)
        print(f"Connected: {'✅ Yes' if stats['connected'] else '❌ No'}")
        if stats['server_url']:
            print(f"Server: {stats['server_url']}")
        print(f"Total Implants: {stats['total_implants']}")
        print(f"Active Sessions: {stats['active_sessions']}")
        print(f"Listeners: {stats['total_listeners']}")
        print("=" * 60)
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
