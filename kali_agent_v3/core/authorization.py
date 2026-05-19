#!/usr/bin/env python3
"""
KaliAgent v3 - Authorization & Safety Gates Module
===================================================

Implements authorization levels for critical actions to ensure safe operation.

Tasks: 5.1.1, 5.1.2, 5.1.3
Status: IMPLEMENTED
"""

import os
import json
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Callable
from enum import Enum
from dataclasses import dataclass
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# =============================================================================
# Task 5.1.1: Define Authorization Levels
# =============================================================================

class AuthorizationLevel(Enum):
    """
    Authorization levels for KaliAgent actions.
    
    NONE: No authorization required (safe, informational)
    BASIC: Simple confirmation (low-risk operations)
    ADVANCED: Password/PIN required (medium-risk)
    CRITICAL: Multi-factor or explicit written confirmation (high-risk)
    """
    NONE = 0
    BASIC = 1
    ADVANCED = 2
    CRITICAL = 3


class ActionCategory(Enum):
    """Categories of actions requiring authorization."""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    CREDENTIAL_ACCESS = "credential_access"
    SYSTEM_MODIFICATION = "system_modification"
    NETWORK_ATTACK = "network_attack"
    SOCIAL_ENGINEERING = "social_engineering"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"


@dataclass
class AuthorizationPolicy:
    """Authorization policy for an action."""
    action_name: str
    category: ActionCategory
    required_level: AuthorizationLevel
    description: str
    risk_score: int  # 1-10
    mitre_technique: Optional[str] = None
    requires_audit: bool = True
    cooldown_minutes: int = 0
    allowed_targets: Optional[List[str]] = None
    blocked_targets: Optional[List[str]] = None


# =============================================================================
# Action Registry with Authorization Levels
# =============================================================================

ACTION_REGISTRY: Dict[str, AuthorizationPolicy] = {
    # =====================================================================
    # NONE - No authorization required (safe, informational)
    # =====================================================================
    'tool_search': AuthorizationPolicy(
        action_name='tool_search',
        category=ActionCategory.RECONNAISSANCE,
        required_level=AuthorizationLevel.NONE,
        description='Search tool database',
        risk_score=1,
        requires_audit=False
    ),
    'tool_info': AuthorizationPolicy(
        action_name='tool_info',
        category=ActionCategory.RECONNAISSANCE,
        required_level=AuthorizationLevel.NONE,
        description='Get tool information',
        risk_score=1,
        requires_audit=False
    ),
    'hardware_status': AuthorizationPolicy(
        action_name='hardware_status',
        category=ActionCategory.RECONNAISSANCE,
        required_level=AuthorizationLevel.NONE,
        description='Check hardware status',
        risk_score=1,
        requires_audit=False
    ),
    'profile_list': AuthorizationPolicy(
        action_name='profile_list',
        category=ActionCategory.RECONNAISSANCE,
        required_level=AuthorizationLevel.NONE,
        description='List installation profiles',
        risk_score=1,
        requires_audit=False
    ),
    'cve_lookup': AuthorizationPolicy(
        action_name='cve_lookup',
        category=ActionCategory.RECONNAISSANCE,
        required_level=AuthorizationLevel.NONE,
        description='Lookup CVE information',
        risk_score=1,
        requires_audit=False
    ),
    'mitre_lookup': AuthorizationPolicy(
        action_name='mitre_lookup',
        category=ActionCategory.RECONNAISSANCE,
        required_level=AuthorizationLevel.NONE,
        description='Lookup MITRE ATT&CK technique',
        risk_score=1,
        requires_audit=False
    ),
    
    # =====================================================================
    # BASIC - Simple confirmation (low-risk operations)
    # =====================================================================
    'nmap_scan': AuthorizationPolicy(
        action_name='nmap_scan',
        category=ActionCategory.SCANNING,
        required_level=AuthorizationLevel.BASIC,
        description='Run Nmap network scan',
        risk_score=3,
        mitre_technique='T1046',
        cooldown_minutes=5
    ),
    'masscan_scan': AuthorizationPolicy(
        action_name='masscan_scan',
        category=ActionCategory.SCANNING,
        required_level=AuthorizationLevel.BASIC,
        description='Run Masscan port scan',
        risk_score=3,
        mitre_technique='T1046',
        cooldown_minutes=10
    ),
    'nikto_scan': AuthorizationPolicy(
        action_name='nikto_scan',
        category=ActionCategory.SCANNING,
        required_level=AuthorizationLevel.BASIC,
        description='Run Nikto web scan',
        risk_score=3,
        mitre_technique='T1046',
        cooldown_minutes=5
    ),
    'wpscan_scan': AuthorizationPolicy(
        action_name='wpscan_scan',
        category=ActionCategory.SCANNING,
        required_level=AuthorizationLevel.BASIC,
        description='Run WPScan WordPress scan',
        risk_score=3,
        mitre_technique='T1046',
        cooldown_minutes=5
    ),
    'subdomain_enum': AuthorizationPolicy(
        action_name='subdomain_enum',
        category=ActionCategory.RECONNAISSANCE,
        required_level=AuthorizationLevel.BASIC,
        description='Enumerate subdomains',
        risk_score=2,
        mitre_technique='T1595',
        cooldown_minutes=5
    ),
    'dir_bruteforce': AuthorizationPolicy(
        action_name='dir_bruteforce',
        category=ActionCategory.SCANNING,
        required_level=AuthorizationLevel.BASIC,
        description='Brute-force directories',
        risk_score=3,
        mitre_technique='T1046',
        cooldown_minutes=5
    ),
    'ssl_scan': AuthorizationPolicy(
        action_name='ssl_scan',
        category=ActionCategory.SCANNING,
        required_level=AuthorizationLevel.BASIC,
        description='Scan SSL/TLS configuration',
        risk_score=2,
        mitre_technique='T1046',
        cooldown_minutes=5
    ),
    'dns_enum': AuthorizationPolicy(
        action_name='dns_enum',
        category=ActionCategory.RECONNAISSANCE,
        required_level=AuthorizationLevel.BASIC,
        description='DNS enumeration',
        risk_score=2,
        mitre_technique='T1595',
        cooldown_minutes=5
    ),
    
    # =====================================================================
    # ADVANCED - Password/PIN required (medium-risk)
    # =====================================================================
    'sql_injection': AuthorizationPolicy(
        action_name='sql_injection',
        category=ActionCategory.EXPLOITATION,
        required_level=AuthorizationLevel.ADVANCED,
        description='SQL injection attack',
        risk_score=7,
        mitre_technique='T1190',
        cooldown_minutes=30,
        requires_audit=True
    ),
    'xss_attack': AuthorizationPolicy(
        action_name='xss_attack',
        category=ActionCategory.EXPLOITATION,
        required_level=AuthorizationLevel.ADVANCED,
        description='Cross-site scripting attack',
        risk_score=6,
        mitre_technique='T1189',
        cooldown_minutes=30,
        requires_audit=True
    ),
    'password_crack': AuthorizationPolicy(
        action_name='password_crack',
        category=ActionCategory.CREDENTIAL_ACCESS,
        required_level=AuthorizationLevel.ADVANCED,
        description='Password cracking (hashcat/john)',
        risk_score=6,
        mitre_technique='T1110',
        cooldown_minutes=60,
        requires_audit=True
    ),
    'wifi_crack': AuthorizationPolicy(
        action_name='wifi_crack',
        category=ActionCategory.NETWORK_ATTACK,
        required_level=AuthorizationLevel.ADVANCED,
        description='WiFi password cracking',
        risk_score=6,
        mitre_technique='T1110',
        cooldown_minutes=60,
        requires_audit=True
    ),
    'monitor_mode': AuthorizationPolicy(
        action_name='monitor_mode',
        category=ActionCategory.NETWORK_ATTACK,
        required_level=AuthorizationLevel.ADVANCED,
        description='Enable WiFi monitor mode',
        risk_score=5,
        mitre_technique='T1046',
        cooldown_minutes=15,
        requires_audit=True
    ),
    'mitm_attack': AuthorizationPolicy(
        action_name='mitm_attack',
        category=ActionCategory.NETWORK_ATTACK,
        required_level=AuthorizationLevel.ADVANCED,
        description='Man-in-the-middle attack',
        risk_score=8,
        mitre_technique='T1557',
        cooldown_minutes=60,
        requires_audit=True
    ),
    'evil_twin': AuthorizationPolicy(
        action_name='evil_twin',
        category=ActionCategory.NETWORK_ATTACK,
        required_level=AuthorizationLevel.ADVANCED,
        description='Evil twin access point',
        risk_score=7,
        mitre_technique='T1557',
        cooldown_minutes=60,
        requires_audit=True
    ),
    'phishing_campaign': AuthorizationPolicy(
        action_name='phishing_campaign',
        category=ActionCategory.SOCIAL_ENGINEERING,
        required_level=AuthorizationLevel.ADVANCED,
        description='Create phishing campaign',
        risk_score=7,
        mitre_technique='T1566',
        cooldown_minutes=120,
        requires_audit=True
    ),
    'exploit_run': AuthorizationPolicy(
        action_name='exploit_run',
        category=ActionCategory.EXPLOITATION,
        required_level=AuthorizationLevel.ADVANCED,
        description='Run exploit against target',
        risk_score=8,
        mitre_technique='T1190',
        cooldown_minutes=60,
        requires_audit=True
    ),
    'payload_generate': AuthorizationPolicy(
        action_name='payload_generate',
        category=ActionCategory.EXPLOITATION,
        required_level=AuthorizationLevel.ADVANCED,
        description='Generate malicious payload',
        risk_score=7,
        mitre_technique='T1204',
        cooldown_minutes=30,
        requires_audit=True
    ),
    'credential_dump': AuthorizationPolicy(
        action_name='credential_dump',
        category=ActionCategory.CREDENTIAL_ACCESS,
        required_level=AuthorizationLevel.ADVANCED,
        description='Dump credentials (mimikatz, etc)',
        risk_score=8,
        mitre_technique='T1003',
        cooldown_minutes=60,
        requires_audit=True
    ),
    'privesc_check': AuthorizationPolicy(
        action_name='privesc_check',
        category=ActionCategory.POST_EXPLOITATION,
        required_level=AuthorizationLevel.ADVANCED,
        description='Privilege escalation check',
        risk_score=5,
        mitre_technique='T1068',
        cooldown_minutes=30,
        requires_audit=True
    ),
    'lateral_movement': AuthorizationPolicy(
        action_name='lateral_movement',
        category=ActionCategory.POST_EXPLOITATION,
        required_level=AuthorizationLevel.ADVANCED,
        description='Lateral movement techniques',
        risk_score=7,
        mitre_technique='T1021',
        cooldown_minutes=60,
        requires_audit=True
    ),
    'persistence_install': AuthorizationPolicy(
        action_name='persistence_install',
        category=ActionCategory.PERSISTENCE,
        required_level=AuthorizationLevel.ADVANCED,
        description='Install persistence mechanism',
        risk_score=8,
        mitre_technique='T1053',
        cooldown_minutes=120,
        requires_audit=True
    ),
    
    # =====================================================================
    # CRITICAL - Multi-factor or explicit written confirmation (high-risk)
    # =====================================================================
    'system_exploit': AuthorizationPolicy(
        action_name='system_exploit',
        category=ActionCategory.EXPLOITATION,
        required_level=AuthorizationLevel.CRITICAL,
        description='Exploit against critical system',
        risk_score=10,
        mitre_technique='T1190',
        cooldown_minutes=240,
        requires_audit=True,
        blocked_targets=['localhost', '127.0.0.1', 'gateway']
    ),
    'data_exfiltration': AuthorizationPolicy(
        action_name='data_exfiltration',
        category=ActionCategory.DATA_EXFILTRATION,
        required_level=AuthorizationLevel.CRITICAL,
        description='Exfiltrate data from target',
        risk_score=10,
        mitre_technique='T1041',
        cooldown_minutes=240,
        requires_audit=True
    ),
    'ransomware_sim': AuthorizationPolicy(
        action_name='ransomware_sim',
        category=ActionCategory.SYSTEM_MODIFICATION,
        required_level=AuthorizationLevel.CRITICAL,
        description='Ransomware simulation',
        risk_score=10,
        mitre_technique='T1486',
        cooldown_minutes=480,
        requires_audit=True,
        allowed_targets=['isolated_lab']
    ),
    'firmware_flash': AuthorizationPolicy(
        action_name='firmware_flash',
        category=ActionCategory.SYSTEM_MODIFICATION,
        required_level=AuthorizationLevel.CRITICAL,
        description='Flash device firmware',
        risk_score=9,
        mitre_technique='T1542',
        cooldown_minutes=180,
        requires_audit=True
    ),
    'bootkit_install': AuthorizationPolicy(
        action_name='bootkit_install',
        category=ActionCategory.PERSISTENCE,
        required_level=AuthorizationLevel.CRITICAL,
        description='Install bootkit (testing only)',
        risk_score=10,
        mitre_technique='T1542',
        cooldown_minutes=480,
        requires_audit=True,
        allowed_targets=['isolated_vm']
    ),
    'kernel_exploit': AuthorizationPolicy(
        action_name='kernel_exploit',
        category=ActionCategory.EXPLOITATION,
        required_level=AuthorizationLevel.CRITICAL,
        description='Kernel-level exploit',
        risk_score=10,
        mitre_technique='T1068',
        cooldown_minutes=240,
        requires_audit=True
    ),
    'rootkit_install': AuthorizationPolicy(
        action_name='rootkit_install',
        category=ActionCategory.DEFENSE_EVASION,
        required_level=AuthorizationLevel.CRITICAL,
        description='Install rootkit (testing only)',
        risk_score=10,
        mitre_technique='T1014',
        cooldown_minutes=480,
        requires_audit=True,
        allowed_targets=['isolated_vm']
    ),
    'destroy_evidence': AuthorizationPolicy(
        action_name='destroy_evidence',
        category=ActionCategory.DEFENSE_EVASION,
        required_level=AuthorizationLevel.CRITICAL,
        description='Destroy forensic evidence',
        risk_score=10,
        mitre_technique='T1070',
        cooldown_minutes=480,
        requires_audit=True
    ),
    'ddos_attack': AuthorizationPolicy(
        action_name='ddos_attack',
        category=ActionCategory.NETWORK_ATTACK,
        required_level=AuthorizationLevel.CRITICAL,
        description='DDoS attack simulation',
        risk_score=10,
        mitre_technique='T1498',
        cooldown_minutes=480,
        requires_audit=True,
        allowed_targets=['isolated_lab']
    ),
}


# =============================================================================
# Task 5.1.2: Implement Authorization Checks
# =============================================================================

@dataclass
class AuthorizationToken:
    """Temporary authorization token for approved actions."""
    token_id: str
    action_name: str
    level: AuthorizationLevel
    granted_at: datetime
    expires_at: datetime
    granted_by: str
    reason: str = ""
    used: bool = False


class AuthorizationManager:
    """
    Manages authorization checks and tokens.
    
    Provides:
    - Action authorization verification
    - Token generation and validation
    - Cooldown tracking
    - Audit logging
    """
    
    def __init__(self, config_dir: Optional[Path] = None):
        """Initialize authorization manager."""
        self.config_dir = config_dir or Path.home() / '.kali_agent_v3'
        self.config_dir.mkdir(exist_ok=True)
        
        self.tokens: Dict[str, AuthorizationToken] = {}
        self.cooldowns: Dict[str, datetime] = {}
        self.audit_log: List[Dict] = []
        
        # Load or create PIN/password
        self.pin_file = self.config_dir / 'auth_pin.json'
        self._init_auth_credentials()
        
        logger.info("Authorization manager initialized")
    
    def _init_auth_credentials(self):
        """Initialize authentication credentials."""
        if not self.pin_file.exists():
            logger.info("No PIN set - creating default (INSECURE)")
            # In production, this would require user to set PIN
            self._set_pin("0000")  # Default insecure PIN
    
    def _set_pin(self, pin: str):
        """Set authorization PIN."""
        pin_hash = hashlib.sha256(pin.encode()).hexdigest()
        credentials = {
            'pin_hash': pin_hash,
            'created_at': datetime.now().isoformat(),
            'level': AuthorizationLevel.ADVANCED.value
        }
        
        with open(self.pin_file, 'w') as f:
            json.dump(credentials, f, indent=2)
        
        # Restrict permissions
        os.chmod(self.pin_file, 0o600)
        
        logger.info("PIN set successfully")
    
    def verify_pin(self, pin: str) -> bool:
        """Verify PIN against stored hash."""
        if not self.pin_file.exists():
            return False
        
        with open(self.pin_file, 'r') as f:
            credentials = json.load(f)
        
        pin_hash = hashlib.sha256(pin.encode()).hexdigest()
        return credentials['pin_hash'] == pin_hash
    
    def check_authorization(self, action_name: str, target: Optional[str] = None) -> Tuple[bool, str]:
        """
        Check if an action is authorized.
        
        Args:
            action_name: Name of action to check
            target: Optional target of action
            
        Returns:
            Tuple of (authorized, reason)
        """
        # Get action policy
        policy = ACTION_REGISTRY.get(action_name)
        if not policy:
            logger.warning(f"Unknown action: {action_name}")
            return False, f"Unknown action: {action_name}"
        
        # Check authorization level
        required_level = policy.required_level
        
        if required_level == AuthorizationLevel.NONE:
            return True, "No authorization required"
        
        # Check for valid token
        if self._has_valid_token(action_name, required_level):
            return True, "Valid token present"
        
        # Check cooldown
        if self._in_cooldown(action_name):
            remaining = self._get_cooldown_remaining(action_name)
            return False, f"Action in cooldown ({remaining} minutes remaining)"
        
        # Check target restrictions
        if target:
            if policy.blocked_targets and any(t in target for t in policy.blocked_targets):
                return False, f"Target '{target}' is blocked for this action"
            
            if policy.allowed_targets and not any(t in target for t in policy.allowed_targets):
                return False, f"Target '{target}' not in allowed list: {policy.allowed_targets}"
        
        # Authorization required
        if required_level == AuthorizationLevel.BASIC:
            return False, "BASIC authorization required (confirm action)"
        elif required_level == AuthorizationLevel.ADVANCED:
            return False, "ADVANCED authorization required (PIN/password)"
        elif required_level == AuthorizationLevel.CRITICAL:
            return False, "CRITICAL authorization required (multi-factor + written confirmation)"
        
        return False, "Authorization check failed"
    
    def _has_valid_token(self, action_name: str, required_level: AuthorizationLevel) -> bool:
        """Check if a valid token exists for the action."""
        now = datetime.now()
        
        for token in self.tokens.values():
            if (token.action_name == action_name and 
                token.level.value >= required_level.value and
                token.expires_at > now and
                not token.used):
                return True
        
        return False
    
    def _in_cooldown(self, action_name: str) -> bool:
        """Check if action is in cooldown period."""
        if action_name not in self.cooldowns:
            return False
        
        policy = ACTION_REGISTRY.get(action_name)
        if not policy or policy.cooldown_minutes == 0:
            return False
        
        cooldown_end = self.cooldowns[action_name]
        return datetime.now() < cooldown_end
    
    def _get_cooldown_remaining(self, action_name: str) -> int:
        """Get remaining cooldown time in minutes."""
        policy = ACTION_REGISTRY.get(action_name)
        if not policy:
            return 0
        
        cooldown_end = self.cooldowns.get(action_name)
        if not cooldown_end:
            return 0
        
        remaining = cooldown_end - datetime.now()
        return max(0, int(remaining.total_seconds() / 60))
    
    def request_authorization(self, action_name: str, pin: Optional[str] = None,
                            confirmation_text: Optional[str] = None,
                            reason: str = "") -> Tuple[bool, str, Optional[AuthorizationToken]]:
        """
        Request authorization for an action.
        
        Args:
            action_name: Name of action
            pin: PIN for ADVANCED level
            confirmation_text: Written confirmation for CRITICAL level
            reason: Reason for action
            
        Returns:
            Tuple of (success, message, token)
        """
        policy = ACTION_REGISTRY.get(action_name)
        if not policy:
            return False, f"Unknown action: {action_name}", None
        
        required_level = policy.required_level
        
        # NONE level - auto-approve
        if required_level == AuthorizationLevel.NONE:
            token = self._create_token(action_name, required_level, "system", reason)
            return True, "Authorized (no authorization required)", token
        
        # BASIC level - simple confirmation
        if required_level == AuthorizationLevel.BASIC:
            token = self._create_token(action_name, required_level, "user", reason)
            return True, "Authorized (basic confirmation)", token
        
        # ADVANCED level - PIN required
        if required_level == AuthorizationLevel.ADVANCED:
            if not pin:
                return False, "PIN required for ADVANCED authorization", None
            
            if not self.verify_pin(pin):
                self._log_attempt(action_name, False, "Invalid PIN")
                return False, "Invalid PIN", None
            
            token = self._create_token(action_name, required_level, "user", reason)
            self._log_attempt(action_name, True, "PIN verified")
            return True, "Authorized (PIN verified)", token
        
        # CRITICAL level - multi-factor + written confirmation
        if required_level == AuthorizationLevel.CRITICAL:
            if not pin:
                return False, "PIN required for CRITICAL authorization", None
            
            if not self.verify_pin(pin):
                self._log_attempt(action_name, False, "Invalid PIN")
                return False, "Invalid PIN", None
            
            if not confirmation_text:
                return False, "Written confirmation required (type action name to confirm)", None
            
            # Verify confirmation text matches action name
            if confirmation_text.lower().strip() != action_name.lower():
                self._log_attempt(action_name, False, "Confirmation mismatch")
                return False, f"Confirmation mismatch. Type '{action_name}' to confirm", None
            
            token = self._create_token(action_name, required_level, "user", reason, expires_minutes=60)
            self._log_attempt(action_name, True, "Multi-factor + written confirmation")
            return True, "Authorized (CRITICAL - multi-factor)", token
        
        return False, "Unknown authorization level", None
    
    def _create_token(self, action_name: str, level: AuthorizationLevel,
                     granted_by: str, reason: str,
                     expires_minutes: int = 30) -> AuthorizationToken:
        """Create authorization token."""
        token_id = hashlib.sha256(
            f"{action_name}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        now = datetime.now()
        expires_at = now + timedelta(minutes=expires_minutes)
        
        token = AuthorizationToken(
            token_id=token_id,
            action_name=action_name,
            level=level,
            granted_at=now,
            expires_at=expires_at,
            granted_by=granted_by,
            reason=reason
        )
        
        self.tokens[token_id] = token
        
        # Set cooldown
        policy = ACTION_REGISTRY.get(action_name)
        if policy and policy.cooldown_minutes > 0:
            self.cooldowns[action_name] = now + timedelta(minutes=policy.cooldown_minutes)
        
        logger.info(f"Created token {token_id} for {action_name} ({level.name})")
        
        return token
    
    def use_token(self, token_id: str) -> Tuple[bool, str]:
        """Mark token as used."""
        if token_id not in self.tokens:
            return False, "Token not found"
        
        token = self.tokens[token_id]
        
        if token.used:
            return False, "Token already used"
        
        if token.expires_at < datetime.now():
            return False, "Token expired"
        
        token.used = True
        self._log_usage(token)
        
        return True, "Token used successfully"
    
    def _log_attempt(self, action_name: str, success: bool, reason: str):
        """Log authorization attempt."""
        self.audit_log.append({
            'timestamp': datetime.now().isoformat(),
            'action': action_name,
            'type': 'attempt',
            'success': success,
            'reason': reason
        })
        
        # Save audit log
        self._save_audit_log()
    
    def _log_usage(self, token: AuthorizationToken):
        """Log token usage."""
        self.audit_log.append({
            'timestamp': datetime.now().isoformat(),
            'action': token.action_name,
            'type': 'usage',
            'token_id': token.token_id,
            'level': token.level.name,
            'granted_by': token.granted_by,
            'reason': token.reason
        })
        
        self._save_audit_log()
    
    def _save_audit_log(self):
        """Save audit log to file."""
        audit_file = self.config_dir / 'audit_log.json'
        
        with open(audit_file, 'w') as f:
            json.dump(self.audit_log[-1000:], f, indent=2)  # Keep last 1000 entries
    
    def get_audit_log(self, limit: int = 100) -> List[Dict]:
        """Get recent audit log entries."""
        return self.audit_log[-limit:]
    
    def list_pending_authorizations(self) -> List[Dict]:
        """List pending/expiring authorizations."""
        now = datetime.now()
        pending = []
        
        for token in self.tokens.values():
            if not token.used and token.expires_at > now:
                pending.append({
                    'token_id': token.token_id,
                    'action': token.action_name,
                    'level': token.level.name,
                    'expires_in_minutes': int((token.expires_at - now).total_seconds() / 60),
                    'reason': token.reason
                })
        
        return pending


# =============================================================================
# Task 5.1.3: Authorization Gates Integration
# =============================================================================

class AuthorizationGate:
    """
    Authorization gate decorator for actions.
    
    Use as decorator on methods that require authorization.
    """
    
    def __init__(self, auth_manager: AuthorizationManager):
        """Initialize gate with auth manager."""
        self.auth_manager = auth_manager
    
    def require_auth(self, action_name: str):
        """
        Decorator to require authorization for an action.
        
        Usage:
            @gate.require_auth('nmap_scan')
            def run_nmap_scan(target):
                ...
        """
        def decorator(func: Callable):
            def wrapper(*args, **kwargs):
                # Check authorization
                authorized, reason = self.auth_manager.check_authorization(action_name)
                
                if not authorized:
                    raise PermissionError(f"Authorization required: {reason}")
                
                # Execute function
                result = func(*args, **kwargs)
                
                # Log execution
                logger.info(f"Executed {action_name} successfully")
                
                return result
            
            return wrapper
        return decorator
    
    def check_and_request(self, action_name: str, pin: Optional[str] = None,
                         confirmation: Optional[str] = None,
                         reason: str = "") -> Tuple[bool, str]:
        """
        Check and request authorization in one call.
        
        Returns:
            Tuple of (authorized, message)
        """
        # First check if already authorized
        authorized, reason = self.auth_manager.check_authorization(action_name)
        
        if authorized:
            return True, reason
        
        # Request authorization
        success, message, token = self.auth_manager.request_authorization(
            action_name, pin, confirmation, reason
        )
        
        return success, message


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    """Command-line interface for authorization system."""
    import argparse
    
    parser = argparse.ArgumentParser(description='KaliAgent v3 - Authorization System')
    parser.add_argument('--set-pin', type=str, help='Set authorization PIN')
    parser.add_argument('--check', type=str, help='Check authorization for action')
    parser.add_argument('--authorize', type=str, help='Request authorization for action')
    parser.add_argument('--pin', type=str, help='PIN for authorization')
    parser.add_argument('--confirm', type=str, help='Written confirmation for CRITICAL actions')
    parser.add_argument('--reason', type=str, default='Security testing', help='Reason for action')
    parser.add_argument('--status', action='store_true', help='Show authorization status')
    parser.add_argument('--audit', action='store_true', help='Show audit log')
    parser.add_argument('--pending', action='store_true', help='Show pending authorizations')
    
    args = parser.parse_args()
    
    auth_manager = AuthorizationManager()
    AuthorizationGate(auth_manager)
    
    if args.set_pin:
        auth_manager._set_pin(args.set_pin)
        print("✅ PIN set successfully")
        print("⚠️  Remember this PIN - it's required for ADVANCED and CRITICAL actions")
    
    elif args.check:
        authorized, reason = auth_manager.check_authorization(args.check)
        status = "✅" if authorized else "❌"
        print(f"{status} Authorization for '{args.check}':")
        print(f"   {reason}")
        
        if not authorized:
            policy = ACTION_REGISTRY.get(args.check)
            if policy:
                print(f"\n   Required Level: {policy.required_level.name}")
                print(f"   Risk Score: {policy.risk_score}/10")
                print(f"   Cooldown: {policy.cooldown_minutes} minutes")
    
    elif args.authorize:
        success, message, token = auth_manager.request_authorization(
            args.authorize,
            pin=args.pin,
            confirmation_text=args.confirm,
            reason=args.reason
        )
        
        status = "✅" if success else "❌"
        print(f"{status} Authorization request for '{args.authorize}':")
        print(f"   {message}")
        
        if success and token:
            print(f"\n   Token ID: {token.token_id}")
            print(f"   Level: {token.level.name}")
            print(f"   Expires: {token.expires_at.isoformat()}")
            print(f"   Valid for: {int((token.expires_at - datetime.now()).total_seconds() / 60)} minutes")
    
    elif args.status:
        print("\nAuthorization Status:")
        print("=" * 60)
        
        pending = auth_manager.list_pending_authorizations()
        if pending:
            print(f"\nPending Authorizations: {len(pending)}")
            for p in pending:
                print(f"  • {p['action']} ({p['level']}) - expires in {p['expires_in_minutes']} min")
        else:
            print("  No pending authorizations")
        
        print("\nActive Cooldowns:")
        for action, cooldown_end in auth_manager.cooldowns.items():
            remaining = auth_manager._get_cooldown_remaining(action)
            if remaining > 0:
                print(f"  • {action}: {remaining} minutes")
        
        print("=" * 60)
    
    elif args.audit:
        log = auth_manager.get_audit_log(20)
        print("\nRecent Audit Log (last 20 entries):")
        print("=" * 60)
        for entry in log:
            timestamp = entry.get('timestamp', 'Unknown')[:19]
            action = entry.get('action', 'Unknown')
            entry_type = entry.get('type', 'Unknown')
            success = entry.get('success', entry.get('type') == 'usage')
            status = "✅" if success else "❌"
            print(f"  {timestamp} | {status} | {entry_type} | {action}")
        print("=" * 60)
    
    elif args.pending:
        pending = auth_manager.list_pending_authorizations()
        if pending:
            print("\nPending Authorizations:")
            print("=" * 60)
            for p in pending:
                print(f"\nToken: {p['token_id']}")
                print(f"  Action: {p['action']}")
                print(f"  Level: {p['level']}")
                print(f"  Expires in: {p['expires_in_minutes']} minutes")
                print(f"  Reason: {p['reason']}")
            print("=" * 60)
        else:
            print("No pending authorizations")
    
    else:
        # Show action registry
        print("\nKaliAgent v3 - Authorization System")
        print("=" * 60)
        print(f"Total registered actions: {len(ACTION_REGISTRY)}")
        
        # Group by level
        by_level = {}
        for action, policy in ACTION_REGISTRY.items():
            level = policy.required_level.name
            if level not in by_level:
                by_level[level] = []
            by_level[level].append((action, policy.risk_score))
        
        for level in ['NONE', 'BASIC', 'ADVANCED', 'CRITICAL']:
            if level in by_level:
                actions = by_level[level]
                print(f"\n{level} ({len(actions)} actions):")
                for action, risk in sorted(actions, key=lambda x: -x[1])[:10]:
                    print(f"  • {action} (risk: {risk}/10)")
                if len(actions) > 10:
                    print(f"  ... and {len(actions) - 10} more")
        
        print("=" * 60)
        print("\nUse --help for usage information")


if __name__ == '__main__':
    main()
