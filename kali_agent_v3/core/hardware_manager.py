#!/usr/bin/env python3
"""
KaliAgent v3 - Hardware Manager Module
=======================================

Manages hardware detection and configuration for:
- WiFi adapters (monitor mode, packet injection)
- SDR devices (RTL-SDR, HackRF)
- USB devices and passthrough

Tasks: 2.1.1, 2.1.2, 2.1.3, 2.2.1, 2.2.2, 2.2.3
Status: IMPLEMENTED
"""

import os
import re
import subprocess
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class WiFiAdapter:
    """WiFi adapter information."""
    interface: str
    chipset: str
    vendor: str
    monitor_capable: bool
    injection_capable: bool
    monitor_mode: bool = False
    monitor_interface: Optional[str] = None
    driver: str = ""
    phy_id: int = 0


@dataclass
class SDRDevice:
    """SDR device information."""
    device_type: str  # rtl-sdr, hackrf, etc.
    vendor_id: str
    product_id: str
    serial: Optional[str]
    index: int
    capabilities: Dict[str, bool] = field(default_factory=dict)
    frequency_range: Optional[Tuple[int, int]] = None


@dataclass
class HardwareStatus:
    """Overall hardware status."""
    wifi_adapters: List[WiFiAdapter]
    sdr_devices: List[SDRDevice]
    monitor_interfaces: List[str]
    injection_ready: bool
    sdr_ready: bool


class HardwareManager:
    """
    Manages hardware detection and configuration.
    
    Provides:
    - WiFi adapter detection and configuration
    - Monitor mode automation
    - Packet injection testing
    - SDR device detection
    - Hardware status reporting
    """
    
    def __init__(self):
        """Initialize hardware manager."""
        self.wifi_adapters: List[WiFiAdapter] = []
        self.sdr_devices: List[SDRDevice] = []
        self.monitor_interfaces: List[str] = []
    
    # =========================================================================
    # Task 2.1.1: WiFi Adapter Detection
    # =========================================================================
    
    def detect_wifi_adapters(self) -> List[WiFiAdapter]:
        """
        Detect all WiFi adapters on the system.
        
        Returns:
            List of WiFiAdapter objects
        """
        logger.info("Detecting WiFi adapters...")
        adapters = []
        
        # Get wireless interfaces
        wireless_interfaces = self._get_wireless_interfaces()
        
        for interface in wireless_interfaces:
            adapter = self._get_adapter_info(interface)
            if adapter:
                adapters.append(adapter)
        
        self.wifi_adapters = adapters
        logger.info(f"Found {len(adapters)} WiFi adapter(s)")
        
        return adapters
    
    def _get_wireless_interfaces(self) -> List[str]:
        """Get list of wireless interfaces."""
        interfaces = []
        
        try:
            # Method 1: Check /sys/class/net
            for iface in os.listdir('/sys/class/net'):
                if os.path.exists(f'/sys/class/net/{iface}/phy80211'):
                    interfaces.append(iface)
        except Exception as e:
            logger.debug(f"Error scanning /sys/class/net: {e}")
        
        # Method 2: Use iwconfig
        if not interfaces:
            try:
                result = subprocess.run(
                    ['iwconfig'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                for line in result.stdout.split('\n'):
                    if 'IEEE 802.11' in line or 'ESSID' in line:
                        match = re.match(r'^(\w+)', line)
                        if match:
                            interfaces.append(match.group(1))
            except Exception as e:
                logger.debug(f"Error running iwconfig: {e}")
        
        return interfaces
    
    def _get_adapter_info(self, interface: str) -> Optional[WiFiAdapter]:
        """Get detailed info about a WiFi adapter."""
        try:
            # Get chipset info from lsusb or lspci
            chipset = "Unknown"
            vendor = "Unknown"
            driver = "Unknown"
            
            # Try lsusb first (USB adapters)
            result = subprocess.run(
                ['lsusb'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            for line in result.stdout.split('\n'):
                if interface in line or 'Wireless' in line or 'WiFi' in line:
                    # Parse vendor and chipset
                    match = re.search(r'ID (\w+):(\w+) (.+)', line)
                    if match:
                        vendor_id = match.group(1)
                        match.group(2)
                        chipset = match.group(3)
                        vendor = self._lookup_vendor(vendor_id)
                    break
            
            # If not found in lsusb, try lspci (PCIe adapters)
            if chipset == "Unknown":
                result = subprocess.run(
                    ['lspci'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                for line in result.stdout.split('\n'):
                    if 'Network' in line and 'Wireless' in line:
                        match = re.search(r'(.+?) \[', line)
                        if match:
                            chipset = match.group(1)
                        break
            
            # Get driver info
            try:
                result = subprocess.run(
                    ['ethtool', '-i', interface],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                for line in result.stdout.split('\n'):
                    if line.startswith('driver:'):
                        driver = line.split(':')[1].strip()
            except Exception:
                pass
            
            # Check capabilities
            monitor_capable = self._check_monitor_capable(interface)
            injection_capable = self._check_injection_capable(interface)
            
            # Get phy ID
            phy_id = 0
            try:
                result = subprocess.run(
                    ['iw', 'dev', interface, 'info'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                for line in result.stdout.split('\n'):
                    if 'wiphy' in line:
                        match = re.search(r'wiphy (\d+)', line)
                        if match:
                            phy_id = int(match.group(1))
            except Exception:
                pass
            
            return WiFiAdapter(
                interface=interface,
                chipset=chipset,
                vendor=vendor,
                monitor_capable=monitor_capable,
                injection_capable=injection_capable,
                driver=driver,
                phy_id=phy_id
            )
            
        except Exception as e:
            logger.error(f"Error getting adapter info for {interface}: {e}")
            return None
    
    def _lookup_vendor(self, vendor_id: str) -> str:
        """Lookup vendor name from vendor ID."""
        vendors = {
            '0cf3': 'Atheros',
            '13d3': 'AzureWave',
            '0b05': 'ASUS',
            '050d': 'Belkin',
            '0bda': 'Realtek',
            '8087': 'Intel',
            '046d': 'Logitech',
            '05ac': 'Apple',
            '0e8d': 'MediaTek',
            '148f': 'Ralink',
            '0a12': 'CSR',
            '03f0': 'HP',
            '04ca': 'Lite-On',
            '0930': 'Toshiba',
            '0489': 'Foxconn',
            '10ec': 'Realtek',
            '174c': 'ASMedia',
        }
        
        return vendors.get(vendor_id, 'Unknown')
    
    def _check_monitor_capable(self, interface: str) -> bool:
        """Check if adapter supports monitor mode."""
        try:
            result = subprocess.run(
                ['iw', 'list'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Look for "valid interface combinations" section
            if 'monitor' in result.stdout.lower():
                return True
            
            return False
        except Exception:
            return False
    
    def _check_injection_capable(self, interface: str) -> bool:
        """Check if adapter supports packet injection."""
        # Common injection-capable chipsets
        injection_chipsets = [
            'Atheros', 'AR9271', 'AR9285', 'AR9287',
            'Ralink', 'RT3070', 'RT3572', 'RT5370',
            'Realtek', 'RTL8812AU', 'RTL8187',
        ]
        
        try:
            result = subprocess.run(
                ['lsusb'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            for chipset in injection_chipsets:
                if chipset.lower() in result.stdout.lower():
                    return True
            
            return False
        except Exception:
            return False
    
    # =========================================================================
    # Task 2.1.2: Monitor Mode Automation
    # =========================================================================
    
    def enable_monitor_mode(self, interface: str) -> Tuple[bool, str]:
        """
        Enable monitor mode on a WiFi adapter.
        
        Args:
            interface: WiFi interface name (e.g., 'wlan0')
            
        Returns:
            Tuple of (success, monitor_interface_name)
        """
        logger.info(f"Enabling monitor mode on {interface}...")
        
        try:
            # Step 1: Kill interfering processes
            self._kill_interfering_processes()
            
            # Step 2: Bring interface down
            subprocess.run(
                ['ip', 'link', 'set', interface, 'down'],
                capture_output=True,
                timeout=10
            )
            
            # Step 3: Set monitor mode using iw
            result = subprocess.run(
                ['iw', interface, 'set', 'type', 'monitor'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                # Try airmon-ng as fallback
                logger.info("iw failed, trying airmon-ng...")
                result = subprocess.run(
                    ['airmon-ng', 'start', interface],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                # Parse airmon-ng output for monitor interface
                match = re.search(r'monitor (wlan\d+mon) enabled', result.stdout)
                if match:
                    monitor_interface = match.group(1)
                    self.monitor_interfaces.append(monitor_interface)
                    logger.info(f"Monitor mode enabled: {monitor_interface}")
                    return True, monitor_interface
                else:
                    logger.error(f"Failed to enable monitor mode: {result.stderr}")
                    return False, ""
            
            # Step 4: Bring interface up
            subprocess.run(
                ['ip', 'link', 'set', interface, 'up'],
                capture_output=True,
                timeout=10
            )
            
            # Verify monitor mode
            if self._verify_monitor_mode(interface):
                self.monitor_interfaces.append(interface)
                logger.info(f"Monitor mode enabled: {interface}")
                return True, interface
            else:
                logger.error("Monitor mode verification failed")
                return False, ""
                
        except Exception as e:
            logger.error(f"Error enabling monitor mode: {e}")
            return False, ""
    
    def disable_monitor_mode(self, interface: str) -> bool:
        """Disable monitor mode on an interface."""
        logger.info(f"Disabling monitor mode on {interface}...")
        
        try:
            # If using airmon-ng interface
            if interface.endswith('mon'):
                result = subprocess.run(
                    ['airmon-ng', 'stop', interface],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                return result.returncode == 0
            
            # Regular interface
            subprocess.run(
                ['ip', 'link', 'set', interface, 'down'],
                capture_output=True,
                timeout=10
            )
            
            subprocess.run(
                ['iw', interface, 'set', 'type', 'managed'],
                capture_output=True,
                timeout=10
            )
            
            subprocess.run(
                ['ip', 'link', 'set', interface, 'up'],
                capture_output=True,
                timeout=10
            )
            
            if interface in self.monitor_interfaces:
                self.monitor_interfaces.remove(interface)
            
            return True
            
        except Exception as e:
            logger.error(f"Error disabling monitor mode: {e}")
            return False
    
    def _kill_interfering_processes(self):
        """Kill processes that interfere with monitor mode."""
        interfering = ['NetworkManager', 'wpa_supplicant', 'wifimanager']
        
        for proc in interfering:
            try:
                subprocess.run(
                    ['pkill', proc],
                    capture_output=True,
                    timeout=5
                )
                logger.debug(f"Killed {proc}")
            except Exception:
                pass
    
    def _verify_monitor_mode(self, interface: str) -> bool:
        """Verify monitor mode is enabled."""
        try:
            result = subprocess.run(
                ['iw', interface, 'info'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            return 'type monitor' in result.stdout.lower() or 'Monitor' in result.stdout
        except Exception:
            return False
    
    # =========================================================================
    # Task 2.1.3: Injection Testing
    # =========================================================================
    
    def test_packet_injection(self, interface: str) -> Tuple[bool, int]:
        """
        Test packet injection capability.
        
        Args:
            interface: Monitor mode interface
            
        Returns:
            Tuple of (injection_working, success_rate)
        """
        logger.info(f"Testing packet injection on {interface}...")
        
        try:
            # Use aireplay-ng injection test
            result = subprocess.run(
                ['aireplay-ng', '-9', '-e', 'test', '-a', '00:00:00:00:00:00', interface],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Parse output for injection rate
            match = re.search(r'(\d+)/(\d+) successful injections', result.stdout)
            if match:
                successful = int(match.group(1))
                total = int(match.group(2))
                success_rate = int((successful / total) * 100) if total > 0 else 0
                
                injection_working = success_rate > 50
                logger.info(f"Injection test: {success_rate}% success rate")
                
                return injection_working, success_rate
            
            # Alternative parsing
            if 'Injection is working' in result.stdout:
                return True, 100
            elif 'Injection failed' in result.stdout:
                return False, 0
            
            # Default: check return code
            return result.returncode == 0, 50
            
        except subprocess.TimeoutExpired:
            logger.error("Injection test timed out")
            return False, 0
        except Exception as e:
            logger.error(f"Error testing injection: {e}")
            return False, 0
    
    # =========================================================================
    # Task 2.2.1: RTL-SDR Detection
    # =========================================================================
    
    def detect_rtlsdr(self) -> List[SDRDevice]:
        """
        Detect RTL-SDR devices.
        
        Returns:
            List of RTL-SDR SDRDevice objects
        """
        logger.info("Detecting RTL-SDR devices...")
        devices = []
        
        try:
            # Use rtl_test to detect devices
            result = subprocess.run(
                ['rtl_test'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Parse output
            for line in result.stderr.split('\n'):
                if 'Found' in line and 'device(s)' in line:
                    match = re.search(r'Found (\d+) device\(s\)', line)
                    if match:
                        count = int(match.group(1))
                        
                        for i in range(count):
                            device = SDRDevice(
                                device_type='rtl-sdr',
                                vendor_id='0bda',
                                product_id='2838',
                                serial=None,
                                index=i,
                                capabilities={
                                    'rx': True,
                                    'tx': False,
                                    'gain_control': True
                                },
                                frequency_range=(24000000, 1766000000)  # 24 MHz - 1.766 GHz
                            )
                            devices.append(device)
            
            self.sdr_devices.extend(devices)
            logger.info(f"Found {len(devices)} RTL-SDR device(s)")
            
        except Exception as e:
            logger.debug(f"RTL-SDR detection error: {e}")
        
        return devices
    
    # =========================================================================
    # Task 2.2.2: HackRF Detection
    # =========================================================================
    
    def detect_hackrf(self) -> List[SDRDevice]:
        """
        Detect HackRF devices.
        
        Returns:
            List of HackRF SDRDevice objects
        """
        logger.info("Detecting HackRF devices...")
        devices = []
        
        try:
            # Use hackrf_info to detect devices
            result = subprocess.run(
                ['hackrf_info'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Parse output
                serial = None
                for line in result.stdout.split('\n'):
                    if 'Serial number' in line:
                        match = re.search(r'Serial number: (\w+)', line)
                        if match:
                            serial = match.group(1)
                
                device = SDRDevice(
                    device_type='hackrf',
                    vendor_id='1fc9',
                    product_id='0001',
                    serial=serial,
                    index=0,
                    capabilities={
                        'rx': True,
                        'tx': True,
                        'gain_control': True,
                        'bias_tee': True
                    },
                    frequency_range=(1000000, 6000000000)  # 1 MHz - 6 GHz
                )
                devices.append(device)
                
                self.sdr_devices.append(device)
                logger.info(f"Found HackRF device (serial: {serial})")
            
        except Exception as e:
            logger.debug(f"HackRF detection error: {e}")
        
        return devices
    
    # =========================================================================
    # Task 2.2.3: SDR Tool Installation
    # =========================================================================
    
    def install_sdr_tools(self) -> Dict[str, bool]:
        """
        Install SDR-related tools.
        
        Returns:
            Dictionary of tool_name -> installed_status
        """
        logger.info("Installing SDR tools...")
        
        tools = {
            'rtl-sdr': False,
            'hackrf': False,
            'gqrx-sdr': False,
            'inspectrum': False,
            'universal-radio-hacker': False,
        }
        
        for tool in tools.keys():
            try:
                logger.info(f"Installing {tool}...")
                result = subprocess.run(
                    ['apt-get', 'install', '-y', tool],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                
                if result.returncode == 0:
                    tools[tool] = True
                    logger.info(f"Installed {tool}")
                else:
                    logger.warning(f"Failed to install {tool}")
                    
            except Exception as e:
                logger.error(f"Error installing {tool}: {e}")
        
        return tools
    
    # =========================================================================
    # Hardware Status
    # =========================================================================
    
    def get_hardware_status(self) -> HardwareStatus:
        """Get complete hardware status."""
        # Detect all hardware
        if not self.wifi_adapters:
            self.detect_wifi_adapters()
        
        if not self.sdr_devices:
            self.detect_rtlsdr()
            self.detect_hackrf()
        
        # Determine readiness
        injection_ready = any(
            adapter.injection_capable and adapter.monitor_mode
            for adapter in self.wifi_adapters
        )
        
        sdr_ready = len(self.sdr_devices) > 0
        
        return HardwareStatus(
            wifi_adapters=self.wifi_adapters,
            sdr_devices=self.sdr_devices,
            monitor_interfaces=self.monitor_interfaces,
            injection_ready=injection_ready,
            sdr_ready=sdr_ready
        )
    
    def print_hardware_status(self):
        """Print hardware status to console."""
        status = self.get_hardware_status()
        
        print("\n" + "="*60)
        print("HARDWARE STATUS")
        print("="*60)
        
        # WiFi Adapters
        print(f"\n📶 WiFi Adapters: {len(status.wifi_adapters)}")
        for adapter in status.wifi_adapters:
            print(f"\n  Interface: {adapter.interface}")
            print(f"  Chipset: {adapter.chipset} ({adapter.vendor})")
            print(f"  Driver: {adapter.driver}")
            print(f"  Monitor Mode: {'✅ Yes' if adapter.monitor_mode else '❌ No'}")
            print(f"  Packet Injection: {'✅ Yes' if adapter.injection_capable else '❌ No'}")
            if adapter.monitor_interface:
                print(f"  Monitor Interface: {adapter.monitor_interface}")
        
        # SDR Devices
        print(f"\n📻 SDR Devices: {len(status.sdr_devices)}")
        for device in status.sdr_devices:
            print(f"\n  Type: {device.device_type}")
            print(f"  Serial: {device.serial or 'N/A'}")
            print(f"  Capabilities: RX={device.capabilities.get('rx', False)}, TX={device.capabilities.get('tx', False)}")
            if device.frequency_range:
                print(f"  Frequency Range: {device.frequency_range[0]/1e6:.0f} MHz - {device.frequency_range[1]/1e6:.0f} MHz")
        
        # Readiness
        print(f"\n🎯 Injection Ready: {'✅ Yes' if status.injection_ready else '❌ No'}")
        print(f"📻 SDR Ready: {'✅ Yes' if status.sdr_ready else '❌ No'}")
        print("="*60 + "\n")


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    """Command-line interface for hardware manager."""
    import argparse
    
    parser = argparse.ArgumentParser(description='KaliAgent v3 - Hardware Manager')
    parser.add_argument('--detect-wifi', action='store_true', help='Detect WiFi adapters')
    parser.add_argument('--detect-sdr', action='store_true', help='Detect SDR devices')
    parser.add_argument('--monitor', type=str, help='Enable monitor mode on interface')
    parser.add_argument('--test-injection', type=str, help='Test packet injection on interface')
    parser.add_argument('--install-sdr', action='store_true', help='Install SDR tools')
    parser.add_argument('--status', action='store_true', help='Show hardware status')
    
    args = parser.parse_args()
    
    manager = HardwareManager()
    
    if args.detect_wifi:
        adapters = manager.detect_wifi_adapters()
        print(f"Found {len(adapters)} WiFi adapter(s):")
        for adapter in adapters:
            print(f"  - {adapter.interface}: {adapter.chipset} ({adapter.vendor})")
            print(f"    Monitor: {'✅' if adapter.monitor_capable else '❌'}, Injection: {'✅' if adapter.injection_capable else '❌'}")
    
    elif args.detect_sdr:
        rtl = manager.detect_rtlsdr()
        hackrf = manager.detect_hackrf()
        print(f"Found {len(rtl)} RTL-SDR device(s)")
        print(f"Found {len(hackrf)} HackRF device(s)")
    
    elif args.monitor:
        success, monitor_iface = manager.enable_monitor_mode(args.monitor)
        if success:
            print(f"✅ Monitor mode enabled: {monitor_iface}")
        else:
            print("❌ Failed to enable monitor mode")
    
    elif args.test_injection:
        working, rate = manager.test_packet_injection(args.test_injection)
        if working:
            print(f"✅ Injection working ({rate}% success rate)")
        else:
            print(f"❌ Injection not working ({rate}% success rate)")
    
    elif args.install_sdr:
        tools = manager.install_sdr_tools()
        print("SDR Tools Installation:")
        for tool, installed in tools.items():
            print(f"  {'✅' if installed else '❌'} {tool}")
    
    elif args.status or True:  # Default to status
        manager.print_hardware_status()
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
