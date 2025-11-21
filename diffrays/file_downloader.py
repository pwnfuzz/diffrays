#!/usr/bin/env python3

import requests
import json
import gzip
import re
import sys
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import os
from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)

def print_success(message):
    """Print success message in green"""
    print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")

def print_info(message):
    """Print info message in blue"""
    print(f"{Fore.BLUE}[*] {message}{Style.RESET_ALL}")

def print_error(message):
    """Print error message in red"""
    print(f"{Fore.RED}[-] {message}{Style.RESET_ALL}")

# ===== CONSTANTS =====
WINBINDEX_BASE_URL = "https://winbindex.m417z.com/data/by_filename_compressed"
MSDL_BASE_URL = "https://msdl.microsoft.com/download/symbols"
DEFAULT_WINDOWS_VERSION = "11-24H2"

def get_component_mapping() -> List[Dict[str, str]]:
    """Returns the component mapping as a list"""
    return [
        {"name": "Windows Common Log File System Driver", "file": "clfs.sys"},
        {"name": "Windows Composite Image File System", "file": "cimfs.sys"},
        {"name": "Windows DWM Core Library", "file": "dwmcore.dll"},
        {"name": "Windows Telephony Service", "file": "tapisrv.dll"},
        {"name": "Windows Kernel", "file": "ntoskrnl.exe"},
        {"name": "Windows USB Print Driver", "file": "usbprint.sys"},
        {"name": "Windows upnphost.dll", "file": "upnphost.dll"},
        {"name": "Windows Internet Information Services", "file": "http.sys"},
        {"name": "Microsoft Streaming Service", "file": "mskssrv.sys"},
        {"name": "Windows Resilient File System (ReFS)", "file": "refs.sys"},
        {"name": "Windows Win32 Kernel Subsystem", "file": "win32kfull.sys"},
        {"name": "Windows TCP/IP", "file": "tcpip.sys"},
        {"name": "Kernel Streaming WOW Thunk Service Driver", "file": "ksthunk.sys"},
        {"name": "Windows exFAT File System", "file": "exfat.sys"},
        {"name": "Windows Fast FAT Driver", "file": "fastfat.sys"},
        {"name": "Windows USB Video Driver", "file": "usbvideo.sys"},
        {"name": "Microsoft Management Console", "file": "mmc.exe"},
        {"name": "Microsoft Local Security Authority Server (lsasrv)", "file": "lsasrv.dll"},
        {"name": "Windows Message Queuing", "file": "mqsvc.exe"},
        {"name": "Windows Kerberos", "file": "kerberos.dll"},
        {"name": "Windows Ancillary Function Driver for WinSock", "file": "afd.sys"},
        {"name": "Winlogon", "file": "winlogon.exe"},
        {"name": "Windows Hyper-V NT Kernel Integration VSP", "file": "vkrnlintvsp.sys"},
        {"name": "Windows Hyper-V", "file": "hvix64.exe"},
        {"name": "Windows Hyper-V", "file": "hvax64.exe"},
        {"name": "Windows Hyper-V", "file": "hvloader.dll"},
        {"name": "Windows Hyper-V", "file": "kdhvcom.dll"},
        {"name": "Windows Power Dependency Coordinator", "file": "pdc.sys"},
        {"name": "Windows Cryptographic Services", "file": "cryptsvc.dll"},
        {"name": "Windows Remote Desktop Services", "file": "termsrv.dll"},
        {"name": "Windows BitLocker", "file": "fvevol.sys"},
        {"name": "Windows Core Messaging", "file": "CoreMessaging.dll"},
        {"name": "Windows Boot Manager", "file": "bootmgfw.efi"},
        {"name": "Windows Boot Loader", "file": "winload.exe"},
        {"name": "Windows Task Scheduler", "file": "WPTaskScheduler.dll"},
        {"name": "Windows Secure Channel", "file": "schannel.dll"},
        {"name": "Windows Local Session Manager (LSM)", "file": "lsm.dll"},
        {"name": "Windows LDAP - Lightweight Directory Access Protocol", "file": "Wldap32.dll"},
        {"name": "Web Threat Defense (WTD.sys)", "file": "wtd.sys"},
        {"name": "Windows Storage Port Driver", "file": "storport.sys"},
        {"name": "Windows NTFS", "file": "ntfs.sys"},
        {"name": "Windows Netlogon", "file":"netlogon.dll"},
        {"name": "Windows Remote Access Connection Manager", "file": "rasman.dll"},
        {"name": "Windows Local Security Authority Subsystem Service (LSASS)", "file": "lsass.exe"},
        {"name": "Windows DHCP Server", "file": "dhcpssvc.dll"}
    ]

def validate_cve_format(cve_id: str) -> bool:
    """Validate CVE ID format (CVE-YYYY-NNNNN+)"""
    pattern = r'^CVE-\d{4}-\d{4,}$'
    return bool(re.match(pattern, cve_id.upper()))

def fetch_cve_data(cve_id: str) -> Optional[Dict]:
    """Fetch CVE data from Microsoft Security Response Center API"""
    base_url = "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability"
    url = f"{base_url}/{cve_id}"
    
    headers = {
        'User-Agent': 'CVE-Extractor/1.0',
        'Accept': 'application/json'
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            print_error(f"CVE {cve_id} not found in Microsoft database")
            return None
        else:
            print_error(f"Error fetching data: HTTP {response.status_code}")
            return None
            
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return None
    except json.JSONDecodeError as e:
        print_error(f"Failed to parse JSON response: {e}")
        return None

def extract_cve_info(data: Dict) -> Dict:
    """Extract required information from CVE data"""
    extracted_info = {
        'cve_title': data.get('cveTitle', 'N/A'),
        'description': data.get('description', 'N/A'),
        'unformatted_description': data.get('unformattedDescription', 'N/A'),
        'tag': data.get('tag', 'N/A'),
        'release_number': data.get('releaseNumber', 'N/A'),
        'articles': []
    }
    
    # Extract articles information
    articles = data.get('articles', [])
    for article in articles:
        article_info = {
            'title': article.get('title', 'N/A'),
            'description': article.get('description', 'N/A')
        }
        extracted_info['articles'].append(article_info)
    
    return extracted_info

def find_matching_components(cve_info: Dict, component_mapping: List[Dict]) -> List[Dict]:
    """Find matching components based on exact CVE tag match only"""
    matches = []
    
    # Get the tag field only
    tag = cve_info.get('tag', '')
    
    if not tag or tag == 'N/A':
        return matches
    
    # Remove "Role: " prefix if present
    if tag.startswith("Role: "):
        tag = tag[6:]  # Remove "Role: "
    
    # Check for exact matches only
    for component in component_mapping:
        if tag == component["name"]:
            matches.append({
                'name': component["name"],
                'file': component["file"]
            })
    
    return matches

def release_number_to_patch_month(release_number: str) -> Optional[str]:
    """Convert release number (e.g., '2025-Sep') to patch month format (e.g., '2025-09')"""
    if not release_number or release_number == 'N/A':
        return None
    
    month_map = {
        'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
        'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
        'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
    }
    
    try:
        year, month_name = release_number.split('-')
        month_num = month_map.get(month_name)
        if month_num:
            return f"{year}-{month_num}"
    except ValueError:
        pass
    
    return None

def download_database(filename: str, dbname: str) -> str:
    """
    Download the JSON.gz database from winbindex for the specified filename.
    
    Returns:
        Path to the downloaded file
    """
    url = f"{WINBINDEX_BASE_URL}/{filename}.json.gz"
    
    print(f"[+] Downloading database from: {url}")
    
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        with open(dbname, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        print_success(f"Database saved as: {dbname}")
        return dbname
    except requests.RequestException as e:
        if hasattr(response, 'status_code') and response.status_code == 404:
            raise Exception(f"Database not found for {filename}. The file may not be available in winbindex.\n"
                          f"Try to find the appropriate database file here: https://winbindex.m417z.com/data/by_filename_compressed or check if '{filename}' is correct.")
        raise Exception(f"Failed to download database: {e}")

def is_near_patch_tuesday(date_str: str, target_month: str, tolerance_days: int = 2) -> bool:
    """
    Check if a date is within tolerance days of Patch Tuesday for the target month.
    
    Args:
        date_str: Date string in YYYY-MM-DD format
        target_month: Target month in YYYY-MM format
        tolerance_days: Number of days before/after to consider (default: 2)
    
    Returns:
        True if date is near Patch Tuesday of the target month
    """
    try:
        date = datetime.strptime(date_str, "%Y-%m-%d")
        target_year, target_month_num = map(int, target_month.split('-'))
        
        # Only consider dates in the target month
        if date.year != target_year or date.month != target_month_num:
            return False
        
        # Calculate Patch Tuesday (second Tuesday) of the target month
        first_day = datetime(target_year, target_month_num, 1)
        first_weekday = first_day.weekday()
        
        # Calculate days until first Tuesday (1 = Tuesday in weekday())
        days_until_first_tuesday = (1 - first_weekday) % 7
        if days_until_first_tuesday == 0 and first_weekday != 1:
            days_until_first_tuesday = 7
            
        first_tuesday_day = 1 + days_until_first_tuesday
        patch_tuesday_day = first_tuesday_day + 7  # Second Tuesday
        
        patch_tuesday = datetime(target_year, target_month_num, patch_tuesday_day)
        
        # Check if the date is within tolerance
        diff = abs((date - patch_tuesday).days)
        return diff <= tolerance_days
    except (ValueError, TypeError):
        return False

def get_patch_tuesday_date(year: int, month: int) -> datetime:
    """
    Calculate the exact Patch Tuesday date for a given month.
    
    Args:
        year: Target year
        month: Target month (1-12)
        
    Returns:
        datetime object representing Patch Tuesday
    """
    first_day = datetime(year, month, 1)
    first_weekday = first_day.weekday()
    
    # Calculate days until first Tuesday (1 = Tuesday in weekday())
    days_until_first_tuesday = (1 - first_weekday) % 7
    if days_until_first_tuesday == 0 and first_weekday != 1:
        days_until_first_tuesday = 7
        
    first_tuesday_day = 1 + days_until_first_tuesday
    patch_tuesday_day = first_tuesday_day + 7  # Second Tuesday
    
    return datetime(year, month, patch_tuesday_day)

def is_version_applicable(kb_data: Dict, target_version: str, current_version: str) -> bool:
    """
    Check if a KB entry applies to the target Windows version.
    First checks direct windowsVersions, then checks otherWindowsVersions.
    
    Args:
        kb_data: KB data dictionary
        target_version: The Windows version we're looking for (e.g., "11-23H2")
        current_version: The Windows version this entry is under (e.g., "11-22H2")
        
    Returns:
        True if this KB applies to the target version
    """
    # Direct match - we're already in the right section
    if current_version == target_version:
        return True
    
    # Check otherWindowsVersions for cross-references
    update_info = kb_data.get("updateInfo", {})
    other_versions = update_info.get("otherWindowsVersions", [])
    
    return target_version in other_versions

def get_target_versions(db_path: str, windows_version: str, patch_month: str) -> Tuple[Optional[Dict], Optional[Dict]]:
    """
    Get the target patch version and vulnerable version (previous month).
    Prioritizes Patch Tuesday releases, falls back to most recent after Patch Tuesday.
    Now includes fallback to otherWindowsVersions when direct version not found.
    
    Args:
        db_path: Path to the JSON.gz database file
        windows_version: Target Windows version
        patch_month: Target patch month in YYYY-MM format
        
    Returns:
        Tuple of (patch_version, vulnerable_version) dictionaries or None if not found
    """
    with gzip.open(db_path, "rt", encoding="utf-8") as f:
        data = json.load(f)
    
    # Use sets to track unique versions by release_version to avoid duplicates
    patch_versions = {}
    vulnerable_patch_tuesday = {}
    vulnerable_after_patch_tuesday = {}
    vulnerable_all = {}
    
    # Parse target month
    target_year, target_month = map(int, patch_month.split('-'))
    
    # Calculate previous month for vulnerable version
    if target_month == 1:
        prev_year, prev_month = target_year - 1, 12
    else:
        prev_year, prev_month = target_year, target_month - 1
    
    prev_month_str = f"{prev_year:04d}-{prev_month:02d}"
    prev_patch_tuesday = get_patch_tuesday_date(prev_year, prev_month)
    current_patch_tuesday = get_patch_tuesday_date(target_year, target_month)
    
    # Enhanced logging for both versions
    print_success(f"Found the patched version in: {patch_month}")
    print(f"\t[*] Patch Tuesday date for the patched version: {current_patch_tuesday.strftime('%Y-%m-%d')}")
    print_success(f"Searching for the vulnerable version in: {prev_month_str}")
    print(f"\t[*] Patch Tuesday date for the vulnerable version: {prev_patch_tuesday.strftime('%Y-%m-%d')}")
    
    # Track what we find for better logging
    direct_matches_found = False
    fallback_matches_found = False
    
    for sha256, entry in data.items():
        file_info = entry.get("fileInfo", {})
        timestamp = file_info.get("timestamp")
        virtual_size = file_info.get("virtualSize")
        win_versions = entry.get("windowsVersions", {})
        
        if timestamp and virtual_size:
            # First pass: Look for direct matches
            if windows_version in win_versions:
                direct_matches_found = True
                version_data = win_versions[windows_version]
                
                for kb_id, kb_data in version_data.items():
                    update_info = kb_data.get("updateInfo", {})
                    release_date = update_info.get("releaseDate")
                    
                    # get assemblies from the correct location
                    assemblies = kb_data.get("assemblies", {})

                    # extract first assembly's version
                    if assemblies:
                        first_assembly = next(iter(assemblies.values()))
                        release_version = first_assembly.get("assemblyIdentity", {}).get("version", "")
                    else:
                        release_version = update_info.get("releaseVersion", "")

                    if not release_date or not release_version:
                        continue

                    version_entry = {
                        "timestamp": timestamp,
                        "virtual_size": virtual_size,
                        "sha256": sha256,
                        "release_date": release_date,
                        "kb_id": kb_id,
                        "release_version": release_version,
                        "update_url": update_info.get("updateUrl", ""),
                        "source": f"direct ({windows_version})"
                    }

                    # Process this entry (same logic as before)
                    if is_near_patch_tuesday(release_date, patch_month):
                        if release_version not in patch_versions or release_date > patch_versions[release_version]["release_date"]:
                            patch_versions[release_version] = version_entry
                        
                    elif release_date.startswith(prev_month_str):
                        if release_version not in vulnerable_all or release_date > vulnerable_all[release_version]["release_date"]:
                            vulnerable_all[release_version] = version_entry
                        
                        try:
                            release_dt = datetime.strptime(release_date, "%Y-%m-%d")
                            
                            if is_near_patch_tuesday(release_date, prev_month_str):
                                if release_version not in vulnerable_patch_tuesday or release_date > vulnerable_patch_tuesday[release_version]["release_date"]:
                                    vulnerable_patch_tuesday[release_version] = version_entry
                            elif release_dt >= prev_patch_tuesday:
                                if release_version not in vulnerable_after_patch_tuesday or release_date > vulnerable_after_patch_tuesday[release_version]["release_date"]:
                                    vulnerable_after_patch_tuesday[release_version] = version_entry
                        except ValueError:
                            continue
            
            # Second pass: Look for fallback matches in otherWindowsVersions
            # Only do this if we haven't found direct matches or if we still need more versions
            for current_version, version_data in win_versions.items():
                for kb_id, kb_data in version_data.items():
                    if is_version_applicable(kb_data, windows_version, current_version) and current_version != windows_version:
                        fallback_matches_found = True
                        update_info = kb_data.get("updateInfo", {})
                        release_date = update_info.get("releaseDate")
                        
                        # get assemblies from the correct location
                        assemblies = kb_data.get("assemblies", {})

                        # extract first assembly's version
                        if assemblies:
                            first_assembly = next(iter(assemblies.values()))
                            release_version = first_assembly.get("assemblyIdentity", {}).get("version", "")
                        else:
                            release_version = update_info.get("releaseVersion", "")

                        if not release_date or not release_version:
                            continue

                        version_entry = {
                            "timestamp": timestamp,
                            "virtual_size": virtual_size,
                            "sha256": sha256,
                            "release_date": release_date,
                            "kb_id": kb_id,
                            "release_version": release_version,
                            "update_url": update_info.get("updateUrl", ""),
                            "source": f"fallback ({current_version} -> {windows_version})"
                        }

                        # Process this entry (same logic as before)
                        if is_near_patch_tuesday(release_date, patch_month):
                            if release_version not in patch_versions or release_date > patch_versions[release_version]["release_date"]:
                                patch_versions[release_version] = version_entry
                            
                        elif release_date.startswith(prev_month_str):
                            if release_version not in vulnerable_all or release_date > vulnerable_all[release_version]["release_date"]:
                                vulnerable_all[release_version] = version_entry
                            
                            try:
                                release_dt = datetime.strptime(release_date, "%Y-%m-%d")
                                
                                if is_near_patch_tuesday(release_date, prev_month_str):
                                    if release_version not in vulnerable_patch_tuesday or release_date > vulnerable_patch_tuesday[release_version]["release_date"]:
                                        vulnerable_patch_tuesday[release_version] = version_entry
                                elif release_dt >= prev_patch_tuesday:
                                    if release_version not in vulnerable_after_patch_tuesday or release_date > vulnerable_after_patch_tuesday[release_version]["release_date"]:
                                        vulnerable_after_patch_tuesday[release_version] = version_entry
                            except ValueError:
                                continue
    
    # Helper function to prioritize direct matches over fallback matches
    def select_best_version(versions_dict):
        if not versions_dict:
            return None
        
        # Sort by release date (most recent first)
        sorted_versions = sorted(versions_dict.values(), key=lambda v: v["release_date"], reverse=True)
        
        # Prioritize direct matches over fallback matches
        direct_matches = [v for v in sorted_versions if v["source"].startswith("direct")]
        fallback_matches = [v for v in sorted_versions if v["source"].startswith("fallback")]
        
        # Return the most recent direct match if available, otherwise most recent fallback
        if direct_matches:
            return direct_matches[0]
        elif fallback_matches:
            return fallback_matches[0]
        else:
            return None
    
    # Select patch version (prioritize direct matches)
    patch_version = select_best_version(patch_versions)
    if patch_version:
        print_success(f"Selected patch version: {patch_version['release_version']} ({patch_version['release_date']})")
    else:
        print_error("No suitable patch version found")
    
    # Select vulnerable version with priority logic (prioritize direct matches within each category)
    vulnerable_version = None
    
    # Try Patch Tuesday versions first
    vulnerable_patch_tuesday_best = select_best_version(vulnerable_patch_tuesday)
    if vulnerable_patch_tuesday_best:
        vulnerable_version = vulnerable_patch_tuesday_best
        print_success(f"Selected vulnerable version: {vulnerable_version['release_version']} ({vulnerable_version['release_date']}) - Patch Tuesday")
    else:
        # Try after Patch Tuesday versions
        vulnerable_after_patch_tuesday_best = select_best_version(vulnerable_after_patch_tuesday)
        if vulnerable_after_patch_tuesday_best:
            vulnerable_version = vulnerable_after_patch_tuesday_best
            print_success(f"Selected vulnerable version: {vulnerable_version['release_version']} ({vulnerable_version['release_date']}) - After Patch Tuesday")
        else:
            # Try all versions from previous month
            vulnerable_all_best = select_best_version(vulnerable_all)
            if vulnerable_all_best:
                vulnerable_version = vulnerable_all_best
                print_success(f"Selected vulnerable version: {vulnerable_version['release_version']} ({vulnerable_version['release_date']}) - General")
            else:
                print_error("No suitable vulnerable version found")
    
    return patch_version, vulnerable_version

def download_symbol_file(version_info: Dict[str, any], version_type: str, filename: str) -> str:
    """
    Download a symbol file from Microsoft Symbol Server.
    
    Args:
        version_info: Dictionary containing version information
        version_type: Either "patch" or "vulnerable" for naming
        filename: The filename to download
        
    Returns:
        Path to the downloaded file
    """
    timestamp = version_info["timestamp"]
    virtual_size = version_info["virtual_size"]
    release_version = version_info["release_version"]
    
    # Convert to hex strings (uppercase, no 0x prefix)
    timestamp_hex = f"{timestamp:08X}"
    size_hex = f"{virtual_size:X}"
    
    # Build URL
    url = f"{MSDL_BASE_URL}/{filename}/{timestamp_hex}{size_hex}/{filename}"
    
    # Create filename with release version
    file_ext = Path(filename).suffix
    file_stem = Path(filename).stem
    local_filename = f"{file_stem}_{release_version}{file_ext}"
    
    print(f"[+] Downloading {version_type} version from: {url}")
    print(f"\t[*] Saving as: {local_filename}")
    
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        with open(local_filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        file_size = os.path.getsize(local_filename)
        print_success(f"Downloaded: {local_filename} ({file_size:,} bytes)")
        return local_filename
        
    except requests.RequestException as e:
        print_error(f"Failed to download {version_type} version: {e}")
        raise Exception(f"Failed to download {version_type} version: {e}")