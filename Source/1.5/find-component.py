#!/usr/bin/env python3

import requests
import json
import re
import sys
from typing import Dict, List, Optional

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
        {"name": "Windows Storage Port Driver", "file": "storport.sys"}
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
            print(f"CVE {cve_id} not found in Microsoft database")
            return None
        else:
            print(f"Error fetching data: HTTP {response.status_code}")
            print(f"Response: {response.text[:500]}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON response: {e}")
        return None

def extract_cve_info(data: Dict) -> Dict:
    """Extract required information from CVE data"""
    extracted_info = {
        'cve_title': data.get('cveTitle', 'N/A'),
        'description': data.get('description', 'N/A'),
        'unformatted_description': data.get('unformattedDescription', 'N/A'),
        'tag': data.get('tag', 'N/A'),
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

def display_results(matching_components: List[Dict], cve_data: Dict):
    """Display only the matching components and release number"""
    # Print release number
    release_number = cve_data.get('releaseNumber', 'N/A')
    print(f"Release Number: {release_number}")
    
    if matching_components:
        for component in matching_components:
            print(f"{component['name']} ({component['file']})")
    else:
        print("No matching components found.")

def main():
    """Main function"""
    if len(sys.argv) != 2:
        print("Usage: python cve_extractor.py CVE-YYYY-NNNNN")
        sys.exit(1)
    
    cve_id = sys.argv[1].strip().upper()
    
    if not validate_cve_format(cve_id):
        print("Invalid CVE format. Please use format: CVE-YYYY-NNNNN")
        sys.exit(1)
    
    # Fetch CVE data
    cve_data = fetch_cve_data(cve_id)
    
    if not cve_data:
        print("Failed to retrieve CVE data.")
        sys.exit(1)
    
    # Extract information
    cve_info = extract_cve_info(cve_data)
    
    # Get component mapping
    component_mapping = get_component_mapping()
    
    # Find matching components
    matching_components = find_matching_components(cve_info, component_mapping)
    
    # Display results
    display_results(matching_components, cve_data)

if __name__ == "__main__":
    main()