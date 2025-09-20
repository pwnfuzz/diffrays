import json
import gzip
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import os

# ===== GLOBAL VARIABLES =====
FILENAME = "clfs.sys"
DBNAME = "clfs.json.gz"  # Will be downloaded from winbindex
WINDOWS_VERSION = "11-22H2"
PATCH_MONTH = "2025-09"  # Format: YYYY-MM

# ===== CONSTANTS =====
WINBINDEX_BASE_URL = "https://winbindex.m417z.com/data/by_filename_compressed"
MSDL_BASE_URL = "https://msdl.microsoft.com/download/symbols"

def download_database() -> str:
    """
    Download the JSON.gz database from winbindex for the specified filename.
    
    Returns:
        Path to the downloaded file
    """
    url = f"{WINBINDEX_BASE_URL}/{FILENAME}.json.gz"
    local_path = DBNAME
    
    print(f"Downloading database from: {url}")
    
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        with open(local_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        print(f"Database saved as: {local_path}")
        return local_path
    except requests.RequestException as e:
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

def get_target_versions(db_path: str) -> Tuple[Optional[Dict], Optional[Dict]]:
    """
    Get the target patch version and vulnerable version (previous month).
    Prioritizes Patch Tuesday releases, falls back to most recent after Patch Tuesday.
    
    Args:
        db_path: Path to the JSON.gz database file
        
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
    target_year, target_month = map(int, PATCH_MONTH.split('-'))
    
    # Calculate previous month for vulnerable version
    if target_month == 1:
        prev_year, prev_month = target_year - 1, 12
    else:
        prev_year, prev_month = target_year, target_month - 1
    
    prev_month_str = f"{prev_year:04d}-{prev_month:02d}"
    prev_patch_tuesday = get_patch_tuesday_date(prev_year, prev_month)
    
    print(f"Looking for patch version in: {PATCH_MONTH}")
    print(f"Looking for vulnerable version in: {prev_month_str}")
    print(f"Previous month Patch Tuesday: {prev_patch_tuesday.strftime('%Y-%m-%d')}")
    
    for sha256, entry in data.items():
        file_info = entry.get("fileInfo", {})
        timestamp = file_info.get("timestamp")
        virtual_size = file_info.get("virtualSize")
        win_versions = entry.get("windowsVersions", {})
        
        if timestamp and virtual_size and WINDOWS_VERSION in win_versions:
            version_data = win_versions[WINDOWS_VERSION]
            
            for kb_id, kb_data in version_data.items():
                update_info = kb_data.get("updateInfo", {})
                release_date = update_info.get("releaseDate")
                
                # get assemblies from the correct location
                assemblies = (
                    kb_data.get("assemblies", {})
                )

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
                    "update_url": update_info.get("updateUrl", "")
                }

                
                # Check if it's a patch version (target month, near Patch Tuesday)
                if is_near_patch_tuesday(release_date, PATCH_MONTH):
                    # Use release_version as key to avoid duplicates, keep most recent
                    if release_version not in patch_versions or release_date > patch_versions[release_version]["release_date"]:
                        patch_versions[release_version] = version_entry
                    
                # Check if it's a vulnerable version (previous month)
                elif release_date.startswith(prev_month_str):
                    # Store all previous month versions
                    if release_version not in vulnerable_all or release_date > vulnerable_all[release_version]["release_date"]:
                        vulnerable_all[release_version] = version_entry
                    
                    try:
                        release_dt = datetime.strptime(release_date, "%Y-%m-%d")
                        
                        # Check if it's near previous month's Patch Tuesday
                        if is_near_patch_tuesday(release_date, prev_month_str):
                            if release_version not in vulnerable_patch_tuesday or release_date > vulnerable_patch_tuesday[release_version]["release_date"]:
                                vulnerable_patch_tuesday[release_version] = version_entry
                        # Check if it's after previous month's Patch Tuesday
                        elif release_dt >= prev_patch_tuesday:
                            if release_version not in vulnerable_after_patch_tuesday or release_date > vulnerable_after_patch_tuesday[release_version]["release_date"]:
                                vulnerable_after_patch_tuesday[release_version] = version_entry
                    except ValueError:
                        continue
    
    # Convert to lists and sort by release date (most recent first)
    patch_list = sorted(patch_versions.values(), key=lambda v: v["release_date"], reverse=True)
    vulnerable_patch_tuesday_list = sorted(vulnerable_patch_tuesday.values(), key=lambda v: v["release_date"], reverse=True)
    vulnerable_after_patch_tuesday_list = sorted(vulnerable_after_patch_tuesday.values(), key=lambda v: v["release_date"], reverse=True)
    vulnerable_all_list = sorted(vulnerable_all.values(), key=lambda v: v["release_date"], reverse=True)
    
    # Select patch version
    patch_version = patch_list[0] if patch_list else None
    
    # Select vulnerable version with priority logic
    vulnerable_version = None
    if vulnerable_patch_tuesday_list:
        vulnerable_version = vulnerable_patch_tuesday_list[0]
    elif vulnerable_after_patch_tuesday_list:
        vulnerable_version = vulnerable_after_patch_tuesday_list[0]
    elif vulnerable_all_list:
        vulnerable_version = vulnerable_all_list[0]
    else:
        print(f"❌ No vulnerable version found in {prev_month_str}")
    
    return patch_version, vulnerable_version

def download_symbol_file(version_info: Dict[str, Any], version_type: str) -> str:
    """
    Download a symbol file from Microsoft Symbol Server.
    
    Args:
        version_info: Dictionary containing version information
        version_type: Either "patch" or "vulnerable" for naming
        
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
    url = f"{MSDL_BASE_URL}/{FILENAME}/{timestamp_hex}{size_hex}/{FILENAME}"
    
    # Create filename with release version
    file_ext = Path(FILENAME).suffix
    file_stem = Path(FILENAME).stem
    local_filename = f"{file_stem}_{release_version}{file_ext}"
    
    print(f"Downloading {version_type} version from: {url}")
    print(f"Saving as: {local_filename}")
    
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        with open(local_filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        file_size = os.path.getsize(local_filename)
        print(f"Downloaded: {local_filename} ({file_size:,} bytes)")
        return local_filename
        
    except requests.RequestException as e:
        raise Exception(f"Failed to download {version_type} version: {e}")

def main():
    """
    Main function to orchestrate the entire process.
    """
    print("=" * 60)
    print("SYMBOL FILE DOWNLOADER")
    print("=" * 60)
    print(f"Filename: {FILENAME}")
    print(f"Windows Version: {WINDOWS_VERSION}")
    print(f"Target Patch Month: {PATCH_MONTH}")
    print("-" * 60)
    
    try:
        # Step 1: Download database
        db_path = download_database()
        print()
        
        # Step 2: Find target versions
        print("Analyzing database for target versions...")
        patch_version, vulnerable_version = get_target_versions(db_path)
        
        if not patch_version:
            print(f"❌ No patch version found for {PATCH_MONTH}")
            return
        
        if not vulnerable_version:
            print(f"❌ No vulnerable version found for previous month")
            return
        
        print(f"✅ Found patch version: {patch_version['release_version']} ({patch_version['release_date']})")
        print(f"✅ Found vulnerable version: {vulnerable_version['release_version']} ({vulnerable_version['release_date']})")
        print()
        
        # Step 3: Download both versions
        print("Downloading symbol files...")
        patch_file = download_symbol_file(patch_version, "patch")
        print()
        vulnerable_file = download_symbol_file(vulnerable_version, "vulnerable")
        
        print()
        print("=" * 60)
        print("DOWNLOAD COMPLETE")
        print("=" * 60)
        print(f"Patch version: {patch_file}")
        print(f"Vulnerable version: {vulnerable_file}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return

    file_path = Path(DBNAME)

    if file_path.exists():
        file_path.unlink()

if __name__ == "__main__":
    main()