"""
Custom logging module for DiffRays.
Supports different log levels and output to console/file.
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

class CustomLogger:
    def __init__(self, name: str = "diffrays", debug: bool = False, log_file: Optional[str] = None):
        self.name = name
        self.debug_mode = debug
        self.log_file = log_file
        self._file_handle = None
        
        if log_file:
            # Create directory if it doesn't exist
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self._file_handle = open(log_file, 'a', encoding='utf-8')
    
    def _write_log(self, level: str, message: str, always_show: bool = False):
        """Internal method to write log messages"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"{timestamp} [{level}] {self.name}: {message}"
        
        # Write to console if debug mode is enabled OR it's an error (always_show)
        if self.debug_mode or always_show:
            print(log_message, file=sys.stderr)
        
        # Write to file if log file is specified (ALWAYS write to file when log file exists)
        if self._file_handle:
            self._file_handle.write(log_message + '\n')
            self._file_handle.flush()
    
    def debug(self, message: str):
        """Log debug message (only shown in debug mode, always written to file if logging enabled)"""
        self._write_log("DEBUG", message)
    
    def info(self, message: str):
        """Log info message (only shown in debug mode, always written to file if logging enabled)"""
        self._write_log("INFO", message)
    
    def warning(self, message: str):
        """Log warning message (only shown in debug mode, always written to file if logging enabled)"""
        self._write_log("WARNING", message)
    
    def error(self, message: str):
        """Log error message (always shown, always written to file if logging enabled)"""
        self._write_log("ERROR", message, always_show=True)
    
    def configure(self, debug: bool = False, log_file: Optional[str] = None):
        """Reconfigure the logger"""
        self.debug_mode = debug
        
        # Close existing file handle if any
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None
        
        # Open new log file if specified
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self._file_handle = open(log_file, 'a', encoding='utf-8')
            # Write a header to indicate new session
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._file_handle.write(f"\n\n=== DiffRays Log Session Started at {timestamp} ===\n\n")
            self._file_handle.flush()
    
    def close(self):
        """Close the log file handle"""
        if self._file_handle:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._file_handle.write(f"\n=== DiffRays Log Session Ended at {timestamp} ===\n")
            self._file_handle.close()
            self._file_handle = None

# Global logger instance
log = CustomLogger()