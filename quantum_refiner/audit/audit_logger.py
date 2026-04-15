"""
Audit Logging Module

Comprehensive audit trail for all cryptographic operations,
access attempts, and security events.

Features:
- Timestamped operation logging
- Security event tracking
- Unauthorized access detection
- Compliance audit trail
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import threading
from enum import Enum


class EventSeverity(Enum):
    """Event severity levels."""
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    ALERT = "ALERT"


class AuditLogger:
    """
    Comprehensive audit logger for cryptographic operations.
    
    Thread-safe logging of:
    - Cryptographic key operations
    - Data encryption/decryption
    - Access attempts
    - Security events and anomalies
    
    Attributes:
        log_dir: Directory for audit logs
        log_file: Current log file path
        logger: Python logger instance
    """
    
    def __init__(
        self,
        log_dir: Optional[Path] = None,
        log_name: str = "quantum_refiner_audit.log",
    ):
        """
        Initialize audit logger.
        
        Args:
            log_dir: Directory for logs (defaults to ./logs)
            log_name: Name of audit log file
        """
        if log_dir is None:
            log_dir = Path.cwd() / "logs"
        
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / log_name
        
        # Thread-safe operation
        self._lock = threading.Lock()
        
        # Configure logger
        self.logger = logging.getLogger("quantum_refiner.audit")
        self.logger.setLevel(logging.INFO)
        
        # File handler
        fh = logging.FileHandler(self.log_file, encoding="utf-8")
        fh.setLevel(logging.INFO)
        
        # Formatter with timestamp
        formatter = logging.Formatter(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        fh.setFormatter(formatter)
        
        # Remove duplicate handlers
        if not self.logger.handlers:
            self.logger.addHandler(fh)
    
    def log_operation(
        self,
        operation_name: str,
        details: Optional[Dict[str, Any]] = None,
        severity: EventSeverity = EventSeverity.INFO,
    ) -> None:
        """
        Log a normal cryptographic operation.
        
        Args:
            operation_name: Name of operation (e.g., "kyber_keygen")
            details: Additional details as dictionary
            severity: Event severity level
        """
        with self._lock:
            details = details or {}
            details["timestamp"] = datetime.utcnow().isoformat()
            
            message = f"OPERATION: {operation_name} | {json.dumps(details)}"
            
            if severity == EventSeverity.INFO:
                self.logger.info(message)
            elif severity == EventSeverity.WARNING:
                self.logger.warning(message)
            elif severity == EventSeverity.CRITICAL:
                self.logger.critical(message)
            else:
                self.logger.warning(message)
    
    def log_security_event(
        self,
        event_type: str,
        details: Optional[str] = None,
        severity: EventSeverity = EventSeverity.WARNING,
    ) -> None:
        """
        Log a security-relevant event (error, tampering, etc.)
        
        Args:
            event_type: Type of security event
            details: Event details/reason
            severity: Severity level (default: WARNING)
        """
        with self._lock:
            message = f"SECURITY_EVENT: {event_type}"
            if details:
                message += f" | {details}"
            
            if severity == EventSeverity.INFO:
                self.logger.info(message)
            elif severity == EventSeverity.WARNING:
                self.logger.warning(message)
            elif severity == EventSeverity.CRITICAL:
                self.logger.critical(message)
            elif severity == EventSeverity.ALERT:
                self.logger.critical(f"🚨 ALERT: {message}")
    
    def log_access_attempt(
        self,
        user: str,
        resource: str,
        granted: bool,
        reason: Optional[str] = None,
    ) -> None:
        """
        Log access attempt (success or failure).
        
        Args:
            user: User/entity attempting access
            resource: Resource being accessed
            granted: Whether access was granted
            reason: Reason for denial (if applicable)
        """
        with self._lock:
            status = "GRANTED" if granted else "DENIED"
            message = f"ACCESS_ATTEMPT: {user} -> {resource} [{status}]"
            
            if reason and not granted:
                message += f" | Reason: {reason}"
            
            severity = EventSeverity.INFO if granted else EventSeverity.WARNING
            
            if severity == EventSeverity.INFO:
                self.logger.info(message)
            else:
                self.logger.warning(message)
    
    def log_data_operation(
        self,
        operation: str,
        data_id: str,
        size_bytes: int,
        status: str = "success",
    ) -> None:
        """
        Log data processing operation.
        
        Args:
            operation: Type of operation (encrypt, decrypt, hash, etc.)
            data_id: Identifier of processed data
            size_bytes: Size of data processed
            status: Operation status
        """
        with self._lock:
            details = {
                "operation": operation,
                "data_id": data_id,
                "size_bytes": size_bytes,
                "status": status,
                "timestamp": datetime.utcnow().isoformat(),
            }
            
            message = f"DATA_OPERATION: {json.dumps(details)}"
            
            if status == "success":
                self.logger.info(message)
            else:
                self.logger.warning(message)
    
    def log_key_lifecycle(
        self,
        key_id: str,
        event: str,  # generated, rotated, compromised, destroyed
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log key lifecycle events.
        
        Args:
            key_id: Identifier of key
            event: Lifecycle event
            details: Additional details
        """
        with self._lock:
            details = details or {}
            details["key_id"] = key_id
            details["event"] = event
            details["timestamp"] = datetime.utcnow().isoformat()
            
            message = f"KEY_LIFECYCLE: {json.dumps(details)}"
            
            if event in ("compromised", "destroyed"):
                self.logger.critical(message)
            else:
                self.logger.info(message)
    
    def get_audit_summary(self) -> Dict[str, Any]:
        """
        Get summary of audit log statistics.
        
        Returns:
            Dictionary with audit statistics
        """
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            summary = {
                "total_events": len(lines),
                "log_file": str(self.log_file),
                "last_event": lines[-1] if lines else None,
                "file_size_bytes": self.log_file.stat().st_size,
            }
            
            return summary
        except Exception as e:
            self.logger.error(f"Failed to read audit summary: {e}")
            return {}
    
    def export_audit_log(self, export_path: Path) -> bool:
        """
        Export audit log to external location.
        
        Args:
            export_path: Path to export to
        
        Returns:
            bool: True if successful
        
        Security:
            - Should be exported encrypted for sensitive environments
            - Maintain chain of custody
        """
        try:
            with open(self.log_file, 'r', encoding='utf-8') as src:
                content = src.read()
            
            export_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(export_path, 'w', encoding='utf-8') as dst:
                dst.write(content)
            
            self.logger.info(f"Audit log exported to {export_path}")
            return True
        except Exception as e:
            self.logger.error(f"Audit export failed: {e}")
            return False
    
    def close(self) -> None:
        """
        Close all file handlers and cleanup resources.
        
        Call this when done logging to prevent file handle leaks.
        """
        with self._lock:
            for handler in self.logger.handlers[:]:
                handler.close()
                self.logger.removeHandler(handler)
    
    def __del__(self) -> None:
        """Ensure handlers are closed on deletion."""
        try:
            self.close()
        except Exception:
            pass  # Ignore errors during cleanup


__all__ = ["AuditLogger", "EventSeverity"]
