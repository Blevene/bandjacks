"""Sigma rule validation and normalization."""

import hashlib
import json
import logging
import re
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime
from ruamel.yaml import YAML
from sigma.rule import SigmaRule
from sigma.exceptions import SigmaError

logger = logging.getLogger(__name__)


class SigmaValidator:
    """Validates and normalizes Sigma detection rules."""
    
    # Allowed licenses for Sigma rules
    ALLOWED_LICENSES = {
        "MIT", "Apache-2.0", "Apache 2.0", "DRL", "CC-BY-4.0", 
        "CC0-1.0", "BSD-3-Clause", "BSD-2-Clause"
    }
    
    # Sigma status values
    VALID_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}
    
    # Sigma severity levels
    VALID_SEVERITY = {"informational", "low", "medium", "high", "critical"}
    
    def __init__(self, enforce_license: bool = True):
        """
        Initialize Sigma validator.
        
        Args:
            enforce_license: Whether to enforce license allowlist
        """
        self.enforce_license = enforce_license
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
        self.yaml.width = 4096
    
    def validate_rule(self, yaml_content: str, metadata: Optional[Dict[str, Any]] = None) -> Tuple[bool, Dict[str, Any], List[str]]:
        """
        Validate a single Sigma rule.
        
        Args:
            yaml_content: Raw YAML content of the rule
            metadata: Optional metadata (repo_url, path, commit_sha)
            
        Returns:
            Tuple of (is_valid, rule_data, errors)
        """
        errors = []
        rule_data = {}
        
        try:
            # Parse YAML
            parsed = self.yaml.load(yaml_content)
            if not parsed:
                return False, {}, ["Empty or invalid YAML content"]
            
            # Try to create SigmaRule for validation
            try:
                sigma_rule = SigmaRule.from_yaml(yaml_content)
            except SigmaError as e:
                errors.append(f"Sigma validation error: {str(e)}")
                # Continue with basic validation even if Sigma parsing fails
            
            # Extract required fields
            if "title" not in parsed:
                errors.append("Missing required field: title")
            else:
                rule_data["title"] = parsed["title"]
            
            # Extract metadata
            if "id" in parsed:
                rule_data["sigma_id"] = str(parsed["id"])
            
            if "status" in parsed:
                if parsed["status"] not in self.VALID_STATUS:
                    errors.append(f"Invalid status: {parsed['status']}. Must be one of {self.VALID_STATUS}")
                rule_data["status"] = parsed["status"]
            else:
                rule_data["status"] = "experimental"  # Default
            
            # Extract optional fields
            if "description" in parsed:
                rule_data["description"] = parsed["description"]
            
            if "author" in parsed:
                rule_data["author"] = parsed["author"]
            
            if "date" in parsed:
                rule_data["date"] = str(parsed["date"])
            
            if "modified" in parsed:
                rule_data["modified"] = str(parsed["modified"])
            
            if "references" in parsed:
                refs = parsed["references"]
                if isinstance(refs, list):
                    rule_data["references"] = refs
                else:
                    rule_data["references"] = [refs]
            
            # Extract tags (including ATT&CK techniques)
            if "tags" in parsed:
                tags = parsed["tags"]
                if isinstance(tags, list):
                    rule_data["tags"] = tags
                    # Extract ATT&CK techniques
                    attack_tags = [t for t in tags if t.startswith("attack.t") or t.startswith("attack.T")]
                    rule_data["attack_techniques"] = [t.replace("attack.", "").upper() for t in attack_tags]
                else:
                    errors.append("Tags must be a list")
            
            # Extract logsource
            if "logsource" in parsed:
                logsource = parsed["logsource"]
                rule_data["logsource"] = logsource
                
                # Normalize logsource fields
                if "product" in logsource:
                    rule_data["logsource_product"] = logsource["product"]
                if "service" in logsource:
                    rule_data["logsource_service"] = logsource["service"]
                if "category" in logsource:
                    rule_data["logsource_category"] = logsource["category"]
                
                # Determine platforms from logsource
                platforms = self._extract_platforms(logsource)
                if platforms:
                    rule_data["platforms"] = platforms
            
            # Extract severity/level
            if "level" in parsed:
                if parsed["level"] not in self.VALID_SEVERITY:
                    errors.append(f"Invalid level: {parsed['level']}. Must be one of {self.VALID_SEVERITY}")
                rule_data["severity"] = parsed["level"]
            
            # Extract false positives
            if "falsepositives" in parsed:
                fps = parsed["falsepositives"]
                if isinstance(fps, list):
                    rule_data["false_positives"] = fps
                else:
                    rule_data["false_positives"] = [fps]
            
            # License validation
            if "license" in parsed:
                license_str = parsed["license"]
                rule_data["license"] = license_str
                
                if self.enforce_license:
                    if not self._is_license_allowed(license_str):
                        errors.append(f"License not in allowlist: {license_str}. Allowed: {self.ALLOWED_LICENSES}")
            
            # Extract detection logic structure (for key extraction)
            if "detection" in parsed:
                detection = parsed["detection"]
                keys = self._extract_detection_keys(detection)
                if keys:
                    rule_data["keys"] = list(keys)
            
            # Calculate content hash
            rule_data["sha256_yaml"] = hashlib.sha256(yaml_content.encode()).hexdigest()
            
            # Add provided metadata
            if metadata:
                if "repo_url" in metadata:
                    rule_data["repo_url"] = metadata["repo_url"]
                if "path" in metadata:
                    rule_data["path"] = metadata["path"]
                if "commit_sha" in metadata:
                    rule_data["commit_sha"] = metadata["commit_sha"]
                
                # Generate stable rule_id
                if all(k in metadata for k in ["repo_url", "path", "commit_sha"]):
                    repo_name = metadata["repo_url"].split("/")[-1].replace(".git", "")
                    rule_id = f"{repo_name}:{metadata['path']}@{metadata['commit_sha'][:7]}"
                    rule_data["rule_id"] = rule_id
            
            # Add ingestion timestamp
            rule_data["ingested_at"] = datetime.utcnow().isoformat()
            
            is_valid = len(errors) == 0
            return is_valid, rule_data, errors
            
        except Exception as e:
            logger.error(f"Failed to validate Sigma rule: {e}")
            return False, {}, [f"YAML parsing error: {str(e)}"]
    
    def _extract_platforms(self, logsource: Dict[str, Any]) -> List[str]:
        """
        Extract platforms from logsource definition.
        
        Args:
            logsource: Logsource dictionary from Sigma rule
            
        Returns:
            List of platforms
        """
        platforms = []
        
        # Map products to platforms
        product_map = {
            "windows": ["windows"],
            "linux": ["linux"],
            "macos": ["macos"],
            "aws": ["aws"],
            "azure": ["azure"],
            "gcp": ["gcp"],
            "okta": ["okta"],
            "office365": ["office365"],
            "apache": ["linux", "windows"],
            "nginx": ["linux", "windows"]
        }
        
        if "product" in logsource:
            product = logsource["product"].lower()
            if product in product_map:
                platforms.extend(product_map[product])
        
        # Service hints
        service_map = {
            "sysmon": ["windows"],
            "powershell": ["windows"],
            "security": ["windows"],
            "system": ["windows"],
            "application": ["windows"],
            "sshd": ["linux"],
            "auth": ["linux"],
            "auditd": ["linux"]
        }
        
        if "service" in logsource:
            service = logsource["service"].lower()
            if service in service_map:
                platforms.extend(service_map[service])
        
        # Deduplicate
        return list(set(platforms)) if platforms else []
    
    def _extract_detection_keys(self, detection: Dict[str, Any]) -> set:
        """
        Extract field keys used in detection logic.
        
        Args:
            detection: Detection dictionary from Sigma rule
            
        Returns:
            Set of field keys
        """
        keys = set()
        
        def extract_from_dict(d: Dict[str, Any]):
            """Recursively extract keys from detection dict."""
            for key, value in d.items():
                if key in ["condition", "timeframe"]:
                    continue
                    
                if isinstance(value, dict):
                    # This is a detection item
                    for field_name in value.keys():
                        if not field_name.startswith("_"):
                            keys.add(field_name)
                    extract_from_dict(value)
                elif isinstance(value, list):
                    # List of detection items
                    for item in value:
                        if isinstance(item, dict):
                            for field_name in item.keys():
                                if not field_name.startswith("_"):
                                    keys.add(field_name)
        
        extract_from_dict(detection)
        return keys
    
    def _is_license_allowed(self, license_str: str) -> bool:
        """
        Check if license is in allowlist.
        
        Args:
            license_str: License string from rule
            
        Returns:
            True if allowed
        """
        if not license_str:
            return False
        
        # Normalize license string
        normalized = license_str.strip().upper()
        
        # Check against allowlist (case insensitive)
        for allowed in self.ALLOWED_LICENSES:
            if allowed.upper() in normalized:
                return True
        
        return False
    
    def validate_bundle(self, rules: List[Dict[str, Any]]) -> Tuple[int, int, List[Dict[str, Any]]]:
        """
        Validate a bundle of Sigma rules.
        
        Args:
            rules: List of rule dictionaries with yaml_content and metadata
            
        Returns:
            Tuple of (valid_count, rejected_count, rejection_details)
        """
        valid_count = 0
        rejected_count = 0
        rejection_details = []
        
        for rule_entry in rules:
            yaml_content = rule_entry.get("yaml_content", "")
            metadata = rule_entry.get("metadata", {})
            
            is_valid, rule_data, errors = self.validate_rule(yaml_content, metadata)
            
            if is_valid:
                valid_count += 1
            else:
                rejected_count += 1
                rejection_details.append({
                    "rule": metadata.get("path", "unknown"),
                    "errors": errors
                })
        
        return valid_count, rejected_count, rejection_details