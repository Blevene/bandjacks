"""Entity ignorelist loader and manager for filtering false positives."""

import yaml
import re
import logging
import threading
from typing import Set, List, Optional, Dict, Any
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class EntityIgnorelist:
    """Manages entity ignorelist for filtering false positive entity extractions."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the entity ignorelist.
        
        Args:
            config_path: Path to the ignorelist YAML file. 
                        Defaults to bandjacks/config/entity_ignorelist.yaml
        """
        if not config_path:
            # Default path relative to this file
            config_path = Path(__file__).parent.parent / "config" / "entity_ignorelist.yaml"
        else:
            config_path = Path(config_path)
        
        self.config_path = config_path
        self.ignorelist = self._load_config(config_path)
        self._lock = threading.Lock()  # Thread-safe operations

        # Pre-compile regex patterns for efficiency
        self.patterns = []
        for pattern_str in self.ignorelist.get("patterns", []):
            try:
                self.patterns.append(re.compile(pattern_str, re.IGNORECASE))
            except re.error as e:
                logger.warning(f"Invalid regex pattern '{pattern_str}': {e}")

        # Convert lists to sets for O(1) lookups
        self.vendors = set(vendor.lower() for vendor in self.ignorelist.get("vendors", []))
        self.file_extensions = set(ext.lower() for ext in self.ignorelist.get("file_extensions", []))
        self.generic_terms = set(term.lower() for term in self.ignorelist.get("generic_terms", []))
        self.code_constructs = set(construct.lower() for construct in self.ignorelist.get("code_constructs", []))

        # Track user-added entities separately
        user_added_raw = self.ignorelist.get("user_added", [])
        self.user_added = set()
        for entry in user_added_raw:
            if isinstance(entry, dict):
                entity_name = entry.get("name", "")
                if entity_name:
                    self.user_added.add(entity_name.lower())
            elif isinstance(entry, str):
                self.user_added.add(entry.lower())

        logger.info(f"Loaded entity ignorelist with {len(self.vendors)} vendors, "
                   f"{len(self.file_extensions)} extensions, {len(self.generic_terms)} generic terms, "
                   f"{len(self.code_constructs)} code constructs, {len(self.patterns)} patterns, "
                   f"and {len(self.user_added)} user-added entities")
    
    def _load_config(self, config_path: Path) -> Dict[str, Any]:
        """Load the YAML configuration file.
        
        Args:
            config_path: Path to the YAML file
            
        Returns:
            Dictionary containing the configuration
        """
        if not config_path.exists():
            logger.warning(f"Entity ignorelist config not found at {config_path}, using defaults")
            return self._get_default_config()
        
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f) or {}
                logger.info(f"Loaded entity ignorelist from {config_path}")
                return config
        except Exception as e:
            logger.error(f"Failed to load entity ignorelist from {config_path}: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default ignorelist configuration.
        
        Returns:
            Default configuration dictionary
        """
        return {
            "vendors": [
                "Unit 42", "Unit42", "MSTIC", "CrowdStrike", "FireEye", "Mandiant",
                "Palo Alto Networks", "Microsoft Threat Intelligence Center"
            ],
            "file_extensions": [
                ".ps1", ".js", ".exe", ".dll", ".bat", ".cmd", ".vbs", ".wsf"
            ],
            "generic_terms": [
                "script", "file", "command", "expression", "payload", "sample"
            ],
            "code_constructs": [
                "Convert.FromBase64String", "ActiveXObject", "Invoke-Expression",
                "Start-Process", "WScript.Shell"
            ],
            "patterns": [
                "^PS1 .*",
                "^JS .*",
                ".*Object\\(.*\\)$"
            ]
        }
    
    def should_ignore(self, entity_name: str) -> bool:
        """Check if an entity name should be filtered out.

        Args:
            entity_name: The entity name to check

        Returns:
            True if the entity should be ignored, False otherwise
        """
        if not entity_name:
            return True

        name_lower = entity_name.lower().strip()

        # Check user-added entities first
        if name_lower in self.user_added:
            logger.debug(f"Ignoring '{entity_name}' - user-added to ignore list")
            return True

        # Check if it's a vendor
        if name_lower in self.vendors:
            logger.debug(f"Ignoring '{entity_name}' - matches vendor/security company")
            return True

        # Check if it's a file extension
        if name_lower in self.file_extensions:
            logger.debug(f"Ignoring '{entity_name}' - matches file extension")
            return True

        # Check if it ends with a file extension
        for ext in self.file_extensions:
            if name_lower.endswith(ext):
                logger.debug(f"Ignoring '{entity_name}' - ends with file extension {ext}")
                return True

        # Check generic terms
        if name_lower in self.generic_terms:
            logger.debug(f"Ignoring '{entity_name}' - matches generic term")
            return True

        # Check code constructs
        if name_lower in self.code_constructs:
            logger.debug(f"Ignoring '{entity_name}' - matches code construct")
            return True

        # Check regex patterns
        for pattern in self.patterns:
            if pattern.match(entity_name):
                logger.debug(f"Ignoring '{entity_name}' - matches pattern {pattern.pattern}")
                return True

        return False
    
    def filter_entities(self, entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter a list of entity dictionaries.
        
        Args:
            entities: List of entity dictionaries with 'name' field
            
        Returns:
            Filtered list of entities
        """
        filtered = []
        ignored_count = 0
        
        for entity in entities:
            entity_name = entity.get("name", "")
            if not self.should_ignore(entity_name):
                filtered.append(entity)
            else:
                ignored_count += 1
        
        if ignored_count > 0:
            logger.info(f"Filtered out {ignored_count} entities using ignorelist")
        
        return filtered
    
    def add_to_ignorelist(self, entity_name: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Add an entity to the user-added ignore list.

        Args:
            entity_name: The entity name to add
            metadata: Optional metadata about why it was added

        Returns:
            True if successfully added, False otherwise
        """
        if not entity_name:
            return False

        with self._lock:
            name_lower = entity_name.lower().strip()

            # Check if already in user_added
            if name_lower in self.user_added:
                logger.info(f"Entity '{entity_name}' already in user-added ignore list")
                return True

            # Add to user_added set
            self.user_added.add(name_lower)

            # Update the config dict
            if "user_added" not in self.ignorelist:
                self.ignorelist["user_added"] = []

            # Add with original casing and metadata
            entry = {
                "name": entity_name,
                "added_at": datetime.utcnow().isoformat(),
            }
            if metadata:
                entry["metadata"] = metadata

            self.ignorelist["user_added"].append(entry)

            # Save to file
            if self._save_config():
                logger.info(f"Added '{entity_name}' to user-added ignore list")
                return True
            else:
                # Rollback on save failure
                self.user_added.discard(name_lower)
                return False

    def remove_from_ignorelist(self, entity_name: str) -> bool:
        """Remove an entity from the user-added ignore list.

        Args:
            entity_name: The entity name to remove

        Returns:
            True if successfully removed, False otherwise
        """
        if not entity_name:
            return False

        with self._lock:
            name_lower = entity_name.lower().strip()

            # Check if in user_added
            if name_lower not in self.user_added:
                logger.info(f"Entity '{entity_name}' not in user-added ignore list")
                return False

            # Remove from set
            self.user_added.discard(name_lower)

            # Remove from config
            if "user_added" in self.ignorelist:
                # Filter out matching entries
                self.ignorelist["user_added"] = [
                    entry for entry in self.ignorelist["user_added"]
                    if (isinstance(entry, dict) and entry.get("name", "").lower() != name_lower) or
                       (isinstance(entry, str) and entry.lower() != name_lower)
                ]

            # Save to file
            if self._save_config():
                logger.info(f"Removed '{entity_name}' from user-added ignore list")
                return True
            else:
                # Rollback on save failure
                self.user_added.add(name_lower)
                return False

    def get_user_additions(self) -> List[Dict[str, Any]]:
        """Get list of user-added entities with metadata.

        Returns:
            List of user-added entities with their metadata
        """
        with self._lock:
            if "user_added" not in self.ignorelist:
                return []

            result = []
            for entry in self.ignorelist.get("user_added", []):
                if isinstance(entry, dict):
                    result.append(entry)
                else:
                    # Convert string entries to dict format
                    result.append({"name": entry, "added_at": None})

            return result

    def _save_config(self) -> bool:
        """Save the configuration back to the YAML file.

        Returns:
            True if successfully saved, False otherwise
        """
        try:
            # Create backup first
            backup_path = self.config_path.with_suffix(".yaml.bak")
            if self.config_path.exists():
                import shutil
                shutil.copy2(self.config_path, backup_path)

            # Write the updated config
            with open(self.config_path, 'w') as f:
                yaml.safe_dump(self.ignorelist, f, default_flow_style=False, sort_keys=False)

            logger.info(f"Saved entity ignorelist to {self.config_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to save entity ignorelist: {e}")
            # Restore from backup if exists
            if backup_path.exists():
                try:
                    import shutil
                    shutil.copy2(backup_path, self.config_path)
                    logger.info("Restored from backup after save failure")
                except Exception:
                    pass
            return False

    def reload(self):
        """Reload the configuration from disk."""
        logger.info("Reloading entity ignorelist configuration")
        self.__init__(str(self.config_path))


# Singleton instance for global use
_ignorelist_instance = None

def get_entity_ignorelist(config_path: Optional[str] = None) -> EntityIgnorelist:
    """Get the singleton entity ignorelist instance.
    
    Args:
        config_path: Optional path to config file (only used on first call)
        
    Returns:
        EntityIgnorelist singleton instance
    """
    global _ignorelist_instance
    if _ignorelist_instance is None:
        _ignorelist_instance = EntityIgnorelist(config_path)
    return _ignorelist_instance