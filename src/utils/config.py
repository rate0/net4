import os
import json
from typing import Dict, Any, Optional

class Config:
    """Configuration manager for Net4 application"""
    
    DEFAULT_CONFIG = {
        "app": {
            "name": "Net4",
            "version": "1.0.0",
            "theme": "dark"
        },
        "paths": {
            "tshark": "",  # Will be auto-detected
            "output_dir": ""  # Default export directory
        },
        "api": {
            "openai": {
                "api_key": "",
                "model": "gpt-4",
                "timeout": 60
            },
            "virustotal": {
                "api_key": "",
                "timeout": 30
            }
        },
        "analysis": {
            "max_packet_display": 10000,
            "enable_ai_analysis": True,
            "enable_threat_intelligence": True,
            "default_pcap_dir": "",
            "auto_analyze": True,
            "auto_threat_intel": True
        },
        "reporting": {
            "company_name": "",
            "analyst_name": "",
            "logo_path": "",
            "default_export_dir": ""
        }
    }
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration manager"""
        self.config_path = config_path or os.path.join(
            os.path.expanduser("~"), ".net4", "config.json"
        )
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default if not exists"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults to ensure all keys exist
                    return self._merge_configs(self.DEFAULT_CONFIG, config)
            else:
                # Create config directory if it doesn't exist
                os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
                # Save default config
                self._save_config(self.DEFAULT_CONFIG)
                return self.DEFAULT_CONFIG
        except Exception as e:
            print(f"Error loading config: {e}")
            return self.DEFAULT_CONFIG
    
    def _save_config(self, config: Dict[str, Any]) -> None:
        """Save configuration to file"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def _merge_configs(self, default: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively merge user config with default config"""
        result = default.copy()
        for key, value in user.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        return result
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value by dot-separated path"""
        keys = key_path.split('.')
        value = self.config
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path: str, value: Any) -> None:
        """Set configuration value by dot-separated path"""
        keys = key_path.split('.')
        config = self.config
        for i, key in enumerate(keys[:-1]):
            if key not in config or not isinstance(config[key], dict):
                config[key] = {}
            config = config[key]
        config[keys[-1]] = value
        self._save_config(self.config)
    
    def save(self) -> None:
        """Save current configuration to file"""
        self._save_config(self.config)