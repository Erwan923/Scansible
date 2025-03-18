"""
Configuration utilities for Scansible
------------------------------------
Handles configuration loading and environment variables.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional

class Config:
    """Configuration manager for Scansible."""
    
    def __init__(self):
        """Initialize the configuration."""
        self.project_root = Path(__file__).parent.parent.parent.absolute()
        self.config_data = {}
        
        # Load configuration from environment variables
        self._load_from_env()
    
    def _load_from_env(self):
        """Load configuration from environment variables."""
        # API keys
        self.config_data['ai_api_key'] = os.getenv('SCANSIBLE_AI_API_KEY', '')
        self.config_data['vulners_api_key'] = os.getenv('SCANSIBLE_VULNERS_API_KEY', '')
        
        # Directories
        reports_dir = os.getenv('SCANSIBLE_REPORTS_DIR')
        if reports_dir:
            self.config_data['reports_dir'] = Path(reports_dir)
        else:
            self.config_data['reports_dir'] = self.project_root / 'reports'
        
        scans_dir = os.getenv('SCANSIBLE_SCANS_DIR')
        if scans_dir:
            self.config_data['scans_dir'] = Path(scans_dir)
        else:
            self.config_data['scans_dir'] = self.project_root / 'scans'
        
        templates_dir = os.getenv('SCANSIBLE_TEMPLATES_DIR')
        if templates_dir:
            self.config_data['templates_dir'] = Path(templates_dir)
        else:
            self.config_data['templates_dir'] = self.project_root / 'scansible' / 'templates'
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        return self.config_data.get(key, default)
    
    def get_reports_dir(self) -> Path:
        """Get the reports directory path."""
        reports_dir = self.get('reports_dir')
        reports_dir.mkdir(exist_ok=True)
        return reports_dir
    
    def get_scans_dir(self) -> Path:
        """Get the scans directory path."""
        scans_dir = self.get('scans_dir')
        scans_dir.mkdir(exist_ok=True)
        return scans_dir
    
    def get_templates_dir(self) -> Path:
        """Get the templates directory path."""
        return self.get('templates_dir')
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get an API key for a specific service."""
        if service == 'ai':
            return self.get('ai_api_key')
        elif service == 'vulners':
            return self.get('vulners_api_key')
        return None
