"""
Template Parser module for Scansible
-----------------------------------
Parses markdown template files to extract scan commands.
"""

from pathlib import Path
from typing import List, Dict, Set, Optional

class TemplateParser:
    """Parser for scan template files in markdown format."""
    
    def __init__(self):
        """Initialize the parser."""
        self.templates_dir = Path(__file__).parent.parent / "templates"
        
    def get_template_for_scan_type(self, scan_type: str) -> Optional[str]:
        """Get the template content for a specific scan type."""
        template_path = self.templates_dir / f"{scan_type}_scan.md"
        
        if template_path.exists():
            return template_path.read_text()
        
        # Try alternative file naming
        template_path = self.templates_dir / f"{scan_type}.md"
        if template_path.exists():
            return template_path.read_text()
            
        return None
    
    def get_all_available_tags(self) -> Set[str]:
        """Get all available tags from all template files."""
        all_tags = set()
        
        # Find all markdown files
        md_files = list(self.templates_dir.glob("*.md"))
        
        for md_file in md_files:
            try:
                content = md_file.read_text()
                
                for line in content.splitlines():
                    if line.strip().startswith("* Tags:"):
                        tags = self._extract_tags_from_line(line)
                        all_tags.update(tags)
            except Exception as e:
                print(f"Error reading template {md_file}: {e}")
        
        return all_tags
    
    def _extract_tags_from_line(self, line: str) -> List[str]:
        """Extract tags from a line in the markdown file."""
        if "Tags:" not in line:
            return []
        
        tags_part = line.split("Tags:")[1].strip()
        return [tag.lower().strip() for tag in tags_part.split("#") if tag.strip()]
    
    def parse_commands_from_template(self, template_content: str, filter_tags: List[str] = None) -> List[Dict]:
        """Parse commands from template content."""
        if not template_content:
            return []
            
        commands = []
        current_command = None
        
        for line in template_content.splitlines():
            line = line.strip()
            
            # Skip empty lines and headers
            if not line or line.startswith('#'):
                continue
                
            # Start of a new command
            if line.startswith('* ') and not line.startswith('* `') and not line.startswith('* Description') and not line.startswith('* Tags'):
                # Save previous command if it exists
                if current_command and 'command' in current_command:
                    if not filter_tags or any(tag in current_command.get('tags', []) for tag in filter_tags):
                        commands.append(current_command)
                
                current_command = {'name': line[2:].strip()}
                
            # Command line
            elif line.startswith('* `') and current_command:
                current_command['command'] = line.split('`')[1].strip()
                
            # Description
            elif line.startswith('* Description:') and current_command:
                current_command['description'] = line.split('Description:')[1].strip()
                
            # Tags
            elif line.startswith('* Tags:') and current_command:
                current_command['tags'] = self._extract_tags_from_line(line)
        
        # Add the last command if it exists
        if current_command and 'command' in current_command:
            if not filter_tags or any(tag in current_command.get('tags', []) for tag in filter_tags):
                commands.append(current_command)
                
        return commands
