"""
Scanner module for Scansible
---------------------------
Handles the execution of security scans and report generation.
"""

import json
import os
import subprocess
import time
import yaml
import xmltodict
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from scansible.core.parser import TemplateParser
from scansible.utils.config import Config

class Scanner:
    """Main scanner class for executing security scans."""
    
    def __init__(self):
        """Initialize the scanner with configuration."""
        self.config = Config()
        self.parser = TemplateParser()
        
        # Ensure directories exist
        self.reports_dir = self.config.get_reports_dir()
        self.reports_dir.mkdir(exist_ok=True)
        
        # Create subdirectories for organization
        self.html_dir = self.reports_dir / "html_reports"
        self.json_dir = self.reports_dir / "json_reports"
        self.xml_dir = self.reports_dir / "xml_reports"
        self.md_dir = self.reports_dir / "markdown_reports"
        
        self.html_dir.mkdir(exist_ok=True)
        self.json_dir.mkdir(exist_ok=True)
        self.xml_dir.mkdir(exist_ok=True)
        self.md_dir.mkdir(exist_ok=True)
        
        self.scans_dir = self.config.get_scans_dir()
        self.scans_dir.mkdir(exist_ok=True)
    
    def check_tool_availability(self, tool_name: str) -> bool:
        """Check if a security tool is available in the system."""
        try:
            result = subprocess.run(['which', tool_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def generate_ansible_playbook(self, commands: List[Dict], target: str, scan_type: str) -> Tuple[Path, str]:
        """Generate an Ansible playbook from scan commands."""
        playbook_path = self.scans_dir / f"{scan_type}_{int(time.time())}_playbook.yml"
        xml_report_filename = self.xml_dir / f"scan_report_{int(time.time())}.xml"
        
        # Check available tools
        available_tools = {
            'nmap': self.check_tool_availability('nmap'),
            'rustscan': self.check_tool_availability('rustscan'),
            'trivy': self.check_tool_availability('trivy')
        }
        
        print(f"\nAvailable tools: {', '.join([tool for tool, available in available_tools.items() if available])}")
        
        tasks = []
        skipped_commands = []
        
        for cmd in commands:
            command = cmd['command']
            
            # Skip if required tool is not available
            if command.startswith('nmap') and not available_tools['nmap']:
                skipped_commands.append(f"{cmd['name']} (nmap not installed)")
                continue
            elif command.startswith('rustscan') and not available_tools['rustscan']:
                skipped_commands.append(f"{cmd['name']} (rustscan not installed)")
                continue
            elif command.startswith('trivy') and not available_tools['trivy']:
                skipped_commands.append(f"{cmd['name']} (trivy not installed)")
                continue
            
            # Build the task based on command type
            if command.startswith('nmap'):
                task = {
                    'name': f"Running: {cmd['name']}",
                    'command': f"{command.replace('[target]', '')} {target} -oX {xml_report_filename}",
                }
            elif command.startswith('rustscan'):
                task = {
                    'name': f"Running: {cmd['name']}",
                    'command': f"{command.replace('[target]', target)}",
                }
            elif command.startswith('trivy'):
                json_output_file = self.json_dir / f"trivy_report_{int(time.time())}.json"
                
                # Replace placeholders
                cmd_str = command
                cmd_str = cmd_str.replace('[image_name:tag]', target)
                cmd_str = cmd_str.replace('[output_file.json]', str(json_output_file))
                
                # Add JSON output format if not present
                if '--format=' not in cmd_str and '-f=' not in cmd_str:
                    cmd_str += ' --format=json'
                
                # Add output path if not present
                if '--output=' not in cmd_str and '-o=' not in cmd_str and '[output_file.json]' not in command:
                    cmd_str += f' --output {json_output_file}'
                
                task = {
                    'name': f"Running: {cmd['name']}",
                    'command': cmd_str,
                }
            else:
                task = {
                    'name': f"Running: {cmd['name']}",
                    'command': f"{command.replace('[target]', '')} {target}",
                }
            
            if 'tags' in cmd:
                task['tags'] = cmd['tags']
                
            tasks.append(task)
        
        # Show skipped commands
        if skipped_commands:
            print("\nSkipped commands (missing tools):")
            for cmd in skipped_commands:
                print(f"- {cmd}")
        
        # Add a default task if no tools are available
        if not tasks:
            print("\nWARNING: No available commands - Adding a placeholder task")
            tasks.append({
                'name': "No available commands - Missing tools",
                'debug': {
                    'msg': "No required tools are installed. Please install nmap, rustscan, or trivy."
                }
            })
        
        # Create the playbook
        playbook = [{
            'hosts': 'localhost',
            'tasks': tasks
        }]
        
        with open(playbook_path, 'w') as file:
            yaml.safe_dump(playbook, file, default_flow_style=False)
        
        return playbook_path, str(xml_report_filename)
    
    def execute_ansible_playbook(self, playbook_path: Path) -> bool:
        """Execute an Ansible playbook."""
        try:
            subprocess.run(['ansible-playbook', str(playbook_path)], check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error executing Ansible playbook: {e}")
            return False
    
    def convert_xml_to_json(self, xml_file_path: str) -> Optional[Path]:
        """Convert an XML report file to JSON."""
        xml_path = Path(xml_file_path)
        
        if not xml_path.exists():
            print(f"XML report file not found: {xml_path}")
            return None
        
        try:
            with open(xml_path) as xml_file:
                xml_string = xml_file.read()
            
            json_data = xmltodict.parse(xml_string)
            
            # Create JSON filename and save to json directory
            json_filename = f"report_{int(time.time())}.json"
            json_path = self.json_dir / json_filename
            
            with open(json_path, 'w') as json_file:
                json.dump(json_data, json_file, indent=4)
            
            print(f"Scan report saved to {json_path}")
            return json_path
            
        except Exception as e:
            print(f"Error converting XML to JSON: {e}")
            return None
    
    def run_scan(self, scan_config: Dict[str, Any]) -> Dict[str, Any]:
        """Run a security scan with the given configuration."""
        try:
            target = scan_config['target']
            scan_type = scan_config.get('scan_type', 'basic')
            tags = scan_config.get('tags', [])
            generate_report = scan_config.get('generate_report', True)
            
            print(f"\nStarting {scan_type} scan on {target}")
            if tags:
                print(f"Using tags: {', '.join(tags)}")
            
            # Get template for scan type
            template = self.parser.get_template_for_scan_type(scan_type)
            if not template:
                return {
                    'success': False,
                    'error': f"No template found for scan type: {scan_type}"
                }
            
            # Parse commands from template
            commands = self.parser.parse_commands_from_template(template, tags)
            if not commands:
                return {
                    'success': False,
                    'error': "No commands found matching the specified criteria"
                }
            
            # Display selected commands
            print("\nSelected commands:")
            for cmd in commands:
                print(f"\n- {cmd['name']}")
                if 'description' in cmd:
                    print(f"  Description: {cmd['description']}")
                if 'tags' in cmd:
                    print(f"  Tags: {' '.join(['#' + tag for tag in cmd['tags']])}")
            
            # Generate and execute Ansible playbook
            playbook_path, report_filename = self.generate_ansible_playbook(commands, target, scan_type)
            
            if not self.execute_ansible_playbook(playbook_path):
                return {
                    'success': False,
                    'error': "Failed to execute Ansible playbook"
                }
            
            # Process report if requested
            json_path = None
            if generate_report:
                json_path = self.convert_xml_to_json(report_filename)
                
                if json_path:
                    # Move any reports that might be in the root reports directory
                    self.organize_reports()
                    
                    return {
                        'success': True,
                        'target': target,
                        'scan_type': scan_type,
                        'report_path': str(json_path)
                    }
                else:
                    return {
                        'success': True,
                        'target': target,
                        'scan_type': scan_type,
                        'message': "Scan completed but report could not be generated"
                    }
            else:
                return {
                    'success': True,
                    'target': target,
                    'scan_type': scan_type,
                    'message': "Scan completed successfully (report generation skipped)"
                }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def organize_reports(self):
        """Move reports to their appropriate directories."""
        # Move json files
        for file in self.reports_dir.glob("*.json"):
            if file.parent == self.reports_dir:  # Only if in root reports dir
                shutil.move(str(file), str(self.json_dir / file.name))
        
        # Move xml files
        for file in self.reports_dir.glob("*.xml"):
            if file.parent == self.reports_dir:  # Only if in root reports dir
                shutil.move(str(file), str(self.xml_dir / file.name))
        
        # Move markdown files
        for file in self.reports_dir.glob("*.md"):
            if file.parent == self.reports_dir:  # Only if in root reports dir
                shutil.move(str(file), str(self.md_dir / file.name))
        
        # Move html files
        for file in self.reports_dir.glob("*.html"):
            if file.parent == self.reports_dir:  # Only if in root reports dir
                shutil.move(str(file), str(self.html_dir / file.name))
