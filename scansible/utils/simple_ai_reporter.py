"""
Simple AI Report Generator for Scansible
----------------------------------------
Generates security reports with minimal dependencies.
"""

import os
import json
import logging
import shutil
from datetime import datetime
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scansible.simple_ai_reporter")


class ReportGenerator:
    """Class to handle the generation of security reports from scan results."""
    
    def __init__(self):
        """Initialize the report generator."""
        pass
        
    def extract_basic_info(self, json_path):
        """Extract basic information from scan results."""
        try:
            logger.info(f"Extracting data from {json_path}")
            with open(json_path, 'r') as f:
                data = json.load(f)
            
            scan_info = {
                'hosts': [],
                'open_ports': [],
                'services': [],
                'os_detection': []
            }
            
            # Process Nmap data
            if 'nmaprun' in data:
                nmaprun = data.get('nmaprun', {})
                hosts = nmaprun.get('host', [])
                
                if not isinstance(hosts, list):
                    hosts = [hosts]
                
                for host in hosts:
                    host_info = {'ip': None, 'ports': []}
                    
                    # Get IP
                    addresses = host.get('address', [])
                    if not isinstance(addresses, list):
                        addresses = [addresses]
                    
                    for addr in addresses:
                        if addr.get('@addrtype') == 'ipv4':
                            host_info['ip'] = addr.get('@addr')
                    
                    # Get ports
                    ports = host.get('ports', {}).get('port', [])
                    if not isinstance(ports, list):
                        ports = [ports]
                    
                    for port in ports:
                        if not port:
                            continue
                        
                        port_id = port.get('@portid')
                        protocol = port.get('@protocol', 'tcp')
                        state = port.get('state', {}).get('@state')
                        service = port.get('service', {}).get('@name', 'unknown')
                        
                        if state == 'open':
                            port_info = {
                                'port': port_id,
                                'protocol': protocol,
                                'service': service
                            }
                            host_info['ports'].append(port_info)
                            scan_info['open_ports'].append(f"{port_id}/{protocol}")
                            scan_info['services'].append(service)
                    
                    # OS detection
                    os_detection = host.get('os', {}).get('osmatch', [])
                    if not isinstance(os_detection, list):
                        os_detection = [os_detection]
                    
                    for os_match in os_detection:
                        if os_match and '@name' in os_match:
                            scan_info['os_detection'].append({
                                'name': os_match.get('@name'),
                                'accuracy': os_match.get('@accuracy')
                            })
                    
                    scan_info['hosts'].append(host_info)
            
            return scan_info
        
        except Exception as e:
            logger.error(f"Error extracting info: {e}")
            return {
                'hosts': [],
                'open_ports': [],
                'services': [],
                'os_detection': []
            }
    
    def generate_basic_report(self, scan_info, target, scan_type):
        """Generate a basic security report."""
        report = f"""# Security Scan Report - {target}

## Scan Information
- **Target:** {target}
- **Scan Type:** {scan_type}
- **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
- **Hosts Scanned:** {len(scan_info['hosts'])}
- **Open Ports Found:** {len(scan_info['open_ports'])}
- **Services Detected:** {len(set(scan_info['services']))}

## Open Ports
"""
        
        if scan_info['open_ports']:
            unique_ports = list(set(scan_info['open_ports']))
            unique_ports.sort()
            for port in unique_ports[:20]:  # Limit to first 20 ports
                report += f"- {port}\n"
            if len(unique_ports) > 20:
                report += f"- ... and {len(unique_ports) - 20} more\n"
        else:
            report += "No open ports detected.\n"
        
        report += "\n## Services Detected\n"
        
        if scan_info['services']:
            unique_services = list(set(scan_info['services']))
            unique_services.sort()
            for service in unique_services:
                report += f"- {service}\n"
        else:
            report += "No services detected.\n"
        
        report += "\n## Security Recommendations\n"
        
        # Basic recommendations based on services
        recommendations = []
        services_set = set(scan_info['services'])
        
        if 'http' in services_set or 'https' in services_set:
            recommendations.append("- Ensure web servers are patched to the latest version")
            recommendations.append("- Consider implementing a Web Application Firewall (WAF)")
            recommendations.append("- Verify that HTTPS is properly configured with strong ciphers")
        
        if 'ssh' in services_set:
            recommendations.append("- Use key-based authentication instead of passwords for SSH")
            recommendations.append("- Restrict SSH access to specific IP addresses")
            recommendations.append("- Consider changing the default SSH port")
        
        if 'ftp' in services_set or 'telnet' in services_set:
            recommendations.append("- Replace FTP/Telnet with more secure alternatives like SFTP/SSH")
            recommendations.append("- If FTP is necessary, ensure it's properly configured and secured")
        
        if 'smb' in services_set:
            recommendations.append("- Ensure SMB is updated to the latest version")
            recommendations.append("- Disable SMBv1 protocol")
            recommendations.append("- Implement proper access controls on SMB shares")
        
        # General recommendations
        general_recommendations = [
            "- Implement a regular patching schedule for all services",
            "- Consider using a host-based firewall to restrict access to services",
            "- Perform regular security scans to identify new vulnerabilities",
            "- Document all exposed services and justify their necessity"
        ]
        
        if recommendations:
            for recommendation in recommendations:
                report += f"{recommendation}\n"
        
        report += "\n### General Recommendations\n"
        for recommendation in general_recommendations:
            report += f"{recommendation}\n"
        
        report += "\n---\n*This report was automatically generated by Scansible.*"
        
        return report
    
    def create_html_report(self, markdown_content, target, scan_type):
        """Convert markdown content to HTML with styling."""
        try:
            import markdown
            html_content = markdown.markdown(markdown_content)
            
            # Get current date/time for report
            report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Add basic styling with a dark theme
            styled_html = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Security Scan Report - {target}</title>
                <style>
                    :root {{
                        --bg-color: #1a1a1a;
                        --text-color: #f0f0f0;
                        --accent-color: #ff3e3e;
                        --secondary-color: #2d2d2d;
                        --border-color: #444;
                        --heading-color: #ff5252;
                        --link-color: #ff8080;
                        --success-color: #4caf50;
                        --warning-color: #ff9800;
                        --danger-color: #f44336;
                    }}
                    
                    body {{
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        line-height: 1.6;
                        color: var(--text-color);
                        background-color: var(--bg-color);
                        max-width: 1000px;
                        margin: 0 auto;
                        padding: 2rem;
                    }}
                    
                    h1, h2, h3, h4, h5, h6 {{
                        font-weight: 600;
                        margin-top: 1.5rem;
                        margin-bottom: 1rem;
                        color: var(--heading-color);
                    }}
                    
                    h1 {{
                        font-size: 2.5rem;
                        text-align: center;
                        border-bottom: 2px solid var(--accent-color);
                        padding-bottom: 1rem;
                        margin-bottom: 2rem;
                    }}
                    
                    h2 {{
                        font-size: 1.8rem;
                        border-bottom: 1px solid var(--border-color);
                        padding-bottom: 0.5rem;
                    }}
                    
                    h3 {{
                        font-size: 1.4rem;
                        color: var(--accent-color);
                    }}
                    
                    ul, ol {{
                        padding-left: 2rem;
                    }}
                    
                    li {{
                        margin-bottom: 0.5rem;
                    }}
                    
                    p {{
                        margin-bottom: 1rem;
                    }}
                    
                    a {{
                        color: var(--link-color);
                        text-decoration: none;
                    }}
                    
                    a:hover {{
                        text-decoration: underline;
                    }}
                    
                    code {{
                        font-family: Consolas, Monaco, 'Andale Mono', monospace;
                        background-color: var(--secondary-color);
                        padding: 0.2rem 0.4rem;
                        border-radius: 3px;
                    }}
                    
                    pre {{
                        background-color: var(--secondary-color);
                        padding: 1rem;
                        border-radius: 4px;
                        overflow-x: auto;
                    }}
                    
                    table {{
                        width: 100%;
                        border-collapse: collapse;
                        margin: 1rem 0;
                    }}
                    
                    th, td {{
                        padding: 0.75rem;
                        text-align: left;
                        border: 1px solid var(--border-color);
                    }}
                    
                    th {{
                        background-color: var(--secondary-color);
                        font-weight: bold;
                    }}
                    
                    tr:nth-child(even) {{
                        background-color: rgba(255, 255, 255, 0.05);
                    }}
                    
                    .header {{
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        margin-bottom: 2rem;
                        background-color: var(--secondary-color);
                        padding: 1rem;
                        border-radius: 8px;
                        border-left: 4px solid var(--accent-color);
                    }}
                    
                    .header-info {{
                        flex: 1;
                    }}
                    
                    .critical {{
                        color: var(--danger-color);
                        font-weight: bold;
                    }}
                    
                    .high {{
                        color: var(--warning-color);
                        font-weight: bold;
                    }}
                    
                    .medium {{
                        color: #ffd600;
                    }}
                    
                    .low {{
                        color: var(--success-color);
                    }}
                    
                    .recommendations {{
                        background-color: rgba(255, 62, 62, 0.1);
                        border-left: 4px solid var(--accent-color);
                        padding: 1.5rem;
                        margin: 1.5rem 0;
                        border-radius: 4px;
                    }}
                    
                    .footer {{
                        margin-top: 3rem;
                        padding-top: 1rem;
                        border-top: 1px solid var(--border-color);
                        text-align: center;
                        font-size: 0.9rem;
                        color: #888;
                    }}
                    
                    .logo {{
                        font-size: 2rem;
                        font-weight: bold;
                        color: var(--accent-color);
                    }}
                    
                    .summary-stats {{
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                        gap: 1rem;
                        margin: 2rem 0;
                    }}
                    
                    .stat-card {{
                        background-color: var(--secondary-color);
                        border-radius: 8px;
                        padding: 1.5rem;
                        text-align: center;
                        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                    }}
                    
                    .stat-value {{
                        font-size: 2.5rem;
                        font-weight: bold;
                        color: var(--accent-color);
                        margin-bottom: 0.5rem;
                    }}
                    
                    .stat-label {{
                        font-size: 1rem;
                        color: #bbb;
                    }}
                </style>
            </head>
            <body>
                <div class="header">
                    <div class="header-info">
                        <div class="logo">SCANSIBLE</div>
                        <p>Security Scan Report</p>
                    </div>
                    <div>
                        <p><strong>Target:</strong> {target}</p>
                        <p><strong>Scan Type:</strong> {scan_type}</p>
                        <p><strong>Date:</strong> {report_date}</p>
                    </div>
                </div>
                
                {html_content}
                
                <div class="footer">
                    <p>Generated by Scansible on {report_date}</p>
                    <p>© 2025 Scansible - Automated Security Scanning Tool</p>
                </div>
                
                <script>
                    // Add some simple JavaScript to enhance the report
                    document.addEventListener('DOMContentLoaded', function() {{
                        // Find the Summary section
                        const summaryHeading = Array.from(document.querySelectorAll('h2')).find(
                            el => el.textContent.includes('Summary')
                        );
                        
                        if (summaryHeading) {{
                            // Get the stats
                            const summaryList = summaryHeading.nextElementSibling;
                            if (summaryList && summaryList.tagName === 'UL') {{
                                const statItems = summaryList.querySelectorAll('li');
                                const statsData = [];
                                
                                statItems.forEach(item => {{
                                    const text = item.textContent;
                                    const match = text.match(/([^:]+):\\s+(\\d+)/);
                                    if (match) {{
                                        statsData.push({{
                                            label: match[1].trim(),
                                            value: match[2].trim()
                                        }});
                                    }}
                                }});
                                
                                // Create stats cards
                                if (statsData.length > 0) {{
                                    const statsContainer = document.createElement('div');
                                    statsContainer.className = 'summary-stats';
                                    
                                    statsData.forEach(stat => {{
                                        const card = document.createElement('div');
                                        card.className = 'stat-card';
                                        
                                        const valueEl = document.createElement('div');
                                        valueEl.className = 'stat-value';
                                        valueEl.textContent = stat.value;
                                        
                                        const labelEl = document.createElement('div');
                                        labelEl.className = 'stat-label';
                                        labelEl.textContent = stat.label;
                                        
                                        card.appendChild(valueEl);
                                        card.appendChild(labelEl);
                                        statsContainer.appendChild(card);
                                    }});
                                    
                                    // Replace the list with our stats cards
                                    summaryList.parentNode.replaceChild(statsContainer, summaryList);
                                }}
                            }}
                        }}
                        
                        // Style recommendations section
                        const recommendationsHeading = Array.from(document.querySelectorAll('h2')).find(
                            el => el.textContent.includes('Recommendations')
                        );
                        
                        if (recommendationsHeading) {{
                            const recommendationsSection = document.createElement('div');
                            recommendationsSection.className = 'recommendations';
                            
                            // Move all elements after the heading and before the next heading into the recommendations section
                            let currentElement = recommendationsHeading.nextElementSibling;
                            const elementsToMove = [];
                            
                            while (currentElement && (currentElement.tagName !== 'H2')) {{
                                elementsToMove.push(currentElement);
                                currentElement = currentElement.nextElementSibling;
                            }}
                            
                            recommendationsHeading.insertAdjacentElement('afterend', recommendationsSection);
                            elementsToMove.forEach(el => recommendationsSection.appendChild(el));
                        }}
                    }});
                </script>
            </body>
            </html>
            """
            
            return styled_html
        except ImportError:
            # If markdown module is not available, return basic HTML
            html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Security Scan Report - {target}</title>
                <style>
                    body {{ font-family: sans-serif; background-color: #1a1a1a; color: #f0f0f0; }}
                    pre {{ white-space: pre-wrap; background-color: #2d2d2d; padding: 1em; }}
                    h1 {{ color: #ff3e3e; }}
                </style>
            </head>
            <body>
                <h1>Security Scan Report - {target}</h1>
                <pre>{markdown_content}</pre>
            </body>
            </html>
            """
            return html
    
    def setup_report_directories(self, reports_base_dir):
        """Set up report directory structure."""
        # Make sure the base reports directory exists
        reports_base_dir = Path(reports_base_dir)
        reports_base_dir.mkdir(exist_ok=True)
        
        # Create subdirectories
        html_dir = reports_base_dir / "html_reports"
        json_dir = reports_base_dir / "json_reports"
        xml_dir = reports_base_dir / "xml_reports"
        md_dir = reports_base_dir / "markdown_reports"
        
        html_dir.mkdir(exist_ok=True)
        json_dir.mkdir(exist_ok=True)
        xml_dir.mkdir(exist_ok=True)
        md_dir.mkdir(exist_ok=True)
        
        return {
            'base_dir': reports_base_dir,
            'html_dir': html_dir,
            'json_dir': json_dir,
            'xml_dir': xml_dir,
            'md_dir': md_dir
        }
    
    def organize_existing_reports(self, dirs):
        """Move existing reports to their appropriate directories."""
        base_dir = dirs['base_dir']
        
        # Move files from base directory to appropriate subdirectories
        for file in base_dir.glob("*.json"):
            if file.parent == base_dir:  # Only if in base reports dir
                shutil.move(str(file), str(dirs['json_dir'] / file.name))
        
        for file in base_dir.glob("*.xml"):
            if file.parent == base_dir:
                shutil.move(str(file), str(dirs['xml_dir'] / file.name))
        
        for file in base_dir.glob("*.md"):
            if file.parent == base_dir:
                shutil.move(str(file), str(dirs['md_dir'] / file.name))
        
        for file in base_dir.glob("*.html"):
            if file.parent == base_dir:
                shutil.move(str(file), str(dirs['html_dir'] / file.name))
    
    def generate_report(self, json_path, target, scan_type):
        """Generate a security report from scan results."""
        try:
            # Debug information
            json_abs_path = Path(json_path).resolve()
            logger.info(f"Generating report from JSON: {json_abs_path}")
            
            # Setup directory structure
            reports_base_dir = Path(json_abs_path).parent.parent
            if reports_base_dir.name != "reports":
                reports_base_dir = Path(json_abs_path).parent
                
            logger.info(f"Using reports base directory: {reports_base_dir}")
            dirs = self.setup_report_directories(reports_base_dir)
            
            # Organize any existing reports
            self.organize_existing_reports(dirs)
            
            # Extract data from the JSON file
            scan_info = self.extract_basic_info(json_abs_path)
            
            # Generate markdown report
            markdown_report = self.generate_basic_report(scan_info, target, scan_type)
            
            # Create timestamp for filenames
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Save markdown report
            md_filename = f"scan_report_{target}_{scan_type}_{timestamp}.md"
            md_path = dirs['md_dir'] / md_filename
            with open(md_path, 'w') as f:
                f.write(markdown_report)
            
            # Generate HTML report
            try:
                html_content = self.create_html_report(markdown_report, target, scan_type)
                html_filename = f"scan_report_{target}_{scan_type}_{timestamp}.html"
                html_path = dirs['html_dir'] / html_filename
                with open(html_path, 'w') as f:
                    f.write(html_content)
                logger.info(f"Reports saved to {md_path} and {html_path}")
                return str(html_path)
            except ImportError as e:
                logger.info(f"Markdown module not available: {e}")
                logger.info(f"Only saving markdown report: {md_path}")
                return str(md_path)
        
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return None


# Helper function for easy access
def generate_report(json_path, target, scan_type):
    """Generate a security report using the ReportGenerator class."""
    generator = ReportGenerator()
    return generator.generate_report(json_path, target, scan_type)


# Test the module directly
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 4:
        print("Usage: python simple_ai_reporter.py <json_file> <target> <scan_type>")
        sys.exit(1)
    
    json_file = sys.argv[1]
    target = sys.argv[2]
    scan_type = sys.argv[3]
    
    report_path = generate_report(json_file, target, scan_type)
    if report_path:
        print(f"Report generated successfully: {report_path}")
    else:
        print("Failed to generate report")
        sys.exit(1)
