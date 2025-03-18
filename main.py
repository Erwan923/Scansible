#!/usr/bin/env python3
"""
Scansible - Automated Security Scanning Tool
-------------------------------------------
A flexible tool for automating security scans with options for CLI or GUI usage.
"""
import os
import sys
import time
import argparse
from pathlib import Path
from dotenv import load_dotenv

# Add the project root to the path so imports work correctly
project_root = Path(__file__).parent.absolute()
sys.path.append(str(project_root))

# Load environment variables from .env file
load_dotenv()

# ASCII art logo
SCANSIBLE_LOGO = """
         ⣀⣀⣤⣴⣶⣶⣶⣶⣦⣤⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣠⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⠏⠁⠀⢶⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀
⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⡿⠿⣿⠀⠀⠀⠀⣿⠿⢿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀
⠀⢠⣾⣿⣿⣿⣿⣿⡿⠋⣠⣴⣿⣷⣤⣤⣾⣿⣦⣄⠙⢿⣿⣿⣿⣿⣿⣷⡄⠀
⠀⣼⣿⣿⣿⣿⣿⡏⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⢹⣿⣿⣿⣿⣿⣧⠀
⢰⣿⣿⣿⣿⣿⡿⠀⣾⣿⣿⣿⣿⠟⠉⠉⠻⣿⣿⣿⣿⣷⠀⢿⣿⣿⣿⣿⣿⡆    SCANSIBLE
⢸⣿⣿⣿⣿⣿⣇⣰⣿⣿⣿⣿⡇⠀⠀⠀⠀⢸⣿⣿⣿⣿⣆⣸⣿⣿⣿⣿⣿⡇   
⠸⣿⣿⣿⡿⣿⠟⠋⠙⠻⣿⣿⣿⣦⣀⣀⣴⣿⣿⣿⣿⠛⠙⠻⣿⣿⣿⣿⣿⠇
⠀⢻⣿⣿⣧⠉⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠈⣿⣿⣿⡟⠀
⠀⠘⢿⣿⣿⣷⣦⣤⣴⣾⠛⠻⢿⣿⣿⣿⣿⡿⠟⠋⣿⣦⣤⠀⣰⣿⣿⡿⠃⠀  v1.0.0
⠀⠀⠈⢿⣿⣿⣿⣿⣿⣿⣷⣶⣤⣄⣈⣁⣠⣤⣶⣾⣿⣿⣷⣾⣿⣿⡿⠁⠀⠀
⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠙⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠋⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠻⠿⠿⠿⠿⠟⠛⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Scansible - Automated Security Scanning Tool",
        epilog="Examples:\n  python main.py 192.168.1.100\n  python main.py example.com --type web",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Target argument
    parser.add_argument('target', nargs='?',
                      help="Target IP, domain, or range to scan")
    
    # Scan options
    parser.add_argument('--type', '-t', choices=['basic', 'web', 'passive', 'infrastructure', 'rustscan', 'trivy', 'light'],
                      default='basic', help="Type of scan to perform")
    parser.add_argument('--tags', '-T', nargs='+',
                      help="Tags to filter commands (e.g., ssl http)")
    parser.add_argument('--no-report', '-n', action='store_true',
                      help="Skip report generation")
    parser.add_argument('--ai-report', '-a', action='store_true',
                      help="Generate an AI-enhanced report")
    
    # GUI mode
    parser.add_argument('--gui', '-g', action='store_true',
                      help="Launch the web-based graphical interface")
    
    # Utility options
    parser.add_argument('--list-tags', '-L', action='store_true',
                      help="List all available tags")
    parser.add_argument('--version', '-v', action='store_true',
                      help="Show version information")
    
    return parser.parse_args()


def show_version():
    """Display version information."""
    print(SCANSIBLE_LOGO)
    print("A modern security scanning automation tool")
    print("https://github.com/yourusername/scansible")
    sys.exit(0)


def generate_ai_report(json_path, target, scan_type):
    """Generate an AI-enhanced security report."""
    print("\n[+] Generating AI-enhanced security report...")
    
    # First, try using the simple AI reporter (always works without external dependencies)
    try:
        from scansible.utils.simple_ai_reporter import generate_report as simple_report
        print("[*] Using simple AI reporter...")
        ai_report_path = simple_report(json_path, target, scan_type)
        if ai_report_path:
            print(f"[+] Simple AI report saved to: {ai_report_path}")
            
            # Now check if we should try more advanced methods
            auto_ai = os.getenv("SCANSIBLE_AUTO_AI_REPORT", "false").lower() in ["true", "1", "yes", "y"]
            use_langchain = os.getenv("SCANSIBLE_USE_LANGCHAIN", "false").lower() in ["true", "1", "yes", "y"]
            
            if not auto_ai and not use_langchain:
                return ai_report_path
    except ImportError as e:
        print(f"[*] Simple reporter not available: {e}")
    except Exception as e:
        print(f"[*] Error with simple report: {e}")
    
    # Next, try LangChain if available and enabled
    try:
        use_langchain = os.getenv("SCANSIBLE_USE_LANGCHAIN", "false").lower() in ["true", "1", "yes", "y"]
        if use_langchain:
            from scansible.utils.langchain_reporter import generate_report as langchain_report
            print("[*] Using LangChain reporter...")
            ai_report_path = langchain_report(json_path, target, scan_type)
            if ai_report_path:
                print(f"[+] LangChain AI report saved to: {ai_report_path}")
                return ai_report_path
    except ImportError as e:
        print(f"[*] LangChain not available: {e}")
        print("[*] To use LangChain, install: pip install langchain langchain-community")
    except Exception as e:
        print(f"[*] Error with LangChain report: {e}")
    
    # Finally, try the original ai_reporter if available
    try:
        from scansible.utils.ai_reporter import generate_report as original_report
        print("[*] Using original AI reporter...")
        ai_report_path = original_report(json_path, target, scan_type)
        if ai_report_path:
            print(f"[+] AI report saved to: {ai_report_path}")
            return ai_report_path
    except ImportError as e:
        print(f"[*] Original AI reporter not available: {e}")
    except Exception as e:
        print(f"[*] Error with original AI report: {e}")
    
    print("[-] Failed to generate AI report with any available method")
    return None


def start_cli_mode(args):
    """Start Scansible in CLI mode."""
    from scansible.core.scanner import Scanner
    from scansible.core.parser import TemplateParser
    
    # Display logo
    print(SCANSIBLE_LOGO)
    
    # Check if we just want to list tags
    if args.list_tags:
        parser = TemplateParser()
        tags = parser.get_all_available_tags()
        print("\nAvailable tags:")
        for tag in sorted(tags):
            print(f"  #{tag}")
        sys.exit(0)
    
    # Make sure we have a target unless we're just listing tags
    if not args.target:
        print("Error: Target is required in CLI mode")
        print("Usage: python main.py <target> [options]")
        print("       python main.py --gui (for graphical interface)")
        sys.exit(1)
    
    print(f"\n[+] Starting {args.type} scan on target: {args.target}")
    if args.tags:
        print(f"[+] Using tags: {', '.join(args.tags)}")
    
    start_time = time.time()
    
    # Initialize scanner
    scanner = Scanner()
    
    # Run scan
    scan_config = {
        'target': args.target,
        'scan_type': args.type,
        'tags': args.tags,
        'generate_report': not args.no_report
    }
    
    # Show scanning animation
    print("[+] Scanning in progress...")
    
    result = scanner.run_scan(scan_config)
    
    end_time = time.time()
    duration = end_time - start_time
    
    if result['success']:
        print(f"\n[+] Scan completed successfully in {duration:.2f} seconds!")
        
        if result.get('report_path') and os.path.exists(result['report_path']):
            print(f"[+] Report saved to: {result['report_path']}")
            
            # Check for auto-generation
            auto_ai_report = os.getenv("SCANSIBLE_AUTO_AI_REPORT", "false").lower() in ["true", "1", "yes", "y"]
            
            # Decide whether to generate AI report
            generate_ai = False
            
            if auto_ai_report:
                generate_ai = True
                print("[*] Auto-generating AI report based on configuration...")
            elif args.ai_report:
                generate_ai = True
            elif not args.no_report:
                # Check if user wants an AI report
                print("\n[?] Would you like to generate an AI-enhanced security report? (y/n)")
                choice = input("> ").lower().strip()
                generate_ai = choice.startswith('y')
            
            if generate_ai:
                generate_ai_report(result['report_path'], args.target, args.type)
    else:
        print(f"\n[-] Scan failed: {result.get('error', 'Unknown error')}")
        sys.exit(1)


def start_gui_mode():
    """Start Scansible in GUI mode with web server."""
    try:
        import uvicorn
        from api.app import app
        
        # Display logo
        print(SCANSIBLE_LOGO)
        
        # Check if frontend build exists, warn if not
        frontend_path = Path(project_root) / "frontend" / "dist"
        if not frontend_path.exists():
            print("\nWarning: Frontend build not found.")
            print("The API will start, but you'll need to build the frontend separately.")
            print("Run these commands in another terminal:")
            print("  cd frontend")
            print("  npm install")
            print("  npm run build")
            
        print("\n[+] Starting Scansible web interface...")
        print("[+] API server running at http://localhost:8000")
        print("[+] Web interface will be available at http://localhost:3000 (if built)")
        print("\nPress CTRL+C to stop the server")
        
        # Start the API server
        uvicorn.run(app, host="0.0.0.0", port=8000)
        
    except ImportError as e:
        print(f"Error: Unable to start GUI mode. Missing dependency: {e}")
        print("Install required packages with: pip install -r requirements.txt")
        sys.exit(1)


def main():
    """Main entry point."""
    args = parse_arguments()
    
    # Show version if requested
    if args.version:
        show_version()
    
    # Choose mode based on arguments
    if args.gui:
        start_gui_mode()
    else:
        start_cli_mode(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
