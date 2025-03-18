#!/usr/bin/env python3
"""
Scansible Report Generator
--------------------------
Standalone script to generate reports from scan results.
"""

import sys
import os
import argparse
from pathlib import Path

# Add the project root to the path
project_root = Path(__file__).parent.parent.absolute()
sys.path.append(str(project_root))

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Scansible Report Generator",
        epilog="Example: python generate_report.py reports/report_1234567890.json 192.168.1.1 basic"
    )
    
    parser.add_argument('json_file', help="Path to the JSON scan result file")
    parser.add_argument('target', help="Target IP or domain")
    parser.add_argument('scan_type', help="Type of scan performed")
    parser.add_argument('--method', choices=['langchain', 'simple', 'ai'], default='auto',
                       help="Report generation method (default: auto)")
    
    return parser.parse_args()

def main():
    """Main entry point."""
    args = parse_arguments()
    
    # Check if the JSON file exists
    if not os.path.exists(args.json_file):
        print(f"Error: File not found: {args.json_file}")
        return 1
    
    # Try to generate the report with the specified method
    if args.method == 'auto' or args.method == 'langchain':
        try:
            print("[+] Trying LangChain reporter...")
            from scansible.utils.langchain_reporter import generate_report
            report_path = generate_report(args.json_file, args.target, args.scan_type)
            if report_path:
                print(f"[+] LangChain report generated: {report_path}")
                return 0
        except ImportError as e:
            if args.method == 'langchain':
                print(f"[-] LangChain not available: {e}")
                print("[-] Try installing with: pip install langchain langchain_community")
                return 1
            print("[*] LangChain not available, trying next method...")
        except Exception as e:
            if args.method == 'langchain':
                print(f"[-] Error generating LangChain report: {e}")
                return 1
            print(f"[*] Error with LangChain: {e}, trying next method...")
    
    if args.method == 'auto' or args.method == 'simple':
        try:
            print("[+] Trying simple reporter...")
            from scansible.utils.simple_ai_reporter import generate_report
            report_path = generate_report(args.json_file, args.target, args.scan_type)
            if report_path:
                print(f"[+] Simple report generated: {report_path}")
                return 0
        except ImportError as e:
            if args.method == 'simple':
                print(f"[-] Simple reporter not available: {e}")
                return 1
            print("[*] Simple reporter not available, trying next method...")
        except Exception as e:
            if args.method == 'simple':
                print(f"[-] Error generating simple report: {e}")
                return 1
            print(f"[*] Error with simple reporter: {e}, trying next method...")
    
    if args.method == 'auto' or args.method == 'ai':
        try:
            print("[+] Trying AI reporter...")
            from scansible.utils.ai_reporter import generate_report
            report_path = generate_report(args.json_file, args.target, args.scan_type)
            if report_path:
                print(f"[+] AI report generated: {report_path}")
                return 0
        except ImportError as e:
            print(f"[-] AI reporter not available: {e}")
            return 1
        except Exception as e:
            print(f"[-] Error generating AI report: {e}")
            return 1
    
    print("[-] Failed to generate report with any available method")
    return 1

if __name__ == "__main__":
    sys.exit(main())
