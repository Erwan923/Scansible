"""
Advanced AI Report Generator using LangChain for Scansible
--------------------------------------------------------
Automatically processes scan results and creates detailed security reports.
"""

import os
import json
import time
from pathlib import Path
from datetime import datetime
import logging
from typing import Dict, List, Optional, Any, Union

# Import LangChain components
from langchain.llms import OpenAI
from langchain.chat_models import ChatOpenAI
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from langchain.chains.combine_documents.stuff import StuffDocumentsChain
from langchain.document_loaders import JSONLoader
from langchain.schema import Document
from langchain.output_parsers import StructuredOutputParser, ResponseSchema
from langchain.text_splitter import CharacterTextSplitter
from dotenv import load_dotenv

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scansible.langchain_reporter")

# Load environment variables
load_dotenv()

class VulnerabilityReportGenerator:
    """Generate professional security reports using LangChain and LLMs."""
    
    def __init__(self):
        """Initialize the report generator with LangChain components."""
        self.llm = self._initialize_llm()
        self.report_sections = [
            "executive_summary",
            "methodology",
            "critical_vulnerabilities",
            "high_vulnerabilities", 
            "medium_vulnerabilities",
            "risk_assessment",
            "recommendations",
            "technical_appendix"
        ]
        
        # Define response schemas for structured output
        self.response_schemas = [
            ResponseSchema(name="executive_summary", 
                          description="Executive summary of the security assessment in 2-3 paragraphs"),
            ResponseSchema(name="methodology", 
                          description="Brief description of the scanning methodology used"),
            ResponseSchema(name="critical_vulnerabilities", 
                          description="Detailed analysis of critical vulnerabilities found"),
            ResponseSchema(name="high_vulnerabilities", 
                          description="Detailed analysis of high severity vulnerabilities found"),
            ResponseSchema(name="medium_vulnerabilities", 
                          description="Summary of medium severity vulnerabilities found"),
            ResponseSchema(name="risk_assessment", 
                          description="Overall risk assessment with business impact analysis"),
            ResponseSchema(name="recommendations", 
                          description="Prioritized recommendations for remediation"),
            ResponseSchema(name="technical_appendix", 
                          description="Technical details including ports, services, and raw vulnerability data")
        ]
        
        self.output_parser = StructuredOutputParser.from_response_schemas(self.response_schemas)
        self.format_instructions = self.output_parser.get_format_instructions()
    
    def _initialize_llm(self) -> Any:
        """Initialize the appropriate LLM based on available API keys."""
        # Check for OpenAI API key
        if os.getenv("SCANSIBLE_OPENAI_API_KEY"):
            return ChatOpenAI(
                openai_api_key=os.getenv("SCANSIBLE_OPENAI_API_KEY"),
                model_name="gpt-4",
                temperature=0.2
            )
            
        # Check for Anthropic API key
        elif os.getenv("SCANSIBLE_ANTHROPIC_API_KEY"):
            try:
                from langchain.llms import Anthropic
                return Anthropic(
                    anthropic_api_key=os.getenv("SCANSIBLE_ANTHROPIC_API_KEY"),
                    model="claude-2",
                    temperature=0.2
                )
            except ImportError:
                logger.warning("Anthropic API key found but langchain Anthropic integration not installed")
                logger.warning("Install with: pip install langchain[anthropic]")
        
        # Default to local model if configured
        elif os.getenv("SCANSIBLE_OLLAMA_API_URL"):
            try:
                from langchain.llms import Ollama
                return Ollama(
                    base_url=os.getenv("SCANSIBLE_OLLAMA_API_URL"),
                    model="llama2",
                    temperature=0.2
                )
            except ImportError:
                logger.warning("Ollama URL found but langchain Ollama integration not installed")
        
        # No suitable LLM found
        logger.error("No suitable LLM found. Please set one of the API keys in your .env file")
        return None
    
    def _extract_metadata(self, json_path: str) -> Dict:
        """Extract scan metadata from the JSON file."""
        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
            
            metadata = {
                "timestamp": datetime.now().isoformat(),
                "scan_type": "unknown",
            }
            
            # Extract scan type from Nmap results
            if "nmaprun" in data:
                nmaprun = data.get("nmaprun", {})
                metadata["scanner"] = "nmap"
                metadata["scan_type"] = nmaprun.get("@scanner", "Nmap scan")
                metadata["nmap_version"] = nmaprun.get("@version", "Unknown")
                metadata["start_time"] = nmaprun.get("@startstr", "Unknown")
                metadata["arguments"] = nmaprun.get("@args", "Unknown")
            
            # Extract scan type from Trivy results
            elif "Results" in data:
                metadata["scanner"] = "trivy"
                metadata["scan_type"] = "Container security scan"
            
            return metadata
            
        except Exception as e:
            logger.error(f"Error extracting metadata: {e}")
            return {"timestamp": datetime.now().isoformat()}
    
    def _extract_vulnerability_summary(self, json_path: str) -> Dict:
        """Extract a vulnerability summary from the scan results."""
        from scansible.utils.ai_reporter import extract_vulnerability_data
        
        try:
            with open(json_path, 'r') as f:
                json_data = json.load(f)
            
            return extract_vulnerability_data(json_data)
        except Exception as e:
            logger.error(f"Error extracting vulnerability summary: {e}")
            return {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "services": [],
                "open_ports": [],
                "vulnerabilities": []
            }
    
    def _create_vulnerability_documents(self, vulnerability_data: Dict) -> List[Document]:
        """Create LangChain documents from vulnerability data."""
        documents = []
        
        # Create summary document
        summary = {
            "total_vulnerabilities": sum([
                vulnerability_data['critical'],
                vulnerability_data['high'],
                vulnerability_data['medium'],
                vulnerability_data['low'],
                vulnerability_data['info']
            ]),
            "critical": vulnerability_data['critical'],
            "high": vulnerability_data['high'],
            "medium": vulnerability_data['medium'],
            "low": vulnerability_data['low'],
            "info": vulnerability_data['info']
        }
        
        summary_doc = Document(
            page_content=json.dumps(summary, indent=2),
            metadata={"source": "vulnerability_summary"}
        )
        documents.append(summary_doc)
        
        # Create service documents
        services_doc = Document(
            page_content=json.dumps(vulnerability_data['services'], indent=2),
            metadata={"source": "services"}
        )
        documents.append(services_doc)
        
        # Create vulnerabilities documents (may need to split for large scans)
        if vulnerability_data['vulnerabilities']:
            # Group vulnerabilities by severity
            critical = [v for v in vulnerability_data['vulnerabilities'] 
                      if v.get('severity') == 'CRITICAL']
            high = [v for v in vulnerability_data['vulnerabilities'] 
                  if v.get('severity') == 'HIGH']
            medium = [v for v in vulnerability_data['vulnerabilities'] 
                    if v.get('severity') == 'MEDIUM']
            low = [v for v in vulnerability_data['vulnerabilities'] 
                 if v.get('severity') == 'LOW']
            
            # Create separate documents for each severity level
            if critical:
                critical_doc = Document(
                    page_content=json.dumps(critical, indent=2),
                    metadata={"source": "critical_vulnerabilities"}
                )
                documents.append(critical_doc)
            
            if high:
                high_doc = Document(
                    page_content=json.dumps(high, indent=2),
                    metadata={"source": "high_vulnerabilities"}
                )
                documents.append(high_doc)
            
            if medium:
                medium_doc = Document(
                    page_content=json.dumps(medium, indent=2),
                    metadata={"source": "medium_vulnerabilities"}
                )
                documents.append(medium_doc)
            
            if low:
                low_doc = Document(
                    page_content=json.dumps(low, indent=2),
                    metadata={"source": "low_vulnerabilities"}
                )
                documents.append(low_doc)
        
        return documents
    
    def _create_report_prompt(self, target: str, scan_type: str) -> str:
        """Create the LangChain prompt for the security report."""
        template = """
You are a cybersecurity expert tasked with creating a detailed security assessment report.

TARGET INFORMATION:
- Target: {target}
- Scan Type: {scan_type}

SCAN RESULTS:
{document_data}

Based on the provided scan results, generate a professional security assessment report with the following sections:

{format_instructions}

Remember to:
1. Provide actionable recommendations for each vulnerability
2. Include practical steps for remediation
3. Prioritize findings based on risk and exploitability
4. Use technical language appropriate for IT professionals
5. Include relevant CVE IDs and CVSS scores when available
"""
        
        prompt = PromptTemplate(
            template=template,
            input_variables=["target", "scan_type", "document_data"],
            partial_variables={"format_instructions": self.format_instructions}
        )
        
        return prompt
    
    def _generate_markdown_report(self, parsed_output: Dict, metadata: Dict, target: str) -> str:
        """Generate a markdown report from the parsed output."""
        report_date = datetime.now().strftime("%Y-%m-%d")
        
        markdown = f"""# Security Assessment Report
## {target}

**Date:** {report_date}  
**Scan Type:** {metadata.get('scan_type', 'Security Scan')}  
**Scanner:** {metadata.get('scanner', 'Scansible')}  

## Executive Summary

{parsed_output.get('executive_summary', 'No executive summary provided.')}

## Methodology

{parsed_output.get('methodology', 'No methodology provided.')}

## Findings

### Critical Vulnerabilities

{parsed_output.get('critical_vulnerabilities', 'No critical vulnerabilities found.')}

### High Vulnerabilities

{parsed_output.get('high_vulnerabilities', 'No high vulnerabilities found.')}

### Medium Vulnerabilities

{parsed_output.get('medium_vulnerabilities', 'No medium vulnerabilities found.')}

## Risk Assessment

{parsed_output.get('risk_assessment', 'No risk assessment provided.')}

## Recommendations

{parsed_output.get('recommendations', 'No recommendations provided.')}

## Technical Appendix

{parsed_output.get('technical_appendix', 'No technical details provided.')}

---

*This report was automatically generated by Scansible using AI analysis.*
"""
        return markdown
    
    def _create_html_report(self, markdown_content: str) -> str:
        """Convert markdown content to styled HTML."""
        try:
            import markdown
            html_content = markdown.markdown(markdown_content, extensions=['tables', 'fenced_code'])
            
            styled_html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Security Assessment Report</title>
                <style>
                    body {{
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                        line-height: 1.6;
                        max-width: 1200px;
                        margin: 0 auto;
                        padding: 2em;
                        color: #333;
                    }}
                    h1, h2, h3, h4 {{
                        color: #2c3e50;
                        margin-top: 1.5em;
                    }}
                    h1 {{
                        border-bottom: 2px solid #3498db;
                        padding-bottom: 0.3em;
                        color: #2980b9;
                    }}
                    h2 {{
                        border-bottom: 1px solid #ddd;
                        padding-bottom: 0.3em;
                    }}
                    h3 {{
                        color: #c0392b;
                    }}
                    table {{
                        border-collapse: collapse;
                        width: 100%;
                        margin: 1em 0;
                        box-shadow: 0 2px 3px rgba(0,0,0,0.1);
                    }}
                    th, td {{
                        border: 1px solid #ddd;
                        padding: 12px;
                    }}
                    th {{
                        background-color: #f2f2f2;
                        text-align: left;
                        font-weight: bold;
                    }}
                    tr:nth-child(even) {{
                        background-color: #f9f9f9;
                    }}
                    tr:hover {{
                        background-color: #f5f5f5;
                    }}
                    code {{
                        background-color: #f8f8f8;
                        border-radius: 3px;
                        padding: 2px 5px;
                        font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
                    }}
                    pre {{
                        background-color: #f8f8f8;
                        border: 1px solid #ddd;
                        border-radius: 3px;
                        padding: 1em;
                        overflow-x: auto;
                    }}
                    blockquote {{
                        border-left: 4px solid #ddd;
                        padding-left: 1em;
                        color: #777;
                        margin-left: 0;
                    }}
                    @media print {{
                        body {{
                            font-size: 12pt;
                        }}
                        h1, h2, h3, h4 {{
                            page-break-after: avoid;
                        }}
                        table, figure {{
                            page-break-inside: avoid;
                        }}
                    }}
                </style>
            </head>
            <body>
                {html_content}
                <footer>
                    <p><em>Generated by Scansible on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</em></p>
                </footer>
            </body>
            </html>
            """
            
            return styled_html
        except Exception as e:
            logger.error(f"Error converting markdown to HTML: {e}")
            return f"<html><body><pre>{markdown_content}</pre></body></html>"
    
    def generate_report(self, json_path: str, target: str, scan_type: str) -> Optional[str]:
        """Generate a comprehensive security report from scan results using LangChain."""
        try:
            if not self.llm:
                logger.error("No LLM available for report generation")
                return None
            
            logger.info(f"Generating LangChain report for {target} ({scan_type})")
            
            # Extract metadata and vulnerability data
            metadata = self._extract_metadata(json_path)
            vulnerability_data = self._extract_vulnerability_summary(json_path)
            
            # Create LangChain documents
            documents = self._create_vulnerability_documents(vulnerability_data)
            
            # Check if we have any vulnerabilities to report on
            if not documents:
                logger.error("No vulnerability data found in the scan results")
                return None
            
            # Create the prompt
            report_prompt = self._create_report_prompt(target, scan_type)
            
            # Create the chain
            chain = LLMChain(llm=self.llm, prompt=report_prompt)
            
            # Combine all document content
            document_data = "\n\n".join([doc.page_content for doc in documents])
            
            # Run the chain
            logger.info("Running LangChain to generate report...")
            result = chain.run(target=target, scan_type=scan_type, document_data=document_data)
            
            # Parse the structured output
            try:
                parsed_output = self.output_parser.parse(result)
            except Exception as e:
                logger.error(f"Error parsing output: {e}")
                # Fall back to using the raw result as executive summary
                parsed_output = {
                    "executive_summary": result,
                    "methodology": f"Security scan was performed on {target} using {scan_type}.",
                    "critical_vulnerabilities": "Error parsing results.",
                    "high_vulnerabilities": "Error parsing results.",
                    "medium_vulnerabilities": "Error parsing results.",
                    "risk_assessment": "Error parsing results.",
                    "recommendations": "Error parsing results.",
                    "technical_appendix": "Error parsing results."
                }
            
            # Generate markdown report
            markdown_report = self._generate_markdown_report(parsed_output, metadata, target)
            
            # Save reports to files
            reports_dir = Path(json_path).parent
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Save markdown report
            md_filename = f"langchain_report_{timestamp}.md"
            md_path = reports_dir / md_filename
            with open(md_path, 'w') as f:
                f.write(markdown_report)
            
            # Save HTML report
            html_content = self._create_html_report(markdown_report)
            html_filename = f"langchain_report_{timestamp}.html"
            html_path = reports_dir / html_filename
            with open(html_path, 'w') as f:
                f.write(html_content)
            
            logger.info(f"Reports saved to {md_path} and {html_path}")
            
            # Return path to HTML report
            return str(html_path)
        
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return None

# Helper function to use the reporter
def generate_report(json_path: str, target: str, scan_type: str) -> Optional[str]:
    """Generate a security report using LangChain."""
    reporter = VulnerabilityReportGenerator()
    return reporter.generate_report(json_path, target, scan_type)

# For command line testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 4:
        print("Usage: python langchain_reporter.py <json_file> <target> <scan_type>")
        sys.exit(1)
    
    json_file = sys.argv[1]
    target = sys.argv[2]
    scan_type = sys.argv[3]
    
    report_path = generate_report(json_file, target, scan_type)
    if report_path:
        print(f"Report generated: {report_path}")
    else:
        print("Failed to generate report")
