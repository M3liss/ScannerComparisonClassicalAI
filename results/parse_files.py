#!/usr/bin/env python3
"""
Simple parser for SpotBugs, Semgrep (SARIF), VUSC, CodeQL, and SonarQube vulnerability outputs
with CWE normalization and error tracking
"""
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import csv
import re
from dataclasses import dataclass, field
from collections import defaultdict
import random
import os

@dataclass
class ParsingStats:
    """Track parsing statistics and errors across all tools"""
    apps_processed: int = 0
    successful_parses: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    failed_parses: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    errors: List[Dict] = field(default_factory=list)
    
    def log_success(self, tool: str, apk_type: str):
        """Log successful parse"""
        key = f"{tool}_{apk_type}"
        self.successful_parses[key] += 1
    
    def log_failure(self, tool: str, apk_type: str, error: str, app_folder: str):
        """Log failed parse with details"""
        key = f"{tool}_{apk_type}"
        self.failed_parses[key] += 1
        self.errors.append({
            'tool': tool,
            'apk_type': apk_type,
            'app': app_folder,
            'error': str(error)
        })
    
    def print_summary(self):
        """Print parsing statistics"""
        print("\n" + "="*60)
        print("PARSING STATISTICS")
        print("="*60)
        print(f"Total apps processed: {self.apps_processed}")
        print("\nSuccessful parses:")
        for key, count in sorted(self.successful_parses.items()):
            print(f"  {key}: {count}")
        print("\nFailed parses:")
        for key, count in sorted(self.failed_parses.items()):
            print(f"  {key}: {count}")
        if self.errors:
            print(f"\nTotal errors: {len(self.errors)}")
            print("\nFirst 10 errors:")
            for i, err in enumerate(self.errors[:10]):
                print(f"  {i+1}. {err['tool']}_{err['apk_type']} on {err['app']}: {err['error']}")
        print("="*60)


# Global stats object
parsing_stats = ParsingStats()

def normalize_file_path(filepath: str) -> str:
    """Return only the filename from a full path."""
    return os.path.basename(filepath)


def normalize_cwe(raw_cwe: str) -> str:
    """
    Normalize CWE identifiers to standard format: CWE-XXX
    
    Handles various input formats:
    - "CWE-79"
    - "79"
    - "CWE-79: Cross-site Scripting"
    - "cwe"
    - ""
    
    Args:
        raw_cwe: Raw CWE string from any tool
    
    Returns:
        Normalized CWE ID (e.g., "CWE-79") or empty string if not found
    """
    if not raw_cwe or not isinstance(raw_cwe, str):
        return ""
    
    # Already in correct format
    if re.match(r'^CWE-\d+$', raw_cwe):
        return raw_cwe
    
    # Extract number from various formats
    match = re.search(r'CWE[-_\s]*(\d+)', raw_cwe, re.IGNORECASE)
    if match:
        return f"CWE-{match.group(1)}"
    
    # Just a number
    match = re.match(r'^\d+$', raw_cwe)
    if match:
        return f"CWE-{raw_cwe}"
    
    return ""


def extract_cwe_from_tags(tags: List) -> str:
    """
    Extract CWE from a list of tags
    
    Args:
        tags: List of tag strings
    
    Returns:
        Normalized CWE ID or empty string
    """
    import re
    
    for tag in tags:
        if not tag:
            continue
        
        # Look for CWE-XXX pattern
        match = re.search(r'CWE-\d+', str(tag), re.IGNORECASE)
        if match:
            return match.group(0).upper()
    
    return ""

def parse_spotbugs(folder_path: str, apk_type: str) -> Tuple[List[Dict], Optional[str]]:
    """
    Parse SpotBugs XML output
    
    Args:
        folder_path: Path to app folder (e.g., "downloaded_results/a2dp.Vol")
        apk_type: Either "normal" or "obfuscated"
    
    Returns:
        Tuple of (vulnerabilities list, error message or None)
    """
    vulnerabilities = []
    spotbugs_file = Path(folder_path) / f"{apk_type}_spotbugs.xml"
    
    if not spotbugs_file.exists():
        return vulnerabilities, f"File not found: {spotbugs_file}"
    
    try:
        tree = ET.parse(spotbugs_file)
        root = tree.getroot()
        
        for bug in root.findall('.//BugInstance'):
            # Extract source line info
            source_line = bug.find('.//SourceLine')
            
            # Extract and normalize CWE
            raw_cweid = bug.get('cweid', '')
            cwe = normalize_cwe(raw_cweid)
            
            vuln = {
                'type': bug.get('type', ''),
                'priority': bug.get('priority', ''),
                'rank': bug.get('rank', ''),
                'category': bug.get('category', ''),
                'abbrev': bug.get('abbrev', ''),
                'cwe': cwe,
                'raw_cwe': raw_cweid,  # Keep original for debugging
                'short_message': bug.find('ShortMessage').text if bug.find('ShortMessage') is not None else '',
                'long_message': bug.find('LongMessage').text if bug.find('LongMessage') is not None else '',
                'source_file': normalize_file_path(source_line.get('sourcepath', '')) if source_line is not None else '',
                'start_line': source_line.get('start', '') if source_line is not None else '',
                'end_line': source_line.get('end', '') if source_line is not None else '',
            }
            vulnerabilities.append(vuln)
        
        parsing_stats.log_success('spotbugs', apk_type)
        return vulnerabilities, None
            
    except Exception as e:
        error_msg = f"Error parsing SpotBugs file {spotbugs_file}: {e}"
        parsing_stats.log_failure('spotbugs', apk_type, error_msg, folder_path)
        return vulnerabilities, error_msg


def parse_semgrep(folder_path: str, apk_type: str) -> Tuple[List[Dict], Optional[str]]:
    """
    Parse Semgrep SARIF output - parses ALL results
    
    Args:
        folder_path: Path to app folder
        apk_type: Either "normal" or "obfuscated"
    
    Returns:
        Tuple of (vulnerabilities list, error message or None)
    """
    vulnerabilities = []
    semgrep_file = Path(folder_path) / f"semgrep.sarif"
    
    if not semgrep_file.exists():
        return vulnerabilities, f"File not found: {semgrep_file}"
    
    try:
        with open(semgrep_file) as f:
            data = json.load(f)
        
        # Parse ALL runs
        for run in data.get('runs', []):
            # Get rules for reference
            rules = {}
            for rule in run.get('tool', {}).get('driver', {}).get('rules', []):
                rules[rule['id']] = rule
            
            # Parse ALL results in this run
            for result in run.get('results', []):
                rule_id = result.get('ruleId', '')
                rule_info = rules.get(rule_id, {})
                
                # Get ALL locations (some findings have multiple locations)
                for location in result.get('locations', []):
                    physical_loc = location.get('physicalLocation', {})
                    artifact = physical_loc.get('artifactLocation', {})
                    region = physical_loc.get('region', {})
                    
                    # Extract CWE from properties/tags
                    tags = rule_info.get('properties', {}).get('tags', [])
                    cwe = extract_cwe_from_tags(tags)
                    
                    vuln = {
                        'rule_id': rule_id,
                        'level': result.get('level', 'warning'),
                        'message': result.get('message', {}).get('text', ''),
                        'file': normalize_file_path(artifact.get('uri', '')),
                        'start_line': region.get('startLine', ''),
                        'end_line': region.get('endLine', ''),
                        'start_column': region.get('startColumn', ''),
                        'end_column': region.get('endColumn', ''),
                        'cwe': cwe,
                        'raw_tags': tags,  # Keep original for debugging
                        'category': rule_info.get('properties', {}).get('category', ''),
                        'full_description': rule_info.get('fullDescription', {}).get('text', ''),
                        'snippet': region.get('snippet', {}).get('text', ''),
                    }
                    vulnerabilities.append(vuln)
        
        parsing_stats.log_success('semgrep', apk_type)
        return vulnerabilities, None
                
    except Exception as e:
        error_msg = f"Error parsing Semgrep file {semgrep_file}: {e}"
        parsing_stats.log_failure('semgrep', apk_type, error_msg, folder_path)
        return vulnerabilities, error_msg


def parse_vusc(folder_path: str, apk_type: str) -> Tuple[List[Dict], Optional[str]]:
    """
    Parse VUSC JSON output (extracts only vulnerability findings with CWE mapping)
    Args:
        folder_path: Path to app folder
        apk_type: Either "normal" or "obfuscated"
    Returns:
        Tuple of (vulnerabilities list, error message or None)
    """
    vulnerabilities = []
    vusc_file = Path(folder_path) / f"vusc_{apk_type}.json"
    
    if not vusc_file.exists():
        return vulnerabilities, f"File not found: {vusc_file}"
    
    try:
        data = None
        with open(str(vusc_file), 'r') as f:
            data = json.load(f)
        
        # VUSC structure: jobResults -> vulnerabilityFindings
        job_results = data.get('jobResults', {})
        findings = job_results.get('vulnerabilityFindings', [])
        
        for finding in findings:
            # Extract location information
            location = finding.get('location', {})
            file_path = location.get('filePath', '')
            
            # For code locations, get additional details
            if location.get('type') == 'CodeLocation':
                class_name = location.get('className', '')
                member_name = location.get('memberName', '')
                statement = location.get('statement', '')
            else:
                class_name = ''
                member_name = ''
                statement = ''
            
            # Extract CWE from references (NEW - the proper way)
            cwe = extract_cwe_from_vusc_references(finding.get('references', []))
            
            # Fallback: try to extract from description/title if no CWE in references
            if not cwe:
                description = finding.get('description', '')
                title = finding.get('title', '')
                cwe = extract_cwe_from_tags([description, title])
            
            vuln = {
                'finding_id': finding.get('id', ''),
                'type': finding.get('type', ''),
                'severity': finding.get('severity', ''),
                'category': finding.get('category', ''),
                'title': finding.get('title', '').strip(),
                'description': finding.get('description', ''),
                'mitigation': finding.get('mitigiation', ''),  # Note: typo in VUSC output
                'file': normalize_file_path(file_path),
                'class_name': class_name,
                'member_name': member_name,
                'statement': statement,
                'location_type': location.get('type', ''),
                'char_start': location.get('characterStart', ''),
                'char_length': location.get('characterLength', ''),
                'cwe': cwe,
            }
            
            vulnerabilities.append(vuln)
        
        # Clear data to free memory
        del data
        parsing_stats.log_success('vusc', apk_type)
        return vulnerabilities, None
        
    except Exception as e:
        error_msg = f"Error parsing VUSC file {vusc_file}: {e}"
        parsing_stats.log_failure('vusc', apk_type, error_msg, folder_path)
        return vulnerabilities, error_msg


def extract_cwe_from_vusc_references(references: List[Dict]) -> str:
    """
    Extract CWE ID from VUSC's references array.
    
    VUSC format example:
    "references": [
        {
            "shortDescription": "MITRE CWE-674*",
            "type": "CatalogReference",
            "referenceGroup": {"name": "CWE", ...},
            "url": "https://cwe.mitre.org/data/definitions/674.html",
            "id": "CWE-674"
        }
    ]
    
    Args:
        references: List of reference dictionaries from VUSC finding
    
    Returns:
        CWE ID string (e.g., "CWE-674") or empty string if not found
    """
    if not references:
        return ""
    
    for ref in references:
        # Check if this is a CWE reference
        ref_group = ref.get('referenceGroup', {})
        if ref_group.get('name') == 'CWE':
            # Try to get ID from the 'id' field first
            cwe_id = ref.get('id', '')
            if cwe_id and cwe_id.startswith('CWE-'):
                return cwe_id
            
            # Fallback: extract from shortDescription
            short_desc = ref.get('shortDescription', '')
            if 'CWE-' in short_desc:
                # Extract "CWE-XXX" pattern
                import re
                match = re.search(r'CWE-\d+', short_desc)
                if match:
                    return match.group(0)
            
            # Fallback: extract from URL
            url = ref.get('url', '')
            if 'cwe.mitre.org' in url:
                import re
                match = re.search(r'/(\d+)\.html', url)
                if match:
                    return f"CWE-{match.group(1)}"
    
    return ""


def extract_cwe_from_tags(tags: List[str]) -> str:
    """
    Extract CWE ID from text (fallback method).
    Searches for patterns like "CWE-XXX" in descriptions/titles.
    
    Args:
        tags: List of strings to search (descriptions, titles, etc.)
    
    Returns:
        CWE ID string or empty string if not found
    """
    import re
    
    for tag in tags:
        if not tag:
            continue
        
        # Look for CWE-XXX pattern
        match = re.search(r'CWE-\d+', str(tag), re.IGNORECASE)
        if match:
            return match.group(0).upper()
    
    return ""


def parse_codeql(folder_path: str, apk_type: str) -> Tuple[List[Dict], Optional[str]]:
    """
    Parse CodeQL CSV output
    
    CodeQL can output in CSV format with columns:
    name, description, severity, message, path, start_line, start_column, end_line, end_column
    
    Args:
        folder_path: Path to app folder
        apk_type: Either "normal" or "obfuscated"
    
    Returns:
        Tuple of (vulnerabilities list, error message or None)
    """
    vulnerabilities = []
    
    # Try CSV format first (most common)
    codeql_file = Path(folder_path) / f"codeql_{apk_type}.csv"
    if not codeql_file.exists():
        codeql_file = Path(folder_path) / f"{apk_type}_codeql.csv"
    
    # If CSV doesn't exist, try SARIF
    if not codeql_file.exists():
        codeql_file = Path(folder_path) / f"codeql_{apk_type}.sarif"
        if not codeql_file.exists():
            codeql_file = Path(folder_path) / f"{apk_type}_codeql.sarif"
            if not codeql_file.exists():
                return vulnerabilities, f"File not found: {codeql_file}"
        
        # Parse SARIF format
        return _parse_codeql_sarif(codeql_file, apk_type, folder_path)
    
    # Parse CSV format
    try:
        with open(codeql_file, newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            
            for row in reader:
                if len(row) < 5:  # Minimum required fields
                    continue
                
                # Extract CWE from name, description, or message
                rule_name = row[0].strip() if len(row) > 0 else ''
                description = row[1].strip() if len(row) > 1 else ''
                message = row[3].strip() if len(row) > 3 else ''
                
                cwe = extract_cwe_from_tags([rule_name, description, message])
                
                # CSV format: name, description, severity, message, path, start_line, start_column, end_line, end_column
                vuln = {
                    'rule_name': rule_name,
                    'description': description,
                    'severity': row[2].strip() if len(row) > 2 else '',
                    'message': message,
                    'file': normalize_file_path(row[4].strip()) if len(row) > 4 else '',
                    'start_line': row[5].strip() if len(row) > 5 else '',
                    'start_column': row[6].strip() if len(row) > 6 else '',
                    'end_line': row[7].strip() if len(row) > 7 else '',
                    'end_column': row[8].strip() if len(row) > 8 else '',
                    'cwe': cwe,
                }
                vulnerabilities.append(vuln)
        
        parsing_stats.log_success('codeql', apk_type)
        return vulnerabilities, None
                
    except Exception as e:
        error_msg = f"Error parsing CodeQL file {codeql_file}: {e}"
        parsing_stats.log_failure('codeql', apk_type, error_msg, folder_path)
        return vulnerabilities, error_msg


def _parse_codeql_sarif(codeql_file: Path, apk_type: str, folder_path: str) -> Tuple[List[Dict], Optional[str]]:
    """
    Helper function to parse CodeQL SARIF format
    """
    vulnerabilities = []
    
    try:
        with open(codeql_file) as f:
            data = json.load(f)
        
        # Parse all runs
        for run in data.get('runs', []):
            # Get rules for reference
            rules = {}
            for rule in run.get('tool', {}).get('driver', {}).get('rules', []):
                rules[rule['id']] = rule
            
            # Parse all results
            for result in run.get('results', []):
                rule_id = result.get('ruleId', '')
                rule_info = rules.get(rule_id, {})
                
                # CodeQL uses 'kind' instead of 'level' sometimes
                level = result.get('level', result.get('kind', 'warning'))
                
                # Get all locations
                for location in result.get('locations', []):
                    physical_loc = location.get('physicalLocation', {})
                    artifact = physical_loc.get('artifactLocation', {})
                    region = physical_loc.get('region', {})
                    
                    # Extract CWE from properties
                    properties = rule_info.get('properties', {})
                    tags = properties.get('tags', [])
                    cwe = extract_cwe_from_tags(tags)
                    
                    # CodeQL also has security-severity
                    security_severity = properties.get('security-severity', '')
                    precision = properties.get('precision', '')
                    
                    vuln = {
                        'rule_id': rule_id,
                        'level': level,
                        'message': result.get('message', {}).get('text', ''),
                        'file': normalize_file_path(artifact.get('uri', '')),
                        'start_line': region.get('startLine', ''),
                        'end_line': region.get('endLine', ''),
                        'start_column': region.get('startColumn', ''),
                        'end_column': region.get('endColumn', ''),
                        'cwe': cwe,
                        'security_severity': security_severity,
                        'precision': precision,
                        'category': properties.get('problem.severity', ''),
                        'full_description': rule_info.get('fullDescription', {}).get('text', ''),
                        'short_description': rule_info.get('shortDescription', {}).get('text', ''),
                        'snippet': region.get('snippet', {}).get('text', ''),
                    }
                    vulnerabilities.append(vuln)
        
        parsing_stats.log_success('codeql', apk_type)
        return vulnerabilities, None
                
    except Exception as e:
        error_msg = f"Error parsing CodeQL SARIF file {codeql_file}: {e}"
        parsing_stats.log_failure('codeql', apk_type, error_msg, folder_path)
        return vulnerabilities, error_msg


def parse_sonarqube(folder_path: str, apk_type: str) -> Tuple[List[Dict], Optional[str]]:
    """
    Parse SonarQube JSON output
    SonarQube can output in multiple formats. This handles the JSON format
    from sonar-scanner with -Dsonar.report.export.path
    
    Args:
        folder_path: Path to app folder
        apk_type: Either "normal" or "obfuscated"
    
    Returns:
        Tuple of (vulnerabilities list, error message or None)
    """
    vulnerabilities = []
    
    # Try different possible SonarQube output formats
    possible_files = [
        Path(folder_path) / f"sonarqube_{apk_type}.json",
        Path(folder_path) / f"{apk_type}_sonarqube.json",
        Path(folder_path) / f"sonar_{apk_type}.json",
        Path(folder_path) / f"{apk_type}_sonar-report.json",
    ]
    
    sonar_file = None
    for file_path in possible_files:
        if file_path.exists():
            sonar_file = file_path
            break
    
    if sonar_file is None:
        return vulnerabilities, f"File not found: {possible_files[0]}"
    
    try:
        with open(sonar_file) as f:
            data = json.load(f)
        
        # SonarQube JSON structure can vary, common structure:
        # {"issues": [...]} or {"hotspots": [...]} or top-level array
        issues = []
        if isinstance(data, list):
            issues = data
        elif 'issues' in data:
            issues = data['issues']
        elif 'components' in data and 'issues' in data:
            # SonarQube scanner format
            issues = data['issues']
        
        for issue in issues:
            # Extract text range information
            text_range = issue.get('textRange', {})
            flows = issue.get('flows', [])
            
            # Extract component (file path)
            component = issue.get('component', '')
            # Remove project key prefix if present
            file_path = component.split(':')[-1] if ':' in component else component
            
            # Get rule information
            rule = issue.get('rule', '')
            
            # Extract CWE from multiple sources (NEW - comprehensive extraction)
            cwe = extract_cwe_from_sonarqube_issue(issue)
            
            # Normalize severity (SonarQube uses different severity levels)
            severity = normalize_sonarqube_severity(issue)
            
            vuln = {
                'rule': rule,
                'severity': severity['original'],  # Original SonarQube severity
                'normalized_severity': severity['normalized'],  # Standardized severity
                'type': issue.get('type', ''),  # BUG, VULNERABILITY, CODE_SMELL, SECURITY_HOTSPOT
                'status': issue.get('status', ''),
                'message': issue.get('message', ''),
                'file': normalize_file_path(file_path),
                'start_line': text_range.get('startLine', ''),
                'end_line': text_range.get('endLine', ''),
                'start_offset': text_range.get('startOffset', ''),
                'end_offset': text_range.get('endOffset', ''),
                'effort': issue.get('effort', ''),  # Time to fix
                'debt': issue.get('debt', ''),
                'tags': issue.get('tags', []),
                'cwe': cwe,
                'creation_date': issue.get('creationDate', ''),
                'update_date': issue.get('updateDate', ''),
                # NEW: SonarQube Clean Code attributes
                'clean_code_attribute': issue.get('cleanCodeAttribute', ''),
                'clean_code_category': issue.get('cleanCodeAttributeCategory', ''),
                # NEW: SonarQube impacts (newer format)
                'impacts': issue.get('impacts', []),
            }
            
            # Add flow information if present (for taint analysis)
            if flows:
                vuln['flows'] = flows
            
            vulnerabilities.append(vuln)
        
        parsing_stats.log_success('sonarqube', apk_type)
        return vulnerabilities, None
        
    except Exception as e:
        error_msg = f"Error parsing SonarQube file {sonar_file}: {e}"
        parsing_stats.log_failure('sonarqube', apk_type, error_msg, folder_path)
        return vulnerabilities, error_msg


def extract_cwe_from_sonarqube_issue(issue: Dict) -> str:
    """
    Extract CWE from SonarQube issue using multiple strategies.
    
    SonarQube stores CWE information in:
    1. tags array (e.g., ["cwe", "android"])
    2. rule ID (sometimes includes CWE)
    3. message text
    4. Rule metadata (if available)
    
    Args:
        issue: SonarQube issue dictionary
    
    Returns:
        CWE ID string (e.g., "CWE-79") or empty string
    """
    import re
    
    # Strategy 1: Check if "cwe" tag exists and extract from rule mapping
    tags = issue.get('tags', [])
    rule = issue.get('rule', '')
    
    if 'cwe' in tags:
        # SonarQube rules have known CWE mappings
        cwe = map_sonarqube_rule_to_cwe(rule)
        if cwe:
            return cwe
    
    # Strategy 2: Extract from rule ID directly
    # Some rules encode CWE: e.g., "squid:S2076" maps to CWE-78
    if rule:
        cwe = map_sonarqube_rule_to_cwe(rule)
        if cwe:
            return cwe
    
    # Strategy 3: Search in message text
    message = issue.get('message', '')
    match = re.search(r'CWE-\d+', message, re.IGNORECASE)
    if match:
        return match.group(0).upper()
    
    # Strategy 4: Extract from tags array (sometimes includes CWE-XXX)
    for tag in tags:
        match = re.search(r'CWE-\d+', str(tag), re.IGNORECASE)
        if match:
            return match.group(0).upper()
    
    return ""


def map_sonarqube_rule_to_cwe(rule_id: str) -> str:
    """
    Map SonarQube rule IDs to CWE IDs.
    
    Based on SonarQube's official CWE mappings:
    https://rules.sonarsource.com/
    
    Args:
        rule_id: SonarQube rule identifier (e.g., "java:S2076", "xml:S7207")
    
    Returns:
        CWE ID string or empty string
    """
    # Common SonarQube rule to CWE mappings
    # This is a subset - add more as you discover them
    SONARQUBE_CWE_MAP = {
        # Java rules
        'java:S2076': 'CWE-78',   # OS Command Injection
        'java:S2078': 'CWE-78',   # LDAP Injection
        'java:S2091': 'CWE-643',  # XPath Injection
        'java:S2631': 'CWE-36',   # Path Traversal
        'java:S3649': 'CWE-89',   # SQL Injection
        'java:S2068': 'CWE-798',  # Hard-coded credentials
        'java:S2070': 'CWE-328',  # Weak hash
        'java:S4790': 'CWE-327',  # Weak cryptography
        'java:S5131': 'CWE-79',   # XSS
        'java:S5144': 'CWE-352',  # CSRF
        'java:S2755': 'CWE-611',  # XXE
        'java:S5042': 'CWE-502',  # Deserialization
        'java:S1313': 'CWE-798',  # Hard-coded IP
        'java:S2245': 'CWE-330',  # Weak random
        'java:S5659': 'CWE-295',  # Certificate validation
        'java:S4784': 'CWE-330',  # Regex DoS
        'java:S2053': 'CWE-327',  # Password hashing
        'java:S120': 'CWE-1099',  # Naming convention (informational)
        
        # XML/Android rules
        'xml:S7207': 'CWE-927',   # Implicit Intent (Android component not exported)
        'xml:S6363': 'CWE-925',   # Improper Intent (Android)
        'xml:S6364': 'CWE-925',   # Exported component
        'xml:S125': 'CWE-546',    # Commented-out code (not really CWE, informational)
        
        # Web rules
        'Web:DoubleQuotesInPathRule': 'CWE-22',
        'Web:IllegalAttributeCheck': 'CWE-79',
        
        # Add more as you encounter them in your dataset
    }
    
    # Direct lookup
    if rule_id in SONARQUBE_CWE_MAP:
        return SONARQUBE_CWE_MAP[rule_id]
    
    # Try without language prefix
    if ':' in rule_id:
        short_rule = rule_id.split(':')[1]
        full_rule_variations = [
            f'java:{short_rule}',
            f'xml:{short_rule}',
            f'kotlin:{short_rule}',
        ]
        for variation in full_rule_variations:
            if variation in SONARQUBE_CWE_MAP:
                return SONARQUBE_CWE_MAP[variation]
    
    return ""


def normalize_sonarqube_severity(issue: Dict) -> Dict[str, str]:
    """
    Normalize SonarQube severity to standard levels.
    
    SonarQube uses: BLOCKER, CRITICAL, MAJOR, MINOR, INFO
    We normalize to: CRITICAL, HIGH, MEDIUM, LOW, INFO
    
    Also considers the new "impacts" field (SonarQube 10+)
    
    Args:
        issue: SonarQube issue dictionary
    
    Returns:
        Dict with 'original' and 'normalized' severity
    """
    original_severity = issue.get('severity', 'UNKNOWN')
    
    # Check new impacts field (SonarQube 10.0+)
    impacts = issue.get('impacts', [])
    if impacts:
        # Get the highest impact severity
        impact_severities = [impact.get('severity', 'LOW') for impact in impacts 
                            if impact.get('softwareQuality') == 'SECURITY']
        if impact_severities:
            # Use impact severity if available
            impact_severity = max(impact_severities, 
                                key=lambda x: ['LOW', 'MEDIUM', 'HIGH'].index(x) if x in ['LOW', 'MEDIUM', 'HIGH'] else 0)
            
            # Map impact severity
            impact_map = {
                'HIGH': 'CRITICAL',
                'MEDIUM': 'HIGH',
                'LOW': 'MEDIUM'
            }
            normalized = impact_map.get(impact_severity, 'MEDIUM')
            return {'original': original_severity, 'normalized': normalized}
    
    # Traditional severity mapping
    severity_map = {
        'BLOCKER': 'CRITICAL',
        'CRITICAL': 'CRITICAL',
        'MAJOR': 'HIGH',
        'MINOR': 'MEDIUM',
        'INFO': 'LOW',
        'UNKNOWN': 'UNKNOWN'
    }
    
    normalized = severity_map.get(original_severity.upper(), 'UNKNOWN')
    return {'original': original_severity, 'normalized': normalized}


def general_metrics(app_folder: str) -> Dict[str, Dict[str, Optional[float]]]:
    """
    Gather general metrics (memory, time, size) per tool for normal and obfuscated APKs.
    Only considers the row matching the app_name inferred from the folder name.
    
    Args:
        app_folder: Path to app folder (e.g., "downloaded_results/a2dp.Vol")
    
    Returns:
        Dictionary structured as:
        {
            "function_number": None,
            "lines_of_code": None,
            "semgrep": {
                "normal": {"memory": None, "time": None},
                "obfuscated": {"memory": None, "time": None}
            },
            ...
        }
    """
    tools = ["semgrep", "vusc", "sonarqube", "codeql", "spotbugs"]
    apk_types = ["normal", "obfuscated"]
    
    # Extract app_name from folder path
    app_name = Path(app_folder).name
    
    # Initialize metrics dict
    metrics: Dict[str, Dict] = {
        "function_number": None,
        "lines_of_code": None
    }
    
    for tool in tools:
        metrics[tool] = {atype: {"memory": None, "time": None} for atype in apk_types}
    
    # Loop over each tool and APK type
    for tool in tools:
        for atype in apk_types:
            csv_file = Path(f"resources_{tool}_{atype}.csv")
            
            if csv_file.exists():
                try:
                    with open(csv_file, newline='') as f:
                        reader = csv.reader(f)
                        header = next(reader, None)  # Read header if exists
                        
                        for row in reader:
                            if not row or not row[0].strip():
                                continue
                            
                            # Check if the row corresponds to the current app
                            if row[0].strip() != app_name:
                                continue
                            
                            # Parse based on tool-specific format
                            if tool == "semgrep":
                                # Format: app_id, time, memory, return_code, lines_of_code, num_of_files
                                if len(row) >= 5:
                                    metrics[tool][atype]["time"] = float(row[1])
                                    metrics[tool][atype]["memory"] = float(row[2])
                                    # Get lines_of_code from normal APK only (avoid duplication)
                                    if atype == "normal" and metrics["lines_of_code"] is None:
                                        metrics["lines_of_code"] = int(row[4])
                            
                            elif tool == "vusc":
                                # Format: app_id, time, memory
                                if len(row) >= 3:
                                    metrics[tool][atype]["time"] = float(row[1])
                                    metrics[tool][atype]["memory"] = float(row[2])
                            
                            elif tool == "sonarqube":
                                # Format: app_id, elapsed_sec, rss_mb
                                if len(row) >= 3:
                                    metrics[tool][atype]["time"] = float(row[1])
                                    metrics[tool][atype]["memory"] = float(row[2])
                            
                            elif tool == "codeql":
                                # Format: app_id, time, memory
                                if len(row) >= 3:
                                    metrics[tool][atype]["time"] = float(row[1])
                                    metrics[tool][atype]["memory"] = float(row[2])
                            
                            elif tool == "spotbugs":
                                # Format: App, BuildTime, BuildMemory, SpotBugsTimeSec, SpotBugsMemoryMB
                                if len(row) >= 5:
                                    metrics[tool][atype]["time"] = float(row[3])
                                    metrics[tool][atype]["memory"] = float(row[4])
                            
                            break  # Found our app, stop reading CSV
                            
                except Exception as e:
                    print(f"Error reading {csv_file}: {e}")
    
    return metrics

def parse_all_tools(folder_path: str, apk_type: str) -> Dict:
    """
    Parse all five tools for a given app and APK type
    
    Args:
        folder_path: Path to app folder
        apk_type: Either "normal" or "obfuscated"
    
    Returns:
        Dictionary with tool names as keys and vulnerability lists as values,
        plus parsing errors and metadata
    """
    results = {
        'vulnerabilities': {},
        'errors': {},
        'metadata': {
            'app_folder': folder_path,
            'apk_type': apk_type,
            'app_name': Path(folder_path).name
        }
    }
    
    # Parse each tool
    tools = {
        'spotbugs': parse_spotbugs,
        'semgrep': parse_semgrep,
        'vusc': parse_vusc,
        'codeql': parse_codeql,
        'sonarqube': parse_sonarqube,
    }
    
    for tool_name, parser_func in tools.items():
        vulns, error = parser_func(folder_path, apk_type)
        results['vulnerabilities'][tool_name] = vulns
        if error:
            results['errors'][tool_name] = error
    
    # Add general metrics
    results['general_metrics'] = general_metrics(folder_path)
    
    return results


# Example usage
if __name__ == "__main__":
    # Test with one app
    app_folder = "downloaded_results/a2dp.Vol"
    
    parsing_stats.apps_processed = 1
    
    print("=== Parsing Normal APK ===")
    normal_results = parse_all_tools(app_folder, "normal")
    for tool, vulns in normal_results['vulnerabilities'].items():
        print(f"{tool}: {len(vulns)} vulnerabilities found")
    
    if normal_results['errors']:
        print("\nErrors encountered:")
        for tool, error in normal_results['errors'].items():
            print(f"  {tool}: {error}")
    
    print("\n=== Parsing Obfuscated APK ===")
    obf_results = parse_all_tools(app_folder, "obfuscated")
    for tool, vulns in obf_results['vulnerabilities'].items():
        print(f"{tool}: {len(vulns)} vulnerabilities found")
    
    if obf_results['errors']:
        print("\nErrors encountered:")
        for tool, error in obf_results['errors'].items():
            print(f"  {tool}: {error}")
    
    # Print first vulnerability from each tool as example
    print("\n=== Example Vulnerabilities (with CWE normalization) ===")
    print("\nGeneral Metrics:")
    print(json.dumps(obf_results["general_metrics"], indent=2))
    
    for tool in ['spotbugs', 'semgrep', 'vusc', 'codeql', 'sonarqube']:
        vulns = normal_results['vulnerabilities'][tool]
        if vulns:
            print(f"\n{tool.upper()} example:")
            print(json.dumps(vulns[0], indent=2))
    
    # Print parsing statistics
    parsing_stats.print_summary()
