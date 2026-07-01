#!/usr/bin/env python3
"""
Comprehensive SAST Tool Analysis for Research Questions
Analyzes a single app across all dimensions for publication-quality insights
"""
import json
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Set, Tuple, Optional
import statistics
from dataclasses import dataclass, field
from parse_files import parse_all_tools, parsing_stats


@dataclass
class ToolMetrics:
    """Metrics for a single tool on one app"""
    total_findings: int = 0
    unique_files: int = 0
    unique_cwes: Set[str] = field(default_factory=set)
    severity_distribution: Dict[str, int] = field(default_factory=dict)
    category_distribution: Dict[str, int] = field(default_factory=dict)
    time_sec: Optional[float] = None
    memory_mb: Optional[float] = None
    findings_per_file: float = 0.0
    cwe_diversity: float = 0.0  # Shannon entropy or simple ratio


class ComprehensiveSASTAnalyzer:
    """
    Single-app analyzer covering all 7 research questions
    Designed for easy aggregation across 700 apps
    """
    
    def __init__(self, app_folder: str, app_name: str = None):
        self.app_folder = Path(app_folder)
        self.app_name = app_name or self.app_folder.name
        
        print(f"\n{'='*80}")
        print(f"Loading data for: {self.app_name}")
        print(f"{'='*80}")
        
        # Parse vulnerabilities
        self.normal_data = parse_all_tools(str(app_folder), "normal")
        self.obf_data = parse_all_tools(str(app_folder), "obfuscated")
        
        # Extract vulnerability lists
        self.normal = self.normal_data['vulnerabilities']
        self.obfuscated = self.obf_data['vulnerabilities']
        
        # Get general metrics (performance data)
        self.general_metrics = self.normal_data.get('general_metrics', {})
        
        # Tools to analyze
        self.tools = ['spotbugs', 'semgrep', 'vusc', 'codeql', 'sonarqube']
        
        # Results storage
        self.results = {
            'app_name': self.app_name,
            'app_folder': str(app_folder),
            'metadata': {}
        }
        
        print(f"✓ Loaded {sum(len(v) for v in self.normal.values())} normal findings")
        print(f"✓ Loaded {sum(len(v) for v in self.obfuscated.values())} obfuscated findings")
    
    def _normalize_file_path(self, filepath: str) -> str:
        """
        Normalize file paths to a consistent format for comparison
        
        Handles various formats from different tools:
        - "a2dp/Vol/service.java" (SpotBugs)
        - "main/java/a2dp/Vol/service.java" (SonarQube)
        - "fdroid_apps/a2dp.Vol/app/src/main/AndroidManifest.xml" (Semgrep)
        - "/src/main/AndroidManifest.xml" (CodeQL)
        """
        if not filepath:
            return ""
        
        # Remove leading/trailing whitespace and slashes
        filepath = filepath.strip().strip('/')
        
        # Common prefixes to remove
        prefixes_to_remove = [
            'fdroid_apps/',
            f'{self.app_name}/',
            'app/src/',
            'src/',
            'main/java/',
            'main/',
        ]
        
        # Remove prefixes iteratively
        for prefix in prefixes_to_remove:
            if filepath.startswith(prefix):
                filepath = filepath[len(prefix):]
        
        # Handle leading slashes after prefix removal
        filepath = filepath.lstrip('/')
        
        # Normalize path separators (in case of mixed \ and /)
        filepath = filepath.replace('\\', '/')
        
        return filepath
    
    # =========================================================================
    # RQ1: Scanner Effectiveness (Similarity, Performance, CWE Coverage)
    # =========================================================================
    
    def rq1_scanner_effectiveness(self):
        """
        RQ1: Evaluate scanner effectiveness through:
        - Detection counts per tool
        - Result similarity (file overlap, finding overlap)
        - Performance metrics (speed, memory)
        - CWE coverage per tool
        """
        print("\n" + "="*80)
        print("RQ1: SCANNER EFFECTIVENESS ANALYSIS")
        print("="*80)
        
        results = {
            'detection_counts': {},
            'result_similarity': {},
            'performance_metrics': {},
            'cwe_coverage': {},
            'tool_specialization': {}
        }
        
        for apk_type in ['normal', 'obfuscated']:
            data = self.normal if apk_type == 'normal' else self.obfuscated
            
            # === Detection Counts ===
            counts = {}
            for tool in self.tools:
                counts[tool] = len(data.get(tool, []))
            results['detection_counts'][apk_type] = counts
            
            # === Result Similarity ===
            # File-level overlap (with path normalization)
            tool_files = {}
            for tool in self.tools:
                files = set()
                for v in data.get(tool, []):
                    f = v.get('file') or v.get('source_file', '')
                    if f:
                        normalized = self._normalize_file_path(f)
                        if normalized:
                            files.add(normalized)
                tool_files[tool] = files
            
            # Pairwise Jaccard similarity for files
            file_similarity = {}
            for i, tool1 in enumerate(self.tools):
                for tool2 in self.tools[i+1:]:
                    intersection = len(tool_files[tool1] & tool_files[tool2])
                    union = len(tool_files[tool1] | tool_files[tool2])
                    jaccard = intersection / union if union > 0 else 0
                    file_similarity[f"{tool1}_vs_{tool2}"] = {
                        'jaccard': round(jaccard, 3),
                        'intersection': intersection,
                        'union': union
                    }
            
            # === NEW: Vulnerability-level overlap (same file + same line) ===
            tool_vuln_locations = {}
            for tool in self.tools:
                locations = set()
                for v in data.get(tool, []):
                    f = v.get('file') or v.get('source_file', '')
                    line = v.get('start_line') or v.get('line', '')
                    if f and line:
                        normalized_f = self._normalize_file_path(f)
                        if normalized_f:
                            # Create signature: file:line
                            locations.add(f"{normalized_f}::{line}")
                tool_vuln_locations[tool] = locations
            
            vuln_location_similarity = {}
            for i, tool1 in enumerate(self.tools):
                for tool2 in self.tools[i+1:]:
                    intersection = len(tool_vuln_locations[tool1] & tool_vuln_locations[tool2])
                    union = len(tool_vuln_locations[tool1] | tool_vuln_locations[tool2])
                    jaccard = intersection / union if union > 0 else 0
                    vuln_location_similarity[f"{tool1}_vs_{tool2}"] = {
                        'jaccard': round(jaccard, 3),
                        'intersection': intersection,
                        'union': union,
                        'exact_matches': intersection
                    }
            
            # === NEW: Semantic overlap (same file + same vulnerability type) ===
            tool_vuln_semantics = {}
            for tool in self.tools:
                semantics = set()
                for v in data.get(tool, []):
                    f = v.get('file') or v.get('source_file', '')
                    vtype = v.get('type') or v.get('rule_id') or v.get('rule', '')
                    if f and vtype:
                        normalized_f = self._normalize_file_path(f)
                        if normalized_f:
                            # Create signature: file::type
                            semantics.add(f"{normalized_f}::{vtype}")
                tool_vuln_semantics[tool] = semantics
            
            semantic_similarity = {}
            for i, tool1 in enumerate(self.tools):
                for tool2 in self.tools[i+1:]:
                    intersection = len(tool_vuln_semantics[tool1] & tool_vuln_semantics[tool2])
                    union = len(tool_vuln_semantics[tool1] | tool_vuln_semantics[tool2])
                    jaccard = intersection / union if union > 0 else 0
                    semantic_similarity[f"{tool1}_vs_{tool2}"] = {
                        'jaccard': round(jaccard, 3),
                        'intersection': intersection,
                        'union': union
                    }
            
            # === NEW: CWE-level overlap (same file + same CWE) ===
            tool_vuln_cwes = {}
            for tool in self.tools:
                cwe_locs = set()
                for v in data.get(tool, []):
                    f = v.get('file') or v.get('source_file', '')
                    cwe = v.get('cwe') or v.get('cweid', '')
                    if f and cwe:
                        normalized_f = self._normalize_file_path(f)
                        if normalized_f:
                            # Create signature: file::cwe
                            cwe_locs.add(f"{normalized_f}::{cwe}")
                tool_vuln_cwes[tool] = cwe_locs
            
            cwe_location_similarity = {}
            for i, tool1 in enumerate(self.tools):
                for tool2 in self.tools[i+1:]:
                    intersection = len(tool_vuln_cwes[tool1] & tool_vuln_cwes[tool2])
                    union = len(tool_vuln_cwes[tool1] | tool_vuln_cwes[tool2])
                    jaccard = intersection / union if union > 0 else 0
                    cwe_location_similarity[f"{tool1}_vs_{tool2}"] = {
                        'jaccard': round(jaccard, 3),
                        'intersection': intersection,
                        'union': union
                    }
            
            # Finding-level overlap (by type/rule) - keep this for rule comparison
            tool_finding_types = {}
            for tool in self.tools:
                types = set()
                for v in data.get(tool, []):
                    ftype = v.get('type') or v.get('rule_id') or v.get('rule', '')
                    if ftype:
                        types.add(ftype)
                tool_finding_types[tool] = types
            
            type_similarity = {}
            for i, tool1 in enumerate(self.tools):
                for tool2 in self.tools[i+1:]:
                    intersection = len(tool_finding_types[tool1] & tool_finding_types[tool2])
                    union = len(tool_finding_types[tool1] | tool_finding_types[tool2])
                    jaccard = intersection / union if union > 0 else 0
                    type_similarity[f"{tool1}_vs_{tool2}"] = {
                        'jaccard': round(jaccard, 3),
                        'intersection': intersection,
                        'union': union
                    }
            
            # Multi-tool agreement on exact vulnerabilities
            all_vuln_locations = set().union(*tool_vuln_locations.values())
            vulns_by_tool_count = Counter()
            for loc in all_vuln_locations:
                count = sum(1 for tool_locs in tool_vuln_locations.values() if loc in tool_locs)
                vulns_by_tool_count[count] += 1
            
            results['result_similarity'][apk_type] = {
                'file_overlap': file_similarity,
                'vulnerability_location_overlap': vuln_location_similarity,
                'semantic_overlap': semantic_similarity,
                'cwe_location_overlap': cwe_location_similarity,
                'finding_type_overlap': type_similarity,
                'multi_tool_agreement_files': dict(Counter(
                    sum(1 for tool_f in tool_files.values() if f in tool_f) 
                    for f in set().union(*tool_files.values())
                )),
                'multi_tool_agreement_vulnerabilities': dict(vulns_by_tool_count),
                'files_detected_by_all': sum(1 for f in set().union(*tool_files.values()) 
                                             if sum(1 for tool_f in tool_files.values() if f in tool_f) == len(self.tools)),
                'files_detected_by_one': sum(1 for f in set().union(*tool_files.values()) 
                                              if sum(1 for tool_f in tool_files.values() if f in tool_f) == 1),
                'vulnerabilities_detected_by_all': vulns_by_tool_count.get(len(self.tools), 0),
                'vulnerabilities_detected_by_one': vulns_by_tool_count.get(1, 0),
                'vulnerabilities_detected_by_2plus': sum(count for tools, count in vulns_by_tool_count.items() if tools >= 2)
            }
            
            # === CWE Coverage ===
            cwe_by_tool = {}
            for tool in self.tools:
                cwes = set()
                for v in data.get(tool, []):
                    cwe = v.get('cwe') or v.get('cweid', '')
                    if cwe and cwe != '':
                        cwes.add(cwe)
                cwe_by_tool[tool] = list(cwes)
            
            # CWE overlap analysis
            all_cwes = set().union(*[set(cwes) for cwes in cwe_by_tool.values()])
            cwe_coverage_matrix = {}
            for cwe in all_cwes:
                tools_detecting = [tool for tool, cwes in cwe_by_tool.items() if cwe in cwes]
                cwe_coverage_matrix[cwe] = tools_detecting
            
            results['cwe_coverage'][apk_type] = {
                'cwes_per_tool': {tool: len(cwes) for tool, cwes in cwe_by_tool.items()},
                'unique_cwes_total': len(all_cwes),
                'cwe_coverage_matrix': cwe_coverage_matrix,
                'cwes_detected_by_all': sum(1 for tools in cwe_coverage_matrix.values() if len(tools) == len(self.tools)),
                'cwes_detected_by_one': sum(1 for tools in cwe_coverage_matrix.values() if len(tools) == 1)
            }
            
            # === Tool Specialization ===
            # Which tools excel at which categories/CWEs?
            specialization = {}
            for tool in self.tools:
                categories = Counter()
                cwes = Counter()
                for v in data.get(tool, []):
                    cat = v.get('category', 'Unknown')
                    if cat and cat != 'Unknown':
                        categories[cat] += 1
                    cwe = v.get('cwe') or v.get('cweid', '')
                    if cwe and cwe != '':
                        cwes[cwe] += 1
                
                specialization[tool] = {
                    'top_categories': dict(categories.most_common(5)),
                    'top_cwes': dict(cwes.most_common(5))
                }
            
            results['tool_specialization'][apk_type] = specialization
        
        # === Performance Metrics ===
        perf_metrics = {}
        for tool in self.tools:
            # Structure is: general_metrics[tool]['normal']['time']
            tool_metrics = self.general_metrics.get(tool, {})
            
            normal_perf = tool_metrics.get('normal', {})
            obf_perf = tool_metrics.get('obfuscated', {})
            
            # Extract time and memory directly
            normal_time = normal_perf.get('time') if isinstance(normal_perf, dict) else None
            normal_mem = normal_perf.get('memory') if isinstance(normal_perf, dict) else None
            obf_time = obf_perf.get('time') if isinstance(obf_perf, dict) else None
            obf_mem = obf_perf.get('memory') if isinstance(obf_perf, dict) else None
            
            perf_metrics[tool] = {
                'normal': {
                    'time_sec': normal_time,
                    'memory_mb': normal_mem
                },
                'obfuscated': {
                    'time_sec': obf_time,
                    'memory_mb': obf_mem
                }
            }
            
            # Calculate efficiency metrics
            normal_findings = len(self.normal.get(tool, []))
            obf_findings = len(self.obfuscated.get(tool, []))
            
            if normal_time is not None and normal_time > 0:
                perf_metrics[tool]['efficiency'] = {
                    'findings_per_sec_normal': round(normal_findings / normal_time, 2),
                    'findings_per_sec_obf': round(obf_findings / obf_time, 2) if obf_time and obf_time > 0 else None,
                    'findings_per_mb_normal': round(normal_findings / normal_mem, 4) if normal_mem and normal_mem > 0 else None,
                    'findings_per_mb_obf': round(obf_findings / obf_mem, 4) if obf_mem and obf_mem > 0 else None
                }
            else:
                perf_metrics[tool]['efficiency'] = None
        
        results['performance_metrics'] = perf_metrics
        
        # === Summary Insights ===
        results['summary'] = {
            'most_detections_normal': max(results['detection_counts']['normal'].items(), key=lambda x: x[1])[0],
            'most_detections_obf': max(results['detection_counts']['obfuscated'].items(), key=lambda x: x[1])[0],
            'highest_cwe_coverage_normal': max(results['cwe_coverage']['normal']['cwes_per_tool'].items(), key=lambda x: x[1])[0],
            'avg_file_jaccard_normal': round(statistics.mean([v['jaccard'] for v in results['result_similarity']['normal']['file_overlap'].values()]), 3),
            'avg_vuln_location_jaccard_normal': round(statistics.mean([v['jaccard'] for v in results['result_similarity']['normal']['vulnerability_location_overlap'].values()]), 3),
            'avg_semantic_jaccard_normal': round(statistics.mean([v['jaccard'] for v in results['result_similarity']['normal']['semantic_overlap'].values()]), 3),
            'avg_type_jaccard_normal': round(statistics.mean([v['jaccard'] for v in results['result_similarity']['normal']['finding_type_overlap'].values()]), 3),
            'total_exact_vulnerability_matches': sum(v['exact_matches'] for v in results['result_similarity']['normal']['vulnerability_location_overlap'].values()),
            'vulnerabilities_by_2plus_tools': results['result_similarity']['normal']['vulnerabilities_detected_by_2plus']
        }
        
        self.results['rq1_scanner_effectiveness'] = results
        print("✓ RQ1 analysis complete")
        return results
    
    # =========================================================================
    # RQ2: Obfuscation Impact
    # =========================================================================
    def rq2_obfuscation_impact(self):
        """
        RQ2: Analyze obfuscation impact on:
        - Detection rate changes per tool
        - Performance overhead
        - Result similarity changes
        - CWE coverage changes
        """
        print("\n" + "="*80)
        print("RQ2: OBFUSCATION IMPACT ANALYSIS")
        print("="*80)
        
        results = {
            'detection_rate_changes': {},
            'performance_overhead': {},
            'similarity_changes': {},
            'cwe_coverage_changes': {},
            'finding_retention': {}
        }
        
        # === Detection Rate Changes ===
        for tool in self.tools:
            normal_count = len(self.normal.get(tool, []))
            obf_count = len(self.obfuscated.get(tool, []))
            
            # DEBUG: Print counts for verification
            if tool == 'semgrep':
                print(f"  [DEBUG] Semgrep - Normal: {normal_count}, Obfuscated: {obf_count}")
            
            change = obf_count - normal_count
            pct_change = (change / normal_count * 100) if normal_count > 0 else 0
            
            # FIX: Retention should be obfuscated / normal
            # This represents "what percentage of detections were retained"
            retention = (obf_count / normal_count) if normal_count > 0 else 0
            
            results['detection_rate_changes'][tool] = {
                'normal': normal_count,
                'obfuscated': obf_count,
                'absolute_change': change,
                'percent_change': round(pct_change, 2),
                'retention_rate': round(retention, 3),
                'impact': 'increase' if change > 0 else 'decrease' if change < 0 else 'no_change'
            }    
        def _create_finding_signatures(self, vulnerabilities: List[Dict]) -> Set[str]:
            """Create unique signatures for findings to track retention"""
            signatures = set()
            for v in vulnerabilities:
                # Create a signature based on file + type + location
                file = v.get('file') or v.get('source_file', '')
                vtype = v.get('type') or v.get('rule_id') or v.get('rule', '')
                line = v.get('start_line') or v.get('line', '')
                
                if file and vtype:
                    sig = f"{file}::{vtype}::{line}"
                    signatures.add(sig)
            
            return signatures
        
        # =========================================================================
        # RQ3: Vulnerability Correlations
        # =========================================================================
        
    def rq3_vulnerability_correlations(self):
        """
        RQ3: Analyze correlations between:
        - Detected vulnerabilities across scanners
        - App characteristics (function count, file count, LOC)
        - File types and vulnerability density
        """
        print("\n" + "="*80)
        print("RQ3: VULNERABILITY CORRELATION ANALYSIS")
        print("="*80)
        
        results = {
            'cross_scanner_correlations': {},
            'app_characteristics': {},
            'file_type_analysis': {},
            'vulnerability_density': {}
        }
        
        # === Cross-Scanner Correlations ===
        for apk_type in ['normal', 'obfuscated']:
            data = self.normal if apk_type == 'normal' else self.obfuscated
            
            # Build file-level vulnerability matrix (with normalized paths)
            all_files = set()
            for tool in self.tools:
                for v in data.get(tool, []):
                    f = v.get('file') or v.get('source_file', '')
                    if f:
                        normalized = self._normalize_file_path(f)
                        if normalized:
                            all_files.add(normalized)
            
            file_vuln_matrix = {}
            for f in all_files:
                file_vuln_matrix[f] = {tool: 0 for tool in self.tools}
                for tool in self.tools:
                    count = sum(1 for v in data.get(tool, []) 
                               if self._normalize_file_path(v.get('file') or v.get('source_file', '')) == f)
                    file_vuln_matrix[f][tool] = count
            
            # Calculate correlation coefficients (simplified Pearson)
            tool_pairs_correlations = {}
            for i, tool1 in enumerate(self.tools):
                for tool2 in self.tools[i+1:]:
                    values1 = [counts[tool1] for counts in file_vuln_matrix.values()]
                    values2 = [counts[tool2] for counts in file_vuln_matrix.values()]
                    
                    if len(values1) > 1 and statistics.stdev(values1) > 0 and statistics.stdev(values2) > 0:
                        correlation = self._pearson_correlation(values1, values2)
                        tool_pairs_correlations[f"{tool1}_vs_{tool2}"] = round(correlation, 3)
                    else:
                        tool_pairs_correlations[f"{tool1}_vs_{tool2}"] = 0
            
            results['cross_scanner_correlations'][apk_type] = {
                'tool_pair_correlations': tool_pairs_correlations,
                'files_analyzed': len(all_files),
                'high_correlation_pairs': [k for k, v in tool_pairs_correlations.items() if v > 0.7],
                'low_correlation_pairs': [k for k, v in tool_pairs_correlations.items() if v < 0.3]
            }
        
        # === App Characteristics ===
        # Extract from general_metrics
        func_count = self.general_metrics.get('function_number')
        loc = self.general_metrics.get('lines_of_code')
        print(loc)
        # Calculate file counts (with normalized paths)
        normal_files = set()
        obf_files = set()
        for tool in self.tools:
            for v in self.normal.get(tool, []):
                f = v.get('file') or v.get('source_file', '')
                if f:
                    normalized = self._normalize_file_path(f)
                    if normalized:
                        normal_files.add(normalized)
            for v in self.obfuscated.get(tool, []):
                f = v.get('file') or v.get('source_file', '')
                if f:
                    normalized = self._normalize_file_path(f)
                    if normalized:
                        obf_files.add(normalized)
        
        total_vulns_normal = sum(len(v) for v in self.normal.values())
        total_vulns_obf = sum(len(v) for v in self.obfuscated.values())
        
        results['app_characteristics'] = {
            'function_count': func_count,
            'lines_of_code': loc,
            'file_count_normal': len(normal_files),
            'file_count_obfuscated': len(obf_files),
            'total_vulnerabilities_normal': total_vulns_normal,
            'total_vulnerabilities_obfuscated': total_vulns_obf,
            'vulns_per_file_normal': round(total_vulns_normal / len(normal_files), 2) if normal_files else 0,
            'vulns_per_file_obf': round(total_vulns_obf / len(obf_files), 2) if obf_files else 0,
            'vulns_per_function': round(total_vulns_normal / func_count, 2) if func_count else None,
            'vulns_per_kloc': round(total_vulns_normal / (loc / 1000), 2) if loc else None
        }
        
        # === File Type Analysis ===
        file_type_vulns = defaultdict(lambda: {'count': 0, 'files': set()})
        
        for tool in self.tools:
            for v in self.normal.get(tool, []):
                f = v.get('file') or v.get('source_file', '')
                if f:
                    normalized = self._normalize_file_path(f)
                    if normalized:
                        ext = Path(normalized).suffix or 'no_extension'
                        file_type_vulns[ext]['count'] += 1
                        file_type_vulns[ext]['files'].add(normalized)
        
        results['file_type_analysis'] = {
            ext: {
                'vulnerability_count': data['count'],
                'file_count': len(data['files']),
                'avg_vulns_per_file': round(data['count'] / len(data['files']), 2)
            }
            for ext, data in file_type_vulns.items()
        }
        
        # === Vulnerability Density by File ===
        file_density = {}
        for tool in self.tools:
            for v in self.normal.get(tool, []):
                f = v.get('file') or v.get('source_file', '')
                if f:
                    normalized = self._normalize_file_path(f)
                    if normalized:
                        file_density[normalized] = file_density.get(normalized, 0) + 1
        
        sorted_density = sorted(file_density.items(), key=lambda x: x[1], reverse=True)
        
        results['vulnerability_density'] = {
            'top_10_files': [{'file': f, 'vuln_count': c} for f, c in sorted_density[:10]],
            'avg_vulns_per_file': round(statistics.mean(file_density.values()), 2) if file_density else 0,
            'median_vulns_per_file': round(statistics.median(file_density.values()), 2) if file_density else 0,
            'files_with_high_density': sum(1 for c in file_density.values() if c > 5)
        }
        
        self.results['rq3_vulnerability_correlations'] = results
        print("✓ RQ3 analysis complete")
        return results
    
    def _pearson_correlation(self, x: List[float], y: List[float]) -> float:
        """Calculate Pearson correlation coefficient"""
        if len(x) != len(y) or len(x) == 0:
            return 0
        
        n = len(x)
        mean_x = statistics.mean(x)
        mean_y = statistics.mean(y)
        
        numerator = sum((x[i] - mean_x) * (y[i] - mean_y) for i in range(n))
        denominator_x = sum((x[i] - mean_x) ** 2 for i in range(n))
        denominator_y = sum((y[i] - mean_y) ** 2 for i in range(n))
        
        denominator = (denominator_x * denominator_y) ** 0.5
        
        return numerator / denominator if denominator != 0 else 0
    
    # =========================================================================
    # RQ4: Hotspot Patterns
    # =========================================================================
    
    def rq4_hotspot_patterns(self):
        """
        RQ4: Identify hotspot patterns:
        - Concentration vs. distribution of vulnerabilities
        - File/function hotspots
        - How patterns change under obfuscation
        - Scanner-specific hotspot patterns
        """
        print("\n" + "="*80)
        print("RQ4: HOTSPOT PATTERN ANALYSIS")
        print("="*80)
        
        results = {
            'concentration_metrics': {},
            'top_hotspots': {},
            'obfuscation_hotspot_changes': {},
            'scanner_hotspot_patterns': {}
        }
        
        for apk_type in ['normal', 'obfuscated']:
            data = self.normal if apk_type == 'normal' else self.obfuscated
            
            # === Build file-level vulnerability map ===
            file_vulns = defaultdict(lambda: {'total': 0, 'by_tool': defaultdict(int), 'by_severity': defaultdict(int)})
            
            for tool in self.tools:
                for v in data.get(tool, []):
                    f = v.get('file') or v.get('source_file', '')
                    if f:
                        normalized = self._normalize_file_path(f)
                        if normalized:
                            file_vulns[normalized]['total'] += 1
                            file_vulns[normalized]['by_tool'][tool] += 1
                            
                            sev = str(v.get('severity') or v.get('priority') or v.get('level', 'UNKNOWN')).upper()
                            file_vulns[normalized]['by_severity'][sev] += 1
            
            # === Concentration Metrics ===
            # Gini coefficient for inequality
            vuln_counts = sorted([v['total'] for v in file_vulns.values()])
            gini = self._calculate_gini(vuln_counts) if vuln_counts else 0
            
            # Top 20% files contain what % of vulnerabilities?
            total_vulns = sum(v['total'] for v in file_vulns.values())
            sorted_files = sorted(file_vulns.items(), key=lambda x: x[1]['total'], reverse=True)
            top_20_pct_count = max(1, int(len(sorted_files) * 0.2))
            top_20_pct_vulns = sum(v['total'] for f, v in sorted_files[:top_20_pct_count])
            concentration_ratio = (top_20_pct_vulns / total_vulns) if total_vulns > 0 else 0
            
            results['concentration_metrics'][apk_type] = {
                'gini_coefficient': round(gini, 3),
                'top_20pct_concentration': round(concentration_ratio, 3),
                'total_files': len(file_vulns),
                'files_with_1_vuln': sum(1 for v in file_vulns.values() if v['total'] == 1),
                'files_with_5plus_vulns': sum(1 for v in file_vulns.values() if v['total'] >= 5),
                'files_with_10plus_vulns': sum(1 for v in file_vulns.values() if v['total'] >= 10)
            }
            
            # === Top Hotspots ===
            top_files = sorted_files[:20]
            results['top_hotspots'][apk_type] = [
                {
                    'file': f,
                    'total_vulns': v['total'],
                    'by_tool': dict(v['by_tool']),
                    'by_severity': dict(v['by_severity']),
                    'tools_detecting': len(v['by_tool'])
                }
                for f, v in top_files
            ]
        
        # === Obfuscation Hotspot Changes ===
        normal_hotspots = {h['file']: h['total_vulns'] for h in results['top_hotspots']['normal']}
        obf_hotspots = {h['file']: h['total_vulns'] for h in results['top_hotspots']['obfuscated']}
        
        # Track which hotspots persist
        common_files = set(normal_hotspots.keys()) & set(obf_hotspots.keys())
        lost_hotspots = set(normal_hotspots.keys()) - set(obf_hotspots.keys())
        new_hotspots = set(obf_hotspots.keys()) - set(normal_hotspots.keys())
        
        results['obfuscation_hotspot_changes'] = {
            'persistent_hotspots': len(common_files),
            'lost_hotspots': len(lost_hotspots),
            'new_hotspots': len(new_hotspots),
            'concentration_change': round(
                results['concentration_metrics']['obfuscated']['gini_coefficient'] - 
                results['concentration_metrics']['normal']['gini_coefficient'], 
                3
            )
        }
        
        # === Scanner-Specific Hotspots ===
        for tool in self.tools:
            tool_file_vulns = defaultdict(int)
            for v in self.normal.get(tool, []):
                f = v.get('file') or v.get('source_file', '')
                if f:
                    normalized = self._normalize_file_path(f)
                    if normalized:
                        tool_file_vulns[normalized] += 1
            
            sorted_tool_files = sorted(tool_file_vulns.items(), key=lambda x: x[1], reverse=True)
            
            results['scanner_hotspot_patterns'][tool] = {
                'top_5_files': [{'file': f, 'vulns': c} for f, c in sorted_tool_files[:5]],
                'unique_files_detected': len(tool_file_vulns),
                'avg_vulns_per_file': round(statistics.mean(tool_file_vulns.values()), 2) if tool_file_vulns else 0
            }
        
        self.results['rq4_hotspot_patterns'] = results
        print("✓ RQ4 analysis complete")
        return results
    
    def _calculate_gini(self, values: List[float]) -> float:
        """Calculate Gini coefficient for inequality measure"""
        if not values or len(values) == 0:
            return 0
        
        sorted_values = sorted(values)
        n = len(sorted_values)
        cumsum = 0
        
        for i, val in enumerate(sorted_values):
            cumsum += (i + 1) * val
        
        return (2 * cumsum) / (n * sum(sorted_values)) - (n + 1) / n
    
    # =========================================================================
    # RQ5: Accuracy Analysis (Placeholder for Manual Validation)
    # =========================================================================
    
    def rq5_accuracy_analysis(self):
        """
        RQ5: Accuracy analysis (requires manual validation)
        This provides data structures for manual FP/FN analysis
        """
        print("\n" + "="*80)
        print("RQ5: ACCURACY ANALYSIS (REQUIRES MANUAL VALIDATION)")
        print("="*80)
        
        results = {
            'findings_for_validation': {},
            'high_confidence_findings': {},
            'low_confidence_findings': {},
            'validation_stats_placeholder': {}
        }
        
        # Sample findings for manual validation
        for tool in self.tools:
            tool_findings = []
            for v in self.normal.get(tool, [])[:10]:  # Sample first 10
                finding = {
                    'file': v.get('file') or v.get('source_file', ''),
                    'type': v.get('type') or v.get('rule_id', ''),
                    'severity': v.get('severity') or v.get('priority', ''),
                    'message': v.get('message') or v.get('short_message', ''),
                    'line': v.get('start_line', ''),
                    'cwe': v.get('cwe', ''),
                    'validated': None,  # To be filled manually
                    'is_fp': None,      # To be filled manually
                    'notes': ''         # For validation notes
                }
                tool_findings.append(finding)
            
            results['findings_for_validation'][tool] = tool_findings
        
        # Identify high-confidence findings (detected by multiple tools)
        file_finding_map = defaultdict(set)
        for tool in self.tools:
            for v in self.normal.get(tool, []):
                f = v.get('file') or v.get('source_file', '')
                ftype = v.get('type') or v.get('rule_id', '')
                if f and ftype:
                    file_finding_map[f'{f}::{ftype}'].add(tool)
        
        high_conf = [k for k, v in file_finding_map.items() if len(v) >= 3]
        low_conf = [k for k, v in file_finding_map.items() if len(v) == 1]
        
        results['high_confidence_findings'] = {
            'count': len(high_conf),
            'examples': high_conf[:10]
        }
        results['low_confidence_findings'] = {
            'count': len(low_conf),
            'examples': low_conf[:10]
        }
        
        # Placeholder for validation statistics
        results['validation_stats_placeholder'] = {
            'note': 'Fill these after manual validation',
            'total_validated': 0,
            'true_positives': 0,
            'false_positives': 0,
            'precision_per_tool': {tool: None for tool in self.tools}
        }
        
        self.results['rq5_accuracy_analysis'] = results
        print("✓ RQ5 analysis complete (validation data prepared)")
        return results
    
    # =========================================================================
    # RQ6: App Category Analysis (Requires Category Metadata)
    # =========================================================================
    
    def rq6_category_analysis(self, app_category: str = None):
        """
        RQ6: Category-based analysis
        Store app-level data for later category aggregation
        """
        print("\n" + "="*80)
        print("RQ6: APP CATEGORY ANALYSIS")
        print("="*80)
        
        results = {
            'app_category': app_category,
            'category_features': {
                'total_vulnerabilities': sum(len(v) for v in self.normal.values()),
                'avg_severity_score': self._calculate_avg_severity(),
                'dominant_cwe': self._get_dominant_cwe(),
                'tool_preference': self._get_tool_preference()
            }
        }
        
        self.results['rq6_category_analysis'] = results
        print("✓ RQ6 analysis complete")
        return results
    
    def _calculate_avg_severity(self) -> float:
        """Calculate average severity score (simplified)"""
        severity_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, '1': 4, '2': 3, '3': 2, '4': 1}
        
        scores = []
        for tool in self.tools:
            for v in self.normal.get(tool, []):
                sev = str(v.get('severity') or v.get('priority') or v.get('level', '')).upper()
                score = severity_map.get(sev, 2)
                scores.append(score)
        
        return round(statistics.mean(scores), 2) if scores else 0
    
    def _get_dominant_cwe(self) -> Optional[str]:
        """Get most common CWE"""
        cwe_counts = Counter()
        for tool in self.tools:
            for v in self.normal.get(tool, []):
                cwe = v.get('cwe') or v.get('cweid', '')
                if cwe:
                    cwe_counts[cwe] += 1
        
        return cwe_counts.most_common(1)[0][0] if cwe_counts else None
    
    def _get_tool_preference(self) -> str:
        """Get tool with most findings"""
        tool_counts = {tool: len(self.normal.get(tool, [])) for tool in self.tools}
        return max(tool_counts.items(), key=lambda x: x[1])[0]
    
    # =========================================================================
    # RQ7: Ethical & Practical Implications
    # =========================================================================
    
    def rq7_ethical_implications(self):
        """
        RQ7: Document ethical and practical implications
        - Scanner biases
        - CWE coverage gaps
        - Recommendations
        """
        print("\n" + "="*80)
        print("RQ7: ETHICAL & PRACTICAL IMPLICATIONS")
        print("="*80)
        
        results = {
            'scanner_biases': {},
            'cwe_coverage_gaps': {},
            'recommendations': []
        }
        
        # === Scanner Biases ===
        for tool in self.tools:
            categories = Counter()
            cwes = Counter()
            
            for v in self.normal.get(tool, []):
                cat = v.get('category', 'Unknown')
                if cat:
                    categories[cat] += 1
                cwe = v.get('cwe', '')
                if cwe:
                    cwes[cwe] += 1
            
            # Check for concentration in specific categories
            total = sum(categories.values())
            if total > 0:
                top_cat_pct = categories.most_common(1)[0][1] / total if categories else 0
                
                results['scanner_biases'][tool] = {
                    'category_concentration': round(top_cat_pct, 3),
                    'top_category': categories.most_common(1)[0][0] if categories else None,
                    'category_diversity': len(categories),
                    'cwe_diversity': len(cwes)
                }
        
        # === CWE Coverage Gaps ===
        all_cwes = set()
        for tool in self.tools:
            for v in self.normal.get(tool, []):
                cwe = v.get('cwe', '')
                if cwe:
                    all_cwes.add(cwe)
        
        # Which CWEs are only detected by one tool?
        cwe_tool_map = defaultdict(set)
        for tool in self.tools:
            for v in self.normal.get(tool, []):
                cwe = v.get('cwe', '')
                if cwe:
                    cwe_tool_map[cwe].add(tool)
        
        single_tool_cwes = {cwe: list(tools)[0] for cwe, tools in cwe_tool_map.items() if len(tools) == 1}
        
        results['cwe_coverage_gaps'] = {
            'total_unique_cwes': len(all_cwes),
            'cwes_detected_by_single_tool': len(single_tool_cwes),
            'single_tool_cwe_list': single_tool_cwes,
            'cwes_detected_by_all': [cwe for cwe, tools in cwe_tool_map.items() if len(tools) == len(self.tools)]
        }
        
        # === Generate Recommendations ===
        recommendations = []
        
        # Check for low inter-tool agreement
        rq1_results = self.results.get('rq1_scanner_effectiveness', {})
        avg_jaccard = rq1_results.get('summary', {}).get('avg_file_jaccard_normal', 1.0)
        if avg_jaccard < 0.3:
            recommendations.append("Low inter-tool agreement detected - consider using multiple tools for comprehensive coverage")
        
        # Check for obfuscation vulnerability
        rq2_results = self.results.get('rq2_obfuscation_impact', {})
        avg_retention = rq2_results.get('summary', {}).get('avg_detection_retention', 1.0)
        if avg_retention < 0.7:
            recommendations.append("Significant detection loss under obfuscation - tools may miss obfuscated vulnerabilities in production apps")
        
        # Check for hotspot concentration
        rq4_results = self.results.get('rq4_hotspot_patterns', {})
        gini = rq4_results.get('concentration_metrics', {}).get('normal', {}).get('gini_coefficient', 0)
        if gini > 0.6:
            recommendations.append("High vulnerability concentration detected - focus remediation efforts on hotspot files")
        
        # Check for single-tool CWE dependencies
        if len(single_tool_cwes) > len(all_cwes) * 0.3:
            recommendations.append("Many CWEs detected by only one tool - using single tool may miss important vulnerability classes")
        
        results['recommendations'] = recommendations
        
        self.results['rq7_ethical_implications'] = results
        print("✓ RQ7 analysis complete")
        return results
    
    # =========================================================================
    # Main Analysis Runner
    # =========================================================================
    
    def run_complete_analysis(self, app_category: str = None):
        """Run all analyses and generate comprehensive report"""
        print("\n" + "="*80)
        print(f"STARTING COMPREHENSIVE SAST ANALYSIS")
        print(f"App: {self.app_name}")
        print("="*80)
        
        # Run all RQ analyses
        self.rq1_scanner_effectiveness()
        self.rq2_obfuscation_impact()
        self.rq3_vulnerability_correlations()
        self.rq4_hotspot_patterns()
        self.rq5_accuracy_analysis()
        self.rq6_category_analysis(app_category)
        self.rq7_ethical_implications()
        
        # Generate executive summary
        self._generate_executive_summary()
        
        # Save results
        output_file = self.app_folder / f"{self.app_name}_comprehensive_analysis.json"
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n{'='*80}")
        print("ANALYSIS COMPLETE")
        print(f"Results saved to: {output_file}")
        print(f"{'='*80}\n")
        
        return self.results
    
    def _generate_executive_summary(self):
        """Generate high-level executive summary"""
        summary = {
            'app_name': self.app_name,
            'total_findings_normal': sum(len(v) for v in self.normal.values()),
            'total_findings_obfuscated': sum(len(v) for v in self.obfuscated.values()),
            'key_metrics': {}
        }
        
        # Extract key metrics from each RQ
        rq1 = self.results.get('rq1_scanner_effectiveness', {})
        rq2 = self.results.get('rq2_obfuscation_impact', {})
        rq3 = self.results.get('rq3_vulnerability_correlations', {})
        rq4 = self.results.get('rq4_hotspot_patterns', {})
        
        summary['key_metrics'] = {
            'most_effective_tool': rq1.get('summary', {}).get('most_detections_normal'),
            'avg_tool_agreement': rq1.get('summary', {}).get('avg_file_jaccard_normal'),
            'obfuscation_resilience': rq2.get('summary', {}).get('avg_detection_retention'),
            'vulnerability_concentration': rq4.get('concentration_metrics', {}).get('normal', {}).get('gini_coefficient'),
            'top_hotspot_file': rq4.get('top_hotspots', {}).get('normal', [{}])[0].get('file') if rq4.get('top_hotspots', {}).get('normal') else None
        }
        
        self.results['executive_summary'] = summary


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python comprehensive_app_analyzer.py <app_folder> [category]")
        print("Example: python comprehensive_app_analyzer.py downloaded_results/a2dp.Vol games")
        sys.exit(1)
    
    app_folder = sys.argv[1]
    app_category = sys.argv[2] if len(sys.argv) > 2 else None
    
    analyzer = ComprehensiveSASTAnalyzer(f"downloaded_results/{app_folder}")
    results = analyzer.run_complete_analysis(app_category)
    
    # Print executive summary
    exec_summary = results['executive_summary']
    print("\n" + "="*80)
    print("EXECUTIVE SUMMARY")
    print("="*80)
    print(f"App: {exec_summary['app_name']}")
    print(f"Total Findings (Normal): {exec_summary['total_findings_normal']}")
    print(f"Total Findings (Obfuscated): {exec_summary['total_findings_obfuscated']}")
    print("\nKey Metrics:")
    for metric, value in exec_summary['key_metrics'].items():
        print(f"  {metric}: {value}")
    print("="*80)
    
    # Print parsing statistics
    parsing_stats.print_summary()
