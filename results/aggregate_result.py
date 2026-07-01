#!/usr/bin/env python3
"""
Complete SAST Aggregation with File Type & Severity Analysis
"""
import json
import csv
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List
import statistics
from dataclasses import dataclass, field
import sys
from analyse_file import ComprehensiveSASTAnalyzer
import numpy as np  # Add if not already there
import pandas as pd  # Add if not already there


@dataclass
class AggregatedMetrics:
    """Store aggregated metrics across all apps"""
    total_apps: int = 0
    successful_analyses: int = 0
    failed_analyses: List[str] = field(default_factory=list)
    
    # Detection counts
    detection_counts: Dict[str, List[int]] = field(default_factory=lambda: defaultdict(list))
    
    # Performance vs LOC
    lines_of_code: List[int] = field(default_factory=list)
    function_counts: List[int] = field(default_factory=list)
    tool_execution_times: Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))
    tool_memory_usage: Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))
    
    # CWE Prevalence per tool
    cwe_counts_per_tool: Dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    
    # NEW: File type analysis
    file_type_vulns: Dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    file_type_counts: Counter = field(default_factory=Counter)
    
    # NEW: Severity distribution
    severity_per_tool: Dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    severity_overall: Counter = field(default_factory=Counter)
    
    # Similarity metrics
    file_jaccard: Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))
    vuln_location_jaccard: Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))
    semantic_jaccard: Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))
    
    # Agreement statistics
    detection_overlap_counts: List[Dict] = field(default_factory=list)
    
    # Obfuscation impact
    detection_retention: Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))
    obf_impact: Dict[str, List[int]] = field(default_factory=lambda: defaultdict(list))
    time_overhead: Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))
    memory_overhead: Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))
    
    # Hotspots
    gini_coefficients: List[float] = field(default_factory=list)
    concentration_ratios: List[float] = field(default_factory=list)
    
    # Per-app summaries
    app_summaries: List[Dict] = field(default_factory=list)


class CompleteSASTAggregator:
    """Complete aggregator with file type and severity analysis"""
    
    def __init__(self, results_dir: str, output_dir: str = "aggregated_results"):
        self.results_dir = Path(results_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.metrics = AggregatedMetrics()
        self.tools = ['spotbugs', 'semgrep', 'vusc', 'codeql', 'sonarqube']
        self.analyze_all_apps()

    def _normalize_severity(self, severity_value) -> str:
        """Normalize severity across all tools"""
        if not severity_value:
            return 'UNKNOWN'
        
        severity = str(severity_value).upper().strip()
        
        if severity.isdigit():
            num = int(severity)
            if num == 1:
                return 'CRITICAL'
            elif num == 2:
                return 'HIGH'
            elif num == 3:
                return 'MEDIUM'
            else:
                return 'LOW'
        
        if any(x in severity for x in ['BLOCKER', 'CRITICAL']):
            return 'CRITICAL'
        elif any(x in severity for x in ['ERROR', 'HIGH', 'MAJOR']):
            return 'HIGH'
        elif any(x in severity for x in ['WARNING', 'MEDIUM', 'MODERATE', 'MINOR']):
            return 'MEDIUM'
        elif any(x in severity for x in ['LOW', 'INFO', 'TRIVIAL', 'NOTE']):
            return 'LOW'
        
        return 'UNKNOWN'
    
    def add_statistical_analysis(self):
        """
        Add statistical tests and confidence intervals to all key metrics.
        Fast to compute - runs in ~5-10 minutes for 5000 apps.
        """
        from scipy import stats
        import numpy as np
        
        print("\n" + "="*80)
        print("STATISTICAL ANALYSIS")
        print("="*80)
        
        results = {
            'retention_rates': {},
            'detection_counts': {},
            'tool_comparisons': {}
        }

        print("\n📊 Retention Rate Statistics:")
        retention_data = []
        tool_names = []

        for tool in self.tools:
            # Only include retention rates where BOTH normal and obfuscated versions exist
            if tool in self.metrics.detection_retention:
                # Filter out None values and ensure we only have valid pairs
                valid_rates = [rate for rate in self.metrics.detection_retention[tool] 
                            if rate is not None]
                
                if len(valid_rates) > 0:
                    retention_data.append(valid_rates)
                    tool_names.append(tool)

        if len(retention_data) >= 2:
            # Kruskal-Wallis H-test (non-parametric ANOVA)
            h_stat, p_value = stats.kruskal(*retention_data)
            print(f"  Kruskal-Wallis H-test: H={h_stat:.3f}, p={p_value:.4f}")
            
            if p_value < 0.05:
                print(f"  ✓ Significant difference between tools (p < 0.05)")
            else:
                print(f"  ✗ No significant difference (p >= 0.05)")
            
            results['retention_rates']['overall_test'] = {
                'test': 'kruskal_wallis',
                'h_statistic': h_stat,
                'p_value': p_value,
                'significant': p_value < 0.05
            }
            
            # Pairwise comparisons with Bonferroni correction
            print("\n  Pairwise Comparisons (Mann-Whitney U):")
            comparisons = []
            n_comparisons = len(tool_names) * (len(tool_names) - 1) / 2
            bonferroni_alpha = 0.05 / n_comparisons  # Corrected significance level
            
            for i in range(len(tool_names)):
                for j in range(i + 1, len(tool_names)):
                    tool_a = tool_names[i]
                    tool_b = tool_names[j]
                    data_a = retention_data[i]
                    data_b = retention_data[j]
                    
                    # Mann-Whitney U test (non-parametric)
                    u_stat, p_val = stats.mannwhitneyu(data_a, data_b, alternative='two-sided')
                    
                    # Effect size (rank-biserial correlation)
                    n_a, n_b = len(data_a), len(data_b)
                    effect_size = 1 - (2*u_stat) / (n_a * n_b)
                    
                    # Confidence intervals (bootstrap)
                    ci_a = stats.t.interval(0.95, len(data_a)-1, 
                                        loc=np.mean(data_a), 
                                        scale=stats.sem(data_a))
                    ci_b = stats.t.interval(0.95, len(data_b)-1,
                                        loc=np.mean(data_b),
                                        scale=stats.sem(data_b))
                    
                    significant = p_val < bonferroni_alpha
                    
                    print(f"    {tool_a} vs {tool_b}:")
                    print(f"      Mean: {np.mean(data_a):.3f} (95% CI: {ci_a[0]:.3f}-{ci_a[1]:.3f}) vs "
                        f"{np.mean(data_b):.3f} (95% CI: {ci_b[0]:.3f}-{ci_b[1]:.3f})")
                    print(f"      U={u_stat:.1f}, p={p_val:.4f}, effect_size={effect_size:.3f}")
                    print(f"      {'✓ SIGNIFICANT' if significant else '✗ Not significant'} "
                        f"(α={bonferroni_alpha:.4f})")
                    
                    comparisons.append({
                        'tool_a': tool_a,
                        'tool_b': tool_b,
                        'mean_a': np.mean(data_a),
                        'mean_b': np.mean(data_b),
                        'ci_a': ci_a,
                        'ci_b': ci_b,
                        'u_statistic': u_stat,
                        'p_value': p_val,
                        'effect_size': effect_size,
                        'significant': significant
                    })
            
            results['retention_rates']['pairwise'] = comparisons
                
                # ============================================================
                # 2. DETECTION COUNTS - Add confidence intervals
        # ============================================================
        print("\n📊 Detection Count Statistics:")
        
        for key in ['spotbugs_normal', 'semgrep_normal', 'vusc_normal', 
                    'codeql_normal', 'sonarqube_normal']:
            if key in self.metrics.detection_counts:
                data = self.metrics.detection_counts[key]
                
                if len(data) > 1:
                    mean = np.mean(data)
                    median = np.median(data)
                    std = np.std(data)
                    
                    # 95% Confidence Interval
                    ci = stats.t.interval(0.95, len(data)-1, loc=mean, scale=stats.sem(data))
                    
                    print(f"\n  {key}:")
                    print(f"    Mean: {mean:.2f} (95% CI: {ci[0]:.2f}-{ci[1]:.2f})")
                    print(f"    Median: {median:.2f}, Std: {std:.2f}")
                    
                    results['detection_counts'][key] = {
                        'mean': mean,
                        'median': median,
                        'std': std,
                        'ci_lower': ci[0],
                        'ci_upper': ci[1],
                        'n': len(data)
                    }
        
        # ============================================================
        # 3. TOOL AGREEMENT - Statistical tests
        # ============================================================
        print("\n📊 Tool Agreement Analysis:")
        
        # Test if Jaccard similarities are significantly different from random
        for metric_name, data_dict in [
            ('File Overlap', self.metrics.file_jaccard),
            ('Vulnerability Location', self.metrics.vuln_location_jaccard),
            ('Semantic Overlap', self.metrics.semantic_jaccard)
        ]:
            print(f"\n  {metric_name}:")
            
            all_values = []
            for values in data_dict.values():
                all_values.extend(values)
            
            if len(all_values) > 0:
                mean = np.mean(all_values)
                ci = stats.t.interval(0.95, len(all_values)-1, 
                                    loc=mean, 
                                    scale=stats.sem(all_values))
                
                # One-sample t-test against 0 (no overlap)
                t_stat, p_val = stats.ttest_1samp(all_values, 0)
                
                print(f"    Mean Jaccard: {mean:.3f} (95% CI: {ci[0]:.3f}-{ci[1]:.3f})")
                print(f"    Significantly > 0? p={p_val:.4f} {'✓ YES' if p_val < 0.05 else '✗ NO'}")
        
        # ============================================================
        # 4. SAVE RESULTS
        # ============================================================
        output_file = self.output_dir / "statistical_analysis.json"
        with open(output_file, 'w') as f:
            import json
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n✓ Statistical analysis saved to {output_file}")
        
        return results
        
    def _calculate_gini(self, values):
        """Calculate Gini coefficient for a list of values"""
        if len(values) == 0:
            return 0.0
        
        # Sort values
        sorted_values = sorted(values)
        n = len(sorted_values)
        
        if n == 0 or sum(sorted_values) == 0:
            return 0.0
        
        # Calculate Gini coefficient
        cumsum = 0
        for i, value in enumerate(sorted_values):
            cumsum += (i + 1) * value
        
        gini = (2 * cumsum) / (n * sum(sorted_values)) - (n + 1) / n
        
        return max(0, min(1, gini))  # Clamp between 0 and 1


    def analyze_all_apps(self):
        """Run comprehensive analysis on all apps"""
        for app_dir in self.results_dir.iterdir():
            if not app_dir.is_dir():
                continue
            try:
                analyzer = ComprehensiveSASTAnalyzer(f"{app_dir}")
                results = analyzer.run_complete_analysis("test")
            except Exception as e:
                print(f"[WARN] Failed to analyze {app_dir.name}: {e}")

    def aggregate_all(self):
        """Main aggregation function"""
        print("\n" + "="*80)
        print("COMPLETE SAST ANALYSIS AGGREGATION")
        print("="*80)
        
        analysis_files = list(self.results_dir.glob("*/*_comprehensive_analysis.json"))
        
        if not analysis_files:
            print(f"❌ No analysis files found in {self.results_dir}")
            return
        
        print(f"Found {len(analysis_files)} analysis files")
        
        for i, file_path in enumerate(analysis_files, 1):
            if i % 50 == 0:
                print(f"  Processed {i}/{len(analysis_files)} apps...")
            
            try:
                self._process_app(file_path)
                self.metrics.successful_analyses += 1
            except Exception as e:
                print(f"  ⚠️  Error processing {file_path.stem}: {e}")
                self.metrics.failed_analyses.append(str(file_path))
        
        self.metrics.total_apps = len(analysis_files)
        
        print(f"\n✓ Successfully processed {self.metrics.successful_analyses}/{self.metrics.total_apps} apps")
        
        # Generate outputs
        self._generate_summary_statistics()
        self._export_to_csv()
        self._generate_cwe_prevalence_report()
        self.generate_file_type_concentration_data()  # NEW - Add this line
        self.add_statistical_analysis()

        
        print(f"\n✓ Aggregation complete! Results saved to {self.output_dir}/")
    
    def _process_app(self, file_path: Path):
        """Process a single app's analysis results"""
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        app_name = data.get('app_name', 'unknown')
        
        # === Extract LOC and function count ===
        rq3 = data.get('rq3_vulnerability_correlations', {})
        app_chars = rq3.get('app_characteristics', {})
        
        loc = app_chars.get('lines_of_code', 0)
        func_count = app_chars.get('function_count', 0)
        
        self.metrics.lines_of_code.append(loc if loc else 0)
        self.metrics.function_counts.append(func_count if func_count else 0)
        
        # === RQ1: Detection counts and CWE extraction ===
        rq1 = data.get('rq1_scanner_effectiveness', {})
        
        # Detection counts
        detection_counts = rq1.get('detection_counts', {})
        for tool in self.tools:
            normal_count = detection_counts.get('normal', {}).get(tool, 0)
            obf_count = detection_counts.get('obfuscated', {}).get(tool, 0)
            self.metrics.detection_counts[f"{tool}_normal"].append(normal_count)
            self.metrics.detection_counts[f"{tool}_obfuscated"].append(obf_count)
        
        # === Extract CWEs from tool_specialization ===
        tool_specialization = rq1.get('tool_specialization', {}).get('normal', {})
        
        for tool in self.tools:
            tool_spec = tool_specialization.get(tool, {})
            top_cwes = tool_spec.get('top_cwes', {})
            
            for cwe, count in top_cwes.items():
                self.metrics.cwe_counts_per_tool[tool][cwe] += count
        
        # === Performance metrics ===
        perf_metrics = rq1.get('performance_metrics', {})
        
        for tool in self.tools:
            tool_perf = perf_metrics.get(tool, {})
            
            normal_perf = tool_perf.get('normal', {})
            if isinstance(normal_perf, dict):
                time_sec = normal_perf.get('time_sec')
                mem_mb = normal_perf.get('memory_mb')
                
                if time_sec is not None and time_sec > 0:
                    self.metrics.tool_execution_times[tool].append(time_sec)
                if mem_mb is not None and mem_mb > 0:
                    self.metrics.tool_memory_usage[tool].append(mem_mb)
        
        # === Similarity metrics ===
        similarity = rq1.get('result_similarity', {}).get('normal', {})
        
        for pair, data_val in similarity.get('file_overlap', {}).items():
            self.metrics.file_jaccard[pair].append(data_val.get('jaccard', 0))
        
        for pair, data_val in similarity.get('vulnerability_location_overlap', {}).items():
            self.metrics.vuln_location_jaccard[pair].append(data_val.get('jaccard', 0))
        
        for pair, data_val in similarity.get('semantic_overlap', {}).items():
            self.metrics.semantic_jaccard[pair].append(data_val.get('jaccard', 0))
        
        # === Agreement statistics ===
        multi_tool_agreement = similarity.get('multi_tool_agreement_vulnerabilities', {})
        
        overlap_counts = {
            'tools_1': multi_tool_agreement.get('1', 0),
            'tools_2': multi_tool_agreement.get('2', 0),
            'tools_3': multi_tool_agreement.get('3', 0),
            'tools_4': multi_tool_agreement.get('4', 0),
            'tools_5': multi_tool_agreement.get('5', 0)
        }
        self.metrics.detection_overlap_counts.append(overlap_counts)
        
        # === NEW: File Type Analysis ===
        file_analysis = rq1.get('file_type_analysis', {}).get('normal', {})
        if file_analysis:
            for ext, ext_data in file_analysis.items():
                total = ext_data.get('total_vulnerabilities', 0)
                if total > 0:
                    self.metrics.file_type_vulns['overall'][ext] += total
                    self.metrics.file_type_counts[ext] += 1
                    
                    for tool, count in ext_data.get('detections_per_tool', {}).items():
                        if count > 0:
                            self.metrics.file_type_vulns[tool][ext] += count
        
        # === NEW: Severity Distribution ===
        severity_dist = rq1.get('severity_distribution', {}).get('normal', {})
        if severity_dist:
            for tool in self.tools:
                tool_severities = severity_dist.get('per_tool', {}).get(tool, {})
                for severity, count in tool_severities.items():
                    if count > 0:
                        self.metrics.severity_per_tool[tool][severity] += count
            
            overall_severities = severity_dist.get('overall', {})
            for severity, count in overall_severities.items():
                if count > 0:
                    self.metrics.severity_overall[severity] += count
        
        # === RQ2: Obfuscation Impact ===
        rq2 = data.get('rq2_obfuscation_impact', {})
        
        for tool in self.tools:
            det_changes = rq2.get('detection_rate_changes', {}).get(tool, {})
            self.metrics.detection_retention[tool].append(det_changes.get('retention_rate', 0))
            self.metrics.obf_impact[tool].append(det_changes.get('absolute_change', 0))
            
            perf_overhead = rq2.get('performance_overhead', {}).get(tool, {})
            time_ovh = perf_overhead.get('time_overhead_pct')
            mem_ovh = perf_overhead.get('memory_overhead_pct')
            
            if time_ovh is not None:
                self.metrics.time_overhead[tool].append(time_ovh)
            if mem_ovh is not None:
                self.metrics.memory_overhead[tool].append(mem_ovh)
        
        # === RQ4: Hotspots ===
        rq4 = data.get('rq4_hotspot_patterns', {})
        
        normal_conc = rq4.get('concentration_metrics', {}).get('normal', {})
        gini = normal_conc.get('gini_coefficient', 0)
        concentration = normal_conc.get('top_20pct_concentration', 0)
        
        if gini > 0:
            self.metrics.gini_coefficients.append(gini)
        if concentration > 0:
            self.metrics.concentration_ratios.append(concentration)
        
        # === Store app summary ===
        exec_summary = data.get('executive_summary', {})
        self.metrics.app_summaries.append({
            'app_name': app_name,
            'lines_of_code': loc,
            'function_count': func_count,
            'total_findings_normal': exec_summary.get('total_findings_normal', 0),
            'total_findings_obfuscated': exec_summary.get('total_findings_obfuscated', 0),
            'most_effective_tool': exec_summary.get('key_metrics', {}).get('most_effective_tool'),
            'obfuscation_resilience': exec_summary.get('key_metrics', {}).get('obfuscation_resilience', 0),
            'vulnerability_concentration': exec_summary.get('key_metrics', {}).get('vulnerability_concentration', 0)
        })
    
    def _generate_cwe_prevalence_report(self):
        """Generate CWE prevalence reports per tool"""
        print("\n" + "="*80)
        print("GENERATING CWE PREVALENCE REPORTS")
        print("="*80)
        
        output_file = self.output_dir / "cwe_prevalence.json"
        
        prevalence_report = {}
        for tool in self.tools:
            top_cwes = self.metrics.cwe_counts_per_tool[tool].most_common(20)
            total_count = sum(self.metrics.cwe_counts_per_tool[tool].values())
            
            prevalence_report[tool] = {
                'top_20_cwes': [
                    {
                        'cwe_id': cwe,
                        'count': count,
                        'percentage': round(count / total_count * 100, 2) if total_count > 0 else 0
                    }
                    for cwe, count in top_cwes
                ],
                'total_unique_cwes': len(self.metrics.cwe_counts_per_tool[tool]),
                'total_detections': total_count
            }
        
        with open(output_file, 'w') as f:
            json.dump(prevalence_report, f, indent=2)
        
        print(f"✓ Saved CWE prevalence to {output_file}")
        
        csv_file = self.output_dir / "cwe_prevalence.csv"
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Tool', 'CWE_ID', 'Count', 'Percentage'])
            
            for tool in self.tools:
                total = sum(self.metrics.cwe_counts_per_tool[tool].values())
                for cwe, count in self.metrics.cwe_counts_per_tool[tool].most_common(20):
                    pct = (count / total * 100) if total > 0 else 0
                    writer.writerow([tool, cwe, count, f"{pct:.2f}%"])
        
        print(f"✓ Saved CWE prevalence CSV to {csv_file}")
    
    def _generate_summary_statistics(self):
        """Generate summary statistics"""
        print("\n" + "="*80)
        print("SUMMARY STATISTICS")
        print("="*80)
        
        summary = {
            'metadata': {
                'total_apps': self.metrics.total_apps,
                'successful_analyses': self.metrics.successful_analyses,
                'failed_analyses': len(self.metrics.failed_analyses)
            },
            'rq1_scanner_effectiveness': {
                'detection_counts': {
                    tool: {
                        'mean': round(statistics.mean(counts), 2) if counts else 0,
                        'median': round(statistics.median(counts), 2) if counts else 0,
                        'std': round(statistics.stdev(counts), 2) if len(counts) > 1 else 0
                    }
                    for tool, counts in self.metrics.detection_counts.items()
                },
                'similarity_metrics': {
                    'file_overlap': self._summarize_dict(self.metrics.file_jaccard),
                    'vulnerability_location_overlap': self._summarize_dict(self.metrics.vuln_location_jaccard),
                    'semantic_overlap': self._summarize_dict(self.metrics.semantic_jaccard)
                },
                'cwe_coverage': {
                    tool: {
                        'unique_cwes': len(self.metrics.cwe_counts_per_tool[tool]),
                        'total_detections': sum(self.metrics.cwe_counts_per_tool[tool].values()),
                        'top_cwe': self.metrics.cwe_counts_per_tool[tool].most_common(1)[0][0] if self.metrics.cwe_counts_per_tool[tool] else None
                    }
                    for tool in self.tools
                }
            },
            'rq2_obfuscation_impact': {
                'detection_retention': {
                    tool: {
                        'mean': round(statistics.mean(ret), 3) if ret else 0,
                        'median': round(statistics.median(ret), 3) if ret else 0
                    }
                    for tool, ret in self.metrics.detection_retention.items()
                },
                'performance_overhead': {
                    tool: {
                        'mean_time_overhead_pct': round(statistics.mean(self.metrics.time_overhead.get(tool, [0])), 2) if self.metrics.time_overhead.get(tool) else None,
                        'mean_memory_overhead_pct': round(statistics.mean(self.metrics.memory_overhead.get(tool, [0])), 2) if self.metrics.memory_overhead.get(tool) else None
                    }
                    for tool in self.tools
                }
            },
            'rq4_hotspots': {
                'gini_coefficient': {
                    'mean': round(statistics.mean(self.metrics.gini_coefficients), 3) if self.metrics.gini_coefficients else 0,
                    'median': round(statistics.median(self.metrics.gini_coefficients), 3) if self.metrics.gini_coefficients else 0
                },
                'concentration_ratio': {
                    'mean': round(statistics.mean(self.metrics.concentration_ratios), 3) if self.metrics.concentration_ratios else 0,
                    'median': round(statistics.median(self.metrics.concentration_ratios), 3) if self.metrics.concentration_ratios else 0
                }
            }
        }
        
        # Add file type and severity to summary
        if self.metrics.file_type_counts:
            top_file_types = sorted(
                self.metrics.file_type_vulns['overall'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
            
            summary['file_type_analysis'] = {
                'top_10_file_types': [
                    {
                        'extension': ext,
                        'total_vulnerabilities': count,
                        'percentage': round(count / sum(self.metrics.file_type_vulns['overall'].values()) * 100, 2) if sum(self.metrics.file_type_vulns['overall'].values()) > 0 else 0
                    }
                    for ext, count in top_file_types
                ],
                'total_file_types': len(self.metrics.file_type_counts)
            }
        
        if self.metrics.severity_overall:
            total_severities = sum(self.metrics.severity_overall.values())
            
            summary['severity_distribution'] = {
                'overall': {
                    severity: {
                        'count': count,
                        'percentage': round(count / total_severities * 100, 2) if total_severities > 0 else 0
                    }
                    for severity, count in self.metrics.severity_overall.items()
                },
                'per_tool': {
                    tool: dict(self.metrics.severity_per_tool[tool])
                    for tool in self.tools
                }
            }
        
        output_file = self.output_dir / "summary_statistics.json"
        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"✓ Saved summary statistics to {output_file}")
        self._print_key_findings(summary)
    
    def _summarize_dict(self, data_dict: Dict[str, List]) -> Dict:
        """Helper to summarize a dictionary of lists"""
        return {
            key: {
                'mean': round(statistics.mean(values), 3) if values else 0,
                'median': round(statistics.median(values), 3) if values else 0
            }
            for key, values in data_dict.items()
        }
    
    def _export_to_csv(self):
        """Export metrics to CSV files"""
        print("\n" + "="*80)
        print("EXPORTING TO CSV")
        print("="*80)
        
        self._export_app_summaries()
        self._export_detection_counts()
        self._export_performance_vs_loc()
        self._export_file_type_analysis()     # NEW
        self._export_severity_analysis()      # NEW
        
        print("✓ CSV export complete")
    
    def _export_app_summaries(self):
        """Export per-app summary data"""
        output_file = self.output_dir / "app_summaries.csv"
        with open(output_file, 'w', newline='') as f:
            fieldnames = ['app_name', 'lines_of_code', 'function_count',
                         'total_findings_normal', 'total_findings_obfuscated',
                         'most_effective_tool', 'obfuscation_resilience',
                         'vulnerability_concentration']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.metrics.app_summaries)
        print(f"  → {output_file}")
    
    def _export_detection_counts(self):
        """Export detection counts"""
        output_file = self.output_dir / "detection_counts.csv"
        rows = []
        for i in range(len(self.metrics.app_summaries)):
            row = {'app_name': self.metrics.app_summaries[i]['app_name']}
            for tool in self.tools:
                row[f'{tool}_normal'] = self.metrics.detection_counts[f'{tool}_normal'][i] if i < len(self.metrics.detection_counts[f'{tool}_normal']) else 0
                row[f'{tool}_obfuscated'] = self.metrics.detection_counts[f'{tool}_obfuscated'][i] if i < len(self.metrics.detection_counts[f'{tool}_obfuscated']) else 0
            rows.append(row)
        
        with open(output_file, 'w', newline='') as f:
            fieldnames = ['app_name'] + [f'{tool}_{apk}' for tool in self.tools for apk in ['normal', 'obfuscated']]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        print(f"  → {output_file}")
    
    def _export_performance_vs_loc(self):
        """Export performance metrics vs LOC"""
        output_file = self.output_dir / "performance_vs_loc.csv"
        rows = []
        for i in range(len(self.metrics.app_summaries)):
            row = {
                'app_name': self.metrics.app_summaries[i]['app_name'],
                'lines_of_code': self.metrics.lines_of_code[i] if i < len(self.metrics.lines_of_code) else 0
            }
            
            for tool in self.tools:
                if i < len(self.metrics.tool_execution_times[tool]):
                    row[f'{tool}_time_seconds'] = self.metrics.tool_execution_times[tool][i]
                if i < len(self.metrics.tool_memory_usage[tool]):
                    row[f'{tool}_memory_mb'] = self.metrics.tool_memory_usage[tool][i]
            
            rows.append(row)
        
        with open(output_file, 'w', newline='') as f:
            if rows:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
        print(f"  → {output_file}")
    
    def _export_file_type_analysis(self):
        """Export file type analysis to CSV"""
        output_file = self.output_dir / "file_type_analysis.csv"
        
        if not self.metrics.file_type_counts:
            print(f"  ⚠️  No file type data to export")
            return
        
        rows = []
        for ext in self.metrics.file_type_counts.keys():
            row = {
                'file_extension': ext,
                'total_vulnerabilities': self.metrics.file_type_vulns['overall'][ext],
                'app_count': self.metrics.file_type_counts[ext],
                'avg_per_file': round(self.metrics.file_type_vulns['overall'][ext] / max(1, self.metrics.file_type_counts[ext]), 2)
            }
            
            for tool in self.tools:
                row[f'{tool}_count'] = self.metrics.file_type_vulns[tool].get(ext, 0)
            
            rows.append(row)
        
        rows = sorted(rows, key=lambda x: x['total_vulnerabilities'], reverse=True)
        
        with open(output_file, 'w', newline='') as f:
            if rows:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
        
        print(f"  → {output_file}")
    
    def _export_severity_analysis(self):
        """Export severity distribution to CSV"""
        output_file = self.output_dir / "severity_distribution.csv"
        
        if not self.metrics.severity_overall:
            print(f"  ⚠️  No severity data to export")
            return
        
        rows = []
        
        # Overall row
        overall_row = {'category': 'OVERALL'}
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
            overall_row[severity] = self.metrics.severity_overall.get(severity, 0)
        rows.append(overall_row)
        
        # Per-tool rows
        for tool in self.tools:
            tool_row = {'category': tool.upper()}
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
                tool_row[severity] = self.metrics.severity_per_tool[tool].get(severity, 0)
            rows.append(tool_row)
        
        with open(output_file, 'w', newline='') as f:
            fieldnames = ['category', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        
        print(f"  → {output_file}")
    
    def generate_file_type_concentration_data(self):
        """
        Generate file type concentration analysis from per-app JSON files.
        Creates two CSV files for RQ4 file type hotspot visualizations.
        """
        print("\n" + "="*80)
        print("GENERATING FILE TYPE CONCENTRATION DATA")
        print("="*80)
        
        import numpy as np
        
        # Data structures
        file_type_aggregates = {}  # Aggregate stats per file type
        per_app_file_type_data = []  # Per-app, per-file-type data
        
        # Get all analysis JSON files
        analysis_files = list(self.results_dir.glob("*/*_comprehensive_analysis.json"))
        
        for app_json_path in analysis_files:
            try:
                with open(app_json_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                app_name = data.get('app_name', app_json_path.stem)
                
                # Get hotspot data
                hotspot_data = data.get('rq4_hotspot_patterns', {})
                top_hotspots_normal = hotspot_data.get('top_hotspots', {}).get('normal', [])
                
                if not top_hotspots_normal:
                    continue
                
                # Calculate per-file-type metrics for this app
                file_type_vulns = {}  # {'.java': [vuln_counts_per_file], ...}
                
                for hotspot in top_hotspots_normal:
                    file_path = hotspot.get('file', '')
                    total_vulns = hotspot.get('total_vulns', 0)
                    
                    if not file_path or total_vulns == 0:
                        continue
                    
                    # Extract file extension
                    if '.' in file_path:
                        ext = '.' + file_path.split('.')[-1].lower()
                    else:
                        ext = 'no_extension'
                    
                    if ext not in file_type_vulns:
                        file_type_vulns[ext] = []
                    
                    file_type_vulns[ext].append(total_vulns)
                
                # Calculate Gini coefficient per file type for this app
                app_file_type_row = {'app_name': app_name}
                primary_hotspot_type = None
                max_concentration = 0
                
                for ext, vuln_counts in file_type_vulns.items():
                    if len(vuln_counts) == 0:
                        continue
                    
                    # Calculate Gini for this file type in this app
                    gini = self._calculate_gini(vuln_counts)
                    app_file_type_row[f'gini_{ext}'] = gini
                    
                    # Track which file type is the primary hotspot
                    total_app_vulns = sum(sum(counts) for counts in file_type_vulns.values())
                    type_vulns = sum(vuln_counts)
                    concentration = type_vulns / total_app_vulns if total_app_vulns > 0 else 0
                    
                    if concentration > max_concentration:
                        max_concentration = concentration
                        primary_hotspot_type = ext
                    
                    # Aggregate data for this file type across all apps
                    if ext not in file_type_aggregates:
                        file_type_aggregates[ext] = {
                            'gini_values': [],
                            'total_files': 0,
                            'total_vulnerabilities': 0,
                            'vuln_counts_per_file': [],
                            'apps_with_hotspot': 0  # Apps where this type has >50% of vulns
                        }
                    
                    file_type_aggregates[ext]['gini_values'].append(gini)
                    file_type_aggregates[ext]['total_files'] += len(vuln_counts)
                    file_type_aggregates[ext]['total_vulnerabilities'] += sum(vuln_counts)
                    file_type_aggregates[ext]['vuln_counts_per_file'].extend(vuln_counts)
                    
                    if concentration > 0.5:
                        file_type_aggregates[ext]['apps_with_hotspot'] += 1
                
                app_file_type_row['primary_hotspot_file_type'] = primary_hotspot_type
                per_app_file_type_data.append(app_file_type_row)
                
            except Exception as e:
                print(f"  ⚠️  Error processing {app_json_path.name}: {e}")
                continue
        
        # Calculate aggregate statistics
        total_apps = len(per_app_file_type_data)
        
        if total_apps == 0:
            print("  ⚠️  No file type concentration data found")
            return
        
        file_type_summary = []
        for ext, stats in file_type_aggregates.items():
            if len(stats['gini_values']) == 0:
                continue
            
            avg_gini = statistics.mean(stats['gini_values'])
            std_gini = statistics.stdev(stats['gini_values']) if len(stats['gini_values']) > 1 else 0
            avg_vulns_per_file = (stats['total_vulnerabilities'] / stats['total_files'] 
                                if stats['total_files'] > 0 else 0)
            hotspot_frequency = stats['apps_with_hotspot'] / total_apps if total_apps > 0 else 0
            
            file_type_summary.append({
                'file_type': ext,
                'avg_gini': round(avg_gini, 4),
                'std_gini': round(std_gini, 4),
                'hotspot_frequency': round(hotspot_frequency, 4),
                'avg_vulnerabilities_per_file': round(avg_vulns_per_file, 2),
                'total_apps': len(stats['gini_values']),
                'total_files': stats['total_files'],
                'total_vulnerabilities': stats['total_vulnerabilities']
            })
        
        # Save file_type_concentration.csv
        if file_type_summary:
            import pandas as pd
            df_summary = pd.DataFrame(file_type_summary)
            df_summary = df_summary.sort_values('avg_gini', ascending=False)
            df_summary.to_csv(self.output_dir / "file_type_concentration.csv", index=False)
            print(f"  ✓ Saved file_type_concentration.csv ({len(df_summary)} file types)")
        
        # Save per_app_file_type_concentration.csv
        if per_app_file_type_data:
            import pandas as pd
            df_per_app = pd.DataFrame(per_app_file_type_data)
            df_per_app.to_csv(self.output_dir / "per_app_file_type_concentration.csv", index=False)
            print(f"  ✓ Saved per_app_file_type_concentration.csv ({len(df_per_app)} apps)")
        
        # Print summary statistics
        print("\n📊 File Type Concentration Summary:")
        if file_type_summary:
            print(f"{'File Type':<15} {'Avg Gini':<12} {'Hotspot %':<12} {'Avg Vulns':<12} {'Apps':<8}")
            print("-" * 65)
            sorted_summary = sorted(file_type_summary, key=lambda x: x['avg_gini'], reverse=True)[:10]
            for item in sorted_summary:
                print(f"{item['file_type']:<15} {item['avg_gini']:<12.3f} "
                    f"{item['hotspot_frequency']*100:<11.1f}% {item['avg_vulnerabilities_per_file']:<12.2f} "
                    f"{item['total_apps']:<8}")
    
    
    
    def _print_key_findings(self, summary: Dict):
        """Print key findings"""
        print("\n" + "="*80)
        print("KEY FINDINGS")
        print("="*80)
        
        rq1 = summary['rq1_scanner_effectiveness']
        rq2 = summary['rq2_obfuscation_impact']
        
        print("\nRQ1: Scanner Effectiveness")
        normal_counts = {k: v['mean'] for k, v in rq1['detection_counts'].items() if 'normal' in k}
        best_tool = max(normal_counts.items(), key=lambda x: x[1])
        print(f"  Most detections: {best_tool[0].replace('_normal', '')} ({best_tool[1]:.1f} avg)")
        
        print("\nRQ2: Obfuscation Impact")
        retention = [(tool, data['mean']) for tool, data in rq2['detection_retention'].items()]
        best = max(retention, key=lambda x: x[1])
        worst = min(retention, key=lambda x: x[1])
        print(f"  Most resilient: {best[0]} ({best[1]:.1%} retention)")
        print(f"  Most affected: {worst[0]} ({worst[1]:.1%} retention)")
        
        # Print file type and severity stats if available
        if 'file_type_analysis' in summary:
            print("\nFile Type Analysis:")
            top_types = summary['file_type_analysis']['top_10_file_types'][:3]
            for ft in top_types:
                print(f"  {ft['extension']}: {ft['total_vulnerabilities']} vulns ({ft['percentage']:.1f}%)")
        
        if 'severity_distribution' in summary:
            print("\nSeverity Distribution:")
            for sev, data in summary['severity_distribution']['overall'].items():
                if data['count'] > 0:
                    print(f"  {sev}: {data['count']} ({data['percentage']:.1f}%)")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python complete_aggregate.py <results_directory>")
        print("Example: python complete_aggregate.py downloaded_results")
        sys.exit(1)
    
    aggregator = CompleteSASTAggregator(sys.argv[1])
    aggregator.aggregate_all()
