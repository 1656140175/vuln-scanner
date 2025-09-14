"""Result aggregation and processing system."""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from collections import defaultdict
from dataclasses import asdict

from .data_structures import ScanResult, ScanSeverity, ScanPhase, ScanJob
from ..exceptions import ScanEngineException


class ResultAggregationError(ScanEngineException):
    """Result aggregation error."""
    pass


class ResultAggregator:
    """Aggregates and processes scan results for analysis and reporting."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize result aggregator.
        
        Args:
            config: System configuration
        """
        self.config = config
        self.logger = logging.getLogger('result_aggregator')
        
        # Aggregation settings
        self.duplicate_threshold = config.get('aggregation', {}).get('duplicate_threshold', 0.8)
        self.correlation_window = config.get('aggregation', {}).get('correlation_window', 300)  # seconds
        self.confidence_threshold = config.get('aggregation', {}).get('confidence_threshold', 0.7)
    
    def aggregate_job_results(self, job: ScanJob) -> Dict[str, Any]:
        """Aggregate all results for a scan job.
        
        Args:
            job: Scan job with results
            
        Returns:
            Aggregated results summary
        """
        self.logger.info(f"Aggregating results for job {job.job_id} ({len(job.results)} results)")
        
        if not job.results:
            return self._empty_aggregation(job.job_id)
        
        # Basic statistics
        stats = self._calculate_basic_stats(job.results)
        
        # Severity distribution
        severity_dist = self._calculate_severity_distribution(job.results)
        
        # Phase breakdown
        phase_breakdown = self._calculate_phase_breakdown(job.results)
        
        # Tool performance
        tool_performance = self._calculate_tool_performance(job.results)
        
        # Deduplicated results
        unique_results = self._deduplicate_results(job.results)
        
        # High-value findings
        high_value_findings = self._identify_high_value_findings(unique_results)
        
        # Correlated findings
        correlated_findings = self._correlate_findings(unique_results)
        
        # Risk assessment
        risk_assessment = self._assess_risk_level(unique_results)
        
        aggregation = {
            'job_id': job.job_id,
            'target': job.target.target,
            'scan_profile': job.scan_profile,
            'aggregation_timestamp': datetime.now().isoformat(),
            'statistics': stats,
            'severity_distribution': severity_dist,
            'phase_breakdown': phase_breakdown,
            'tool_performance': tool_performance,
            'unique_results_count': len(unique_results),
            'duplicates_removed': len(job.results) - len(unique_results),
            'high_value_findings': high_value_findings,
            'correlated_findings': correlated_findings,
            'risk_assessment': risk_assessment,
            'recommendations': self._generate_recommendations(unique_results, job)
        }
        
        self.logger.info(f"Aggregation complete: {len(unique_results)} unique findings, "
                        f"risk level: {risk_assessment['level']}")
        
        return aggregation
    
    def _empty_aggregation(self, job_id: str) -> Dict[str, Any]:
        """Create empty aggregation for jobs with no results.
        
        Args:
            job_id: Scan job ID
            
        Returns:
            Empty aggregation structure
        """
        return {
            'job_id': job_id,
            'aggregation_timestamp': datetime.now().isoformat(),
            'statistics': {'total_results': 0},
            'severity_distribution': {},
            'phase_breakdown': {},
            'tool_performance': {},
            'unique_results_count': 0,
            'duplicates_removed': 0,
            'high_value_findings': [],
            'correlated_findings': [],
            'risk_assessment': {'level': 'NONE', 'score': 0},
            'recommendations': []
        }
    
    def _calculate_basic_stats(self, results: List[ScanResult]) -> Dict[str, Any]:
        """Calculate basic statistics for results.
        
        Args:
            results: List of scan results
            
        Returns:
            Basic statistics dictionary
        """
        if not results:
            return {'total_results': 0}
        
        total_results = len(results)
        unique_targets = len(set(result.target.target for result in results))
        unique_tools = len(set(result.tool for result in results))
        
        # Calculate average confidence
        confidences = [result.confidence for result in results]
        avg_confidence = sum(confidences) / len(confidences)
        
        # Calculate false positive likelihood
        fp_likelihoods = [result.false_positive_likelihood for result in results]
        avg_fp_likelihood = sum(fp_likelihoods) / len(fp_likelihoods)
        
        # Time span
        timestamps = [result.timestamp for result in results]
        time_span = (max(timestamps) - min(timestamps)).total_seconds() if len(timestamps) > 1 else 0
        
        return {
            'total_results': total_results,
            'unique_targets': unique_targets,
            'unique_tools': unique_tools,
            'average_confidence': round(avg_confidence, 3),
            'average_false_positive_likelihood': round(avg_fp_likelihood, 3),
            'time_span_seconds': round(time_span, 2),
            'earliest_result': min(timestamps).isoformat(),
            'latest_result': max(timestamps).isoformat()
        }
    
    def _calculate_severity_distribution(self, results: List[ScanResult]) -> Dict[str, Any]:
        """Calculate severity distribution of results.
        
        Args:
            results: List of scan results
            
        Returns:
            Severity distribution dictionary
        """
        severity_counts = defaultdict(int)
        for result in results:
            severity_counts[result.severity.value] += 1
        
        total = len(results)
        distribution = {}
        
        for severity in ScanSeverity:
            count = severity_counts[severity.value]
            percentage = (count / total * 100) if total > 0 else 0
            distribution[severity.value] = {
                'count': count,
                'percentage': round(percentage, 2)
            }
        
        return distribution
    
    def _calculate_phase_breakdown(self, results: List[ScanResult]) -> Dict[str, Any]:
        """Calculate breakdown of results by scan phase.
        
        Args:
            results: List of scan results
            
        Returns:
            Phase breakdown dictionary
        """
        phase_data = defaultdict(lambda: {
            'count': 0,
            'tools': set(),
            'severities': defaultdict(int)
        })
        
        for result in results:
            phase_key = result.phase.value
            phase_data[phase_key]['count'] += 1
            phase_data[phase_key]['tools'].add(result.tool)
            phase_data[phase_key]['severities'][result.severity.value] += 1
        
        # Convert sets to lists for JSON serialization
        breakdown = {}
        for phase, data in phase_data.items():
            breakdown[phase] = {
                'count': data['count'],
                'unique_tools': list(data['tools']),
                'tool_count': len(data['tools']),
                'severity_breakdown': dict(data['severities'])
            }
        
        return breakdown
    
    def _calculate_tool_performance(self, results: List[ScanResult]) -> Dict[str, Any]:
        """Calculate tool performance metrics.
        
        Args:
            results: List of scan results
            
        Returns:
            Tool performance dictionary
        """
        tool_data = defaultdict(lambda: {
            'results': 0,
            'high_confidence': 0,
            'high_severity': 0,
            'phases': set(),
            'avg_confidence': []
        })
        
        for result in results:
            tool = result.tool
            tool_data[tool]['results'] += 1
            tool_data[tool]['avg_confidence'].append(result.confidence)
            tool_data[tool]['phases'].add(result.phase.value)
            
            if result.confidence >= 0.8:
                tool_data[tool]['high_confidence'] += 1
            
            if result.severity in [ScanSeverity.HIGH, ScanSeverity.CRITICAL]:
                tool_data[tool]['high_severity'] += 1
        
        # Calculate final metrics
        performance = {}
        for tool, data in tool_data.items():
            avg_conf = sum(data['avg_confidence']) / len(data['avg_confidence'])
            performance[tool] = {
                'total_results': data['results'],
                'high_confidence_results': data['high_confidence'],
                'high_severity_results': data['high_severity'],
                'average_confidence': round(avg_conf, 3),
                'phases_used': list(data['phases']),
                'effectiveness_score': self._calculate_tool_effectiveness(data, avg_conf)
            }
        
        return performance
    
    def _calculate_tool_effectiveness(self, tool_data: Dict[str, Any], avg_confidence: float) -> float:
        """Calculate tool effectiveness score.
        
        Args:
            tool_data: Tool performance data
            avg_confidence: Average confidence score
            
        Returns:
            Effectiveness score (0-1)
        """
        if tool_data['results'] == 0:
            return 0.0
        
        # Weight factors
        confidence_weight = 0.4
        high_severity_weight = 0.3
        result_count_weight = 0.2
        phase_coverage_weight = 0.1
        
        # Normalize metrics
        confidence_score = avg_confidence
        high_severity_ratio = tool_data['high_severity'] / tool_data['results']
        result_score = min(tool_data['results'] / 10, 1.0)  # Cap at 10 results for normalization
        phase_score = len(tool_data['phases']) / len(ScanPhase)
        
        effectiveness = (
            confidence_score * confidence_weight +
            high_severity_ratio * high_severity_weight +
            result_score * result_count_weight +
            phase_score * phase_coverage_weight
        )
        
        return round(effectiveness, 3)
    
    def _deduplicate_results(self, results: List[ScanResult]) -> List[ScanResult]:
        """Remove duplicate results based on similarity.
        
        Args:
            results: List of scan results
            
        Returns:
            List of unique results
        """
        unique_results = []
        
        for result in results:
            is_duplicate = False
            
            for existing in unique_results:
                similarity = self._calculate_result_similarity(result, existing)
                if similarity >= self.duplicate_threshold:
                    is_duplicate = True
                    
                    # Keep the result with higher confidence
                    if result.confidence > existing.confidence:
                        unique_results.remove(existing)
                        unique_results.append(result)
                    
                    break
            
            if not is_duplicate:
                unique_results.append(result)
        
        self.logger.debug(f"Deduplication: {len(results)} -> {len(unique_results)} results")
        return unique_results
    
    def _calculate_result_similarity(self, result1: ScanResult, result2: ScanResult) -> float:
        """Calculate similarity between two results.
        
        Args:
            result1: First result
            result2: Second result
            
        Returns:
            Similarity score (0-1)
        """
        # Different tools can't be duplicates
        if result1.tool != result2.tool:
            return 0.0
        
        # Different phases can't be duplicates
        if result1.phase != result2.phase:
            return 0.0
        
        # Different targets can't be duplicates
        if result1.target.target != result2.target.target:
            return 0.0
        
        # Compare data content
        data_similarity = self._compare_result_data(result1.data, result2.data)
        
        # Compare severity (exact match required for high similarity)
        severity_similarity = 1.0 if result1.severity == result2.severity else 0.5
        
        # Weighted similarity
        return (data_similarity * 0.7) + (severity_similarity * 0.3)
    
    def _compare_result_data(self, data1: Dict[str, Any], data2: Dict[str, Any]) -> float:
        """Compare similarity of result data dictionaries.
        
        Args:
            data1: First data dictionary
            data2: Second data dictionary
            
        Returns:
            Data similarity score (0-1)
        """
        if not data1 or not data2:
            return 0.0
        
        # Get common keys
        keys1 = set(data1.keys())
        keys2 = set(data2.keys())
        common_keys = keys1.intersection(keys2)
        all_keys = keys1.union(keys2)
        
        if not common_keys:
            return 0.0
        
        # Compare values for common keys
        matches = 0
        for key in common_keys:
            if data1[key] == data2[key]:
                matches += 1
        
        # Calculate similarity based on key overlap and value matches
        key_similarity = len(common_keys) / len(all_keys)
        value_similarity = matches / len(common_keys)
        
        return (key_similarity + value_similarity) / 2
    
    def _identify_high_value_findings(self, results: List[ScanResult]) -> List[Dict[str, Any]]:
        """Identify high-value findings from results.
        
        Args:
            results: List of unique scan results
            
        Returns:
            List of high-value findings
        """
        high_value = []
        
        for result in results:
            score = self._calculate_finding_value_score(result)
            
            if score >= 0.7:  # High-value threshold
                finding = {
                    'result_id': f"{result.scan_id}_{result.tool}_{result.timestamp.timestamp()}",
                    'tool': result.tool,
                    'phase': result.phase.value,
                    'severity': result.severity.value,
                    'confidence': result.confidence,
                    'value_score': score,
                    'data': result.data,
                    'timestamp': result.timestamp.isoformat(),
                    'reason': self._explain_value_score(result, score)
                }
                high_value.append(finding)
        
        # Sort by value score
        high_value.sort(key=lambda x: x['value_score'], reverse=True)
        
        self.logger.debug(f"Identified {len(high_value)} high-value findings")
        return high_value
    
    def _calculate_finding_value_score(self, result: ScanResult) -> float:
        """Calculate value score for a finding.
        
        Args:
            result: Scan result
            
        Returns:
            Value score (0-1)
        """
        # Base score from severity
        severity_scores = {
            ScanSeverity.INFO: 0.2,
            ScanSeverity.LOW: 0.4,
            ScanSeverity.MEDIUM: 0.6,
            ScanSeverity.HIGH: 0.8,
            ScanSeverity.CRITICAL: 1.0
        }
        base_score = severity_scores.get(result.severity, 0.2)
        
        # Adjust for confidence
        confidence_factor = result.confidence
        
        # Adjust for false positive likelihood (inverse)
        fp_factor = 1.0 - result.false_positive_likelihood
        
        # Special scoring for specific finding types
        data_bonus = self._calculate_data_value_bonus(result.data)
        
        # Calculate final score
        score = (base_score * confidence_factor * fp_factor) + data_bonus
        return min(score, 1.0)  # Cap at 1.0
    
    def _calculate_data_value_bonus(self, data: Dict[str, Any]) -> float:
        """Calculate bonus score based on finding data content.
        
        Args:
            data: Result data dictionary
            
        Returns:
            Bonus score (0-0.3)
        """
        bonus = 0.0
        
        finding_type = data.get('type', '').lower()
        
        # High-value finding types
        if finding_type in ['vulnerability', 'exploit', 'sensitive_data']:
            bonus += 0.2
        elif finding_type in ['open_port', 'service', 'subdomain']:
            bonus += 0.1
        
        # Check for specific high-value indicators
        if 'admin' in str(data).lower() or 'password' in str(data).lower():
            bonus += 0.1
        
        if 'sql' in str(data).lower() or 'xss' in str(data).lower():
            bonus += 0.15
        
        return min(bonus, 0.3)  # Cap bonus at 0.3
    
    def _explain_value_score(self, result: ScanResult, score: float) -> str:
        """Generate explanation for value score.
        
        Args:
            result: Scan result
            score: Calculated value score
            
        Returns:
            Human-readable explanation
        """
        reasons = []
        
        if result.severity in [ScanSeverity.HIGH, ScanSeverity.CRITICAL]:
            reasons.append(f"High/Critical severity ({result.severity.value})")
        
        if result.confidence >= 0.9:
            reasons.append("High confidence")
        elif result.confidence >= 0.8:
            reasons.append("Good confidence")
        
        if result.false_positive_likelihood <= 0.1:
            reasons.append("Low false positive likelihood")
        
        finding_type = result.data.get('type', '')
        if finding_type in ['vulnerability', 'exploit']:
            reasons.append("Security vulnerability detected")
        
        return "; ".join(reasons) if reasons else "General finding"
    
    def _correlate_findings(self, results: List[ScanResult]) -> List[Dict[str, Any]]:
        """Correlate related findings across tools and phases.
        
        Args:
            results: List of unique scan results
            
        Returns:
            List of correlated finding groups
        """
        correlations = []
        processed = set()
        
        for i, result in enumerate(results):
            if i in processed:
                continue
            
            # Find related results
            related_results = [result]
            related_indices = {i}
            
            for j, other_result in enumerate(results[i+1:], i+1):
                if j in processed:
                    continue
                
                if self._are_results_correlated(result, other_result):
                    related_results.append(other_result)
                    related_indices.add(j)
            
            if len(related_results) > 1:  # Only include correlations with multiple results
                correlation = {
                    'correlation_id': f"corr_{len(correlations)}",
                    'primary_result': result.tool,
                    'related_count': len(related_results),
                    'correlation_strength': self._calculate_correlation_strength(related_results),
                    'findings': [
                        {
                            'tool': r.tool,
                            'phase': r.phase.value,
                            'severity': r.severity.value,
                            'data_type': r.data.get('type', 'unknown'),
                            'timestamp': r.timestamp.isoformat()
                        }
                        for r in related_results
                    ],
                    'correlation_reason': self._explain_correlation(related_results)
                }
                correlations.append(correlation)
                processed.update(related_indices)
        
        self.logger.debug(f"Found {len(correlations)} correlated finding groups")
        return correlations
    
    def _are_results_correlated(self, result1: ScanResult, result2: ScanResult) -> bool:
        """Check if two results are correlated.
        
        Args:
            result1: First result
            result2: Second result
            
        Returns:
            True if results are correlated
        """
        # Same target required
        if result1.target.target != result2.target.target:
            return False
        
        # Time correlation (within window)
        time_diff = abs((result1.timestamp - result2.timestamp).total_seconds())
        if time_diff > self.correlation_window:
            return False
        
        # Content correlation
        data1 = result1.data
        data2 = result2.data
        
        # Check for related ports/services
        if data1.get('type') == 'open_port' and data2.get('type') == 'vulnerability':
            port1 = data1.get('port')
            port2 = data2.get('port')
            if port1 and port2 and port1 == port2:
                return True
        
        # Check for related URLs/paths
        url1 = data1.get('url', '') or data1.get('matched_at', '')
        url2 = data2.get('url', '') or data2.get('matched_at', '')
        if url1 and url2 and url1 == url2:
            return True
        
        # Check for service correlation
        service1 = data1.get('service', '').lower()
        service2 = data2.get('service', '').lower()
        if service1 and service2 and service1 == service2:
            return True
        
        return False
    
    def _calculate_correlation_strength(self, results: List[ScanResult]) -> float:
        """Calculate strength of correlation between results.
        
        Args:
            results: List of correlated results
            
        Returns:
            Correlation strength (0-1)
        """
        if len(results) < 2:
            return 0.0
        
        # Factor in number of related results
        count_factor = min(len(results) / 5, 1.0)  # Max benefit at 5 results
        
        # Factor in time clustering
        timestamps = [r.timestamp for r in results]
        time_span = (max(timestamps) - min(timestamps)).total_seconds()
        time_factor = max(0, 1.0 - (time_span / self.correlation_window))
        
        # Factor in severity consistency
        severities = [r.severity for r in results]
        high_severity_count = sum(1 for s in severities if s in [ScanSeverity.HIGH, ScanSeverity.CRITICAL])
        severity_factor = high_severity_count / len(results)
        
        strength = (count_factor * 0.4) + (time_factor * 0.3) + (severity_factor * 0.3)
        return round(strength, 3)
    
    def _explain_correlation(self, results: List[ScanResult]) -> str:
        """Explain why results are correlated.
        
        Args:
            results: List of correlated results
            
        Returns:
            Human-readable explanation
        """
        if len(results) < 2:
            return "No correlation"
        
        tools = [r.tool for r in results]
        phases = [r.phase.value for r in results]
        
        return f"Related findings from {len(set(tools))} tools across {len(set(phases))} phases"
    
    def _assess_risk_level(self, results: List[ScanResult]) -> Dict[str, Any]:
        """Assess overall risk level based on findings.
        
        Args:
            results: List of unique scan results
            
        Returns:
            Risk assessment dictionary
        """
        if not results:
            return {'level': 'NONE', 'score': 0, 'factors': []}
        
        # Count by severity
        severity_counts = defaultdict(int)
        for result in results:
            severity_counts[result.severity] += 1
        
        # Calculate base risk score
        risk_score = (
            severity_counts[ScanSeverity.CRITICAL] * 10 +
            severity_counts[ScanSeverity.HIGH] * 5 +
            severity_counts[ScanSeverity.MEDIUM] * 2 +
            severity_counts[ScanSeverity.LOW] * 1 +
            severity_counts[ScanSeverity.INFO] * 0.1
        )
        
        # Apply confidence weighting
        total_confidence = sum(r.confidence for r in results)
        avg_confidence = total_confidence / len(results)
        confidence_weighted_score = risk_score * avg_confidence
        
        # Determine risk level
        if confidence_weighted_score >= 20:
            risk_level = 'CRITICAL'
        elif confidence_weighted_score >= 10:
            risk_level = 'HIGH'
        elif confidence_weighted_score >= 5:
            risk_level = 'MEDIUM'
        elif confidence_weighted_score >= 1:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        # Identify risk factors
        factors = []
        if severity_counts[ScanSeverity.CRITICAL] > 0:
            factors.append(f"{severity_counts[ScanSeverity.CRITICAL]} critical vulnerabilities")
        if severity_counts[ScanSeverity.HIGH] > 0:
            factors.append(f"{severity_counts[ScanSeverity.HIGH]} high severity findings")
        if avg_confidence >= 0.9:
            factors.append("High confidence in findings")
        if len(results) > 20:
            factors.append("High number of findings")
        
        return {
            'level': risk_level,
            'score': round(confidence_weighted_score, 2),
            'raw_score': round(risk_score, 2),
            'confidence_factor': round(avg_confidence, 3),
            'severity_breakdown': {s.value: severity_counts[s] for s in ScanSeverity},
            'factors': factors
        }
    
    def _generate_recommendations(self, results: List[ScanResult], job: ScanJob) -> List[Dict[str, Any]]:
        """Generate recommendations based on findings.
        
        Args:
            results: List of unique scan results
            job: Original scan job
            
        Returns:
            List of recommendation dictionaries
        """
        recommendations = []
        
        # Analyze results for recommendations
        severity_counts = defaultdict(int)
        finding_types = defaultdict(int)
        tools_used = set()
        
        for result in results:
            severity_counts[result.severity] += 1
            finding_types[result.data.get('type', 'unknown')] += 1
            tools_used.add(result.tool)
        
        # Critical/High severity recommendations
        if severity_counts[ScanSeverity.CRITICAL] > 0:
            recommendations.append({
                'type': 'urgent_action',
                'priority': 'critical',
                'title': 'Critical Vulnerabilities Detected',
                'description': f"Immediate attention required for {severity_counts[ScanSeverity.CRITICAL]} critical vulnerabilities",
                'action': 'Review and remediate critical findings immediately'
            })
        
        if severity_counts[ScanSeverity.HIGH] > 0:
            recommendations.append({
                'type': 'high_priority',
                'priority': 'high',
                'title': 'High Severity Issues Found',
                'description': f"Address {severity_counts[ScanSeverity.HIGH]} high severity findings",
                'action': 'Plan remediation within 24-48 hours'
            })
        
        # Tool-specific recommendations
        missing_tools = self._identify_missing_tools(tools_used, job.scan_profile)
        if missing_tools:
            recommendations.append({
                'type': 'scan_improvement',
                'priority': 'medium',
                'title': 'Additional Scanning Recommended',
                'description': f"Consider using {', '.join(missing_tools)} for comprehensive coverage",
                'action': f"Run supplemental scans with: {', '.join(missing_tools)}"
            })
        
        # Finding type recommendations
        if finding_types.get('open_port', 0) > 10:
            recommendations.append({
                'type': 'security_hardening',
                'priority': 'medium',
                'title': 'Excessive Open Ports',
                'description': f"{finding_types['open_port']} open ports detected",
                'action': 'Review and close unnecessary ports, implement port filtering'
            })
        
        if finding_types.get('vulnerability', 0) > 0:
            recommendations.append({
                'type': 'vulnerability_management',
                'priority': 'high',
                'title': 'Vulnerability Patching Required',
                'description': f"{finding_types['vulnerability']} vulnerabilities require attention",
                'action': 'Implement vulnerability management process, prioritize by severity'
            })
        
        # General recommendations
        if len(results) == 0:
            recommendations.append({
                'type': 'scan_validation',
                'priority': 'low',
                'title': 'No Issues Detected',
                'description': 'Scan completed with no significant findings',
                'action': 'Consider running more comprehensive scans or different scan profiles'
            })
        
        return recommendations
    
    def _identify_missing_tools(self, tools_used: Set[str], scan_profile: str) -> List[str]:
        """Identify potentially useful tools not used in scan.
        
        Args:
            tools_used: Set of tools that were used
            scan_profile: Scan profile that was executed
            
        Returns:
            List of recommended additional tools
        """
        # Define tool recommendations by profile
        profile_tools = {
            'quick': ['nmap', 'nuclei'],
            'comprehensive': ['nmap', 'nuclei', 'gobuster', 'subfinder'],
            'webapp': ['httpx', 'gobuster', 'nuclei']
        }
        
        recommended = profile_tools.get(scan_profile, [])
        missing = [tool for tool in recommended if tool not in tools_used]
        
        return missing