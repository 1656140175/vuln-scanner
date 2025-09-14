"""Template management system for reports."""

import os
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from jinja2 import Environment, FileSystemLoader, Template, select_autoescape, TemplateNotFound

from .models import VulnerabilityReport, SeverityLevel, RiskLevel
from .config import ReportConfig, ReportFormat


class TemplateError(Exception):
    """Template-related error."""
    pass


class TemplateManager:
    """Manages report templates using Jinja2."""
    
    def __init__(self, template_path: Union[str, Path]):
        """Initialize template manager.
        
        Args:
            template_path: Path to template directory
        """
        self.template_path = Path(template_path)
        self.logger = logging.getLogger('template_manager')
        
        # Ensure template directory exists
        self.template_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_path)),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Register custom filters
        self._register_custom_filters()
        
        # Register custom functions
        self._register_custom_functions()
        
        self.logger.info(f"Template manager initialized with path: {self.template_path}")
    
    def _register_custom_filters(self) -> None:
        """Register custom Jinja2 filters for report generation."""
        
        @self.jinja_env.finalize
        def finalize(value):
            """Custom finalizer to handle None values."""
            if value is None:
                return ''
            return value
        
        @self.jinja_env.filter('severity_color')
        def severity_color_filter(severity: Union[str, SeverityLevel]) -> str:
            """Get CSS color class for severity level."""
            if isinstance(severity, str):
                severity = SeverityLevel(severity.lower())
            
            color_map = {
                SeverityLevel.CRITICAL: 'danger',
                SeverityLevel.HIGH: 'warning', 
                SeverityLevel.MEDIUM: 'info',
                SeverityLevel.LOW: 'secondary',
                SeverityLevel.INFO: 'light'
            }
            return color_map.get(severity, 'secondary')
        
        @self.jinja_env.filter('severity_icon')
        def severity_icon_filter(severity: Union[str, SeverityLevel]) -> str:
            """Get icon class for severity level."""
            if isinstance(severity, str):
                severity = SeverityLevel(severity.lower())
            
            icon_map = {
                SeverityLevel.CRITICAL: 'fas fa-exclamation-triangle',
                SeverityLevel.HIGH: 'fas fa-exclamation-circle',
                SeverityLevel.MEDIUM: 'fas fa-info-circle',
                SeverityLevel.LOW: 'fas fa-check-circle',
                SeverityLevel.INFO: 'fas fa-lightbulb'
            }
            return icon_map.get(severity, 'fas fa-question-circle')
        
        @self.jinja_env.filter('risk_color')
        def risk_color_filter(risk_level: Union[str, RiskLevel]) -> str:
            """Get CSS color class for risk level."""
            if isinstance(risk_level, str):
                risk_level = RiskLevel(risk_level.lower())
            
            color_map = {
                RiskLevel.CRITICAL: 'danger',
                RiskLevel.HIGH: 'warning',
                RiskLevel.MEDIUM: 'info',
                RiskLevel.LOW: 'success',
                RiskLevel.NEGLIGIBLE: 'light'
            }
            return color_map.get(risk_level, 'secondary')
        
        @self.jinja_env.filter('cvss_rating')
        def cvss_rating_filter(cvss_score: Optional[float]) -> str:
            """Convert CVSS score to rating."""
            if cvss_score is None:
                return 'Unknown'
            
            if cvss_score >= 9.0:
                return 'Critical'
            elif cvss_score >= 7.0:
                return 'High'
            elif cvss_score >= 4.0:
                return 'Medium'
            elif cvss_score > 0.0:
                return 'Low'
            else:
                return 'None'
        
        @self.jinja_env.filter('format_timestamp')
        def timestamp_filter(timestamp: datetime, format_str: str = '%Y-%m-%d %H:%M:%S') -> str:
            """Format datetime timestamp."""
            if isinstance(timestamp, str):
                return timestamp
            return timestamp.strftime(format_str)
        
        @self.jinja_env.filter('format_duration')
        def duration_filter(duration) -> str:
            """Format duration in human readable format."""
            if hasattr(duration, 'total_seconds'):
                seconds = int(duration.total_seconds())
            else:
                seconds = int(duration)
            
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            remaining_seconds = seconds % 60
            
            if hours > 0:
                return f"{hours}h {minutes}m {remaining_seconds}s"
            elif minutes > 0:
                return f"{minutes}m {remaining_seconds}s"
            else:
                return f"{remaining_seconds}s"
        
        @self.jinja_env.filter('truncate_words')
        def truncate_words_filter(text: str, count: int = 50, suffix: str = '...') -> str:
            """Truncate text to specified word count."""
            if not text:
                return ''
            
            words = text.split()
            if len(words) <= count:
                return text
            
            return ' '.join(words[:count]) + suffix
        
        @self.jinja_env.filter('highlight_code')
        def highlight_code_filter(code: str, language: str = 'text') -> str:
            """Add syntax highlighting to code (placeholder for now)."""
            # In a real implementation, you might use pygments
            return f'<pre><code class="language-{language}">{code}</code></pre>'
        
        @self.jinja_env.filter('pluralize')
        def pluralize_filter(count: int, singular: str = '', plural: str = 's') -> str:
            """Return singular or plural form based on count."""
            if count == 1:
                return singular
            return plural
        
        @self.jinja_env.filter('percentage')
        def percentage_filter(value: float, total: float, decimal_places: int = 1) -> str:
            """Calculate and format percentage."""
            if total == 0:
                return '0%'
            percentage = (value / total) * 100
            return f"{percentage:.{decimal_places}f}%"
        
        @self.jinja_env.filter('format_list')
        def format_list_filter(items: List[Any], separator: str = ', ', 
                              max_items: int = 5, suffix: str = '...') -> str:
            """Format list items with separator and optional truncation."""
            if not items:
                return ''
            
            str_items = [str(item) for item in items]
            
            if len(str_items) <= max_items:
                return separator.join(str_items)
            else:
                visible_items = str_items[:max_items]
                remaining = len(str_items) - max_items
                return separator.join(visible_items) + f"{separator}{suffix} (+{remaining} more)"
    
    def _register_custom_functions(self) -> None:
        """Register custom Jinja2 global functions."""
        
        def current_timestamp() -> str:
            """Get current timestamp."""
            return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        def severity_count(findings: List, severity: str) -> int:
            """Count findings by severity."""
            return len([f for f in findings if f.severity.value.lower() == severity.lower()])
        
        def filter_by_severity(findings: List, severity: str) -> List:
            """Filter findings by severity."""
            return [f for f in findings if f.severity.value.lower() == severity.lower()]
        
        def calculate_risk_score(findings: List) -> float:
            """Calculate simple risk score based on findings."""
            score = 0.0
            severity_weights = {
                'critical': 4.0,
                'high': 3.0, 
                'medium': 2.0,
                'low': 1.0,
                'info': 0.1
            }
            
            for finding in findings:
                weight = severity_weights.get(finding.severity.value.lower(), 0.0)
                score += weight
            
            return min(score, 10.0)  # Cap at 10.0
        
        def generate_chart_data(findings: List) -> Dict[str, Any]:
            """Generate data for charts."""
            severity_counts = {}
            for finding in findings:
                severity = finding.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            return {
                'labels': list(severity_counts.keys()),
                'data': list(severity_counts.values()),
                'colors': [self.jinja_env.filters['severity_color'](s) for s in severity_counts.keys()]
            }
        
        def get_top_findings(findings: List, count: int = 5) -> List:
            """Get top N critical findings."""
            # Sort by severity (critical first) then by confidence
            severity_order = ['critical', 'high', 'medium', 'low', 'info']
            
            def sort_key(finding):
                severity_index = severity_order.index(finding.severity.value.lower())
                confidence_score = {'confirmed': 4, 'firm': 3, 'tentative': 2, 'possible': 1}.get(
                    finding.confidence.value.lower(), 0)
                return (severity_index, -confidence_score)  # Negative for descending confidence
            
            sorted_findings = sorted(findings, key=sort_key)
            return sorted_findings[:count]
        
        # Register functions
        self.jinja_env.globals.update({
            'current_timestamp': current_timestamp,
            'severity_count': severity_count,
            'filter_by_severity': filter_by_severity,
            'calculate_risk_score': calculate_risk_score,
            'generate_chart_data': generate_chart_data,
            'get_top_findings': get_top_findings
        })
    
    async def render_template(self, template_name: str, context: Dict[str, Any]) -> str:
        """Render template with given context.
        
        Args:
            template_name: Name of template file
            context: Template context variables
            
        Returns:
            Rendered template content
        """
        try:
            template = self.jinja_env.get_template(template_name)
            rendered_content = template.render(**context)
            
            self.logger.debug(f"Successfully rendered template: {template_name}")
            return rendered_content
            
        except TemplateNotFound:
            raise TemplateError(f"Template not found: {template_name}")
        except Exception as e:
            self.logger.error(f"Template rendering failed: {e}")
            raise TemplateError(f"Failed to render template {template_name}: {e}")
    
    async def render_template_string(self, template_string: str, context: Dict[str, Any]) -> str:
        """Render template from string.
        
        Args:
            template_string: Template content as string
            context: Template context variables
            
        Returns:
            Rendered content
        """
        try:
            template = self.jinja_env.from_string(template_string)
            return template.render(**context)
        except Exception as e:
            raise TemplateError(f"Failed to render template string: {e}")
    
    def template_exists(self, template_name: str) -> bool:
        """Check if template exists.
        
        Args:
            template_name: Name of template file
            
        Returns:
            True if template exists
        """
        try:
            self.jinja_env.get_template(template_name)
            return True
        except TemplateNotFound:
            return False
    
    def list_templates(self, pattern: str = '*.html') -> List[str]:
        """List available templates.
        
        Args:
            pattern: File pattern to match
            
        Returns:
            List of template names
        """
        templates = []
        for template_file in self.template_path.rglob(pattern):
            relative_path = template_file.relative_to(self.template_path)
            templates.append(str(relative_path))
        
        return sorted(templates)
    
    async def create_template_from_content(self, template_name: str, content: str) -> None:
        """Create new template file from content.
        
        Args:
            template_name: Name for new template
            content: Template content
        """
        template_file = self.template_path / template_name
        template_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(template_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        self.logger.info(f"Created template: {template_name}")
    
    def get_template_context(self, vulnerability_report: VulnerabilityReport, 
                           report_config: ReportConfig) -> Dict[str, Any]:
        """Build template context from vulnerability report.
        
        Args:
            vulnerability_report: Vulnerability report data
            report_config: Report configuration
            
        Returns:
            Template context dictionary
        """
        # Group findings by severity
        findings_by_severity = {}
        for severity in SeverityLevel:
            findings_by_severity[severity.value] = vulnerability_report.get_findings_by_severity(severity)
        
        # Calculate statistics
        total_findings = len(vulnerability_report.technical_findings)
        verified_findings = len(vulnerability_report.get_verified_findings())
        critical_findings = len(vulnerability_report.get_critical_findings())
        high_findings = len(vulnerability_report.get_high_findings())
        
        # Build context
        context = {
            # Core report data
            'report': vulnerability_report,
            'config': report_config,
            
            # Target information
            'target': vulnerability_report.target_info,
            'scan_metadata': vulnerability_report.scan_metadata,
            
            # Findings data
            'findings': vulnerability_report.technical_findings,
            'findings_by_severity': findings_by_severity,
            'total_findings': total_findings,
            'verified_findings': verified_findings,
            
            # Key metrics
            'critical_count': critical_findings,
            'high_count': high_findings,
            'critical_high_count': critical_findings + high_findings,
            'verification_rate': (verified_findings / total_findings * 100) if total_findings > 0 else 0,
            
            # Risk assessment
            'risk_assessment': vulnerability_report.risk_assessment,
            'overall_risk_level': vulnerability_report.risk_assessment.overall_risk_score.risk_level.value if vulnerability_report.risk_assessment else 'unknown',
            
            # Executive summary
            'executive_summary': vulnerability_report.executive_summary,
            
            # Remediation
            'remediation_plan': vulnerability_report.remediation_plan,
            
            # Compliance
            'compliance_mapping': vulnerability_report.compliance_mapping,
            
            # Appendices
            'appendices': vulnerability_report.appendices,
            
            # Metadata
            'generation_time': datetime.now(),
            'report_version': vulnerability_report.version,
            'branding': report_config.branding,
            'classification': report_config.classification.value,
            
            # Utility data
            'severity_levels': [s.value for s in SeverityLevel],
            'risk_levels': [r.value for r in RiskLevel],
            
            # Chart data
            'severity_chart_data': {
                'labels': [s.value.title() for s in SeverityLevel],
                'data': [len(findings_by_severity[s.value]) for s in SeverityLevel],
                'colors': ['#dc3545', '#fd7e14', '#ffc107', '#28a745', '#17a2b8']  # Bootstrap colors
            }
        }
        
        return context
    
    def validate_template(self, template_name: str) -> List[str]:
        """Validate template syntax and structure.
        
        Args:
            template_name: Template to validate
            
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        try:
            # Check if template exists
            if not self.template_exists(template_name):
                errors.append(f"Template not found: {template_name}")
                return errors
            
            # Try to compile template
            template = self.jinja_env.get_template(template_name)
            
            # Try rendering with minimal context to catch syntax errors
            minimal_context = {
                'report': None,
                'findings': [],
                'target': None,
                'scan_metadata': None
            }
            
            try:
                template.render(**minimal_context)
            except Exception as e:
                errors.append(f"Template rendering test failed: {e}")
            
        except Exception as e:
            errors.append(f"Template compilation failed: {e}")
        
        return errors
    
    async def get_template_for_format(self, template_base: str, 
                                    format_type: ReportFormat) -> str:
        """Get template filename for specific format.
        
        Args:
            template_base: Base template name (e.g., 'executive')
            format_type: Target format
            
        Returns:
            Template filename
        """
        format_extensions = {
            ReportFormat.HTML: 'html',
            ReportFormat.PDF: 'html',  # PDF uses HTML template
            ReportFormat.MARKDOWN: 'md',
            ReportFormat.JSON: 'json',
            ReportFormat.XML: 'xml'
        }
        
        extension = format_extensions.get(format_type, 'html')
        template_name = f"{template_base}/{template_base}.{extension}"
        
        # Check if format-specific template exists
        if self.template_exists(template_name):
            return template_name
        
        # Fall back to default template
        default_template = f"{template_base}/default.{extension}"
        if self.template_exists(default_template):
            return default_template
        
        # Final fallback to base template
        fallback_template = f"base/report.{extension}"
        if self.template_exists(fallback_template):
            return fallback_template
        
        raise TemplateError(f"No suitable template found for {template_base} in {format_type.value} format")


class TemplateBuilder:
    """Helper class for building templates programmatically."""
    
    def __init__(self):
        self.sections = []
        self.css_classes = []
        self.javascript = []
    
    def add_section(self, section_name: str, content: str) -> 'TemplateBuilder':
        """Add a section to the template."""
        self.sections.append({
            'name': section_name,
            'content': content
        })
        return self
    
    def add_css_class(self, css_class: str) -> 'TemplateBuilder':
        """Add CSS class definition."""
        self.css_classes.append(css_class)
        return self
    
    def add_javascript(self, script: str) -> 'TemplateBuilder':
        """Add JavaScript code."""
        self.javascript.append(script)
        return self
    
    def build_html_template(self) -> str:
        """Build complete HTML template."""
        template_parts = []
        
        # HTML header
        template_parts.append("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ report.target_info.primary_target }} - Security Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
""")
        
        # Add CSS
        if self.css_classes:
            template_parts.extend(self.css_classes)
        
        template_parts.append("""
    </style>
</head>
<body>
    <div class="container-fluid">
""")
        
        # Add sections
        for section in self.sections:
            template_parts.append(f"""
        <!-- {section['name']} -->
        <section class="{section['name'].replace(' ', '-').lower()}">
            {section['content']}
        </section>
""")
        
        # HTML footer
        template_parts.append("""
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
""")
        
        # Add JavaScript
        if self.javascript:
            template_parts.extend(self.javascript)
        
        template_parts.append("""
    </script>
</body>
</html>
""")
        
        return '\n'.join(template_parts)