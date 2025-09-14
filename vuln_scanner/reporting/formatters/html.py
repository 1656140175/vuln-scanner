"""HTML report formatter."""

import logging
from typing import Union

from .base import BaseFormatter, FormatterError
from ..models import VulnerabilityReport
from ..config import ReportConfig, ReportFormat
from ..templates import TemplateManager


class HTMLFormatter(BaseFormatter):
    """HTML report formatter with responsive design."""
    
    @property
    def supported_format(self) -> ReportFormat:
        return ReportFormat.HTML
    
    @property
    def output_extension(self) -> str:
        return "html"
    
    @property
    def content_type(self) -> str:
        return "text/html"
    
    async def format_report(self, report: VulnerabilityReport,
                          config: ReportConfig,
                          template_manager: TemplateManager) -> str:
        """Format report as HTML.
        
        Args:
            report: Vulnerability report data
            config: Report configuration
            template_manager: Template manager instance
            
        Returns:
            HTML report content
        """
        self.logger.info(f"Formatting HTML report for {report.target_info.primary_target}")
        
        try:
            # Get HTML-specific configuration
            html_config = config.format_config.html
            
            # Prepare template context
            context = template_manager.get_template_context(report, config)
            
            # Add HTML-specific context
            context.update({
                'html_config': html_config,
                'include_css': html_config.include_css,
                'responsive_design': html_config.responsive_design,
                'include_charts': html_config.include_charts,
                'chart_library': html_config.chart_library,
                'theme': html_config.theme,
                'css_framework': html_config.css_framework
            })
            
            # Get appropriate template
            template_name = await template_manager.get_template_for_format(
                config.template_name, ReportFormat.HTML
            )
            
            # Render template
            html_content = await template_manager.render_template(template_name, context)
            
            # Post-process content
            if html_config.minify_html:
                html_content = self._minify_html(html_content)
            
            self.logger.info(f"Successfully generated HTML report ({len(html_content)} chars)")
            return html_content
            
        except Exception as e:
            self.logger.error(f"HTML formatting failed: {e}")
            raise FormatterError(f"Failed to format HTML report: {e}")
    
    def _minify_html(self, html_content: str) -> str:
        """Minify HTML content.
        
        Args:
            html_content: HTML content to minify
            
        Returns:
            Minified HTML content
        """
        import re
        
        # Simple HTML minification (can be enhanced with proper HTML minifier)
        # Remove comments
        html_content = re.sub(r'<!--.*?-->', '', html_content, flags=re.DOTALL)
        
        # Remove extra whitespace
        html_content = re.sub(r'\s+', ' ', html_content)
        
        # Remove whitespace around tags
        html_content = re.sub(r'>\s+<', '><', html_content)
        
        return html_content.strip()
    
    def prepare_context(self, report: VulnerabilityReport, 
                       config: ReportConfig) -> dict:
        """Prepare HTML-specific template context.
        
        Args:
            report: Vulnerability report
            config: Report configuration
            
        Returns:
            Enhanced template context
        """
        context = super().prepare_context(report, config)
        
        # Add HTML-specific utilities
        context.update({
            'bootstrap_severity_class': self._get_bootstrap_severity_class,
            'generate_progress_bar': self._generate_progress_bar,
            'format_code_snippet': self._format_code_snippet,
            'generate_badge': self._generate_badge,
            'create_collapsible_section': self._create_collapsible_section
        })
        
        return context
    
    def _get_bootstrap_severity_class(self, severity: str) -> str:
        """Get Bootstrap CSS class for severity.
        
        Args:
            severity: Severity level
            
        Returns:
            Bootstrap CSS class
        """
        severity_map = {
            'critical': 'danger',
            'high': 'warning',
            'medium': 'info',
            'low': 'success',
            'info': 'secondary'
        }
        return severity_map.get(severity.lower(), 'secondary')
    
    def _generate_progress_bar(self, value: float, max_value: float = 100.0, 
                              label: str = "", css_class: str = "primary") -> str:
        """Generate Bootstrap progress bar.
        
        Args:
            value: Current value
            max_value: Maximum value
            label: Progress bar label
            css_class: Bootstrap color class
            
        Returns:
            HTML progress bar
        """
        percentage = (value / max_value * 100) if max_value > 0 else 0
        
        return f'''
        <div class="progress">
            <div class="progress-bar bg-{css_class}" role="progressbar" 
                 style="width: {percentage:.1f}%" 
                 aria-valuenow="{value}" aria-valuemin="0" aria-valuemax="{max_value}">
                {label} {percentage:.1f}%
            </div>
        </div>
        '''
    
    def _format_code_snippet(self, code: str, language: str = "text") -> str:
        """Format code snippet with syntax highlighting.
        
        Args:
            code: Code to format
            language: Programming language
            
        Returns:
            Formatted HTML code block
        """
        return f'''
        <pre><code class="language-{language} hljs">{self._escape_html(code)}</code></pre>
        '''
    
    def _generate_badge(self, text: str, badge_type: str = "primary") -> str:
        """Generate Bootstrap badge.
        
        Args:
            text: Badge text
            badge_type: Bootstrap badge type
            
        Returns:
            HTML badge element
        """
        return f'<span class="badge bg-{badge_type}">{self._escape_html(text)}</span>'
    
    def _create_collapsible_section(self, title: str, content: str, 
                                  section_id: str) -> str:
        """Create Bootstrap collapsible section.
        
        Args:
            title: Section title
            content: Section content
            section_id: Unique section ID
            
        Returns:
            HTML collapsible section
        """
        return f'''
        <div class="accordion-item">
            <h2 class="accordion-header" id="heading{section_id}">
                <button class="accordion-button collapsed" type="button" 
                        data-bs-toggle="collapse" data-bs-target="#collapse{section_id}" 
                        aria-expanded="false" aria-controls="collapse{section_id}">
                    {self._escape_html(title)}
                </button>
            </h2>
            <div id="collapse{section_id}" class="accordion-collapse collapse" 
                 aria-labelledby="heading{section_id}">
                <div class="accordion-body">
                    {content}
                </div>
            </div>
        </div>
        '''
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters.
        
        Args:
            text: Text to escape
            
        Returns:
            HTML-escaped text
        """
        import html
        return html.escape(text)