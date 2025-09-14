"""Base formatter classes and registry."""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Union

from ..models import VulnerabilityReport, GeneratedReport
from ..config import ReportConfig, ReportFormat
from ..templates import TemplateManager


class FormatterError(Exception):
    """Formatter-specific error."""
    pass


class BaseFormatter(ABC):
    """Base class for all report formatters."""
    
    def __init__(self):
        """Initialize base formatter."""
        self.logger = logging.getLogger(f'{self.__class__.__name__.lower()}')
    
    @abstractmethod
    async def format_report(self, report: VulnerabilityReport,
                          config: ReportConfig,
                          template_manager: TemplateManager) -> Union[bytes, str]:
        """Format vulnerability report to specific format.
        
        Args:
            report: Vulnerability report data
            config: Report configuration
            template_manager: Template manager instance
            
        Returns:
            Formatted report content (bytes or string)
        """
        pass
    
    @property
    @abstractmethod
    def supported_format(self) -> ReportFormat:
        """Get supported report format."""
        pass
    
    @property
    @abstractmethod
    def output_extension(self) -> str:
        """Get output file extension."""
        pass
    
    @property
    @abstractmethod
    def content_type(self) -> str:
        """Get MIME content type."""
        pass
    
    def validate_config(self, config: ReportConfig) -> None:
        """Validate formatter-specific configuration.
        
        Args:
            config: Report configuration
            
        Raises:
            FormatterError: If configuration is invalid
        """
        # Base validation - can be overridden by subclasses
        if self.supported_format not in config.output_formats:
            raise FormatterError(f"Format {self.supported_format.value} not enabled in configuration")
    
    def get_template_name(self, config: ReportConfig) -> str:
        """Get template name for this formatter.
        
        Args:
            config: Report configuration
            
        Returns:
            Template name
        """
        return f"{config.template_name}/{config.template_name}.{self.output_extension}"
    
    def prepare_context(self, report: VulnerabilityReport, 
                       config: ReportConfig) -> Dict[str, Any]:
        """Prepare template context for this formatter.
        
        Args:
            report: Vulnerability report
            config: Report configuration
            
        Returns:
            Template context dictionary
        """
        # Base context - can be extended by subclasses
        return {
            'report': report,
            'config': config,
            'formatter': {
                'name': self.__class__.__name__,
                'format': self.supported_format.value,
                'extension': self.output_extension,
                'content_type': self.content_type
            }
        }
    
    async def post_process(self, content: Union[bytes, str], 
                         config: ReportConfig) -> Union[bytes, str]:
        """Post-process generated content.
        
        Args:
            content: Generated content
            config: Report configuration
            
        Returns:
            Post-processed content
        """
        # Base implementation - no post-processing
        return content


class FormatterRegistry:
    """Registry for managing report formatters."""
    
    def __init__(self):
        """Initialize formatter registry."""
        self.logger = logging.getLogger('formatter_registry')
        self.formatters: Dict[ReportFormat, BaseFormatter] = {}
        
        # Register default formatters
        self._register_default_formatters()
    
    def _register_default_formatters(self) -> None:
        """Register default formatters."""
        try:
            from .html import HTMLFormatter
            from .json import JSONFormatter
            from .csv import CSVFormatter
            from .xml import XMLFormatter
            from .markdown import MarkdownFormatter
            
            # Register basic formatters
            self.register_formatter(HTMLFormatter())
            self.register_formatter(JSONFormatter())
            self.register_formatter(CSVFormatter())
            self.register_formatter(XMLFormatter())
            self.register_formatter(MarkdownFormatter())
            
            # Register advanced formatters if dependencies are available
            try:
                from .pdf import PDFFormatter
                self.register_formatter(PDFFormatter())
            except ImportError:
                self.logger.warning("PDF formatter not available - missing dependencies")
            
            try:
                from .docx import DOCXFormatter
                self.register_formatter(DOCXFormatter())
            except ImportError:
                self.logger.warning("DOCX formatter not available - missing dependencies")
            
            try:
                from .sarif import SARIFFormatter
                self.register_formatter(SARIFFormatter())
            except ImportError:
                self.logger.warning("SARIF formatter not available")
            
        except ImportError as e:
            self.logger.error(f"Failed to register default formatters: {e}")
    
    def register_formatter(self, formatter: BaseFormatter) -> None:
        """Register a formatter.
        
        Args:
            formatter: Formatter instance to register
        """
        format_type = formatter.supported_format
        self.formatters[format_type] = formatter
        self.logger.info(f"Registered formatter for {format_type.value} format")
    
    def get_formatter(self, format_type: ReportFormat) -> Optional[BaseFormatter]:
        """Get formatter for specific format.
        
        Args:
            format_type: Report format type
            
        Returns:
            Formatter instance or None if not found
        """
        return self.formatters.get(format_type)
    
    def get_supported_formats(self) -> list[ReportFormat]:
        """Get list of supported formats.
        
        Returns:
            List of supported ReportFormat values
        """
        return list(self.formatters.keys())
    
    def is_format_supported(self, format_type: ReportFormat) -> bool:
        """Check if format is supported.
        
        Args:
            format_type: Report format type
            
        Returns:
            True if format is supported
        """
        return format_type in self.formatters
    
    def validate_formats(self, formats: list[ReportFormat]) -> list[str]:
        """Validate list of formats.
        
        Args:
            formats: List of formats to validate
            
        Returns:
            List of validation errors (empty if all valid)
        """
        errors = []
        
        for format_type in formats:
            if not self.is_format_supported(format_type):
                errors.append(f"Unsupported format: {format_type.value}")
        
        return errors
    
    async def format_report_multiple(self, report: VulnerabilityReport,
                                   config: ReportConfig,
                                   template_manager: TemplateManager) -> Dict[ReportFormat, Union[bytes, str]]:
        """Format report in multiple formats concurrently.
        
        Args:
            report: Vulnerability report
            config: Report configuration
            template_manager: Template manager
            
        Returns:
            Dictionary mapping format to content
        """
        import asyncio
        
        results = {}
        
        # Prepare formatting tasks
        tasks = []
        formats = []
        
        for format_type in config.output_formats:
            formatter = self.get_formatter(format_type)
            if formatter:
                task = formatter.format_report(report, config, template_manager)
                tasks.append(task)
                formats.append(format_type)
        
        # Execute formatting tasks
        if tasks:
            contents = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Map results back to formats
            for format_type, content in zip(formats, contents):
                if isinstance(content, Exception):
                    self.logger.error(f"Failed to format {format_type.value}: {content}")
                else:
                    results[format_type] = content
        
        return results
    
    def get_formatter_info(self) -> Dict[str, Dict[str, Any]]:
        """Get information about all registered formatters.
        
        Returns:
            Dictionary with formatter information
        """
        info = {}
        
        for format_type, formatter in self.formatters.items():
            info[format_type.value] = {
                'class_name': formatter.__class__.__name__,
                'extension': formatter.output_extension,
                'content_type': formatter.content_type,
                'description': formatter.__class__.__doc__ or 'No description available'
            }
        
        return info