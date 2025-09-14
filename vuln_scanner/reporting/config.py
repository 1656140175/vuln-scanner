"""Report configuration and format definitions."""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from pathlib import Path


class ReportFormat(Enum):
    """Supported report formats."""
    PDF = "pdf"
    HTML = "html"
    DOCX = "docx"
    JSON = "json"
    XML = "xml"
    SARIF = "sarif"
    CSV = "csv"
    EXCEL = "xlsx"
    MARKDOWN = "markdown"


class ReportSection(Enum):
    """Available report sections."""
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_FINDINGS = "technical_findings"
    RISK_ASSESSMENT = "risk_assessment"
    REMEDIATION_PLAN = "remediation_plan"
    COMPLIANCE_MAPPING = "compliance_mapping"
    APPENDICES = "appendices"
    METHODOLOGY = "methodology"
    LIMITATIONS = "limitations"
    SCAN_DETAILS = "scan_details"
    EVIDENCE = "evidence"
    GLOSSARY = "glossary"


class ClassificationLevel(Enum):
    """Report classification levels."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"


class ColorScheme(Enum):
    """Available color schemes."""
    PROFESSIONAL = "professional"  # Blue and gray tones
    SECURITY = "security"          # Red and dark tones
    CORPORATE = "corporate"        # Company brand colors
    MINIMAL = "minimal"           # Black and white
    VIBRANT = "vibrant"           # Colorful scheme


@dataclass
class ContactInfo:
    """Contact information structure."""
    name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    website: Optional[str] = None


@dataclass
class BrandingConfig:
    """Branding configuration for reports."""
    company_name: str
    logo_path: Optional[str] = None
    color_scheme: ColorScheme = ColorScheme.PROFESSIONAL
    primary_color: Optional[str] = None  # Hex color code
    secondary_color: Optional[str] = None
    footer_text: str = ""
    header_text: str = ""
    contact_information: Optional[ContactInfo] = None
    watermark: Optional[str] = None
    show_page_numbers: bool = True
    show_table_of_contents: bool = True
    custom_css: Optional[str] = None


@dataclass
class PDFConfig:
    """PDF-specific configuration."""
    page_size: str = "A4"  # A4, Letter, Legal
    orientation: str = "portrait"  # portrait, landscape
    margin_top: str = "1in"
    margin_bottom: str = "1in"
    margin_left: str = "1in"
    margin_right: str = "1in"
    font_family: str = "Arial"
    font_size: int = 11
    enable_bookmarks: bool = True
    enable_links: bool = True
    compress: bool = True
    include_metadata: bool = True
    password_protect: bool = False
    password: Optional[str] = None
    pdf_options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HTMLConfig:
    """HTML-specific configuration."""
    include_css: bool = True
    css_framework: str = "bootstrap"  # bootstrap, bulma, custom, none
    responsive_design: bool = True
    include_charts: bool = True
    chart_library: str = "chart.js"  # chart.js, d3, plotly
    theme: str = "light"  # light, dark, auto
    include_print_styles: bool = True
    minify_html: bool = False
    include_interactive_elements: bool = True


@dataclass
class DOCXConfig:
    """Word document specific configuration."""
    template_path: Optional[str] = None
    page_orientation: str = "portrait"
    page_size: str = "A4"
    margins: Dict[str, str] = field(default_factory=lambda: {
        "top": "1in", "bottom": "1in", "left": "1in", "right": "1in"
    })
    font_name: str = "Arial"
    font_size: int = 11
    include_header: bool = True
    include_footer: bool = True
    include_page_numbers: bool = True
    track_changes: bool = False
    compatibility_mode: str = "2019"  # 2019, 2016, 2013


@dataclass
class JSONConfig:
    """JSON-specific configuration."""
    pretty_print: bool = True
    indent: int = 2
    sort_keys: bool = True
    include_schema: bool = True
    validate_output: bool = True
    include_metadata: bool = True
    date_format: str = "iso"  # iso, timestamp, human_readable


@dataclass
class SARIFConfig:
    """SARIF format specific configuration."""
    sarif_version: str = "2.1.0"
    schema_uri: str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    include_snippets: bool = True
    include_fixes: bool = True
    include_graphs: bool = False
    tool_name: str = "VulnMiner"
    tool_version: str = "1.0.0"
    notification_level: str = "warning"  # error, warning, note


@dataclass
class ExportConfig:
    """Export configuration for different formats."""
    output_directory: str = "reports"
    filename_template: str = "{report_id}_{timestamp}_{format}"
    timestamp_format: str = "%Y%m%d_%H%M%S"
    overwrite_existing: bool = False
    create_archive: bool = False
    archive_format: str = "zip"  # zip, tar, tar.gz
    cleanup_temp_files: bool = True
    
    
@dataclass
class FormatConfig:
    """Format-specific configuration container."""
    pdf: PDFConfig = field(default_factory=PDFConfig)
    html: HTMLConfig = field(default_factory=HTMLConfig)
    docx: DOCXConfig = field(default_factory=DOCXConfig)
    json: JSONConfig = field(default_factory=JSONConfig)
    sarif: SARIFConfig = field(default_factory=SARIFConfig)


@dataclass
class ReportConfig:
    """Main report generation configuration."""
    # Output configuration
    output_formats: List[ReportFormat] = field(default_factory=lambda: [ReportFormat.PDF, ReportFormat.HTML])
    template_name: str = "default"
    include_sections: List[ReportSection] = field(default_factory=lambda: [
        ReportSection.EXECUTIVE_SUMMARY,
        ReportSection.TECHNICAL_FINDINGS,
        ReportSection.RISK_ASSESSMENT,
        ReportSection.REMEDIATION_PLAN
    ])
    
    # Content configuration
    max_findings_per_section: int = 100
    include_low_severity: bool = True
    include_info_severity: bool = False
    include_false_positives: bool = False
    include_unverified_findings: bool = True
    group_similar_findings: bool = True
    similarity_threshold: float = 0.8
    
    # Compliance and frameworks
    compliance_frameworks: List[str] = field(default_factory=list)
    include_compliance_mapping: bool = True
    include_regulatory_notes: bool = True
    
    # Branding and styling
    branding: BrandingConfig = field(default_factory=lambda: BrandingConfig(company_name="Security Team"))
    classification: ClassificationLevel = ClassificationLevel.CONFIDENTIAL
    
    # Format-specific configurations
    format_config: FormatConfig = field(default_factory=FormatConfig)
    export_config: ExportConfig = field(default_factory=ExportConfig)
    
    # Advanced options
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    include_raw_data: bool = False
    include_debug_info: bool = False
    enable_performance_metrics: bool = True
    parallel_generation: bool = True
    max_concurrent_formats: int = 3
    
    # Language and localization
    language: str = "en"
    timezone: str = "UTC"
    date_format: str = "%Y-%m-%d %H:%M:%S"
    number_format: str = "US"  # US, EU, etc.
    
    # Quality assurance
    validate_before_generation: bool = True
    include_generation_metadata: bool = True
    enable_audit_trail: bool = True
    
    def get_output_filename(self, report_id: str, format_type: ReportFormat) -> str:
        """Generate output filename based on configuration."""
        from datetime import datetime
        
        timestamp = datetime.now().strftime(self.export_config.timestamp_format)
        
        filename = self.export_config.filename_template.format(
            report_id=report_id,
            timestamp=timestamp,
            format=format_type.value
        )
        
        return f"{filename}.{format_type.value}"
    
    def get_output_path(self, report_id: str, format_type: ReportFormat) -> Path:
        """Get full output path for a report."""
        filename = self.get_output_filename(report_id, format_type)
        return Path(self.export_config.output_directory) / filename
    
    def validate(self) -> List[str]:
        """Validate configuration and return any errors."""
        errors = []
        
        if not self.branding.company_name:
            errors.append("Company name is required in branding configuration")
        
        if not self.output_formats:
            errors.append("At least one output format must be specified")
        
        if not self.include_sections:
            errors.append("At least one report section must be included")
        
        if self.max_findings_per_section <= 0:
            errors.append("Max findings per section must be positive")
        
        if not (0.0 <= self.similarity_threshold <= 1.0):
            errors.append("Similarity threshold must be between 0.0 and 1.0")
        
        # Validate branding logo path if provided
        if self.branding.logo_path:
            logo_path = Path(self.branding.logo_path)
            if not logo_path.exists():
                errors.append(f"Logo file not found: {self.branding.logo_path}")
        
        # Validate output directory
        try:
            output_dir = Path(self.export_config.output_directory)
            output_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            errors.append(f"Cannot create output directory: {e}")
        
        return errors
    
    def is_format_enabled(self, format_type: ReportFormat) -> bool:
        """Check if a specific format is enabled."""
        return format_type in self.output_formats
    
    def is_section_included(self, section: ReportSection) -> bool:
        """Check if a specific section is included."""
        return section in self.include_sections


# Predefined configurations for common use cases

def get_executive_config() -> ReportConfig:
    """Get configuration for executive-level reports."""
    return ReportConfig(
        output_formats=[ReportFormat.PDF],
        template_name="executive",
        include_sections=[
            ReportSection.EXECUTIVE_SUMMARY,
            ReportSection.RISK_ASSESSMENT,
            ReportSection.REMEDIATION_PLAN
        ],
        include_low_severity=False,
        include_info_severity=False,
        include_unverified_findings=False,
        classification=ClassificationLevel.CONFIDENTIAL
    )


def get_technical_config() -> ReportConfig:
    """Get configuration for technical reports."""
    return ReportConfig(
        output_formats=[ReportFormat.HTML, ReportFormat.JSON],
        template_name="technical",
        include_sections=[
            ReportSection.TECHNICAL_FINDINGS,
            ReportSection.METHODOLOGY,
            ReportSection.EVIDENCE,
            ReportSection.APPENDICES
        ],
        include_low_severity=True,
        include_info_severity=True,
        include_unverified_findings=True,
        include_raw_data=True
    )


def get_compliance_config() -> ReportConfig:
    """Get configuration for compliance reports."""
    return ReportConfig(
        output_formats=[ReportFormat.PDF, ReportFormat.SARIF],
        template_name="compliance",
        include_sections=[
            ReportSection.EXECUTIVE_SUMMARY,
            ReportSection.TECHNICAL_FINDINGS,
            ReportSection.COMPLIANCE_MAPPING,
            ReportSection.REMEDIATION_PLAN
        ],
        include_compliance_mapping=True,
        include_regulatory_notes=True,
        classification=ClassificationLevel.RESTRICTED
    )


def get_developer_config() -> ReportConfig:
    """Get configuration for developer-focused reports."""
    return ReportConfig(
        output_formats=[ReportFormat.JSON, ReportFormat.SARIF, ReportFormat.MARKDOWN],
        template_name="developer",
        include_sections=[
            ReportSection.TECHNICAL_FINDINGS,
            ReportSection.REMEDIATION_PLAN,
            ReportSection.EVIDENCE
        ],
        include_low_severity=True,
        include_info_severity=True,
        include_raw_data=True,
        include_debug_info=True
    )