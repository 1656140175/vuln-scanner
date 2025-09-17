"""Tool registry for managing security tool definitions and metadata."""

import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Type
from dataclasses import dataclass, asdict
from enum import Enum

from .base import SecurityTool, ToolStatus


class ToolCategory(Enum):
    """Categories of security tools."""
    NETWORK_SCANNER = "network_scanner"
    VULNERABILITY_SCANNER = "vulnerability_scanner"
    WEB_SCANNER = "web_scanner"
    SUBDOMAIN_ENUM = "subdomain_enum"
    DIRECTORY_BRUTE = "directory_brute"
    SQL_INJECTION = "sql_injection"
    RECON = "recon"
    EXPLOITATION = "exploitation"
    UTILITY = "utility"


@dataclass
class ToolDefinition:
    """Definition of a security tool."""
    name: str
    display_name: str
    category: ToolCategory
    description: str
    homepage: Optional[str] = None
    repository: Optional[str] = None
    install_url: Optional[str] = None
    package_name: Optional[str] = None
    binary_name: Optional[str] = None
    dependencies: List[str] = None
    supported_platforms: List[str] = None
    default_config: Dict[str, Any] = None
    version_command: List[str] = None
    version_regex: Optional[str] = None
    install_methods: List[str] = None
    tags: List[str] = None
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []
        if self.supported_platforms is None:
            self.supported_platforms = ['linux', 'darwin', 'windows']
        if self.default_config is None:
            self.default_config = {}
        if self.version_command is None:
            self.version_command = [self.binary_name or self.name, '--version']
        if self.install_methods is None:
            self.install_methods = ['package_manager']
        if self.tags is None:
            self.tags = []
        if self.binary_name is None:
            self.binary_name = self.name
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        result['category'] = self.category.value
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ToolDefinition':
        """Create from dictionary."""
        if isinstance(data.get('category'), str):
            data['category'] = ToolCategory(data['category'])
        return cls(**data)


class ToolRegistry:
    """Registry for security tools."""
    
    def __init__(self, registry_file: Optional[str] = None):
        """Initialize tool registry.
        
        Args:
            registry_file: Path to registry file (optional)
        """
        self.logger = logging.getLogger('tool_registry')
        self.registry_file = Path(registry_file) if registry_file else None
        
        # Tool definitions
        self.tools: Dict[str, ToolDefinition] = {}
        
        # Tool class mappings
        self.tool_classes: Dict[str, Type[SecurityTool]] = {}
        
        # Load built-in tools
        self._load_builtin_tools()
        
        # Load from file if provided
        if self.registry_file and self.registry_file.exists():
            self.load_from_file(self.registry_file)
    
    def _load_builtin_tools(self) -> None:
        """Load built-in tool definitions."""
        builtin_tools = [
            ToolDefinition(
                name="nmap",
                display_name="Nmap",
                category=ToolCategory.NETWORK_SCANNER,
                description="Network discovery and security auditing tool",
                homepage="https://nmap.org",
                repository="https://github.com/nmap/nmap",
                package_name="nmap",
                binary_name="nmap",
                dependencies=[],
                supported_platforms=["linux", "darwin", "windows"],
                default_config={
                    "timeout": 300,
                    "default_args": ["-sS", "-sV"]
                },
                version_command=["nmap", "--version"],
                version_regex=r"Nmap version (\d+\.\d+)",
                install_methods=["package_manager", "binary"],
                tags=["network", "port_scan", "os_detection"]
            ),
            ToolDefinition(
                name="nuclei",
                display_name="Nuclei",
                category=ToolCategory.VULNERABILITY_SCANNER,
                description="Fast and customizable vulnerability scanner",
                homepage="https://nuclei.projectdiscovery.io",
                repository="https://github.com/projectdiscovery/nuclei",
                install_url="github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
                binary_name="nuclei",
                dependencies=["go"],
                supported_platforms=["linux", "darwin", "windows"],
                default_config={
                    "timeout": 600,
                    "templates_dir": "data/nuclei-templates",
                    "default_args": ["-c", "50"]
                },
                version_command=["nuclei", "-version"],
                version_regex=r"Current Version: v(\d+\.\d+\.\d+)",
                install_methods=["go_install", "binary"],
                tags=["vulnerability", "template_based", "web"]
            ),
            ToolDefinition(
                name="subfinder",
                display_name="Subfinder", 
                category=ToolCategory.SUBDOMAIN_ENUM,
                description="Subdomain discovery tool",
                homepage="https://github.com/projectdiscovery/subfinder",
                repository="https://github.com/projectdiscovery/subfinder",
                install_url="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                binary_name="subfinder",
                dependencies=["go"],
                supported_platforms=["linux", "darwin", "windows"],
                default_config={
                    "timeout": 300,
                    "default_args": ["-silent"]
                },
                version_command=["subfinder", "-version"],
                version_regex=r"Current Version: v(\d+\.\d+\.\d+)",
                install_methods=["go_install", "binary"],
                tags=["subdomain", "recon", "passive"]
            ),
            ToolDefinition(
                name="httpx",
                display_name="Httpx",
                category=ToolCategory.WEB_SCANNER,
                description="Fast and multi-purpose HTTP toolkit",
                homepage="https://github.com/projectdiscovery/httpx",
                repository="https://github.com/projectdiscovery/httpx",
                install_url="github.com/projectdiscovery/httpx/cmd/httpx@latest",
                binary_name="httpx",
                dependencies=["go"],
                supported_platforms=["linux", "darwin", "windows"],
                default_config={
                    "timeout": 300,
                    "default_args": ["-silent"]
                },
                version_command=["httpx", "-version"],
                version_regex=r"Current Version: v(\d+\.\d+\.\d+)",
                install_methods=["go_install", "binary"],
                tags=["http", "web", "probe"]
            ),
            ToolDefinition(
                name="gobuster",
                display_name="Gobuster",
                category=ToolCategory.DIRECTORY_BRUTE,
                description="Directory/file, DNS and VHost busting tool",
                homepage="https://github.com/OJ/gobuster",
                repository="https://github.com/OJ/gobuster",
                install_url="github.com/OJ/gobuster/v3@latest",
                binary_name="gobuster",
                dependencies=["go"],
                supported_platforms=["linux", "darwin", "windows"],
                default_config={
                    "timeout": 600,
                    "default_args": ["-q"]
                },
                version_command=["gobuster", "version"],
                version_regex=r"Version: (\d+\.\d+\.\d+)",
                install_methods=["go_install", "package_manager"],
                tags=["directory", "brute_force", "dns"]
            ),
            ToolDefinition(
                name="sqlmap",
                display_name="SQLMap",
                category=ToolCategory.SQL_INJECTION,
                description="Automatic SQL injection and database takeover tool",
                homepage="http://sqlmap.org",
                repository="https://github.com/sqlmapproject/sqlmap",
                binary_name="sqlmap",
                dependencies=["python3"],
                supported_platforms=["linux", "darwin", "windows"],
                default_config={
                    "timeout": 1800,
                    "default_args": ["--batch"]
                },
                version_command=["sqlmap", "--version"],
                version_regex=r"sqlmap/(\d+\.\d+\.\d+)",
                install_methods=["package_manager", "git"],
                tags=["sql_injection", "database", "web"]
            ),
            ToolDefinition(
                name="amass",
                display_name="OWASP Amass",
                category=ToolCategory.RECON,
                description="In-depth attack surface mapping and asset discovery",
                homepage="https://owasp.org/www-project-amass/",
                repository="https://github.com/OWASP/Amass",
                install_url="github.com/OWASP/Amass/v3/...@master",
                binary_name="amass",
                dependencies=["go"],
                supported_platforms=["linux", "darwin", "windows"],
                default_config={
                    "timeout": 1800,
                    "default_args": []
                },
                version_command=["amass", "-version"],
                version_regex=r"version (\d+\.\d+\.\d+)",
                install_methods=["go_install", "package_manager"],
                tags=["recon", "subdomain", "asset_discovery"]
            ),
            ToolDefinition(
                name="curl",
                display_name="cURL",
                category=ToolCategory.UTILITY,
                description="Command line tool for transferring data",
                homepage="https://curl.se",
                binary_name="curl",
                dependencies=[],
                supported_platforms=["linux", "darwin", "windows"],
                default_config={
                    "timeout": 60,
                    "default_args": ["-s"]
                },
                version_command=["curl", "--version"],
                version_regex=r"curl (\d+\.\d+\.\d+)",
                install_methods=["package_manager"],
                tags=["http", "utility", "download"]
            ),
            ToolDefinition(
                name="wget",
                display_name="Wget",
                category=ToolCategory.UTILITY,
                description="Non-interactive network downloader",
                homepage="https://www.gnu.org/software/wget/",
                binary_name="wget",
                dependencies=[],
                supported_platforms=["linux", "darwin"],
                default_config={
                    "timeout": 300,
                    "default_args": ["-q"]
                },
                version_command=["wget", "--version"],
                version_regex=r"GNU Wget (\d+\.\d+)",
                install_methods=["package_manager"],
                tags=["download", "utility"]
            ),
            ToolDefinition(
                name="ffuf",
                display_name="ffuf",
                category=ToolCategory.WEB_SCANNER,
                description="Fast web fuzzer written in Go for content discovery and parameter fuzzing",
                homepage="https://github.com/ffuf/ffuf",
                repository="https://github.com/ffuf/ffuf",
                install_url="github.com/ffuf/ffuf/v2@latest",
                binary_name="ffuf",
                dependencies=["go"],
                supported_platforms=["linux", "darwin", "windows"],
                default_config={
                    "timeout": 300,
                    "default_args": ["-c", "-v"],
                    "threads": 40,
                    "rate_limit": 0
                },
                version_command=["ffuf", "-V"],
                version_regex=r"ffuf version (\d+\.\d+\.\d+)",
                install_methods=["go_install", "binary", "package_manager"],
                tags=["fuzzer", "web", "directory", "parameter"]
            )
        ]
        
        for tool in builtin_tools:
            self.tools[tool.name] = tool
    
    def register_tool(self, tool_def: ToolDefinition, 
                     tool_class: Optional[Type[SecurityTool]] = None) -> None:
        """Register a new tool.
        
        Args:
            tool_def: Tool definition
            tool_class: Tool implementation class (optional)
        """
        self.tools[tool_def.name] = tool_def
        if tool_class:
            self.tool_classes[tool_def.name] = tool_class
        
        self.logger.info(f"Registered tool: {tool_def.name}")
    
    def register_tool_class(self, tool_name: str, tool_class: Type[SecurityTool]) -> None:
        """Register a tool implementation class.
        
        Args:
            tool_name: Name of the tool
            tool_class: Tool implementation class
        """
        if tool_name not in self.tools:
            raise ValueError(f"Tool '{tool_name}' not found in registry")
        
        self.tool_classes[tool_name] = tool_class
        self.logger.info(f"Registered tool class for: {tool_name}")
    
    def get_tool_definition(self, name: str) -> Optional[ToolDefinition]:
        """Get tool definition by name.
        
        Args:
            name: Tool name
            
        Returns:
            Tool definition or None if not found
        """
        return self.tools.get(name)
    
    def get_tool_class(self, name: str) -> Optional[Type[SecurityTool]]:
        """Get tool implementation class by name.
        
        Args:
            name: Tool name
            
        Returns:
            Tool class or None if not found
        """
        return self.tool_classes.get(name)
    
    def list_tools(self, category: Optional[ToolCategory] = None,
                   platform: Optional[str] = None,
                   tags: Optional[List[str]] = None) -> List[ToolDefinition]:
        """List tools matching criteria.
        
        Args:
            category: Filter by category
            platform: Filter by supported platform
            tags: Filter by tags (any match)
            
        Returns:
            List of matching tool definitions
        """
        tools = list(self.tools.values())
        
        if category:
            tools = [t for t in tools if t.category == category]
        
        if platform:
            tools = [t for t in tools if platform in t.supported_platforms]
        
        if tags:
            tools = [t for t in tools if any(tag in t.tags for tag in tags)]
        
        return tools
    
    def search_tools(self, query: str) -> List[ToolDefinition]:
        """Search tools by name or description.
        
        Args:
            query: Search query
            
        Returns:
            List of matching tool definitions
        """
        query_lower = query.lower()
        matching_tools = []
        
        for tool in self.tools.values():
            if (query_lower in tool.name.lower() or
                query_lower in tool.display_name.lower() or
                query_lower in tool.description.lower() or
                any(query_lower in tag.lower() for tag in tool.tags)):
                matching_tools.append(tool)
        
        return matching_tools
    
    def get_tools_by_category(self, category: ToolCategory) -> List[ToolDefinition]:
        """Get tools by category.
        
        Args:
            category: Tool category
            
        Returns:
            List of tools in the category
        """
        return [tool for tool in self.tools.values() if tool.category == category]
    
    def get_dependency_graph(self) -> Dict[str, List[str]]:
        """Get dependency graph for all tools.
        
        Returns:
            Dictionary mapping tool names to their dependencies
        """
        return {name: tool.dependencies for name, tool in self.tools.items()}
    
    def validate_tool_definition(self, tool_def: ToolDefinition) -> List[str]:
        """Validate a tool definition.
        
        Args:
            tool_def: Tool definition to validate
            
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        if not tool_def.name:
            errors.append("Tool name is required")
        
        if not tool_def.display_name:
            errors.append("Tool display name is required")
        
        if not tool_def.description:
            errors.append("Tool description is required")
        
        if not tool_def.supported_platforms:
            errors.append("At least one supported platform is required")
        
        if tool_def.binary_name and not isinstance(tool_def.binary_name, str):
            errors.append("Binary name must be a string")
        
        if tool_def.dependencies and not isinstance(tool_def.dependencies, list):
            errors.append("Dependencies must be a list")
        
        return errors
    
    def save_to_file(self, file_path: Path) -> None:
        """Save registry to file.
        
        Args:
            file_path: Path to save registry
        """
        registry_data = {
            'version': '1.0',
            'tools': {name: tool.to_dict() for name, tool in self.tools.items()}
        }
        
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(file_path, 'w') as f:
            json.dump(registry_data, f, indent=2, default=str)
        
        self.logger.info(f"Registry saved to {file_path}")
    
    def load_from_file(self, file_path: Path) -> None:
        """Load registry from file.
        
        Args:
            file_path: Path to load registry from
        """
        try:
            with open(file_path, 'r') as f:
                registry_data = json.load(f)
            
            tools_data = registry_data.get('tools', {})
            
            for name, tool_data in tools_data.items():
                try:
                    tool_def = ToolDefinition.from_dict(tool_data)
                    self.tools[name] = tool_def
                except Exception as e:
                    self.logger.warning(f"Failed to load tool '{name}': {e}")
            
            self.logger.info(f"Registry loaded from {file_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to load registry from {file_path}: {e}")
    
    def export_markdown_docs(self, output_path: Path) -> None:
        """Export tool registry as markdown documentation.
        
        Args:
            output_path: Path to save markdown file
        """
        lines = ["# Security Tools Registry", "", ""]
        
        # Group tools by category
        categories = {}
        for tool in self.tools.values():
            if tool.category not in categories:
                categories[tool.category] = []
            categories[tool.category].append(tool)
        
        # Generate documentation for each category
        for category, tools in categories.items():
            lines.append(f"## {category.value.replace('_', ' ').title()}")
            lines.append("")
            
            for tool in sorted(tools, key=lambda t: t.name):
                lines.append(f"### {tool.display_name}")
                lines.append("")
                lines.append(f"**Name:** `{tool.name}`")
                lines.append(f"**Description:** {tool.description}")
                
                if tool.homepage:
                    lines.append(f"**Homepage:** {tool.homepage}")
                
                if tool.repository:
                    lines.append(f"**Repository:** {tool.repository}")
                
                lines.append(f"**Platforms:** {', '.join(tool.supported_platforms)}")
                
                if tool.dependencies:
                    lines.append(f"**Dependencies:** {', '.join(tool.dependencies)}")
                
                if tool.tags:
                    lines.append(f"**Tags:** {', '.join(tool.tags)}")
                
                lines.append("")
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            f.write('\n'.join(lines))
        
        self.logger.info(f"Documentation exported to {output_path}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get registry statistics.
        
        Returns:
            Dictionary with registry statistics
        """
        stats = {
            'total_tools': len(self.tools),
            'categories': {},
            'platforms': {},
            'dependencies': {},
            'install_methods': {}
        }
        
        for tool in self.tools.values():
            # Count by category
            cat_name = tool.category.value
            stats['categories'][cat_name] = stats['categories'].get(cat_name, 0) + 1
            
            # Count by platform
            for platform in tool.supported_platforms:
                stats['platforms'][platform] = stats['platforms'].get(platform, 0) + 1
            
            # Count by dependencies
            for dep in tool.dependencies:
                stats['dependencies'][dep] = stats['dependencies'].get(dep, 0) + 1
            
            # Count by install method
            for method in tool.install_methods:
                stats['install_methods'][method] = stats['install_methods'].get(method, 0) + 1
        
        return stats