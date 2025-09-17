#!/usr/bin/env python3
"""
Valkyrie CLI - A command-line tool.
"""

import argparse
from typing import List
from pathlib import Path

import yaml

from valkyrie.core import (
    ValkyrieConfig, ValkyrieScanner,
    ScanStatus, get_formatter
)
from valkyrie.rules.repositories import (
    LocalRuleRepository, GitHubRuleRepository
)
from valkyrie.utils import (
    get_context,
    get_logger
)


####
##      VALKYRIE CLI ENTRY POINT
#####
class ValkyrieCLI:
    """Command line interface for Valkyrie scanner"""
    
    def __init__(self):

        self.logger = get_logger('Valkyrie.CLI')
        self.context = get_context()
        # self.ci_integrations = [
        #     GitHubActionsIntegration(),
        #     GitLabCIIntegration()
        # ]
        # self.formatters = {
        #     "json": JSONFormatter(),
        #     "sarif": SARIFFormatter(),
        #     "html": HTMLFormatter()
        # }
        ...
    
    def create_parser(self) -> argparse.ArgumentParser:
        """Create CLI argument parser"""
        parser = argparse.ArgumentParser(
            description="Valkyrie - Security scanner for CI/CD pipelines",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  valkyrie scan                                 # Scan current directory
  valkyrie scan --target <TARGET_DIR>           # Target directoory to scan
  valkyrie scan --config-file <CONFIG_FILE>     # Valyrie config file
            """
        )
        
        subparsers = parser.add_subparsers(dest="command", help="Available commands")
        
        # Scan command
        scan_parser = subparsers.add_parser("scan", help="Run security scan")
        scan_parser.add_argument("target", nargs="?", default=".", help="Target path to scan")
        scan_parser.add_argument("--config-file", "-f", nargs="?", default="valkyrie.yml", help="Valkyrie configuration file path")
        # scan_parser.add_argument("--format", choices=["json", "sarif", "html"], default="json", help="Output format")
        # scan_parser.add_argument("--output", "-o", type=Path, help="Output file path")
        # scan_parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], default="low", help="Minimum severity level")
        # scan_parser.add_argument("--rules-repo", default="valkyrie-community/rules", help="Rules repository")
        # scan_parser.add_argument("--no-fail", action="store_true", help="Don't fail on findings")
        # scan_parser.add_argument("--include", action="append", help="Include patterns")
        # scan_parser.add_argument("--exclude", action="append", help="Exclude patterns")
        # scan_parser.add_argument("--workers", type=int, default=4, help="Number of parallel workers")
        # scan_parser.add_argument("--diff-only", action="store_true", help="Only scan changed files")
        scan_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
        
        # Version command
        subparsers.add_parser("version", help="Show version information")
        
        return parser
    
    async def run(self, args: List[str] = None) -> int:
        """Run CLI with given arguments"""

        parser = self.create_parser()
        parsed_args = parser.parse_args(args)
        
        if parsed_args.command == "version":
            print("Valkyrie Security Scanner v1.0.0")
            return 0
        
        elif parsed_args.command == "scan":
            return await self._run_scan(parsed_args)
        
        else:
            parser.print_help()
            return 1
    
    async def _run_scan(self, args) -> int:
        """Execute security scan"""
        
        # Load Config file
        file = Path(args.config_file)

        print(file)

        # Create configuration
        config = ValkyrieConfig.from_json(
            yaml.safe_load(file.read_text())
        )

        # Add cmd args to the global context
        self.context.set_data('cmd_args', args)

        # Detect and register configured plugins
        # PluginManager.load_from_config(config.plugins)

        
        # Detect CI environment
        # active_ci = None
        # for ci_integration in self.ci_integrations:
        #     if ci_integration.detect_environment():
        #         active_ci = ci_integration
        #         break
        
        # if active_ci and args.verbose:
        #     print(f"Detected CI environment: {active_ci.__class__.__name__}")
        
        # # Filter files if diff-only mode
        # if args.diff_only and active_ci:
        #     changed_files = active_ci.get_changed_files()
        #     if changed_files:
        #         # Convert to include patterns
        #         config.scanner.include_patterns = [str(f) for f in changed_files]
        #         if args.verbose:
        #             print(f"Scanning {len(changed_files)} changed files")
        
        # Set up scanner
        

        # Init GH repository with config options
        gh_repo = GitHubRuleRepository(
            config = config.rules.repository
        )
        # local_repo = LocalRuleRepository(Path("rules"))  # In practice, use GitHub repo
        scanner = ValkyrieScanner(
            rule_repository = gh_repo,
            config = config.scanner
        )
        
        # Run scan
        if args.verbose:
            print(f"Starting security scan of {config.scanner.target_path}")
        
        result = await scanner.scan()
        
        # Format results
        formatter = get_formatter(config.output.format)
        formatted_output = formatter().format(result)
        
        # Output results
        if config.output.file:
            Path(config.output.file).write_text(formatted_output, encoding='utf-8')
            print(f"Results saved to: {args.output}")
        else:
            print(formatted_output)
        
        # Post to CI if in CI environment
        # if active_ci:
        #     await active_ci.post_results(result, {})
        
        # Determine exit code
        if result.status == ScanStatus.FAILED:
            return 2  # Scan failure
        elif config.scanner.fail_on_findings and result.has_blocking_issues:
            return 1  # Security issues found
        else:
            return 0  # Success
        