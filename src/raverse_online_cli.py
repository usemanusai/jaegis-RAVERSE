"""
RAVERSE Online CLI - Command-line interface for remote target analysis.
"""

import argparse
import logging
import json
import sys
from pathlib import Path
from datetime import datetime

from agents.online_orchestrator import OnlineOrchestrationAgent


def setup_logging(log_level=None, log_file=None):
    """Configure logging with file and console handlers."""
    level = getattr(logging, (log_level or 'INFO').upper(), logging.INFO)
    log_file = log_file or 'raverse_online.log'

    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )


def load_scope_config(scope_file):
    """Load scope configuration from JSON file."""
    try:
        with open(scope_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading scope config: {e}")
        sys.exit(1)


def load_options_config(options_file):
    """Load execution options from JSON file."""
    try:
        with open(options_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading options config: {e}")
        sys.exit(1)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='RAVERSE Online - AI-Powered Remote Target Analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic analysis with scope file
  python raverse_online_cli.py https://example.com --scope scope.json
  
  # Full analysis with custom options
  python raverse_online_cli.py https://example.com --scope scope.json --options options.json --report pdf
  
  # Verbose logging
  python raverse_online_cli.py https://example.com --scope scope.json --log-level DEBUG
        """
    )
    
    # Required arguments
    parser.add_argument(
        'target_url',
        help='Target URL to analyze (e.g., https://example.com)'
    )
    
    # Scope and authorization
    parser.add_argument(
        '--scope',
        required=True,
        help='Path to scope configuration JSON file (defines authorized targets)'
    )
    
    # Execution options
    parser.add_argument(
        '--options',
        help='Path to execution options JSON file'
    )
    
    # Report format
    parser.add_argument(
        '--report',
        choices=['markdown', 'json', 'html', 'pdf'],
        default='markdown',
        help='Report output format (default: markdown)'
    )
    
    # Logging
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level (default: INFO)'
    )
    
    parser.add_argument(
        '--log-file',
        help='Log file path (default: raverse_online.log)'
    )
    
    # Output
    parser.add_argument(
        '--output',
        help='Output directory for results (default: ./results)'
    )
    
    # API configuration
    parser.add_argument(
        '--api-key',
        help='OpenRouter API key (falls back to OPENROUTER_API_KEY env var)'
    )
    
    parser.add_argument(
        '--model',
        help='LLM model to use (falls back to OPENROUTER_MODEL env var)'
    )
    
    # Execution options
    parser.add_argument(
        '--traffic-duration',
        type=int,
        default=30,
        help='Traffic interception duration in seconds (default: 30)'
    )
    
    parser.add_argument(
        '--skip-validation',
        action='store_true',
        help='Skip validation phase'
    )
    
    parser.add_argument(
        '--skip-ai-analysis',
        action='store_true',
        help='Skip AI co-pilot analysis'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level, args.log_file)
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 80)
    logger.info("RAVERSE Online - AI-Powered Remote Target Analysis")
    logger.info("=" * 80)
    logger.info(f"Target: {args.target_url}")
    logger.info(f"Report Format: {args.report}")
    logger.info(f"Log Level: {args.log_level}")
    
    try:
        # Load scope configuration
        logger.info(f"Loading scope configuration from: {args.scope}")
        scope = load_scope_config(args.scope)
        
        # Load execution options
        options = {}
        if args.options:
            logger.info(f"Loading execution options from: {args.options}")
            options = load_options_config(args.options)
        
        # Add CLI options to execution options
        options['report_format'] = args.report
        options['traffic_duration'] = args.traffic_duration
        
        if args.skip_validation:
            options['skip_validation'] = True
        
        if args.skip_ai_analysis:
            options['skip_ai_copilot'] = True
        
        # Initialize orchestrator
        logger.info("Initializing Online Orchestration Agent")
        orchestrator = OnlineOrchestrationAgent(
            api_key=args.api_key,
            model=args.model
        )
        
        # Run analysis
        logger.info("Starting analysis pipeline")
        results = orchestrator.run(args.target_url, scope, options)
        
        # Save results
        output_dir = Path(args.output or './results')
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save JSON results
        results_file = output_dir / f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"Results saved to: {results_file}")
        
        # Print summary
        print("\n" + "=" * 80)
        print("ANALYSIS COMPLETE")
        print("=" * 80)
        print(f"Run ID: {results['run_id']}")
        print(f"Target: {results['target_url']}")
        print(f"Duration: {results['duration_seconds']:.2f} seconds")
        print(f"\nSummary:")
        summary = results.get('summary', {})
        print(f"  Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        print(f"  Critical: {summary.get('critical_count', 0)}")
        print(f"  High: {summary.get('high_count', 0)}")
        print(f"  Endpoints Discovered: {summary.get('endpoints_discovered', 0)}")
        print(f"  API Calls Captured: {summary.get('api_calls_captured', 0)}")
        print(f"  Overall Risk: {summary.get('overall_risk', 'UNKNOWN')}")
        print(f"\nResults saved to: {results_file}")
        print("=" * 80)
        
        return 0
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        print(f"\nERROR: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())

