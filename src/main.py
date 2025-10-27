"""
RAVERSE - AI Multi-Agent Binary Patching System
Enhanced with PostgreSQL and Redis integration
Date: October 25, 2025
"""

import logging
import argparse
import sys
import os
from agents.orchestrator import OrchestratingAgent

try:
    from config.settings import Settings
    SETTINGS_AVAILABLE = True
except ImportError:
    Settings = None
    SETTINGS_AVAILABLE = False


def setup_logging(log_level=None, log_file=None):
    """Configure logging with file and console handlers"""
    level = getattr(logging, (log_level or 'INFO').upper(), logging.INFO)
    log_file = log_file or 'raverse.log'

    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='RAVERSE - AI Multi-Agent Binary Patching System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py binary.exe
  python main.py binary.exe --model meta-llama/llama-3.2-3b-instruct:free
  python main.py binary.exe --no-database
  python main.py --config
        """
    )

    parser.add_argument(
        'binary_path',
        nargs='?',
        help='Path to the binary file to analyze and patch'
    )

    parser.add_argument(
        '--model',
        help='OpenRouter model to use (default: from env or config)'
    )

    parser.add_argument(
        '--no-database',
        action='store_true',
        help='Run in standalone mode without PostgreSQL/Redis'
    )

    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Set logging level (default: INFO)'
    )

    parser.add_argument(
        '--log-file',
        help='Log file path (default: raverse.log)'
    )

    parser.add_argument(
        '--config',
        action='store_true',
        help='Print current configuration and exit'
    )

    return parser.parse_args()


def main():
    """Main entry point"""
    args = parse_arguments()

    # Setup logging
    setup_logging(args.log_level, args.log_file)
    logger = logging.getLogger(__name__)

    # Print configuration if requested
    if args.config:
        if SETTINGS_AVAILABLE:
            Settings.print_config()
        else:
            print("Configuration module not available")
        return 0

    # Validate binary path
    if not args.binary_path:
        print("Error: binary_path is required")
        print("Usage: python main.py <binary_path>")
        print("Run 'python main.py --help' for more information")
        return 1

    if not os.path.exists(args.binary_path):
        print(f"Error: Binary file not found: {args.binary_path}")
        return 1

    try:
        # Validate configuration
        if SETTINGS_AVAILABLE and not Settings.validate():
            return 1

        # Initialize orchestrator
        logger.info("=" * 60)
        logger.info("RAVERSE - AI Multi-Agent Binary Patching System")
        logger.info("=" * 60)

        use_database = not args.no_database
        oa = OrchestratingAgent(model=args.model, use_database=use_database)

        logger.info(f"Processing binary: {args.binary_path}")
        logger.info(f"Model: {oa.model}")
        logger.info(f"Database mode: {'Enabled' if use_database else 'Disabled'}")
        logger.info("=" * 60)

        # Run analysis
        result = oa.run(args.binary_path)

        # Print results
        logger.info("=" * 60)
        logger.info("Analysis Complete")
        logger.info("=" * 60)

        if result:
            print("\n" + "=" * 60)
            print("RAVERSE Analysis Results")
            print("=" * 60)
            print(f"Binary: {args.binary_path}")
            print(f"Success: {result.get('success', False)}")
            if 'message' in result:
                print(f"Message: {result['message']}")
            print("=" * 60)
            return 0 if result.get('success') else 1
        else:
            print("\nAnalysis failed. Check logs for details.")
            return 1

    except ValueError as e:
        logger.error(f"Configuration Error: {e}")
        print(f"\nConfiguration Error: {e}")
        print("Please set OPENROUTER_API_KEY in your environment or .env file")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        print(f"\nUnexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())