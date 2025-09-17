# -*- coding: utf-8 -*-

""" MAIN ENTRY POINT FOR Valkyrie CLI
This module serves as the main entry point for the Valkyrie CLI. It handles command-line
arguments, initializes the command registry, and executes the specified command.
"""

import sys
import asyncio
from valkyrie.cli import (
    ValkyrieCLI
)

import tracemalloc
tracemalloc.start()

async def main():
    """ 
    Main function to handle command-line arguments and execute commands.
    This function checks if any command is provided, retrieves the command class
    from the command registry, and executes the command with the provided arguments.
    If no command is provided, it lists all available commands.
    """

    cli = ValkyrieCLI()
    exit_code = await cli.run()
    sys.exit(exit_code)

if __name__ == "__main__":
    asyncio.run(main())
