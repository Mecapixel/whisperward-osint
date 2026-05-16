#!/usr/bin/env python3
# Imports and setup
"""
WhisperWard OSINT - Professional Demo Script
Uses fictional test data only. For portfolio demonstration purposes.
Run: python3 demo.py
"""

from rich.console import Console
import os
import time

console = Console()

# Demo function
def demo():
    console.print('[bold magenta]WhisperWard OSINT - Professional Demo[/bold magenta]\n')
    console.print('[dim]All data in this demo is fictional and for demonstration only.[/dim]\n')

    steps = [
        (
            'python3 whisperward.py init-db',
            'Initialize Database'
        ),
        (
            'python3 whisperward.py new-case --name "Operation-SafePlay-2026"',
            'Create Investigation Case'
        ),
        (
            'python3 whisperward.py add-target --case CASE-2026 '
            '--username "FictionalUser123" --platform roblox',
            'Add Fictional Roblox Target'
        ),
        (
            'python3 whisperward.py add-target --case CASE-2026 '
            '--username "FictionalUser123" --platform discord',
            'Add Fictional Discord Target (same username)'
        ),
        (
            'python3 whisperward.py scan --case CASE-2026',
            'Run OSINT Collection'
        ),
        (
            'python3 whisperward.py analyze --case CASE-2026 --ai',
            'Run Behavioral Analysis (AI enabled)'
        ),
        (
            'python3 whisperward.py graph --case CASE-2026',
            'Generate Identity Relationship Graph'
        ),
        (
            'python3 whisperward.py export --case CASE-2026',
            'Create Evidence Package'
        ),
        (
            'python3 whisperward.py status --case CASE-2026',
            'Show Case Summary'
        ),
    ]

    for command, desc in steps:
        console.print(f'[bold yellow]-> {desc}[/bold yellow]')
        os.system(command)
        time.sleep(1.2)

    console.print('\n[bold green]Demo completed successfully![/bold green]')
    console.print('Check the exports/ and reports/ folders for output.')
    console.print('[dim]Take screenshots of this output for your portfolio.[/dim]')


# Entry point
if __name__ == '__main__':
    demo()
