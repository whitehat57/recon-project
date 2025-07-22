import os
from rich.console import Console
import fofa

console = Console()

def get_fofa_data(ip_address, api_key=None, email=None):
    """
    Performs a FOFA lookup for the given IP address.
    API key and email can be provided as parameters or read from FOFA_API_KEY and FOFA_EMAIL environment variables.
    """
    if not api_key:
        api_key = os.environ.get('FOFA_API_KEY')
    if not email:
        email = os.environ.get('FOFA_EMAIL')

    if not api_key or not email:
        console.log("[yellow]FOFA API key or Email not found. Skipping FOFA lookup. Provide with --fofa-api-key and --fofa-email or set FOFA_API_KEY and FOFA_EMAIL environment variables.[/yellow]")
        return None

    try:
        client = fofa.Client(email, api_key)
        # FOFA query for IP address
        query = f'ip="{ip_address}"'
        # You can specify fields to retrieve, e.g., 'host,ip,port,protocol,title,os,server,banner,header'
        # For simplicity, we'll fetch all available fields for now
        data = client.search(query)
        console.log(f"[bold cyan]Performing FOFA lookup for {ip_address}...[/bold cyan]")
        return data
    except Exception as e:
        console.log(f"[red]An error occurred during FOFA lookup for {ip_address}: {e}[/red]")
        return None

if __name__ == '__main__':
    # Example usage (for testing purposes)
    # Set FOFA_API_KEY and FOFA_EMAIL environment variables or pass them directly
    # For example: export FOFA_API_KEY="YOUR_API_KEY"
    #              export FOFA_EMAIL="your_email@example.com"

    # Test with a known IP
    ip = "8.8.8.8" # Google DNS
    fofa_info = get_fofa_data(ip)
    if fofa_info:
        console.print(f"[bold green]FOFA Info for {ip}:[/bold green]")
        console.print(fofa_info)
    else:
        console.print(f"[red]Failed to retrieve FOFA info for {ip}[/red]")
