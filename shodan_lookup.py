import shodan
import os
from rich.console import Console

console = Console()

def get_shodan_data(ip_address, api_key=None):
    """
    Performs a Shodan lookup for the given IP address.
    API key can be provided as a parameter or read from SHODAN_API_KEY environment variable.
    """
    if not api_key:
        api_key = os.environ.get('SHODAN_API_KEY')

    if not api_key:
        console.log("[yellow]Shodan API key not found. Skipping Shodan lookup. Provide with --shodan-api-key or set SHODAN_API_KEY environment variable.[/yellow]")
        return None

    try:
        api = shodan.Shodan(api_key)
        host_info = api.host(ip_address)
        console.log(f"[bold cyan]Performing Shodan lookup for {ip_address}...[/bold cyan]")
        return host_info
    except shodan.exception.APIError as e:
        console.log(f"[red]Shodan API Error for {ip_address}: {e}[/red]")
        return None
    except Exception as e:
        console.log(f"[red]An unexpected error occurred during Shodan lookup for {ip_address}: {e}[/red]")
        return None

if __name__ == '__main__':
    # Example usage (for testing purposes)
    # Set SHODAN_API_KEY environment variable or pass it directly
    # For example: export SHODAN_API_KEY="YOUR_API_KEY"
    
    # Test with a known IP
    ip = "8.8.8.8" # Google DNS
    shodan_info = get_shodan_data(ip)
    if shodan_info:
        console.print(f"[bold green]Shodan Info for {ip}:[/bold green]")
        console.print(shodan_info)
    else:
        console.print(f"[red]Failed to retrieve Shodan info for {ip}[/red]")
