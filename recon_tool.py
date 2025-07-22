import argparse
import requests
import socket
import whois
import os
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from shodan_lookup import get_shodan_data
from fofa_lookup import get_fofa_data
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.box import MINIMAL
from colorama import init, Fore, Style

# Initialize Colorama for cross-platform terminal colors
init(autoreset=True)

console = Console()

# Common User-Agents to rotate
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/109.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Bingbot/2.0 (+http://www.bing.com/bingbot.htm)",
]

def get_request_headers(user_agent=None):
    """Returns a dictionary of headers for HTTP requests."""
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    if user_agent:
        headers["User-Agent"] = user_agent
    else:
        import random
        headers["User-Agent"] = random.choice(USER_AGENTS)
    return headers

def make_request(url, headers, proxies=None, timeout=10, retries=3):
    """
    Makes an HTTP GET request with retry mechanism and proxy support.
    Returns the response object or None on failure.
    """
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers, proxies=proxies, timeout=timeout, allow_redirects=True)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            return response
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                console.log(f"[yellow]Attempt {attempt + 1}: Access to {url} forbidden (403). Trying again with different User-Agent/proxy if available.[/yellow]")
                # For 403, we might want to try a different UA or proxy immediately
                if attempt < retries - 1:
                    import random
                    headers["User-Agent"] = random.choice(USER_AGENTS) # Rotate User-Agent
                    if proxies: # If proxies are used, rotate them too (simple rotation for now)
                        proxy_keys = list(proxies.keys())
                        for key in proxy_keys:
                            proxies[key] = random.choice(list(proxies.values())) # This is a very basic rotation, could be improved
                    continue
            console.log(f"[red]HTTP Error for {url} (Attempt {attempt + 1}/{retries}): {e}[/red]")
        except requests.exceptions.ConnectionError as e:
            console.log(f"[red]Connection Error for {url} (Attempt {attempt + 1}/{retries}): {e}[/red]")
        except requests.exceptions.Timeout as e:
            console.log(f"[red]Timeout Error for {url} (Attempt {attempt + 1}/{retries}): {e}[/red]")
        except requests.exceptions.RequestException as e:
            console.log(f"[red]An unexpected error occurred for {url} (Attempt {attempt + 1}/{retries}): {e}[/red]")
        
        if attempt < retries - 1:
            import time
            time.sleep(2 ** attempt) # Exponential backoff

    return None

def http_fingerprint(url, headers, proxies):
    """Analyzes HTTP headers for web server and tech stack information."""
    console.log(f"[bold cyan]Performing HTTP Fingerprinting on {url}...[/bold cyan]")
    tech_info = {}
    response = make_request(url, headers, proxies)

    if response:
        for header, value in response.headers.items():
            tech_info[header] = value
        
        # Common headers for tech stack detection
        if 'Server' in response.headers:
            tech_info['Web Server'] = response.headers['Server']
        if 'X-Powered-By' in response.headers:
            tech_info['Powered By'] = response.headers['X-Powered-By']
        if 'Set-Cookie' in response.headers:
            # Look for common framework cookies
            cookies = response.headers['Set-Cookie']
            if 'PHPSESSID' in cookies or 'laravel_session' in cookies:
                tech_info['Framework/Language'] = tech_info.get('Framework/Language', '') + 'PHP'
            if 'ASP.NET_SessionId' in cookies:
                tech_info['Framework/Language'] = tech_info.get('Framework/Language', '') + 'ASP.NET'
            if 'JSESSIONID' in cookies:
                tech_info['Framework/Language'] = tech_info.get('Framework/Language', '') + 'Java/JSP'
        
        # Check for common CMS headers (e.g., X-Generator for WordPress)
        if 'X-Generator' in response.headers:
            tech_info['CMS'] = response.headers['X-Generator']
        
        return tech_info
    return None

def html_fingerprint(url, headers, proxies):
    """Analyzes HTML content for CMS and tech stack information."""
    console.log(f"[bold cyan]Performing HTML Fingerprinting on {url}...[/bold cyan]")
    tech_info = {}
    response = make_request(url, headers, proxies)

    if response and response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')

        # Check for generator meta tag (common for CMS)
        generator_meta = soup.find('meta', attrs={'name': 'generator'})
        if generator_meta and 'content' in generator_meta.attrs:
            tech_info['CMS'] = generator_meta['content']

        # Check for common CMS/framework patterns in script tags
        for script in soup.find_all('script', src=True):
            src = script['src'].lower()
            if 'wp-includes' in src or 'wp-content' in src:
                tech_info['CMS'] = tech_info.get('CMS', '') + 'WordPress'
            if 'joomla' in src:
                tech_info['CMS'] = tech_info.get('CMS', '') + 'Joomla'
            if 'drupal' in src:
                tech_info['CMS'] = tech_info.get('CMS', '') + 'Drupal'
            if 'react.production' in src or 'react.development' in src:
                tech_info['Frontend Framework'] = tech_info.get('Frontend Framework', '') + 'React'
            if 'vue.js' in src:
                tech_info['Frontend Framework'] = tech_info.get('Frontend Framework', '') + 'Vue.js'
            if 'angular.js' in src:
                tech_info['Frontend Framework'] = tech_info.get('Frontend Framework', '') + 'AngularJS'
        
        # Check for common CMS/framework patterns in link tags (CSS)
        for link in soup.find_all('link', href=True):
            href = link['href'].lower()
            if 'wp-content' in href or 'wp-includes' in href:
                tech_info['CMS'] = tech_info.get('CMS', '') + 'WordPress'
            if 'joomla' in href:
                tech_info['CMS'] = tech_info.get('CMS', '') + 'Joomla'
            if 'drupal' in href:
                tech_info['CMS'] = tech_info.get('CMS', '') + 'Drupal'

        return tech_info
    return None

def dns_lookup(domain):
    """Performs DNS lookup for IP address and other DNS records."""
    console.log(f"[bold cyan]Performing DNS Lookup for {domain}...[/bold cyan]")
    dns_info = {}
    try:
        ip_address = socket.gethostbyname(domain)
        dns_info['IP Address'] = ip_address
    except socket.gaierror:
        dns_info['IP Address'] = "Could not resolve IP"

    try:
        w = whois.whois(domain)
        dns_info['WHOIS Info'] = w.text
    except Exception as e:
        dns_info['WHOIS Info'] = f"Could not retrieve WHOIS info: {e}"
    
    return dns_info

def display_results(url, http_data, html_data, dns_data, shodan_data=None, fofa_data=None):
    """Displays the collected reconnaissance data using Rich."""
    console.print(Panel(f"[bold green]Reconnaissance Report for:[/bold green] [cyan]{url}[/cyan]", expand=False, box=MINIMAL))

    # HTTP Fingerprinting Results
    if http_data:
        http_table = Table(title="[bold magenta]HTTP Headers & Server Info[/bold magenta]", show_header=True, header_style="bold blue")
        http_table.add_column("Header/Info", style="cyan", no_wrap=True)
        http_table.add_column("Value", style="green")
        for key, value in http_data.items():
            http_table.add_row(key, str(value))
        console.print(http_table)
    else:
        console.print(Panel("[red]No HTTP Fingerprinting data found.[/red]", expand=False))

    # HTML Fingerprinting Results
    if html_data:
        html_table = Table(title="[bold magenta]HTML Fingerprinting (CMS/Frontend)[/bold magenta]", show_header=True, header_style="bold blue")
        html_table.add_column("Category", style="cyan", no_wrap=True)
        html_table.add_column("Detected Tech", style="green")
        for key, value in html_data.items():
            html_table.add_row(key, str(value))
        console.print(html_table)
    else:
        console.print(Panel("[red]No HTML Fingerprinting data found.[/red]", expand=False))

    # DNS Report
    if dns_data:
        dns_table = Table(title="[bold magenta]DNS & WHOIS Report[/bold magenta]", show_header=True, header_style="bold blue")
        dns_table.add_column("Category", style="cyan", no_wrap=True)
        dns_table.add_column("Value", style="green")
        for key, value in dns_data.items():
            dns_table.add_row(key, str(value))
        console.print(dns_table)
    else:
        console.print(Panel("[red]No DNS/WHOIS data found.[/red]", expand=False))

    # Shodan Data
    if shodan_data:
        shodan_table = Table(title="[bold magenta]Shodan Data[/bold magenta]", show_header=True, header_style="bold blue")
        shodan_table.add_column("Category", style="cyan", no_wrap=True)
        shodan_table.add_column("Value", style="green")
        for key, value in shodan_data.items():
            # Limit the length of WHOIS info for better display
            if key == 'whois' and isinstance(value, dict):
                for w_key, w_value in value.items():
                    shodan_table.add_row(f"WHOIS: {w_key}", str(w_value)[:200] + "..." if len(str(w_value)) > 200 else str(w_value))
            elif isinstance(value, (list, dict)):
                shodan_table.add_row(key, Text(str(value), overflow="fold"))
            else:
                shodan_table.add_row(key, str(value))
        console.print(shodan_table)
    else:
        console.print(Panel("[yellow]No Shodan data retrieved (API key missing or error).[/yellow]", expand=False))

    # FOFA Data
    if fofa_data and fofa_data.get('results'):
        fofa_table = Table(title="[bold magenta]FOFA Data[/bold magenta]", show_header=True, header_style="bold blue")
        fofa_table.add_column("Field", style="cyan", no_wrap=True)
        fofa_table.add_column("Value", style="green")
        for result in fofa_data['results']:
            for key, value in result.items():
                fofa_table.add_row(key, str(value))
        console.print(fofa_table)
    else:
        console.print(Panel("[yellow]No FOFA data retrieved (API key/email missing or error).[/yellow]", expand=False))


def main():
    parser = argparse.ArgumentParser(description="Web Reconnaissance and Tech Stack Fingerprinting Tool")
    parser.add_argument("url", help="The target URL (e.g., https://example.com)")
    parser.add_argument("--user-agent", help="Specify a custom User-Agent string.")
    parser.add_argument("--random-user-agent", action="store_true", help="Use a random User-Agent from a predefined list.")
    parser.add_argument("--proxy", help="Specify a single proxy (e.g., http://host:port or socks5://host:port)")
    parser.add_argument("--proxy-file", help="Path to a file containing a list of proxies (one per line). Prioritized over --proxy.")
    parser.add_argument("--shodan-api-key", help="Your Shodan API key. Overrides SHODAN_API_KEY environment variable.")
    parser.add_argument("--fofa-api-key", help="Your FOFA API key. Overrides FOFA_API_KEY environment variable.")
    parser.add_argument("--fofa-email", help="Your FOFA email. Overrides FOFA_EMAIL environment variable.")


    args = parser.parse_args()

    target_url = args.url
    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc

    if not parsed_url.scheme:
        console.log("[yellow]Warning: No scheme provided in URL. Defaulting to https://[/yellow]")
        target_url = "https://" + target_url
        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc

    headers = get_request_headers(args.user_agent if args.user_agent else (random.choice(USER_AGENTS) if args.random_user_agent else None))

    proxies = None
    proxy_list = []

    if args.proxy_file:
        try:
            with open(args.proxy_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        proxy_list.append(line)
            if proxy_list:
                console.log(f"[green]Loaded {len(proxy_list)} proxies from {args.proxy_file}[/green]")
                selected_proxy = random.choice(proxy_list)
                if selected_proxy.startswith("http://"):
                    proxies = {"http": selected_proxy, "https": selected_proxy}
                elif selected_proxy.startswith("socks5://"):
                    proxies = {"http": selected_proxy, "https": selected_proxy}
                else:
                    console.log(f"[yellow]Warning: Unknown proxy scheme for '{selected_proxy}'. Skipping.[/yellow]")
                    proxies = None
            else:
                console.log("[yellow]No valid proxies found in the file.[/yellow]")
        except FileNotFoundError:
            console.log(f"[red]Error: Proxy file '{args.proxy_file}' not found.[/red]")
        except Exception as e:
            console.log(f"[red]Error reading proxy file: {e}[/red]")
    elif args.proxy:
        if args.proxy.startswith("http://"):
            proxies = {"http": args.proxy, "https": args.proxy}
        elif args.proxy.startswith("socks5://"):
            proxies = {"http": args.proxy, "https": args.proxy}
        else:
            console.log(f"[yellow]Warning: Unknown proxy scheme for '{args.proxy}'. Please use http:// or socks5://[/yellow]")
            proxies = None

    console.log(f"[bold green]Starting reconnaissance for: {target_url}[/bold green]")
    if proxies:
        console.log(f"[bold green]Using proxy: {list(proxies.values())[0]}[/bold green]")
    if headers.get("User-Agent"):
        console.log(f"[bold green]Using User-Agent: {headers['User-Agent']}[/bold green]")

    http_data = http_fingerprint(target_url, headers, proxies)
    html_data = html_fingerprint(target_url, headers, proxies)
    dns_data = dns_lookup(domain)

    shodan_data = None
    fofa_data = None

    # Get IP address from DNS data for Shodan/FOFA lookups
    ip_for_api_lookup = dns_data.get('IP Address') if dns_data else None

    if ip_for_api_lookup and ip_for_api_lookup != "Could not resolve IP":
        shodan_api_key = args.shodan_api_key if args.shodan_api_key else os.environ.get('SHODAN_API_KEY')
        if shodan_api_key:
            shodan_data = get_shodan_data(ip_for_api_lookup, shodan_api_key)
        else:
            console.log("[yellow]Shodan API key not provided via argument or environment variable. Skipping Shodan lookup.[/yellow]")

        fofa_api_key = args.fofa_api_key if args.fofa_api_key else os.environ.get('FOFA_API_KEY')
        fofa_email = args.fofa_email if args.fofa_email else os.environ.get('FOFA_EMAIL')
        if fofa_api_key and fofa_email:
            fofa_data = get_fofa_data(ip_for_api_lookup, fofa_api_key, fofa_email)
        else:
            console.log("[yellow]FOFA API key or Email not provided via argument or environment variable. Skipping FOFA lookup.[/yellow]")
    else:
        console.log("[yellow]Could not resolve IP address for API lookups. Skipping Shodan and FOFA.[/yellow]")

    display_results(target_url, http_data, html_data, dns_data, shodan_data, fofa_data)

if __name__ == "__main__":
    main()
