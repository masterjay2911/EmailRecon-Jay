#!/usr/bin/env python3
"""
EmailRecon-Jay - Email Reconnaissance Tool
Created By Jay Mali
Description: A comprehensive email reconnaissance tool that performs DNS lookups, 
WHOIS queries, reputation checks, and generates Google search dorks.
"""

import sys
import re
import argparse
import requests
import dns.resolver
import whois
from urllib.parse import quote

def print_banner():
    """Display the tool banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                        EmailRecon-Jay                        ║
    ║                  Email Reconnaissance Tool                   ║
    ║                         Version 1.0                         ║
    ║                  Created By Jay Mali                        ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def validate_email(email):
    """
    Validate email format using regex
    Args:
        email (str): Email address to validate
    Returns:
        bool: True if valid, False otherwise
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def extract_domain(email):
    """
    Extract domain name from email address
    Args:
        email (str): Email address
    Returns:
        str: Domain name
    """
    return email.split('@')[1]

def dns_mx_lookup(domain):
    """
    Perform DNS MX record lookup
    Args:
        domain (str): Domain name to lookup
    """
    print(f"\n[+] DNS MX Record Lookup for {domain}")
    print("=" * 50)
    
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        if mx_records:
            print(f"[+] Found {len(mx_records)} MX record(s):")
            for mx in mx_records:
                print(f"    Priority: {mx.preference}, Mail Server: {mx.exchange}")
        else:
            print("[-] No MX records found")
    except dns.resolver.NXDOMAIN:
        print("[-] Domain does not exist")
    except dns.resolver.NoAnswer:
        print("[-] No MX records found for this domain")
    except Exception as e:
        print(f"[-] Error performing MX lookup: {str(e)}")

def whois_lookup(domain):
    """
    Perform WHOIS lookup on domain
    Args:
        domain (str): Domain name to lookup
    """
    print(f"\n[+] WHOIS Lookup for {domain}")
    print("=" * 50)
    
    try:
        domain_info = whois.whois(domain)
        
        if domain_info:
            print("[+] WHOIS Information found:")
            
            # Domain name
            if domain_info.domain_name:
                if isinstance(domain_info.domain_name, list):
                    print(f"    Domain Name: {domain_info.domain_name[0]}")
                else:
                    print(f"    Domain Name: {domain_info.domain_name}")
            
            # Registrar
            if domain_info.registrar:
                print(f"    Registrar: {domain_info.registrar}")
            
            # Creation date
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    print(f"    Creation Date: {domain_info.creation_date[0]}")
                else:
                    print(f"    Creation Date: {domain_info.creation_date}")
            
            # Expiration date
            if domain_info.expiration_date:
                if isinstance(domain_info.expiration_date, list):
                    print(f"    Expiration Date: {domain_info.expiration_date[0]}")
                else:
                    print(f"    Expiration Date: {domain_info.expiration_date}")
            
            # Name servers
            if domain_info.name_servers:
                print(f"    Name Servers: {', '.join(domain_info.name_servers)}")
            
            # Organization
            if domain_info.org:
                print(f"    Organization: {domain_info.org}")
            
            # Country
            if domain_info.country:
                print(f"    Country: {domain_info.country}")
        else:
            print("[-] No WHOIS information available")
            
    except Exception as e:
        print(f"[-] Error performing WHOIS lookup: {str(e)}")

def email_reputation_check(email):
    """
    Check email reputation using emailrep.io API
    Args:
        email (str): Email address to check
    """
    print(f"\n[+] Email Reputation Check for {email}")
    print("=" * 50)
    
    try:
        url = f"https://emailrep.io/{email}"
        headers = {
            'User-Agent': 'EmailRecon-Jay/1.0 (Educational Purpose)'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            print("[+] Email reputation data found:")
            
            # Email address
            if 'email' in data:
                print(f"    Email: {data['email']}")
            
            # Reputation score
            if 'reputation' in data:
                reputation = data['reputation']
                if reputation == 'high':
                    print(f"    Reputation: {reputation} [+]")
                elif reputation == 'medium':
                    print(f"    Reputation: {reputation} [!]")
                else:
                    print(f"    Reputation: {reputation} [-]")
            
            # Suspicious status
            if 'suspicious' in data:
                suspicious = data['suspicious']
                if suspicious:
                    print(f"    Suspicious: Yes [-]")
                else:
                    print(f"    Suspicious: No [+]")
            
            # References count
            if 'references' in data:
                print(f"    References: {data['references']}")
            
            # Details
            if 'details' in data:
                details = data['details']
                if 'malicious_activity' in details:
                    print(f"    Malicious Activity: {details['malicious_activity']}")
                if 'spam' in details:
                    print(f"    Spam Reports: {details['spam']}")
                if 'credentials_leaked' in details:
                    print(f"    Credentials Leaked: {details['credentials_leaked']}")
                if 'data_breach' in details:
                    print(f"    Data Breach: {details['data_breach']}")
            
            # Tags
            if 'tags' in data and data['tags']:
                print(f"    Tags: {', '.join(data['tags'])}")
                
        elif response.status_code == 404:
            print("[-] No reputation data found for this email")
        else:
            print(f"[-] API request failed with status code: {response.status_code}")
            
    except requests.exceptions.Timeout:
        print("[-] Request timeout - emailrep.io may be slow or unavailable")
    except requests.exceptions.ConnectionError:
        print("[-] Connection error - check your internet connection")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error making API request: {str(e)}")
    except Exception as e:
        print(f"[-] Error checking email reputation: {str(e)}")

def generate_google_dorks(email, domain):
    """
    Generate Google search URLs using various dorks
    Args:
        email (str): Email address
        domain (str): Domain name
    """
    print(f"\n[+] Google Search Dorks for {email}")
    print("=" * 50)
    
    try:
        # URL encode the email for safe use in URLs
        encoded_email = quote(email)
        encoded_domain = quote(domain)
        
        dorks = [
            {
                'description': 'General email search',
                'url': f'https://www.google.com/search?q=intext:"{encoded_email}"'
            },
            {
                'description': 'Email on Pastebin',
                'url': f'https://www.google.com/search?q=site:pastebin.com+"{encoded_email}"'
            },
            {
                'description': 'Email on LinkedIn',
                'url': f'https://www.google.com/search?q=site:linkedin.com+"{encoded_email}"'
            },
            {
                'description': 'Email on GitHub',
                'url': f'https://www.google.com/search?q=site:github.com+"{encoded_email}"'
            },
            {
                'description': 'Email on Twitter',
                'url': f'https://www.google.com/search?q=site:twitter.com+"{encoded_email}"'
            },
            {
                'description': 'Domain on social media',
                'url': f'https://www.google.com/search?q="{encoded_domain}"+site:facebook.com+OR+site:twitter.com+OR+site:instagram.com'
            },
            {
                'description': 'Email in documents',
                'url': f'https://www.google.com/search?q="{encoded_email}"+filetype:pdf+OR+filetype:doc+OR+filetype:docx'
            },
            {
                'description': 'Email data breaches',
                'url': f'https://www.google.com/search?q="{encoded_email}"+breach+OR+leak+OR+dump'
            }
        ]
        
        print("[+] Generated Google search dorks:")
        for i, dork in enumerate(dorks, 1):
            print(f"\n    {i}. {dork['description']}:")
            print(f"       {dork['url']}")
            
    except Exception as e:
        print(f"[-] Error generating Google dorks: {str(e)}")

def main():
    """Main function to orchestrate the email reconnaissance"""
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='EmailRecon-Jay - Email Reconnaissance Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python emailrecon_jay.py john.doe@example.com
  python emailrecon_jay.py -e test@gmail.com
        """
    )
    
    parser.add_argument(
        'email',
        nargs='?',
        help='Email address to investigate'
    )
    
    parser.add_argument(
        '-e', '--email',
        dest='email_flag',
        help='Email address to investigate (alternative flag)'
    )
    
    args = parser.parse_args()
    
    # Display banner
    print_banner()
    
    # Get email from arguments
    email = args.email or args.email_flag
    
    if not email:
        print("[-] Error: Please provide an email address")
        print("Usage: python emailrecon_jay.py <email@domain.com>")
        print("   or: python emailrecon_jay.py -e <email@domain.com>")
        sys.exit(1)
    
    # Validate email format
    if not validate_email(email):
        print(f"[-] Error: Invalid email format: {email}")
        sys.exit(1)
    
    print(f"[+] Starting reconnaissance for: {email}")
    
    # Extract domain
    try:
        domain = extract_domain(email)
        print(f"[+] Extracted domain: {domain}")
    except Exception as e:
        print(f"[-] Error extracting domain: {str(e)}")
        sys.exit(1)
    
    # Perform all reconnaissance tasks
    dns_mx_lookup(domain)
    whois_lookup(domain)
    email_reputation_check(email)
    generate_google_dorks(email, domain)
    
    print(f"\n[+] Reconnaissance completed for {email}")
    print("\n" + "=" * 60)
    print("Note: This tool is for educational and legitimate security research purposes only.")
    print("Always ensure you have proper authorization before investigating email addresses.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Unexpected error: {str(e)}")
        sys.exit(1)
