"""
Chapter 1 — Feel the Problem: Can You Spot Every Threat?
=========================================================
GOAL: Experience how unsystematic security thinking leaves critical gaps.

You DON'T need to have read Chapter 1 yet. Just use your intuition.

WHAT TO DO:
  Run this script. It will describe a small web application and ask you
  to identify all the security threats you can think of. Then it will
  reveal a structured analysis — and show you what you missed.
"""

import time
import textwrap


def print_slow(text, delay=0.02):
    """Print text with a slight delay for readability."""
    for line in text.split("\n"):
        print(line)
        time.sleep(delay)


def print_header(text):
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}\n")


def print_system_description():
    print_header("SYSTEM DESCRIPTION: MiniShop")
    description = textwrap.dedent("""\
        MiniShop is a small online store run by two people.

        Components:
          - A web server running a Python app (Flask)
          - A PostgreSQL database storing:
              * User accounts (email, password, address)
              * Product catalog (names, prices, stock counts)
              * Order history (who bought what, payment status)
          - An admin panel at /admin (password-protected)
          - File uploads for product images (stored on disk)
          - Email notifications sent via SMTP for order confirmations
          - Weekly database backup saved to the same server

        Users:
          - Customers: browse, buy, view their order history
          - Two admins: manage products, view all orders, add/remove users

        The app uses HTTP (not HTTPS) during development.
        Passwords are stored as SHA-1 hashes in the database.
        The admin panel uses the same login system as customers.
    """)
    print_slow(description)


def collect_user_threats():
    print_header("YOUR TURN: IDENTIFY THE THREATS")
    print(textwrap.dedent("""\
        Think about what could go wrong with this system.
        Consider: What could be stolen? What could be broken?
        What could be made unavailable? Who might attack it and how?

        Type each threat you can think of, one per line.
        When you're done, type 'done' on an empty line.
    """))

    user_threats = []
    while True:
        threat = input(f"  Threat #{len(user_threats)+1} (or 'done'): ").strip()
        if threat.lower() == "done":
            break
        if threat:
            user_threats.append(threat)

    return user_threats


# The structured threat analysis the user will learn to build
STRUCTURED_ANALYSIS = {
    "assets": [
        {
            "name": "User credentials",
            "type": "Data",
            "cia": {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "MEDIUM"},
            "threats": [
                "Passwords intercepted over HTTP (no TLS)",
                "SHA-1 hashes cracked via rainbow tables (weak hashing)",
                "Credential stuffing from breached databases",
            ],
        },
        {
            "name": "Customer personal data (email, address)",
            "type": "Data",
            "cia": {"confidentiality": "HIGH", "integrity": "MEDIUM", "availability": "LOW"},
            "threats": [
                "SQL injection exposes customer records",
                "Admin account compromise leaks all user data",
                "Database backup stolen (same server, no encryption)",
            ],
        },
        {
            "name": "Payment and order data",
            "type": "Data",
            "cia": {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "MEDIUM"},
            "threats": [
                "Order tampering (price manipulation)",
                "Unauthorized access to other users' order history",
                "Payment status modification",
            ],
        },
        {
            "name": "Product catalog",
            "type": "Data",
            "cia": {"confidentiality": "LOW", "integrity": "HIGH", "availability": "HIGH"},
            "threats": [
                "Price tampering by unauthorized users",
                "Stock count manipulation",
                "Defacement via product image upload",
            ],
        },
        {
            "name": "Admin panel",
            "type": "Service",
            "cia": {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "HIGH"},
            "threats": [
                "No separation between admin and user auth (shared login = shared vulnerabilities)",
                "Brute force attack on /admin endpoint",
                "No rate limiting on login attempts",
            ],
        },
        {
            "name": "File upload system",
            "type": "Service",
            "cia": {"confidentiality": "MEDIUM", "integrity": "HIGH", "availability": "MEDIUM"},
            "threats": [
                "Malicious file upload (web shell disguised as image)",
                "Path traversal to overwrite server files",
                "Disk space exhaustion via large uploads",
            ],
        },
        {
            "name": "Web server availability",
            "type": "Infrastructure",
            "cia": {"confidentiality": "LOW", "integrity": "MEDIUM", "availability": "HIGH"},
            "threats": [
                "Single server = single point of failure",
                "Backup on same server lost if server fails",
                "DoS attack takes down entire business",
            ],
        },
        {
            "name": "Email system (SMTP)",
            "type": "Service",
            "cia": {"confidentiality": "MEDIUM", "integrity": "MEDIUM", "availability": "LOW"},
            "threats": [
                "SMTP credentials exposed in config files",
                "Email spoofing (no SPF/DKIM)",
                "Order confirmation used for phishing",
            ],
        },
    ]
}


def count_all_threats():
    total = 0
    for asset in STRUCTURED_ANALYSIS["assets"]:
        total += len(asset["threats"])
    return total


def reveal_analysis(user_threats):
    total_threats = count_all_threats()
    user_count = len(user_threats)

    print_header("STRUCTURED THREAT ANALYSIS")
    print(f"You identified {user_count} threat(s).\n")
    print(f"A systematic CIA-based analysis finds {total_threats} distinct threats")
    print(f"across {len(STRUCTURED_ANALYSIS['assets'])} assets.\n")

    if user_count < total_threats * 0.5:
        print("Don't worry -- almost everyone misses the majority on their first try.")
        print("That's exactly why structured frameworks exist.\n")
    elif user_count < total_threats * 0.75:
        print("Good intuition! But notice the gaps a structured approach catches.\n")
    else:
        print("Impressive coverage! Let's see if the structure reveals anything new.\n")

    input("Press Enter to see the full analysis...\n")

    for asset in STRUCTURED_ANALYSIS["assets"]:
        cia = asset["cia"]
        print(f"  ASSET: {asset['name']} ({asset['type']})")
        print(f"  CIA Impact:  C={cia['confidentiality']}  I={cia['integrity']}  A={cia['availability']}")
        print(f"  Threats:")
        for threat in asset["threats"]:
            print(f"    - {threat}")
        print()

    print_header("WHAT DID YOU NOTICE?")
    print(textwrap.dedent("""\
        The structured analysis works by:
          1. Identifying ASSETS (what needs protection)
          2. Classifying each by CIA IMPACT (Confidentiality, Integrity, Availability)
          3. Mapping THREATS to each asset through its ATTACK SURFACE

        Without this structure, most people:
          - Focus on the obvious (passwords, SQL injection)
          - Miss infrastructure threats (single point of failure, backup on same server)
          - Forget about integrity and availability (fixating on confidentiality)
          - Overlook indirect attack paths (email spoofing, file upload abuse)

        Chapter 1 of Stallings introduces exactly this framework.
        After reading it, you'll build a tool that does this analysis
        systematically for ANY system -- not just MiniShop.
    """))


def main():
    print_header("FEEL THE PROBLEM")
    print("Before reading Chapter 1, let's test your security intuition.\n")
    print("You'll see a description of a small web application.")
    print("Your job: identify every security threat you can think of.\n")
    input("Press Enter to see the system description...\n")

    print_system_description()
    user_threats = collect_user_threats()
    reveal_analysis(user_threats)

    print("=" * 60)
    print("  Now read Chapter 1. Then come back and BUILD the tool.")
    print("=" * 60)
    print()


if __name__ == "__main__":
    main()
