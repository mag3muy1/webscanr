import argparse
import json
from datetime import datetime, timezone
import os
import random
import requests  # <-- Add this import
from dotenv import load_dotenv
from scanner import (
    PayloadManager,
    TechnologyScanner,
    XSSScanner,
    SQLiScanner,
    OutdatedComponentChecker,
    MisconfigurationChecker,
    WebCrawler,
    NVDChecker,
    ReportGenerator
)

def print_banner(color=None):
    """Print WebScanr banner with centered ASCII emoji"""
    ascii_emojis = [
        r"ʕノ•ᴥ•ʔノ ︵ ┻━┻",
        r"ヽ༼ ຈل͜ຈ༼ ▀̿̿Ĺ̯̿̿▀̿ ̿༽Ɵ͆ل͜Ɵ͆ ༽ﾉ",
        r"(╯°□°）╯︵ ┻━┻",
        r"┬─┬ノ( º _ ºノ)",
        r"(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧",
        r"ヽ(•̀ω•́ )ゝ✧",
        r"(ง •̀_•́)ง",
        r"༼ つ ◕_◕ ༽つ",
        r"¯\\_(ツ)_/¯",
        r"╰(°▽°)╯",
        r"╭( ･ㅂ･)و ̑̑",
        r"╰(°▽°)╯︵ ┻━┻",
        r"╭( ･ㅂ･)و ̑̑",
    ]
    
    selected_emoji = random.choice(ascii_emojis)
    title = "w e b s c a n r"
    
    # Calculate center padding for the emoji
    emoji_padding = (len(title) - len(selected_emoji)) // 2
    if emoji_padding < 0:
        emoji_padding = 0
    
    banner = f"""
    {' ' * emoji_padding}{selected_emoji}
    =======================
        {title}  ᵛ¹      
    =======================
    
    """
    
    colors = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'purple': '\033[95m',
        'cyan': '\033[96m',
        'white': '\033[97m',
        'orange': '\033[38;5;208m',
        'pink': '\033[38;5;206m',
        'end': '\033[0m'
    }
    
    if color is None:
        color = random.choice(list(colors.keys())[:-1])  # Exclude 'end'
    
    selected_color = colors.get(color.lower(), colors['green'])
    print(f"{selected_color}{banner}{colors['end']}")

def is_generic_error(response_text):
    ERROR_STRINGS = [
        "500 - Error",
        "An error happened sorry",
        "I'm so sorry about that.",
        "Contact Us let us know we'll fix it.",
        "Internal Server Error",
        "Oops! Something went wrong"
    ]
    return any(err.lower() in response_text.lower() for err in ERROR_STRINGS)

def is_sql_error(response_text):
    SQL_ERROR_STRINGS = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "sqlstate",
        "syntax error",
        "mysql_fetch",
        "odbc",
        "ora-",
        "postgresql",
        "fatal error"
    ]
    return any(err in response_text.lower() for err in SQL_ERROR_STRINGS)

def get_response_text(url):
    try:
        resp = requests.get(url, timeout=10)
        return resp.text
    except Exception:
        return ""

def main():
    load_dotenv()
    print_banner()
    parser = argparse.ArgumentParser(description="WebScanr - Modular Web Vulnerability Scanner")

    parser.add_argument("url", help="Target URL")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--stop-on-success", action="store_true", help="Stop when first vulnerability is found")

    # === Scan options ===
    scan_group = parser.add_argument_group('Scan options')
    scan_group.add_argument("--all", action="store_true", help="Run all available scans")
    scan_group.add_argument("--tech", action="store_true", help="Run technology fingerprinting")
    scan_group.add_argument("--check-outdated", action="store_true", help="Check if detected technologies are outdated")
    scan_group.add_argument("--xss", action="store_true", help="Run reflected XSS scan")
    # scan_group.add_argument("--popup", action="store_true", help="Run popup-based XSS detection (Selenium)")  # Removed popup scan
    scan_group.add_argument("--dom", action="store_true", help="Run DOM-based XSS detection (Selenium)")
    scan_group.add_argument("--sqli", action="store_true", help="Run SQL injection scan")
    scan_group.add_argument("--check-misconfig", action="store_true", help="Run misconfiguration checks (headers, SSL, exposed files)")
    scan_group.add_argument("--crawl", action="store_true", help="Crawl and list internal pages")
    scan_group.add_argument("--scan-crawled", action="store_true", help="Scan all crawled pages with enabled scans (XSS, DOM XSS, SQLi)")
    scan_group.add_argument("--max-pages", type=int, default=30, help="Maximum number of pages to crawl (default: 30)")
    scan_group.add_argument("--nvd-check", action="store_true", help="Check detected technologies against NVD")

    # === Reporting options ===
    report_group = parser.add_argument_group('Reporting options')
    report_group.add_argument("--hf-token", type=str, help="Hugging Face API token (overrides env HF_TOKEN)")
    report_group.add_argument("--report-format", choices=["word", "pdf", "json"], help="Generate report in the specified format")
    report_group.add_argument("--report-name", type=str, help="Specify the output report filename (without extension)")
    report_group.add_argument("--stdout", action="store_true", help="Print output as JSON in terminal")
    report_group.add_argument("--verbose", action="store_true", help="Show verbose output when using --stdout")

    args = parser.parse_args()

    # If --all is specified, enable all scan types
    if args.all:
        args.tech = True
        args.check_outdated = True
        args.xss = True
        # args.popup = True  # Removed popup scan
        args.dom = True
        args.sqli = True
        args.check_misconfig = True
        args.crawl = True
        args.nvd_check = True
        # Do NOT enable scan-crawled with --all

    # Only print scan started message if a URL is provided and looks like a URL
    if args.url and (args.url.startswith('http://') or args.url.startswith('https://')):
        print(f"Scan started at: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")

    report_data = {
        "url": args.url,
        "timestamp": None,
        "vulnerabilities": []
    }

    if args.report_format:
        from tqdm import tqdm
        tqdm.disable = True

    try:
        # === Technology Fingerprinting ===
        tech_info = {'frontend': [], 'backend': [], 'other': []}
        if args.tech:
            detected_tech = TechnologyScanner.get_website_technologies(args.url)
            if detected_tech:
                tech_info = detected_tech
            if not args.report_format and not args.stdout:
                TechnologyScanner.print_technologies(tech_info, args.url)

        # === Outdated Components Check ===
        if args.check_outdated:
            if not tech_info:
                print("[!] No technology information available for outdated check")
            else:
                tech_list = []
                for category in ['frontend', 'backend', 'other']:
                    if isinstance(tech_info.get(category), list):
                        tech_list.extend(tech_info[category])
                checker = OutdatedComponentChecker(tech_list)
                outdated = checker.check_outdated(verbose=args.verbose)
                if outdated:
                    report_data["vulnerabilities"].extend(outdated)
            if args.nvd_check:
                nvd_checker = NVDChecker(tech_info)
                nvd_results = nvd_checker.check(verbose=args.verbose)  
                report_data["vulnerabilities"].extend(nvd_results)

        # === XSS Scanning ===
        if args.xss or args.dom:
            scanner = XSSScanner(
                url=args.url,
                max_workers=args.threads,
                stop_on_success=args.stop_on_success,
                headless=True
            )

            # For the XSS scanner results as well:
            if args.xss:
                xss_results = scanner.scan_reflected_xss()
                if xss_results:
                    report_data["vulnerabilities"].extend(xss_results)

            if args.dom:
                dom_results = scanner.scan_dom_xss()
                filtered_dom = []
                for finding in (dom_results or []):
                    url = finding.get('url')
                    if (
                        finding.get('payload')
                        and url
                        and url.strip()
                        and not url.strip().lower().startswith('data:text/html')
                    ):
                        resp_text = get_response_text(url)
                        if not is_generic_error(resp_text):
                            filtered_dom.append(finding)
                report_data["vulnerabilities"].extend(filtered_dom)
                # Print a refined DOM XSS summary if not reporting to file/stdout
                if not args.report_format and not args.stdout:
                    print("\n========== DOM-based XSS Summary ==========")
                    if not filtered_dom:
                        print('\033[92m' + "[-] No DOM-based XSS vulnerabilities found." + '\033[0m')
                    else:
                        for idx, finding in enumerate(filtered_dom, 1):
                            print(f"[#{idx}] Payload: {finding.get('payload','')}")
                            print(f"Type: {finding.get('type','')}")
                            if finding.get('alert_text'):
                                print(f"Alert Text: {finding['alert_text']}")
                            print(f"Affecting URL: {finding.get('url','')}")
                            print()

            # === SQL Injection ===
            if args.sqli:
                sql_scanner = SQLiScanner(
                    url=args.url,
                    stop_on_success=args.stop_on_success
                )
                sqli_results = sql_scanner.scan()
                filtered_sqli = []
                for finding in (sqli_results or []):
                    test_url = finding.get('test_url', args.url)
                    if finding.get('payload') and (
                        (finding.get('type') == 'form' and finding.get('form_name')) or
                        (finding.get('type') != 'form' and finding.get('param'))
                    ):
                        resp_text = get_response_text(test_url)
                        if is_sql_error(resp_text):
                            filtered_sqli.append(finding)
                report_data["vulnerabilities"].extend(filtered_sqli)
                # Print a refined SQLi summary if not reporting to file/stdout
                if not args.report_format and not args.stdout:
                    print("\n========== SQL Injection Summary ==========")
                    if not filtered_sqli:
                        print('\033[92m' + "[-] No SQL injection vulnerabilities found." + '\033[0m')
                    else:
                        for finding in filtered_sqli:
                            if finding.get('type') == 'form':
                                print(f"[Form] {finding.get('form_name','')}, Payload: {finding.get('payload','')}, Input: {finding.get('input','')}")
                            else:
                                print(f"[Param] {finding.get('param','')}, Payload: {finding.get('payload','')}")

        # === Misconfigurations ===
        if args.check_misconfig:
            misconfig = MisconfigurationChecker(args.url)
            misconfig_results = misconfig.run_checks(silent=bool(args.report_format or args.stdout))
            report_data["vulnerabilities"].extend(misconfig_results)

        # === Crawler ===
        crawled_links = []
        if args.crawl:
            crawler = WebCrawler(args.url, max_pages=args.max_pages)
            crawled_links = crawler.crawl()
            # Remove duplicates while preserving order
            seen = set()
            unique_links = []
            for link in crawled_links:
                if link not in seen:
                    unique_links.append(link)
                    seen.add(link)
            crawled_links = unique_links
            # Add unique crawled pages to report if crawl is enabled
            report_data["crawled_pages"] = crawled_links
            if not args.report_format and not args.stdout:
                for i, link in enumerate(crawled_links, 1):
                    print(f"[{i}] {link}")

        # === Scan Crawled Pages Option ===
        if args.scan_crawled and crawled_links:
            print("\n[+] Scanning all crawled pages... This might take some ~ a lot of time")
            for page_url in crawled_links:
                if args.xss or args.dom:
                    scanner = XSSScanner(
                        url=page_url,
                        max_workers=args.threads,
                        stop_on_success=args.stop_on_success,
                        headless=True
                    )
                    if args.xss:
                        xss_results = scanner.scan_reflected_xss()
                        if xss_results:
                            report_data["vulnerabilities"].extend(xss_results)
                    if args.dom:
                        dom_results = scanner.scan_dom_xss()
                        filtered_dom = []
                        for finding in (dom_results or []):
                            url = finding.get('url')
                            if (
                                finding.get('payload')
                                and url
                                and url.strip()
                                and not url.strip().lower().startswith('data:text/html')
                            ):
                                resp_text = get_response_text(url)
                                if not is_generic_error(resp_text):
                                    filtered_dom.append(finding)
                        report_data["vulnerabilities"].extend(filtered_dom)
                if args.sqli:
                    sql_scanner = SQLiScanner(
                        url=page_url,
                        stop_on_success=args.stop_on_success
                    )
                    sqli_results = sql_scanner.scan()
                    filtered_sqli = []
                    for finding in (sqli_results or []):
                        test_url = finding.get('test_url', page_url)
                        if finding.get('payload') and (
                            (finding.get('type') == 'form' and finding.get('form_name')) or
                            (finding.get('type') != 'form' and finding.get('param'))
                        ):
                            resp_text = get_response_text(test_url)
                            if is_sql_error(resp_text):
                                filtered_sqli.append(finding)
                    report_data["vulnerabilities"].extend(filtered_sqli)

        # === Report Generation ===
        report_data["timestamp"] = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

        # Initialize ReportGenerator with Hugging Face API
        hf_token = args.hf_token or os.getenv("HF_TOKEN")
        if not hf_token:
            print("[!] Hugging Face token (hf_token) is not set. AI-based reporting will be disabled.")
        generator = ReportGenerator(
            use_ai=bool(hf_token and args.report_format),
            api_token=hf_token
        )

        if args.stdout:
            generator.print_terminal(report_data, verbose=args.verbose)
        elif args.report_format:
            output_path = generator.generate(data=report_data, fmt=args.report_format, filename=args.report_name)
            print(f"[+] Report saved to: {output_path}")
        elif not args.all and not any([args.tech, args.check_outdated, args.xss, args.dom, 
                     args.sqli, args.check_misconfig, args.nvd_check, args.crawl]):
            print("[!] No scan type specified. Use --help to see available options.")
    except KeyboardInterrupt:
        print("\n[!] Scan manually interrupted. Exiting cleanly...")

if __name__ == "__main__":
    main()