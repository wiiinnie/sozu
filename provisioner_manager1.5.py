#!/usr/bin/env python3
"""
Provisioner Management CLI Tool - Version 1.5
A command-line interface for managing provisioners with arrow key navigation.

Version: 1.4
Release Date: 2026-02-03
Author: Dusk Network Infrastructure Team

New in v1.4:
- Monitor Epoch Transitions (automated monitoring with 10s checks)
- Epoch calculation (every 2160 blocks)
- Auto-trigger at 50 blocks before epoch end
- Sync monitoring across all instances

New in v1.3:
- Check block heights for all rusk instances from logs

New in v1.2:
- Single encryption password prompt per session
- Encryption password stored in memory for key decryption
- No more repeated password prompts during operations
- Consistent provisioner selection across all functions
- Check stake info for all provisioners

New in v1.1:
- Encrypted wallet password storage
- Single encryption password prompt at startup
- Automatic password injection for all wallet operations
- Zero interactive password prompts during operations

Features:
- Add/List/Manage Provisioners
- Encrypted secret key storage
- Stake allocation and deactivation
- Node liquidation and termination (separate & combined operations)
- Configuration management (network, contract, gas limit, operator, wallet password)
- Check available stake
- Check stake info for all provisioners
- Check block heights for all rusk instances
- Monitor epoch transitions with automated checks
- Arrow key navigation interface
"""

import subprocess
import sys
import os
import curses
import json
import re
import base64
import time
from typing import Optional, List, Dict
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import getpass


class ProvisionerManager:
    """Main class for the Provisioner Management CLI"""
    
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.running = True
        self.current_row = 0
        
        # Secure storage setup
        self.storage_dir = Path.home() / ".provisioner_manager"
        self.storage_dir.mkdir(mode=0o700, exist_ok=True)
        self.keys_file = self.storage_dir / "provisioner_keys.enc"
        self.salt_file = self.storage_dir / "salt.bin"
        self.config_file = self.storage_dir / "config.json"
        
        # Wallet password (decrypted at startup, kept in memory)
        self.wallet_password_decrypted = None
        
        # Encryption password (entered once at startup, kept in memory for session)
        self.encryption_password = None
        
        # Load or create default config
        self._load_config()
        
        # Decrypt wallet password at startup if stored
        self._decrypt_wallet_password_at_startup()
        
        # Initialize colors
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)      # Headers
        curses.init_pair(2, curses.COLOR_GREEN, -1)     # Selected item
        curses.init_pair(3, curses.COLOR_WHITE, -1)     # Normal text
        curses.init_pair(4, curses.COLOR_YELLOW, -1)    # Warnings
        curses.init_pair(5, curses.COLOR_RED, -1)       # Errors/Exit
        curses.init_pair(6, curses.COLOR_MAGENTA, -1)   # Title
        
        # Menu options
        self.menu_items = [
            "Add a Provisioner",
            "List Provisioners",
            "Get Provisioner(s) Secret Key(s)",
            "Allocate Stake to a Provisioner",
            "Remove Stake from a Provisioner (stake_deactivate)",
            "Liquidate Provisioner (Remove from Consensus)",
            "Terminate Provisioner (Complete Removal)",
            "Liquidate + Terminate Provisioner (Full Removal)",
            "Completely Remove a Provisioner",
            "Check Available Stake",
            "Check Stake Info",
            "Check Block Heights",
            "Monitor Epoch Transitions",
            "Configuration",
            "Exit"
        ]
        
        # Hide cursor
        curses.curs_set(0)
    
    def print_header(self, y_pos: int = 0) -> int:
        """Print the application header and return next Y position"""
        height, width = self.stdscr.getmaxyx()
        
        # Title
        title = "PROVISIONER MANAGEMENT TOOL"
        separator = "=" * min(70, width - 4)
        
        self.stdscr.attron(curses.color_pair(6) | curses.A_BOLD)
        self.stdscr.addstr(y_pos, (width - len(separator)) // 2, separator)
        self.stdscr.addstr(y_pos + 1, (width - len(title)) // 2, title)
        self.stdscr.addstr(y_pos + 2, (width - len(separator)) // 2, separator)
        self.stdscr.attroff(curses.color_pair(6) | curses.A_BOLD)
        
        return y_pos + 4
    
    def print_menu(self, start_y: int):
        """Display the menu with arrow key navigation"""
        self.stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
        self.stdscr.addstr(start_y, 2, "Use ↑/↓ arrow keys to navigate, Enter to select:")
        self.stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
        
        for idx, item in enumerate(self.menu_items):
            y = start_y + 2 + idx
            x = 4
            
            if idx == self.current_row:
                # Highlighted item
                self.stdscr.attron(curses.color_pair(2) | curses.A_BOLD | curses.A_REVERSE)
                prefix = "➤ "
            else:
                # Normal item
                if idx == len(self.menu_items) - 1:  # Exit option
                    self.stdscr.attron(curses.color_pair(5))
                else:
                    self.stdscr.attron(curses.color_pair(3))
                prefix = "  "
            
            self.stdscr.addstr(y, x, f"{prefix}{idx + 1}. {item}")
            
            if idx == self.current_row:
                self.stdscr.attroff(curses.color_pair(2) | curses.A_BOLD | curses.A_REVERSE)
            else:
                if idx == len(self.menu_items) - 1:
                    self.stdscr.attroff(curses.color_pair(5))
                else:
                    self.stdscr.attroff(curses.color_pair(3))
    
    def show_menu(self):
        """Show the main menu and handle navigation"""
        while self.running:
            self.stdscr.clear()
            height, width = self.stdscr.getmaxyx()
            
            # Print header
            y_pos = self.print_header(1)
            
            # Print menu
            self.print_menu(y_pos)
            
            # Footer instructions
            self.stdscr.attron(curses.color_pair(4))
            self.stdscr.addstr(height - 2, 2, "Press 'q' to quit at any time")
            self.stdscr.attroff(curses.color_pair(4))
            
            self.stdscr.refresh()
            
            # Get user input
            key = self.stdscr.getch()
            
            if key == curses.KEY_UP and self.current_row > 0:
                self.current_row -= 1
            elif key == curses.KEY_DOWN and self.current_row < len(self.menu_items) - 1:
                self.current_row += 1
            elif key == ord('\n'):  # Enter key
                if self.current_row == len(self.menu_items) - 1:  # Exit
                    self.running = False
                else:
                    self.handle_menu_selection(self.current_row)
            elif key == ord('q') or key == ord('Q'):
                self.running = False
    
    def handle_menu_selection(self, selection: int):
        """Handle the selected menu option"""
        if selection == 0:
            self.add_provisioner()
        elif selection == 1:
            self.list_provisioners()
        elif selection == 2:
            self.get_provisioner_secret_keys()
        elif selection == 3:
            self.allocate_stake()
        elif selection == 4:
            self.deactivate_stake()
        elif selection == 5:
            self.liquidate_provisioner()
        elif selection == 6:
            self.terminate_provisioner()
        elif selection == 7:
            self.liquidate_and_terminate()
        elif selection == 8:
            self.remove_provisioner()
        elif selection == 9:
            self.check_available_stake()
        elif selection == 10:
            self.check_stake_info()
        elif selection == 11:
            self.check_block_heights()
        elif selection == 12:
            self.monitor_epoch_transitions()
        elif selection == 13:
            self.show_configuration()
    
    def get_input_curses(self, prompt: str, y: int, x: int = 2) -> Optional[str]:
        """Get user input in curses mode"""
        curses.echo()
        curses.curs_set(1)
        
        self.stdscr.attron(curses.color_pair(2))
        self.stdscr.addstr(y, x, f"{prompt}: ")
        self.stdscr.attroff(curses.color_pair(2))
        self.stdscr.refresh()
        
        # Get input
        input_str = self.stdscr.getstr(y, x + len(prompt) + 2, 60).decode('utf-8').strip()
        
        curses.noecho()
        curses.curs_set(0)
        
        return input_str if input_str else None
    
    def confirm_action_curses(self, message: str, y: int, x: int = 2) -> bool:
        """Ask user to confirm an action in curses mode"""
        self.stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
        self.stdscr.addstr(y, x, f"⚠  {message}")
        self.stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
        
        self.stdscr.attron(curses.color_pair(3))
        self.stdscr.addstr(y + 1, x, "Press 'y' for Yes, 'n' for No: ")
        self.stdscr.attroff(curses.color_pair(3))
        self.stdscr.refresh()
        
        while True:
            key = self.stdscr.getch()
            if key == ord('y') or key == ord('Y'):
                return True
            elif key == ord('n') or key == ord('N'):
                return False
    
    def show_message(self, message: str, color_pair: int = 2, wait: bool = True):
        """Display a message and optionally wait for user"""
        self.stdscr.clear()
        height, width = self.stdscr.getmaxyx()
        
        y_pos = height // 2
        self.stdscr.attron(curses.color_pair(color_pair) | curses.A_BOLD)
        self.stdscr.addstr(y_pos, (width - len(message)) // 2, message)
        self.stdscr.attroff(curses.color_pair(color_pair) | curses.A_BOLD)
        
        if wait:
            self.stdscr.attron(curses.color_pair(3))
            msg = "Press any key to continue..."
            self.stdscr.addstr(y_pos + 2, (width - len(msg)) // 2, msg)
            self.stdscr.attroff(curses.color_pair(3))
            self.stdscr.refresh()
            self.stdscr.getch()
    
    def _get_encryption_key(self, password: str) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        # Load or generate salt
        if self.salt_file.exists():
            with open(self.salt_file, 'rb') as f:
                salt = f.read()
        else:
            salt = os.urandom(16)
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
            os.chmod(self.salt_file, 0o600)
        
        # Derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def _encrypt_keys(self, keys_data: Dict, password: str):
        """Encrypt and save provisioner keys"""
        key = self._get_encryption_key(password)
        fernet = Fernet(key)
        
        # Convert to JSON and encrypt
        json_data = json.dumps(keys_data, indent=2)
        encrypted_data = fernet.encrypt(json_data.encode())
        
        # Save encrypted data
        with open(self.keys_file, 'wb') as f:
            f.write(encrypted_data)
        os.chmod(self.keys_file, 0o600)
    
    def _decrypt_keys(self, password: str) -> Dict:
        """Decrypt and load provisioner keys"""
        if not self.keys_file.exists():
            return {}
        
        try:
            key = self._get_encryption_key(password)
            fernet = Fernet(key)
            
            with open(self.keys_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception:
            return None
    
    def _select_provisioner_from_list(self, title: str = "Select Provisioner") -> Optional[str]:
        """Helper method to select a provisioner from stored keys
        Returns the provisioner address or None if cancelled/failed"""
        
        # Check encryption password is available
        if not self.encryption_password:
            print(f"\n\033[91m✗ Encryption password not available.\033[0m")
            print(f"\033[93mPlease restart the application.\033[0m")
            return None
        
        # Load stored keys
        stored_keys = self._decrypt_keys(self.encryption_password)
        
        if stored_keys is None:
            print(f"\n\033[91m✗ Could not load stored keys.\033[0m")
            return None
        
        if not stored_keys:
            print(f"\n\033[93m⚠ No provisioners stored yet.\033[0m")
            print(f"\033[90mUse 'Get Provisioner(s) Secret Key(s)' to import provisioners first.\033[0m")
            return None
        
        # Display available provisioners
        print(f"\n\033[92m{title}:\033[0m")
        print(f"\033[94m{'─' * 70}\033[0m")
        provisioner_list = []
        for i, (prov_id, data) in enumerate(stored_keys.items(), 1):
            address = data.get('address', 'N/A')
            print(f"  {i}. {prov_id}")
            print(f"     Address: {address[:50]}{'...' if len(address) > 50 else ''}")
            provisioner_list.append((prov_id, address))
        print(f"\033[94m{'─' * 70}\033[0m")
        
        # Let user select
        while True:
            choice = input(f"\n\033[96mSelect provisioner (1-{len(provisioner_list)}) or 'c' to cancel: \033[0m").strip()
            
            if choice.lower() == 'c':
                print(f"\033[93mOperation cancelled.\033[0m")
                return None
            
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(provisioner_list):
                    selected_address = provisioner_list[idx][1]
                    print(f"\n\033[92m✓ Selected: {provisioner_list[idx][0]}\033[0m")
                    print(f"\033[90m  Address: {selected_address}\033[0m")
                    return selected_address
                else:
                    print(f"\033[91m✗ Invalid selection. Please enter 1-{len(provisioner_list)}\033[0m")
            except ValueError:
                print(f"\033[91m✗ Invalid input. Please enter a number or 'c'\033[0m")
    
    def _decrypt_wallet_password_at_startup(self):
        """Decrypt wallet password at startup for use during runtime"""
        # Check if wallet password is stored in config OR if there are encrypted keys
        has_wallet_password = 'wallet_password_encrypted' in self.config and self.config['wallet_password_encrypted']
        has_encrypted_keys = self.keys_file.exists()
        
        if not has_wallet_password and not has_encrypted_keys:
            # No encrypted data, no need for encryption password
            return
        
        # Temporarily exit curses mode for password input
        curses.endwin()
        
        print(f"\n\033[96mEncryption password required for session.\033[0m")
        encryption_password = getpass.getpass("\033[96mEnter encryption password: \033[0m")
        
        # Store encryption password for the session
        self.encryption_password = encryption_password
        
        # If wallet password is encrypted, decrypt it now
        if has_wallet_password:
            try:
                key = self._get_encryption_key(encryption_password)
                fernet = Fernet(key)
                
                encrypted_password = self.config['wallet_password_encrypted'].encode()
                decrypted_password = fernet.decrypt(base64.b64decode(encrypted_password))
                self.wallet_password_decrypted = decrypted_password.decode()
                
                print(f"\033[92m✓ Wallet password decrypted successfully\033[0m")
                print(f"\033[92m✓ All wallet operations will be automated (no password prompts)\033[0m")
            except Exception as e:
                print(f"\033[91m✗ Failed to decrypt wallet password: {str(e)}\033[0m")
                print(f"\033[93mYou will be prompted for wallet password during operations\033[0m")
                # Clear the encryption password since it was wrong
                self.encryption_password = None
        else:
            print(f"\033[92m✓ Encryption password stored for session\033[0m")
        
        input("\nPress Enter to continue...")
        
        # Re-initialize curses
        self._reinit_curses()
    
    def execute_wallet_command(self, command: str) -> tuple:
        """
        Execute wallet command with stored password or interactive prompt
        Returns: (success: bool, output: str)
        """
        if self.wallet_password_decrypted:
            # Use pexpect to handle interactive password prompt
            try:
                import pexpect
            except ImportError:
                print(f"\033[91mERROR: pexpect module not installed\033[0m")
                print(f"\033[93mInstall with: pip install pexpect --break-system-packages\033[0m")
                print(f"\033[93mFalling back to interactive prompt...\033[0m\n")
                result = subprocess.call(command, shell=True)
                return (result == 0, "")
            
            try:
                # Wrap command in bash -c to ensure proper shell expansion (tilde, etc.)
                bash_command = f'/bin/bash -c "{command}"'
                
                # Spawn the process
                child = pexpect.spawn(bash_command, timeout=180, encoding='utf-8', echo=False)
                
                # Collect all output
                all_output = []
                
                # Wait for password prompt
                index = child.expect([r'.*[Pp]assword.*[:?]', pexpect.EOF, pexpect.TIMEOUT], timeout=10)
                
                if index == 0:
                    # Password prompt found - send password
                    all_output.append(child.before)
                    child.sendline(self.wallet_password_decrypted)
                    
                    # For contract calls, show progress indicator
                    if 'contract-call' in command:
                        print(f"\033[93m⏳ Executing transaction on-chain (this may take 10-30 seconds)...\033[0m")
                    
                    # Wait for command to complete (with longer timeout for blockchain operations)
                    child.expect(pexpect.EOF, timeout=180)
                    all_output.append(child.before)
                    
                elif index == 1:
                    # EOF - command finished without password prompt
                    all_output.append(child.before)
                else:
                    # Timeout
                    print(f"\n\033[91mERROR: Timeout waiting for password prompt\033[0m")
                    child.close(force=True)
                    return (False, child.before or "Timeout")
                
                # Combine all output
                output = ''.join(all_output)
                
                # Print output for user
                if output and output.strip():
                    print(output)
                
                # Close and get exit status
                child.close()
                
                # Check for transaction errors in output (more reliable than exit code)
                output_lower = output.lower()
                has_error = any([
                    'transaction error:' in output_lower,
                    'error:' in output_lower and 'transaction' in output_lower,
                    'panic:' in output_lower,
                    'failed' in output_lower and ('transaction' in output_lower or 'contract' in output_lower),
                    'encryption error' in output_lower,
                    'aead::error' in output_lower,
                ])
                
                # Check for success indicators (transaction hash = 64 hex characters)
                has_tx_hash = bool(re.search(r'\b[0-9a-f]{64}\b', output_lower))
                
                # Check for stake-info success (read-only query)
                has_stake_info = any([
                    'eligible stake:' in output_lower,
                    'a stake does not exist' in output_lower,
                ])
                
                # Determine success: has tx hash AND no errors, OR has stake info, OR exit code 0 and no errors
                if has_error:
                    success = False
                elif has_tx_hash or has_stake_info:
                    success = True
                else:
                    success = (child.exitstatus == 0)
                
                # Special error messages
                if "Encryption error" in output or "aead::Error" in output:
                    print(f"\n\033[91mWARNING: Wallet encryption error - stored password is incorrect\033[0m")
                    print(f"\033[93mPlease re-set wallet password in Configuration menu\033[0m")
                    return (False, output)
                
                return (success, output)
                
            except pexpect.TIMEOUT:
                print(f"\n\033[91mERROR: Transaction timed out after 3 minutes\033[0m")
                print(f"\033[93mThe transaction may still complete - check your balance\033[0m")
                try:
                    child.close(force=True)
                except:
                    pass
                return (False, "Timeout")
            except Exception as e:
                print(f"\n\033[91mERROR: {str(e)}\033[0m")
                return (False, str(e))
        else:
            # Fall back to interactive prompt
            result = subprocess.call(command, shell=True)
            return (result == 0, "")
    
    def _load_config(self):
        """Load configuration from file or create default"""
        default_config = {
            "network_id": 2,
            "contract_address": "72883945ac1aa032a88543aacc9e358d1dfef07717094c05296ce675f23078f2",
            "gas_limit": 2000000,
            "operator_address": "",
            "stake_limit": 1000000,  # Maximum stake to allocate per provisioner in DUSK
            "rotation_trigger_blocks": 50  # Blocks before epoch end to trigger rotation
        }
        
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
                # Ensure all keys exist (in case of config updates)
                for key, value in default_config.items():
                    if key not in self.config:
                        self.config[key] = value
            except Exception:
                self.config = default_config
        else:
            self.config = default_config
            self._save_config()
    
    def _save_config(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
        os.chmod(self.config_file, 0o600)
    
    def execute_command(self, command: str, description: str) -> bool:
        """Execute a bash command in a subprocess"""
        # Temporarily exit curses mode
        curses.endwin()
        
        print(f"\n\033[94mExecuting: {description}\033[0m")
        print(f"\033[1mCommand:\033[0m {command}\n")
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                check=True,
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                print(f"\033[92mOutput:\033[0m")
                print(result.stdout)
            
            print(f"\033[92m✓ Command executed successfully!\033[0m")
            success = True
            
        except subprocess.CalledProcessError as e:
            print(f"\033[91m✗ Command failed with error:\033[0m")
            if e.stderr:
                print(e.stderr)
            success = False
        except Exception as e:
            print(f"\033[91m✗ Unexpected error: {str(e)}\033[0m")
            success = False
        
        input("\nPress Enter to continue...")
        
        # Re-initialize curses
        self.stdscr = curses.initscr()
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)
        curses.init_pair(2, curses.COLOR_GREEN, -1)
        curses.init_pair(3, curses.COLOR_WHITE, -1)
        curses.init_pair(4, curses.COLOR_YELLOW, -1)
        curses.init_pair(5, curses.COLOR_RED, -1)
        curses.init_pair(6, curses.COLOR_MAGENTA, -1)
        curses.curs_set(0)
        self.stdscr.keypad(True)
        
        return success
    
    def execute_command_interactive(self, command: str, description: str) -> bool:
        """Execute a bash command with full interactive mode (for password prompts, etc.)"""
        # Temporarily exit curses mode
        curses.endwin()
        
        print(f"\n\033[94m{'=' * 70}\033[0m")
        print(f"\033[1m\033[94mExecuting: {description}\033[0m")
        print(f"\033[94m{'=' * 70}\033[0m")
        print(f"\033[1mCommand:\033[0m {command}\n")
        print(f"\033[93mNote: You may be prompted for a password.\033[0m\n")
        
        try:
            # Use subprocess.call for full interactivity (stdin, stdout, stderr all connected to terminal)
            result = subprocess.call(command, shell=True)
            
            print()
            if result == 0:
                print(f"\033[92m{'=' * 70}\033[0m")
                print(f"\033[92m✓ Command executed successfully!\033[0m")
                print(f"\033[92m{'=' * 70}\033[0m")
                success = True
            else:
                print(f"\033[91m{'=' * 70}\033[0m")
                print(f"\033[91m✗ Command failed with exit code: {result}\033[0m")
                print(f"\033[91m{'=' * 70}\033[0m")
                success = False
            
        except Exception as e:
            print(f"\033[91m✗ Unexpected error: {str(e)}\033[0m")
            success = False
        
        input("\nPress Enter to continue...")
        
        # Re-initialize curses
        self.stdscr = curses.initscr()
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)
        curses.init_pair(2, curses.COLOR_GREEN, -1)
        curses.init_pair(3, curses.COLOR_WHITE, -1)
        curses.init_pair(4, curses.COLOR_YELLOW, -1)
        curses.init_pair(5, curses.COLOR_RED, -1)
        curses.init_pair(6, curses.COLOR_MAGENTA, -1)
        curses.curs_set(0)
        self.stdscr.keypad(True)
        
        return success
    
    def add_provisioner(self):
        """Option 1: Add a Provisioner"""
        # Temporarily exit curses mode
        curses.endwin()
        
        print(f"\n\033[94m{'=' * 70}\033[0m")
        print(f"\033[1m\033[96mADD A PROVISIONER\033[0m")
        print(f"\033[94m{'=' * 70}\033[0m\n")
        
        try:
            # Check if operator address is configured
            if not self.config.get('operator_address'):
                print(f"\033[91m✗ Operator Address not configured\033[0m")
                print(f"\033[93mPlease set the Operator Address in Configuration first.\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            operator_address = self.config['operator_address']
            print(f"\033[96mOperator Address:\033[0m {operator_address}\n")
            
            # Option to select from saved provisioners or enter manually
            print(f"\033[96mProvisioner Selection:\033[0m")
            print(f"  1. Select from saved provisioners")
            print(f"  2. Enter provisioner address manually")
            
            choice = input(f"\n\033[96mSelect option (1-2): \033[0m").strip()
            
            provisioner_address = None
            
            if choice == '1':
                # Load saved provisioners
                # Use stored encryption password from session
                if not self.encryption_password:
                    print(f"\n\033[91m✗ Encryption password not available.\033[0m")
                    print(f"\033[93mPlease restart the application.\033[0m")
                    input("\nPress Enter to continue...")
                    self._reinit_curses()
                    return
                
                stored_keys = self._decrypt_keys(self.encryption_password)
                
                if stored_keys is None or not stored_keys:
                    print(f"\033[91m✗ Could not load stored keys. Wrong password or no keys stored.\033[0m")
                    input("\nPress Enter to continue...")
                    self._reinit_curses()
                    return
                
                # Display available provisioners with addresses
                print(f"\n\033[92mAvailable Provisioners:\033[0m")
                provisioner_list = []
                for i, (prov_id, data) in enumerate(stored_keys.items(), 1):
                    addr_display = data.get('address', '(no address stored)')
                    print(f"  {i}. Provisioner Index {data['index']} - {addr_display[:32]}...")
                    provisioner_list.append((prov_id, data))
                
                # Get user selection
                while True:
                    try:
                        selection = input(f"\n\033[96mSelect provisioner (1-{len(provisioner_list)}): \033[0m").strip()
                        selection_idx = int(selection) - 1
                        if 0 <= selection_idx < len(provisioner_list):
                            break
                        print(f"\033[91mInvalid selection. Please choose 1-{len(provisioner_list)}\033[0m")
                    except ValueError:
                        print(f"\033[91mPlease enter a number.\033[0m")
                
                selected_prov_id, selected_prov_data = provisioner_list[selection_idx]
                provisioner_address = selected_prov_data.get('address', '')
                
                if not provisioner_address:
                    print(f"\033[91m✗ Selected provisioner has no address stored.\033[0m")
                    input("\nPress Enter to continue...")
                    self._reinit_curses()
                    return
                
                print(f"\n\033[92m✓ Selected: Provisioner Index {selected_prov_data['index']}\033[0m")
                print(f"\033[96mAddress:\033[0m {provisioner_address}\n")
            
            elif choice == '2':
                print(f"\n\033[96mEnter the Provisioner Address:\033[0m")
                print(f"\033[90m(Example: rFHBm9mFGjzCRe51WwEHkSX8ugtY3pPxKmRb96rqFoFsTT2w5udeshc3A86WzLGvuX53MVhahdJ6oLvnWJ9JPgAkW3fexMuMF8FN77J5ygce1eYxe1fiUhHGBtQnN4M6pKQ)\033[0m")
                provisioner_address = input("Address: ").strip()
                
                if not provisioner_address:
                    print(f"\033[91m✗ Provisioner address is required\033[0m")
                    input("\nPress Enter to continue...")
                    self._reinit_curses()
                    return
            
            else:
                print(f"\033[91m✗ Invalid option\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # Confirm action
            confirm = input(f"\n\033[93mAdd this provisioner? (yes/no): \033[0m").strip().lower()
            if confirm not in ['yes', 'y']:
                print(f"\033[93mOperation cancelled.\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # STEP 1: Calculate add provisioner payload
            print(f"\n\033[1m\033[96mSTEP 1: Calculating Add Provisioner Payload\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            payload_command = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet calculate-payload-add-provisioner \
  --operator {operator_address} \
  --provisioner {provisioner_address}"""
            
            if self.wallet_password_decrypted:
                print(f"\033[92mExecuting payload calculation (using stored password)...\033[0m\n")
            else:
                print(f"\033[94mExecuting payload calculation...\033[0m")
                print(f"\033[93mNote: You will be prompted for your wallet password.\033[0m\n")
            
            payload_result, payload_output = self.execute_wallet_command(payload_command)
            
            print()
            
            if not payload_result:
                print(f"\033[91m✗ Failed to calculate add provisioner payload\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # Try to extract the quoted payload
            payload_match = re.search(r'"([0-9a-fA-F]+)"', payload_output)
            if not payload_match:
                # Maybe the payload is the entire output or last line
                lines = [line.strip() for line in payload_output.split('\n') if line.strip()]
                if lines:
                    payload = lines[-1].strip().strip('"')
                else:
                    print(f"\033[91m✗ Could not extract payload from output\033[0m")
                    input("\nPress Enter to continue...")
                    self._reinit_curses()
                    return
            else:
                payload = payload_match.group(1)
            
            print(f"\033[92m✓ Add provisioner payload generated successfully\033[0m")
            print(f"\033[90m  (Payload: {payload[:32]}...{payload[-32:]})\033[0m\n")
            
            # STEP 2: Execute add provisioner
            print(f"\033[1m\033[96mSTEP 2: Adding Provisioner\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            add_command = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet contract-call \
  --contract-id {self.config['contract_address']} \
  --fn-name add_provisioner \
  --fn-args "{payload}" \
  --gas-limit {self.config['gas_limit']}"""
            
            if self.wallet_password_decrypted:
                print(f"\033[92mExecuting add provisioner (using stored password)...\033[0m\n")
            else:
                print(f"\033[94mExecuting add provisioner...\033[0m")
                print(f"\033[93mNote: You will be prompted for your wallet password.\033[0m\n")
            
            add_result, _ = self.execute_wallet_command(add_command)
            
            print()
            if add_result:
                print(f"\033[92m{'=' * 70}\033[0m")
                print(f"\033[92m✓ Provisioner added successfully!\033[0m")
                print(f"\033[92m  Operator:    {operator_address[:32]}...\033[0m")
                print(f"\033[92m  Provisioner: {provisioner_address[:32]}...\033[0m")
                print(f"\033[92m{'=' * 70}\033[0m")
            else:
                print(f"\033[91m{'=' * 70}\033[0m")
                print(f"\033[91m✗ Add provisioner failed\033[0m")
                print(f"\033[91m{'=' * 70}\033[0m")
        
        except Exception as e:
            print(f"\033[91m✗ Unexpected error: {str(e)}\033[0m")
            import traceback
            traceback.print_exc()
        
        input("\nPress Enter to continue...")
        self._reinit_curses()
    
    def list_provisioners(self):
        """Option 2: List Provisioners"""
        # Temporarily exit curses mode
        curses.endwin()
        
        print(f"\n\033[94m{'=' * 70}\033[0m")
        print(f"\033[1m\033[96mLIST PROVISIONERS\033[0m")
        print(f"\033[94m{'=' * 70}\033[0m\n")
        
        try:
            # Use stored encryption password from session
            if not self.encryption_password:
                print(f"\n\033[91m✗ Encryption password not available.\033[0m")
                print(f"\033[93mPlease restart the application.\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            stored_keys = self._decrypt_keys(self.encryption_password)
            
            if stored_keys is None:
                print(f"\n\033[91m✗ Could not load stored keys. Wrong password.\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            if not stored_keys:
                print(f"\n\033[93m⚠ No provisioners stored yet.\033[0m")
                print(f"\033[90mUse 'Get Provisioner(s) Secret Key(s)' to import provisioners.\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # Display all provisioners
            print(f"\n\033[1m\033[92m{'=' * 70}\033[0m")
            print(f"\033[1m\033[92mSTORED PROVISIONERS ({len(stored_keys)} total)\033[0m")
            print(f"\033[1m\033[92m{'=' * 70}\033[0m\n")
            
            # Sort by index for consistent display
            sorted_provisioners = sorted(stored_keys.items(), key=lambda x: int(x[1].get('index', 0)))
            
            for prov_id, data in sorted_provisioners:
                print(f"\033[96mProvisioner Index {data['index']}:\033[0m")
                print(f"  Secret Key: {data['secret_key']}")
                
                address = data.get('address', '')
                if address:
                    print(f"  Address:    {address}")
                else:
                    print(f"  Address:    \033[90m(not stored)\033[0m")
                
                print()
            
            print(f"\033[1m\033[92m{'=' * 70}\033[0m")
            print(f"\033[90mStorage location: {self.keys_file}\033[0m")
            
        except Exception as e:
            print(f"\033[91m✗ Unexpected error: {str(e)}\033[0m")
            import traceback
            traceback.print_exc()
        
        input("\nPress Enter to continue...")
        self._reinit_curses()
    
    
    def get_provisioner_secret_keys(self):
        """Option 2: Get Provisioner(s) Secret Key(s)"""
        # Temporarily exit curses mode
        curses.endwin()
        
        print(f"\n\033[94m{'=' * 70}\033[0m")
        print(f"\033[1m\033[96mGET PROVISIONER SECRET KEY(S)\033[0m")
        print(f"\033[94m{'=' * 70}\033[0m\n")
        
        command = "sozu-beta3-rusk-wallet -w ~/sozu_provisioner -n testnet print-secret-key"
        
        print(f"\033[94mExecuting: Print Secret Keys\033[0m")
        print(f"\033[1mCommand:\033[0m {command}\n")
        
        if self.wallet_password_decrypted:
            print(f"\033[92mUsing stored wallet password (no prompts)...\033[0m\n")
        else:
            print(f"\033[93mNote: You will be prompted for your wallet password.\033[0m\n")
        
        try:
            result_code, output = self.execute_wallet_command(command)
            
            print()  # Add newline after command output
            
            if result_code and output:
                # Parse the output to extract secret keys
                secret_keys = {}
                lines = output.split('\n')
                current_idx = None
                current_address = None
                
                for line in lines:
                    # Look for idx lines
                    idx_match = re.match(r'>\s*idx\s+(\d+)', line)
                    if idx_match:
                        current_idx = idx_match.group(1)
                        current_address = None  # Reset address for new provisioner
                    
                    # Look for provisioner address (the long string before SecretKey)
                    # It's typically a long alphanumeric string starting with 'r' or similar
                    if current_idx is not None and current_address is None:
                        addr_match = re.match(r'^([a-zA-Z0-9]{100,})$', line.strip())
                        if addr_match:
                            current_address = addr_match.group(1)
                    
                    # Look for SecretKey lines
                    secret_match = re.match(r'SecretKey\s+([a-fA-F0-9]+)', line)
                    if secret_match and current_idx is not None:
                        secret_key = secret_match.group(1)
                        secret_keys[f"provisioner_{current_idx}"] = {
                            "index": current_idx,
                            "secret_key": secret_key,
                            "address": current_address if current_address else ""
                        }
                
                if secret_keys:
                    print(f"\n\033[1m\033[92m{'=' * 70}\033[0m")
                    print(f"\033[1m\033[92mEXTRACTED SECRET KEYS\033[0m")
                    print(f"\033[1m\033[92m{'=' * 70}\033[0m")
                    
                    for prov_id, data in secret_keys.items():
                        print(f"\033[96mProvisioner Index {data['index']}:\033[0m")
                        print(f"  Secret Key: {data['secret_key']}")
                        if data['address']:
                            print(f"  Address:    {data['address']}")
                        print()
                    
                    # Ask if user wants to save encrypted
                    save = input(f"\033[93mDo you want to save these keys in encrypted storage? (yes/no): \033[0m").strip().lower()
                    
                    if save in ['yes', 'y']:
                        # Get encryption password
                        print(f"\n\033[96mEnter a password to encrypt the keys:\033[0m")
                        encrypt_password = getpass.getpass("Password: ")
                        confirm_password = getpass.getpass("Confirm password: ")
                        
                        if encrypt_password != confirm_password:
                            print(f"\033[91m✗ Passwords do not match. Keys not saved.\033[0m")
                        elif not encrypt_password:
                            print(f"\033[91m✗ Password cannot be empty. Keys not saved.\033[0m")
                        else:
                            # Load existing keys or create new storage
                            existing_keys = self._decrypt_keys(encrypt_password)
                            if existing_keys is None:
                                # Wrong password or corrupted file
                                if self.keys_file.exists():
                                    overwrite = input(f"\033[93mStorage file exists but password is incorrect. Overwrite? (yes/no): \033[0m").strip().lower()
                                    if overwrite not in ['yes', 'y']:
                                        print(f"\033[91m✗ Keys not saved.\033[0m")
                                        existing_keys = None
                                    else:
                                        existing_keys = {}
                                else:
                                    existing_keys = {}
                            
                            if existing_keys is not None:
                                # Merge new keys with existing
                                existing_keys.update(secret_keys)
                                
                                # Encrypt and save
                                self._encrypt_keys(existing_keys, encrypt_password)
                                
                                print(f"\n\033[92m{'=' * 70}\033[0m")
                                print(f"\033[92m✓ Keys saved securely to: {self.keys_file}\033[0m")
                                print(f"\033[92m  Total provisioners stored: {len(existing_keys)}\033[0m")
                                print(f"\033[92m{'=' * 70}\033[0m")
                    else:
                        print(f"\033[93mKeys displayed but not saved.\033[0m")
                else:
                    print(f"\033[93m⚠ No secret keys found in output.\033[0m")
            else:
                print(f"\033[91m✗ Command failed with exit code: {result}\033[0m")
        
        except Exception as e:
            print(f"\033[91m✗ Unexpected error: {str(e)}\033[0m")
            import traceback
            traceback.print_exc()
        
        input("\nPress Enter to continue...")
        
        # Re-initialize curses
        self.stdscr = curses.initscr()
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)
        curses.init_pair(2, curses.COLOR_GREEN, -1)
        curses.init_pair(3, curses.COLOR_WHITE, -1)
        curses.init_pair(4, curses.COLOR_YELLOW, -1)
        curses.init_pair(5, curses.COLOR_RED, -1)
        curses.init_pair(6, curses.COLOR_MAGENTA, -1)
        curses.curs_set(0)
        self.stdscr.keypad(True)
    
    def allocate_stake(self):
        """Option 3: Allocate Stake to a Provisioner"""
        # Temporarily exit curses mode
        curses.endwin()
        
        print(f"\n\033[94m{'=' * 70}\033[0m")
        print(f"\033[1m\033[96mALLOCATE STAKE TO PROVISIONER\033[0m")
        print(f"\033[94m{'=' * 70}\033[0m\n")
        
        try:
            # STEP 1: Check available stake
            print(f"\033[1m\033[96mSTEP 1: Checking Available Stake\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            check_command = """curl -s -X POST -H "Content-Type: application/json" \
  -d '"72883945ac1aa032a88543aacc9e358d1dfef07717094c05296ce675f23078f2"' \
  https://testnet.nodes.dusk.network/on/contracts:0100000000000000000000000000000000000000000000000000000000000000/contract_balance"""
            
            result = subprocess.run(check_command, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout:
                balance_str = result.stdout.strip()
                try:
                    balance_lux = int(json.loads(balance_str))
                except (json.JSONDecodeError, ValueError):
                    numbers = re.findall(r'\d+', balance_str)
                    if numbers:
                        balance_lux = int(numbers[0])
                    else:
                        raise ValueError("Could not extract balance value")
                
                balance_dusk = balance_lux / 1_000_000_000
                
                print(f"\033[92mAvailable Balance:\033[0m")
                print(f"  LUX:  {balance_lux:,}")
                print(f"  DUSK: {balance_dusk:,.9f}")
                print()
            else:
                print(f"\033[91m✗ Failed to check balance\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # STEP 2: Get stored secret keys and let user choose
            print(f"\033[1m\033[96mSTEP 2: Select Provisioner and Amount\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            # Use stored encryption password from session
            if not self.encryption_password:
                print(f"\n\033[91m✗ Encryption password not available.\033[0m")
                print(f"\033[93mPlease restart the application.\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            stored_keys = self._decrypt_keys(self.encryption_password)
            
            if stored_keys is None or not stored_keys:
                print(f"\033[91m✗ Could not load stored keys. Wrong password or no keys stored.\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # Display available provisioners
            print(f"\n\033[92mAvailable Provisioners:\033[0m")
            provisioner_list = list(stored_keys.items())
            for i, (prov_id, data) in enumerate(provisioner_list, 1):
                print(f"  {i}. Provisioner Index {data['index']}")
            
            # Get user selection
            while True:
                try:
                    selection = input(f"\n\033[96mSelect provisioner (1-{len(provisioner_list)}): \033[0m").strip()
                    selection_idx = int(selection) - 1
                    if 0 <= selection_idx < len(provisioner_list):
                        break
                    print(f"\033[91mInvalid selection. Please choose 1-{len(provisioner_list)}\033[0m")
                except ValueError:
                    print(f"\033[91mPlease enter a number.\033[0m")
            
            selected_prov_id, selected_prov_data = provisioner_list[selection_idx]
            provisioner_sk = selected_prov_data['secret_key']
            
            print(f"\n\033[92m✓ Selected: Provisioner Index {selected_prov_data['index']}\033[0m")
            
            # Get stake amount in DUSK
            while True:
                amount_dusk_str = input(f"\n\033[96mEnter amount to stake (in DUSK): \033[0m").strip()
                try:
                    amount_dusk = float(amount_dusk_str)
                    if amount_dusk <= 0:
                        print(f"\033[91mAmount must be greater than 0\033[0m")
                        continue
                    if amount_dusk > balance_dusk:
                        print(f"\033[91mInsufficient balance. Available: {balance_dusk:,.9f} DUSK\033[0m")
                        continue
                    break
                except ValueError:
                    print(f"\033[91mPlease enter a valid number.\033[0m")
            
            # Convert DUSK to LUX
            amount_lux = int(amount_dusk * 1_000_000_000)
            
            print(f"\n\033[96mStaking:\033[0m")
            print(f"  Amount (DUSK): {amount_dusk:,.9f}")
            print(f"  Amount (LUX):  {amount_lux:,}")
            
            # Confirm
            confirm = input(f"\n\033[93mProceed with staking? (yes/no): \033[0m").strip().lower()
            if confirm not in ['yes', 'y']:
                print(f"\033[93mOperation cancelled.\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # Calculate payload
            print(f"\n\033[1m\033[96mCalculating Stake Payload...\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            payload_command = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet calculate-payload-stake-activate \
  --provisioner-sk {provisioner_sk} \
  --amount {amount_lux} \
  --network-id {self.config['network_id']}"""
            
            if self.wallet_password_decrypted:
                print(f"\033[92mExecuting payload calculation (using stored password)...\033[0m\n")
            else:
                print(f"\033[94mExecuting payload calculation...\033[0m")
                print(f"\033[93mNote: You will be prompted for your wallet password.\033[0m\n")
            
            payload_result, payload_output = self.execute_wallet_command(payload_command)
            
            print()
            
            if not payload_result:
                print(f"\033[91m✗ Failed to calculate payload\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # Try to extract the quoted payload
            payload_match = re.search(r'"([0-9a-fA-F]+)"', payload_output)
            if not payload_match:
                # Maybe the payload is the entire output or last line
                lines = [line.strip() for line in payload_output.split('\n') if line.strip()]
                if lines:
                    payload = lines[-1].strip().strip('"')
                else:
                    print(f"\033[91m✗ Could not extract payload from output\033[0m")
                    input("\nPress Enter to continue...")
                    self._reinit_curses()
                    return
            else:
                payload = payload_match.group(1)
            
            print(f"\033[92m✓ Payload generated successfully\033[0m")
            print(f"\033[90m  (Payload: {payload[:32]}...{payload[-32:]})\033[0m\n")
            
            # STEP 3: Execute stake activation
            print(f"\033[1m\033[96mSTEP 3: Activating Stake\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            activate_command = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet contract-call \
  --contract-id {self.config['contract_address']} \
  --fn-name stake_activate \
  --fn-args "{payload}" \
  --gas-limit {self.config['gas_limit']}"""
            
            if self.wallet_password_decrypted:
                print(f"\033[92mExecuting stake activation (using stored password)...\033[0m\n")
            else:
                print(f"\033[94mExecuting stake activation...\033[0m")
                print(f"\033[93mNote: You will be prompted for your wallet password.\033[0m\n")
            
            # Run interactively for password prompt
            activate_result, _ = self.execute_wallet_command(activate_command)
            
            print()
            if activate_result:
                print(f"\033[92m{'=' * 70}\033[0m")
                print(f"\033[92m✓ Stake activation completed successfully!\033[0m")
                print(f"\033[92m  Provisioner Index: {selected_prov_data['index']}\033[0m")
                print(f"\033[92m  Amount Staked: {amount_dusk:,.9f} DUSK ({amount_lux:,} LUX)\033[0m")
                print(f"\033[92m{'=' * 70}\033[0m")
            else:
                print(f"\033[91m{'=' * 70}\033[0m")
                print(f"\033[91m✗ Stake activation failed\033[0m")
                print(f"\033[91m{'=' * 70}\033[0m")
        
        except Exception as e:
            print(f"\033[91m✗ Unexpected error: {str(e)}\033[0m")
            import traceback
            traceback.print_exc()
        
        input("\nPress Enter to continue...")
        self._reinit_curses()
    
    def _reinit_curses(self):
        """Helper method to reinitialize curses"""
        self.stdscr = curses.initscr()
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)
        curses.init_pair(2, curses.COLOR_GREEN, -1)
        curses.init_pair(3, curses.COLOR_WHITE, -1)
        curses.init_pair(4, curses.COLOR_YELLOW, -1)
        curses.init_pair(5, curses.COLOR_RED, -1)
        curses.init_pair(6, curses.COLOR_MAGENTA, -1)
        curses.curs_set(0)
        self.stdscr.keypad(True)
    
    def deactivate_stake(self):
        """Option 4: Remove Stake from a Provisioner (not yet in consensus)"""
        # Temporarily exit curses mode
        curses.endwin()
        
        print(f"\n\033[94m{'=' * 70}\033[0m")
        print(f"\033[1m\033[96mREMOVE STAKE FROM PROVISIONER (DEACTIVATE)\033[0m")
        print(f"\033[94m{'=' * 70}\033[0m")
        print(f"\033[93mNote: This is for provisioners NOT yet in consensus\033[0m\n")
        
        try:
            # Select provisioner from stored list
            provisioner_address = self._select_provisioner_from_list("Select Provisioner to Deactivate Stake")
            
            if not provisioner_address:
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # Confirm action
            confirm = input(f"\n\033[93mProceed with stake deactivation for this provisioner? (yes/no): \033[0m").strip().lower()
            if confirm not in ['yes', 'y']:
                print(f"\033[93mOperation cancelled.\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # STEP 1: Calculate payload for deactivation
            print(f"\n\033[1m\033[96mSTEP 1: Calculating Deactivation Payload\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            payload_command = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet calculate-payload-stake-deactivate \
  --provisioner {provisioner_address}"""
            
            if self.wallet_password_decrypted:
                print(f"\033[92mExecuting payload calculation (using stored password)...\033[0m\n")
            else:
                print(f"\033[94mExecuting payload calculation...\033[0m")
                print(f"\033[93mNote: You will be prompted for your wallet password.\033[0m\n")
            
            payload_result, payload_output = self.execute_wallet_command(payload_command)
            
            print()
            
            if not payload_result:
                print(f"\033[91m✗ Failed to calculate deactivation payload\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # Try to extract the quoted payload
            payload_match = re.search(r'"([0-9a-fA-F]+)"', payload_output)
            if not payload_match:
                # Maybe the payload is the entire output or last line
                lines = [line.strip() for line in payload_output.split('\n') if line.strip()]
                if lines:
                    payload = lines[-1].strip().strip('"')
                else:
                    print(f"\033[91m✗ Could not extract payload from output\033[0m")
                    input("\nPress Enter to continue...")
                    self._reinit_curses()
                    return
            else:
                payload = payload_match.group(1)
            
            print(f"\033[92m✓ Deactivation payload generated successfully\033[0m")
            print(f"\033[90m  (Payload: {payload[:32]}...{payload[-32:]})\033[0m\n")
            
            # STEP 2: Execute stake deactivation
            print(f"\033[1m\033[96mSTEP 2: Executing Stake Deactivation\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            deactivate_command = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet contract-call \
  --contract-id {self.config['contract_address']} \
  --fn-name stake_deactivate \
  --fn-args "{payload}" \
  --gas-limit {self.config['gas_limit']}"""
            
            if self.wallet_password_decrypted:
                print(f"\033[92mExecuting stake deactivation (using stored password)...\033[0m\n")
            else:
                print(f"\033[94mExecuting stake deactivation...\033[0m")
                print(f"\033[93mNote: You will be prompted for your wallet password.\033[0m\n")
            
            # Run interactively for password prompt
            deactivate_result, _ = self.execute_wallet_command(deactivate_command)
            
            print()
            if deactivate_result:
                print(f"\033[92m{'=' * 70}\033[0m")
                print(f"\033[92m✓ Stake deactivation completed successfully!\033[0m")
                print(f"\033[92m  Provisioner: {provisioner_address[:32]}...\033[0m")
                print(f"\033[92m{'=' * 70}\033[0m")
            else:
                print(f"\033[91m{'=' * 70}\033[0m")
                print(f"\033[91m✗ Stake deactivation failed\033[0m")
                print(f"\033[91m{'=' * 70}\033[0m")
        
        except Exception as e:
            print(f"\033[91m✗ Unexpected error: {str(e)}\033[0m")
            import traceback
            traceback.print_exc()
        
        input("\nPress Enter to continue...")
        self._reinit_curses()
    
    def liquidate_provisioner(self):
        """Option 5: Liquidate Provisioner (Remove from Consensus)"""
        # Temporarily exit curses mode
        curses.endwin()
        
        print(f"\n\033[94m{'=' * 70}\033[0m")
        print(f"\033[1m\033[96mLIQUIDATE PROVISIONER\033[0m")
        print(f"\033[94m{'=' * 70}\033[0m")
        print(f"\033[93mNote: This will liquidate the provisioner (remove from consensus)\033[0m")
        print(f"\033[93mYou can terminate later using the Terminate option\033[0m\n")
        
        try:
            # Select provisioner from stored list
            provisioner_address = self._select_provisioner_from_list("Select Provisioner to Liquidate")
            
            if not provisioner_address:
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # Confirm action
            print(f"\n\033[93m{'!' * 70}\033[0m")
            print(f"\033[93m⚠  WARNING: This will LIQUIDATE the provisioner!\033[0m")
            print(f"\033[93m{'!' * 70}\033[0m")
            confirm = input(f"\n\033[93mProceed with liquidation? (yes/no): \033[0m").strip().lower()
            if confirm not in ['yes', 'y']:
                print(f"\033[93mOperation cancelled.\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # STEP 1: Calculate liquidation payload
            print(f"\n\033[1m\033[96mSTEP 1: Calculating Liquidation Payload\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            payload_command = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet calculate-payload-liquidate \
  --provisioner {provisioner_address}"""
            
            if self.wallet_password_decrypted:
                print(f"\033[92mExecuting payload calculation (using stored password)...\033[0m\n")
            else:
                print(f"\033[94mExecuting payload calculation...\033[0m")
                print(f"\033[93mNote: You will be prompted for your wallet password.\033[0m\n")
            
            payload_result, payload_output = self.execute_wallet_command(payload_command)
            
            print()
            
            if not payload_result:
                print(f"\033[91m✗ Failed to calculate liquidation payload\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # Extract the payload
            payload_match = re.search(r'"([0-9a-fA-F]+)"', payload_output)
            if not payload_match:
                lines = [line.strip() for line in payload_output.split('\n') if line.strip()]
                if lines:
                    liquidate_payload = lines[-1].strip().strip('"')
                else:
                    print(f"\033[91m✗ Could not extract liquidation payload from output\033[0m")
                    input("\nPress Enter to continue...")
                    self._reinit_curses()
                    return
            else:
                liquidate_payload = payload_match.group(1)
            
            print(f"\033[92m✓ Liquidation payload generated successfully\033[0m")
            print(f"\033[90m  (Payload: {liquidate_payload[:32]}...{liquidate_payload[-32:]})\033[0m\n")
            
            # STEP 2: Execute liquidation
            print(f"\033[1m\033[96mSTEP 2: Executing Liquidation\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            liquidate_command = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet contract-call \
  --contract-id {self.config['contract_address']} \
  --fn-name liquidate \
  --fn-args "{liquidate_payload}" \
  --gas-limit {self.config['gas_limit']}"""
            
            if self.wallet_password_decrypted:
                print(f"\033[92mExecuting liquidation (using stored password)...\033[0m\n")
            else:
                print(f"\033[94mExecuting liquidation...\033[0m")
                print(f"\033[93mNote: You will be prompted for your wallet password.\033[0m\n")
            
            liquidate_result, _ = self.execute_wallet_command(liquidate_command)
            
            print()
            if liquidate_result:
                print(f"\033[92m{'=' * 70}\033[0m")
                print(f"\033[92m✓ PROVISIONER LIQUIDATED SUCCESSFULLY!\033[0m")
                print(f"\033[92m  Provisioner: {provisioner_address[:32]}...\033[0m")
                print(f"\033[92m  Status: Removed from consensus\033[0m")
                print(f"\033[92m{'=' * 70}\033[0m")
                print(f"\n\033[93mNote: You can terminate this provisioner later using the Terminate option\033[0m")
            else:
                print(f"\033[91m{'=' * 70}\033[0m")
                print(f"\033[91m✗ Liquidation failed\033[0m")
                print(f"\033[91m{'=' * 70}\033[0m")
        
        except Exception as e:
            print(f"\033[91m✗ Unexpected error: {str(e)}\033[0m")
            import traceback
            traceback.print_exc()
        
        input("\nPress Enter to continue...")
        self._reinit_curses()
    
    def terminate_provisioner(self):
        """Option 6: Terminate Provisioner (Complete Removal)"""
        # Temporarily exit curses mode
        curses.endwin()
        
        print(f"\n\033[94m{'=' * 70}\033[0m")
        print(f"\033[1m\033[96mTERMINATE PROVISIONER\033[0m")
        print(f"\033[94m{'=' * 70}\033[0m")
        print(f"\033[93mNote: This will terminate the provisioner (complete removal)\033[0m")
        print(f"\033[93mProvisioner must be liquidated first!\033[0m\n")
        
        try:
            # Select provisioner from stored list
            provisioner_address = self._select_provisioner_from_list("Select Provisioner to Terminate")
            
            if not provisioner_address:
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # Confirm action
            print(f"\n\033[93m{'!' * 70}\033[0m")
            print(f"\033[93m⚠  WARNING: This will TERMINATE the provisioner!\033[0m")
            print(f"\033[93m⚠  Ensure the provisioner has been liquidated first!\033[0m")
            print(f"\033[93m{'!' * 70}\033[0m")
            confirm = input(f"\n\033[93mProceed with termination? (yes/no): \033[0m").strip().lower()
            if confirm not in ['yes', 'y']:
                print(f"\033[93mOperation cancelled.\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # STEP 1: Calculate termination payload
            print(f"\n\033[1m\033[96mSTEP 1: Calculating Termination Payload\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            terminate_payload_command = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet calculate-payload-terminate \
  --provisioner {provisioner_address}"""
            
            if self.wallet_password_decrypted:
                print(f"\033[92mExecuting payload calculation (using stored password)...\033[0m\n")
            else:
                print(f"\033[94mExecuting payload calculation...\033[0m")
                print(f"\033[93mNote: You will be prompted for your wallet password.\033[0m\n")
            
            terminate_payload_result, terminate_payload_output = self.execute_wallet_command(terminate_payload_command)
            
            print()
            
            if not terminate_payload_result:
                print(f"\033[91m✗ Failed to calculate termination payload\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # Extract the payload
            terminate_payload_match = re.search(r'"([0-9a-fA-F]+)"', terminate_payload_output)
            if not terminate_payload_match:
                lines = [line.strip() for line in terminate_payload_output.split('\n') if line.strip()]
                if lines:
                    terminate_payload = lines[-1].strip().strip('"')
                else:
                    print(f"\033[91m✗ Could not extract termination payload from output\033[0m")
                    input("\nPress Enter to continue...")
                    self._reinit_curses()
                    return
            else:
                terminate_payload = terminate_payload_match.group(1)
            
            print(f"\033[92m✓ Termination payload generated successfully\033[0m")
            print(f"\033[90m  (Payload: {terminate_payload[:32]}...{terminate_payload[-32:]})\033[0m\n")
            
            # STEP 2: Execute termination
            print(f"\033[1m\033[96mSTEP 2: Executing Termination\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            terminate_command = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet contract-call \
  --contract-id {self.config['contract_address']} \
  --fn-name terminate \
  --fn-args "{terminate_payload}" \
  --gas-limit {self.config['gas_limit']}"""
            
            if self.wallet_password_decrypted:
                print(f"\033[92mExecuting termination (using stored password)...\033[0m\n")
            else:
                print(f"\033[94mExecuting termination...\033[0m")
                print(f"\033[93mNote: You will be prompted for your wallet password.\033[0m\n")
            
            terminate_result, _ = self.execute_wallet_command(terminate_command)
            
            print()
            if terminate_result:
                print(f"\033[92m{'=' * 70}\033[0m")
                print(f"\033[92m✓ PROVISIONER TERMINATED SUCCESSFULLY!\033[0m")
                print(f"\033[92m  Provisioner: {provisioner_address[:32]}...\033[0m")
                print(f"\033[92m  Status: Completely removed\033[0m")
                print(f"\033[92m{'=' * 70}\033[0m")
            else:
                print(f"\033[91m{'=' * 70}\033[0m")
                print(f"\033[91m✗ Termination failed\033[0m")
                print(f"\033[91m{'=' * 70}\033[0m")
        
        except Exception as e:
            print(f"\033[91m✗ Unexpected error: {str(e)}\033[0m")
            import traceback
            traceback.print_exc()
        
        input("\nPress Enter to continue...")
        self._reinit_curses()
    
    def liquidate_and_terminate(self):
        """Option 7: Remove a Provisioner from Consensus (Liquidate + Terminate)"""
        # Temporarily exit curses mode
        curses.endwin()
        
        print(f"\n\033[94m{'=' * 70}\033[0m")
        print(f"\033[1m\033[96mREMOVE PROVISIONER FROM CONSENSUS (LIQUIDATE + TERMINATE)\033[0m")
        print(f"\033[94m{'=' * 70}\033[0m")
        print(f"\033[93mNote: This will liquidate AND terminate the provisioner\033[0m\n")
        
        try:
            # Select provisioner from stored list
            provisioner_address = self._select_provisioner_from_list("Select Provisioner to Liquidate & Terminate")
            
            if not provisioner_address:
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # Confirm action - this is a significant operation
            print(f"\n\033[91m{'!' * 70}\033[0m")
            print(f"\033[91m⚠  WARNING: This will LIQUIDATE and TERMINATE the provisioner!\033[0m")
            print(f"\033[91m{'!' * 70}\033[0m")
            confirm = input(f"\n\033[93mAre you absolutely sure you want to proceed? (yes/no): \033[0m").strip().lower()
            if confirm not in ['yes', 'y']:
                print(f"\033[93mOperation cancelled.\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # ============================================================
            # PART 1: LIQUIDATE
            # ============================================================
            
            # STEP 1: Calculate liquidation payload
            print(f"\n\033[1m\033[95m{'═' * 70}\033[0m")
            print(f"\033[1m\033[95mPART 1: LIQUIDATE\033[0m")
            print(f"\033[1m\033[95m{'═' * 70}\033[0m\n")
            
            print(f"\033[1m\033[96mSTEP 1: Calculating Liquidation Payload\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            payload_command = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet calculate-payload-liquidate \
  --provisioner {provisioner_address}"""
            
            if self.wallet_password_decrypted:
                print(f"\033[92mExecuting payload calculation (using stored password)...\033[0m\n")
            else:
                print(f"\033[94mExecuting payload calculation...\033[0m")
                print(f"\033[93mNote: You will be prompted for your wallet password.\033[0m\n")
            
            payload_result, payload_output = self.execute_wallet_command(payload_command)
            
            print()
            
            if not payload_result:
                print(f"\033[91m✗ Failed to calculate liquidation payload\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # Try to extract the quoted payload
            payload_match = re.search(r'"([0-9a-fA-F]+)"', payload_output)
            if not payload_match:
                # Maybe the payload is the entire output or last line
                lines = [line.strip() for line in payload_output.split('\n') if line.strip()]
                if lines:
                    liquidate_payload = lines[-1].strip().strip('"')
                else:
                    print(f"\033[91m✗ Could not extract liquidation payload from output\033[0m")
                    input("\nPress Enter to continue...")
                    self._reinit_curses()
                    return
            else:
                liquidate_payload = payload_match.group(1)
            
            print(f"\033[92m✓ Liquidation payload generated successfully\033[0m")
            print(f"\033[90m  (Payload: {liquidate_payload[:32]}...{liquidate_payload[-32:]})\033[0m\n")
            
            # STEP 2: Execute liquidation
            print(f"\033[1m\033[96mSTEP 2: Executing Liquidation\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            liquidate_command = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet contract-call \
  --contract-id {self.config['contract_address']} \
  --fn-name liquidate \
  --fn-args "{liquidate_payload}" \
  --gas-limit {self.config['gas_limit']}"""
            
            if self.wallet_password_decrypted:
                print(f"\033[92mExecuting liquidation (using stored password)...\033[0m\n")
            else:
                print(f"\033[94mExecuting liquidation...\033[0m")
                print(f"\033[93mNote: You will be prompted for your wallet password.\033[0m\n")
            
            # Run interactively for password prompt
            liquidate_result, _ = self.execute_wallet_command(liquidate_command)
            
            print()
            if not liquidate_result:
                print(f"\033[91m{'=' * 70}\033[0m")
                print(f"\033[91m✗ Liquidation failed - cannot proceed to terminate\033[0m")
                print(f"\033[91m{'=' * 70}\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            print(f"\033[92m✓ Liquidation completed successfully\033[0m\n")
            
            # ============================================================
            # PART 2: TERMINATE
            # ============================================================
            
            print(f"\033[1m\033[95m{'═' * 70}\033[0m")
            print(f"\033[1m\033[95mPART 2: TERMINATE\033[0m")
            print(f"\033[1m\033[95m{'═' * 70}\033[0m\n")
            
            # STEP 3: Calculate termination payload
            print(f"\033[1m\033[96mSTEP 3: Calculating Termination Payload\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            terminate_payload_command = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet calculate-payload-terminate \
  --provisioner {provisioner_address}"""
            
            if self.wallet_password_decrypted:
                print(f"\033[92mExecuting payload calculation (using stored password)...\033[0m\n")
            else:
                print(f"\033[94mExecuting payload calculation...\033[0m")
                print(f"\033[93mNote: You will be prompted for your wallet password.\033[0m\n")
            
            terminate_payload_result, terminate_payload_output = self.execute_wallet_command(terminate_payload_command)
            
            print()
            
            if not terminate_payload_result:
                print(f"\033[91m✗ Failed to calculate termination payload\033[0m")
                print(f"\033[93m⚠ Provisioner was liquidated but not terminated\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # Try to extract the quoted payload
            terminate_payload_match = re.search(r'"([0-9a-fA-F]+)"', terminate_payload_output)
            if not terminate_payload_match:
                # Maybe the payload is the entire output or last line
                lines = [line.strip() for line in terminate_payload_output.split('\n') if line.strip()]
                if lines:
                    terminate_payload = lines[-1].strip().strip('"')
                else:
                    print(f"\033[91m✗ Could not extract termination payload from output\033[0m")
                    print(f"\033[93m⚠ Provisioner was liquidated but not terminated\033[0m")
                    input("\nPress Enter to continue...")
                    self._reinit_curses()
                    return
            else:
                terminate_payload = terminate_payload_match.group(1)
            
            print(f"\033[92m✓ Termination payload generated successfully\033[0m")
            print(f"\033[90m  (Payload: {terminate_payload[:32]}...{terminate_payload[-32:]})\033[0m\n")
            
            # STEP 4: Execute termination
            print(f"\033[1m\033[96mSTEP 4: Executing Termination\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            terminate_command = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet contract-call \
  --contract-id {self.config['contract_address']} \
  --fn-name terminate \
  --fn-args "{terminate_payload}" \
  --gas-limit {self.config['gas_limit']}"""
            
            if self.wallet_password_decrypted:
                print(f"\033[92mExecuting termination (using stored password)...\033[0m\n")
            else:
                print(f"\033[94mExecuting termination...\033[0m")
                print(f"\033[93mNote: You will be prompted for your wallet password.\033[0m\n")
            
            # Run interactively for password prompt
            terminate_result, _ = self.execute_wallet_command(terminate_command)
            
            print()
            if terminate_result:
                print(f"\033[92m{'=' * 70}\033[0m")
                print(f"\033[92m✓ PROVISIONER FULLY REMOVED FROM CONSENSUS!\033[0m")
                print(f"\033[92m  Provisioner: {provisioner_address[:32]}...\033[0m")
                print(f"\033[92m  Status: Liquidated ✓ and Terminated ✓\033[0m")
                print(f"\033[92m{'=' * 70}\033[0m")
            else:
                print(f"\033[91m{'=' * 70}\033[0m")
                print(f"\033[91m✗ Termination failed\033[0m")
                print(f"\033[93m⚠ Provisioner was liquidated but termination failed\033[0m")
                print(f"\033[91m{'=' * 70}\033[0m")
        
        except Exception as e:
            print(f"\033[91m✗ Unexpected error: {str(e)}\033[0m")
            import traceback
            traceback.print_exc()
        
        input("\nPress Enter to continue...")
        self._reinit_curses()
    
    def remove_provisioner(self):
        """Option 8: Completely Remove a Provisioner"""
        self.stdscr.clear()
        y_pos = self.print_header(1)
        
        self.stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
        self.stdscr.addstr(y_pos, 2, "COMPLETELY REMOVE PROVISIONER")
        self.stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
        
        self.stdscr.attron(curses.color_pair(5) | curses.A_BOLD)
        self.stdscr.addstr(y_pos + 1, 2, "WARNING: This will completely remove the provisioner!")
        self.stdscr.attroff(curses.color_pair(5) | curses.A_BOLD)
        
        y_pos += 3
        
        provisioner_id = self.get_input_curses("Enter Provisioner ID", y_pos)
        if not provisioner_id:
            self.show_message("Operation cancelled", 4)
            return
        
        y_pos += 2
        if self.confirm_action_curses(f"COMPLETELY REMOVE provisioner {provisioner_id}? This cannot be undone!", y_pos):
            command = f"echo 'Completely removing provisioner {provisioner_id}'"
            self.execute_command(command, "Removing Provisioner Completely")
        else:
            self.show_message("Operation cancelled", 4)
    
    def check_available_stake(self):
        """Option 6: Check Available Stake"""
        # Temporarily exit curses mode
        curses.endwin()
        
        print(f"\n\033[94m{'=' * 70}\033[0m")
        print(f"\033[1m\033[96mCHECK AVAILABLE STAKE\033[0m")
        print(f"\033[94m{'=' * 70}\033[0m\n")
        
        # The curl command
        command = """curl -X POST -H "Content-Type: application/json" \
  -d '"72883945ac1aa032a88543aacc9e358d1dfef07717094c05296ce675f23078f2"' \
  https://testnet.nodes.dusk.network/on/contracts:0100000000000000000000000000000000000000000000000000000000000000/contract_balance"""
        
        print(f"\033[94mExecuting: Check Available Stake\033[0m\n")
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                check=True,
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                # Try to parse the balance value
                balance_str = result.stdout.strip()
                print(f"\033[92mRaw Response:\033[0m")
                print(balance_str)
                print()
                
                try:
                    # Try to extract numeric value (handles both plain numbers and JSON responses)
                    import json
                    import re
                    
                    # Try parsing as JSON first
                    try:
                        balance_lux = int(json.loads(balance_str))
                    except (json.JSONDecodeError, ValueError):
                        # Try extracting number from string
                        numbers = re.findall(r'\d+', balance_str)
                        if numbers:
                            balance_lux = int(numbers[0])
                        else:
                            raise ValueError("Could not extract balance value")
                    
                    balance_dusk = balance_lux / 1_000_000_000
                    
                    print(f"\033[1m\033[92m{'─' * 70}\033[0m")
                    print(f"\033[1m\033[92mBALANCE INFORMATION\033[0m")
                    print(f"\033[1m\033[92m{'─' * 70}\033[0m")
                    print(f"\033[96mBalance (LUX):\033[0m  {balance_lux:,}")
                    print(f"\033[96mBalance (DUSK):\033[0m {balance_dusk:,.9f}")
                    print(f"\033[1m\033[92m{'─' * 70}\033[0m\n")
                    
                except (ValueError, IndexError) as e:
                    print(f"\033[93m⚠ Could not parse balance value: {e}\033[0m\n")
            
            print(f"\033[92m✓ Query completed successfully!\033[0m")
            
        except subprocess.CalledProcessError as e:
            print(f"\033[91m✗ Command failed with error:\033[0m")
            if e.stderr:
                print(e.stderr)
        except Exception as e:
            print(f"\033[91m✗ Unexpected error: {str(e)}\033[0m")
        
        input("\nPress Enter to continue...")
        
        # Re-initialize curses
        self.stdscr = curses.initscr()
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)
        curses.init_pair(2, curses.COLOR_GREEN, -1)
        curses.init_pair(3, curses.COLOR_WHITE, -1)
        curses.init_pair(4, curses.COLOR_YELLOW, -1)
        curses.init_pair(5, curses.COLOR_RED, -1)
        curses.init_pair(6, curses.COLOR_MAGENTA, -1)
        curses.curs_set(0)
        self.stdscr.keypad(True)
    
    def check_stake_info(self):
        """Option 10: Check Stake Info for Each Provisioner"""
        # Temporarily exit curses mode
        curses.endwin()
        
        print(f"\n\033[94m{'=' * 70}\033[0m")
        print(f"\033[1m\033[96mCHECK STAKE INFO (ALL PROVISIONERS)\033[0m")
        print(f"\033[94m{'=' * 70}\033[0m\n")
        
        try:
            # Use stored encryption password from session
            if not self.encryption_password:
                print(f"\n\033[91m✗ Encryption password not available.\033[0m")
                print(f"\033[93mPlease restart the application.\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # Load stored provisioners to get their indices
            stored_keys = self._decrypt_keys(self.encryption_password)
            
            if stored_keys is None:
                print(f"\n\033[91m✗ Could not load stored keys.\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            if not stored_keys:
                print(f"\n\033[93m⚠ No provisioners stored yet.\033[0m")
                print(f"\033[90mUse 'Get Provisioner(s) Secret Key(s)' to import provisioners first.\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # Sort provisioners by index
            sorted_provisioners = sorted(stored_keys.items(), key=lambda x: int(x[1].get('index', 0)))
            
            print(f"\033[92mQuerying stake info for {len(sorted_provisioners)} provisioner(s)...\033[0m\n")
            
            # Query each provisioner
            all_results = []
            for prov_id, data in sorted_provisioners:
                idx = data['index']
                address = data.get('address', 'N/A')
                
                print(f"\033[1m\033[96m{'─' * 70}\033[0m")
                print(f"\033[1m\033[96mProvisioner Index {idx}\033[0m")
                print(f"\033[96mAddress: {address[:50]}{'...' if len(address) > 50 else ''}\033[0m")
                print(f"\033[1m\033[96m{'─' * 70}\033[0m\n")
                
                # Build the command
                stake_info_command = f"sozu-beta3-rusk-wallet -w ~/sozu_provisioner -n testnet stake-info --profile-idx {idx}"
                
                if self.wallet_password_decrypted:
                    print(f"\033[92mQuerying stake info (using stored password)...\033[0m\n")
                else:
                    print(f"\033[94mQuerying stake info...\033[0m")
                    print(f"\033[93mNote: You will be prompted for your wallet password.\033[0m\n")
                
                # Execute command
                success, output = self.execute_wallet_command(stake_info_command)
                
                print()
                
                if success:
                    # Store result for summary
                    all_results.append({
                        'idx': idx,
                        'prov_id': prov_id,
                        'address': address,
                        'output': output
                    })
                    print(f"\033[92m✓ Stake info retrieved for index {idx}\033[0m\n")
                else:
                    print(f"\033[91m✗ Failed to retrieve stake info for index {idx}\033[0m\n")
                    all_results.append({
                        'idx': idx,
                        'prov_id': prov_id,
                        'address': address,
                        'output': None
                    })
            
            # Display summary
            print(f"\n\033[1m\033[92m{'═' * 70}\033[0m")
            print(f"\033[1m\033[92mSTAKE INFO SUMMARY\033[0m")
            print(f"\033[1m\033[92m{'═' * 70}\033[0m\n")
            
            for result in all_results:
                print(f"\033[96mProvisioner Index {result['idx']} ({result['prov_id']}):\033[0m")
                if result['output']:
                    # Try to parse key information from output
                    # The output format may vary, so we'll display it as-is
                    print(f"\033[90m{result['address'][:60]}{'...' if len(result['address']) > 60 else ''}\033[0m")
                    print(f"\033[92m  Status: Retrieved ✓\033[0m")
                else:
                    print(f"\033[91m  Status: Failed ✗\033[0m")
                print()
            
            print(f"\033[1m\033[92m{'═' * 70}\033[0m")
            print(f"\033[92m✓ Queried {len(all_results)} provisioner(s)\033[0m")
            
        except Exception as e:
            print(f"\033[91m✗ Unexpected error: {str(e)}\033[0m")
            import traceback
            traceback.print_exc()
        
        input("\nPress Enter to continue...")
        self._reinit_curses()
    
    def check_block_heights(self):
        """Option 11: Check Block Heights for All Rusk Instances"""
        # Temporarily exit curses mode
        curses.endwin()
        
        print(f"\n\033[94m{'=' * 70}\033[0m")
        print(f"\033[1m\033[96mCHECK BLOCK HEIGHTS (ALL RUSK INSTANCES)\033[0m")
        print(f"\033[94m{'=' * 70}\033[0m\n")
        
        try:
            # Define log files to check
            log_files = [
                '/var/log/rusk-1.log',
                '/var/log/rusk-2.log',
                '/var/log/rusk-3.log'
            ]
            
            results = []
            
            for log_file in log_files:
                instance_num = log_file.split('-')[1].split('.')[0]
                
                print(f"\033[1m\033[96m{'─' * 70}\033[0m")
                print(f"\033[1m\033[96mRusk Instance {instance_num}\033[0m")
                print(f"\033[96mLog: {log_file}\033[0m")
                print(f"\033[1m\033[96m{'─' * 70}\033[0m\n")
                
                # Check if log file exists
                if not os.path.exists(log_file):
                    print(f"\033[91m✗ Log file not found: {log_file}\033[0m\n")
                    results.append({
                        'instance': instance_num,
                        'log_file': log_file,
                        'height': None,
                        'error': 'Log file not found'
                    })
                    continue
                
                try:
                    # Tail the log and grep for current_height=
                    # Remove ANSI color codes first, then extract height
                    command = f"tail -n 100 {log_file} | sed 's/\\x1b\\[[0-9;]*m//g' | grep -o 'current_height=[0-9]*' | tail -n 1 | cut -d= -f2"
                    
                    result = subprocess.run(
                        command,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if result.stdout.strip():
                        height = result.stdout.strip()
                        print(f"\033[92m✓ Current block height: {height}\033[0m\n")
                        results.append({
                            'instance': instance_num,
                            'log_file': log_file,
                            'height': height,
                            'error': None
                        })
                    else:
                        print(f"\033[93m⚠ No height information found in recent logs\033[0m\n")
                        results.append({
                            'instance': instance_num,
                            'log_file': log_file,
                            'height': None,
                            'error': 'No height found in logs'
                        })
                
                except subprocess.TimeoutExpired:
                    print(f"\033[91m✗ Timeout reading log file\033[0m\n")
                    results.append({
                        'instance': instance_num,
                        'log_file': log_file,
                        'height': None,
                        'error': 'Timeout'
                    })
                except Exception as e:
                    print(f"\033[91m✗ Error reading log: {str(e)}\033[0m\n")
                    results.append({
                        'instance': instance_num,
                        'log_file': log_file,
                        'height': None,
                        'error': str(e)
                    })
            
            # Display summary
            print(f"\n\033[1m\033[92m{'═' * 70}\033[0m")
            print(f"\033[1m\033[92mBLOCK HEIGHT SUMMARY\033[0m")
            print(f"\033[1m\033[92m{'═' * 70}\033[0m\n")
            
            for result in results:
                print(f"\033[96mRusk Instance {result['instance']}:\033[0m")
                if result['height']:
                    print(f"\033[92m  Block Height: {result['height']}\033[0m")
                    print(f"\033[92m  Status: Running ✓\033[0m")
                else:
                    print(f"\033[91m  Status: {result['error']} ✗\033[0m")
                print()
            
            # Calculate sync status if we have multiple heights
            valid_heights = [int(r['height']) for r in results if r['height']]
            if len(valid_heights) > 1:
                max_height = max(valid_heights)
                min_height = min(valid_heights)
                diff = max_height - min_height
                
                if diff == 0:
                    print(f"\033[92m✓ All instances are in sync (same height)\033[0m")
                elif diff <= 5:
                    print(f"\033[93m⚠ Instances are mostly in sync (max difference: {diff} blocks)\033[0m")
                else:
                    print(f"\033[91m⚠ Instances have significant height difference: {diff} blocks\033[0m")
                    print(f"\033[93m  Highest: {max_height}, Lowest: {min_height}\033[0m")
            elif len(valid_heights) == 1:
                print(f"\033[93m⚠ Only 1 instance reporting height\033[0m")
            else:
                print(f"\033[91m✗ No instances reporting height\033[0m")
            
            print(f"\n\033[1m\033[92m{'═' * 70}\033[0m")
            print(f"\033[92m✓ Checked {len(log_files)} rusk instance(s)\033[0m")
            
        except Exception as e:
            print(f"\033[91m✗ Unexpected error: {str(e)}\033[0m")
            import traceback
            traceback.print_exc()
        
        input("\nPress Enter to continue...")
        self._reinit_curses()
    
    def _get_block_height_from_log(self, log_file: str) -> Optional[int]:
        """Helper function to get block height from a single log file"""
        try:
            command = f"tail -n 100 {log_file} | sed 's/\\x1b\\[[0-9;]*m//g' | grep -o 'current_height=[0-9]*' | tail -n 1 | cut -d= -f2"
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
            
            if result.stdout.strip():
                return int(result.stdout.strip())
            return None
        except Exception:
            return None
    
    def _check_provisioner_stake(self, idx: int) -> Dict:
        """Check stake for a single provisioner by index
        Returns dict with 'has_stake', 'amount', and 'output'
        """
        try:
            stake_info_command = f"sozu-beta3-rusk-wallet -w ~/sozu_provisioner -n testnet stake-info --profile-idx {idx}"
            success, output = self.execute_wallet_command(stake_info_command)
            
            # Debug output
            # print(f"\n[DEBUG] idx={idx}, success={success}, output_length={len(output) if output else 0}")
            # if output:
            #     print(f"[DEBUG] First 200 chars: {output[:200]}")
            
            if success and output:
                # Parse output for "Eligible stake: <amount> DUSK"
                if "Eligible stake:" in output:
                    # Extract amount
                    match = re.search(r'Eligible stake:\s*(\d+(?:\.\d+)?)\s*DUSK', output)
                    if match:
                        amount = float(match.group(1))
                        return {
                            'has_stake': True,
                            'amount': amount,
                            'output': output
                        }
                elif "A stake does not exist for this key" in output:
                    return {
                        'has_stake': False,
                        'amount': 0,
                        'output': output
                    }
            
            # Check output even if success=False (might still have useful info)
            if output:
                if "Eligible stake:" in output:
                    match = re.search(r'Eligible stake:\s*(\d+(?:\.\d+)?)\s*DUSK', output)
                    if match:
                        amount = float(match.group(1))
                        return {
                            'has_stake': True,
                            'amount': amount,
                            'output': output
                        }
                elif "A stake does not exist for this key" in output:
                    return {
                        'has_stake': False,
                        'amount': 0,
                        'output': output
                    }
            
            return {
                'has_stake': False,
                'amount': 0,
                'output': output if output else "No output"
            }
        except Exception as e:
            return {
                'has_stake': False,
                'amount': 0,
                'output': f"Error: {str(e)}"
            }
    
    def _get_active_provisioner(self) -> Optional[Dict]:
        """Find which provisioner is currently active (has >1000 DUSK staked)
        Only checks idx 0 and 1
        Returns dict with 'idx', 'prov_id', 'address', 'amount' or None
        """
        try:
            # Load stored provisioners
            if not self.encryption_password:
                return None
            
            stored_keys = self._decrypt_keys(self.encryption_password)
            if not stored_keys:
                return None
            
            # Only check idx 0 and 1 (instances 1 and 2)
            # Instance 3 (idx 2) is fallback only
            for prov_id, data in stored_keys.items():
                idx = int(data['index'])  # Convert to int!
                if idx not in [0, 1]:  # Only instances 1 and 2
                    continue
                    
                stake_info = self._check_provisioner_stake(idx)
                
                # Active provisioner has MORE than 1000 DUSK
                if stake_info['has_stake'] and stake_info['amount'] > 1000:
                    return {
                        'idx': idx,
                        'prov_id': prov_id,
                        'address': data.get('address', 'N/A'),
                        'amount': stake_info['amount']
                    }
            
            return None
        except Exception:
            return None
    
    def _get_inactive_provisioners(self, exclude_idx: int = None) -> List[Dict]:
        """Find provisioners that are inactive (have ≤1000 DUSK or no stake)
        Only checks idx 0 and 1
        Returns list of dicts with 'idx', 'prov_id', 'address', 'amount'
        """
        try:
            if not self.encryption_password:
                return []
            
            stored_keys = self._decrypt_keys(self.encryption_password)
            if not stored_keys:
                return []
            
            inactive = []
            for prov_id, data in stored_keys.items():
                idx = int(data['index'])  # Convert to int!
                if idx not in [0, 1]:  # Only instances 1 and 2
                    continue
                if exclude_idx is not None and idx == exclude_idx:
                    continue
                
                stake_info = self._check_provisioner_stake(idx)
                
                # Inactive provisioner has ≤1000 DUSK or no stake
                if not stake_info['has_stake'] or stake_info['amount'] <= 1000:
                    inactive.append({
                        'idx': idx,
                        'prov_id': prov_id,
                        'address': data.get('address', 'N/A'),
                        'amount': stake_info['amount'] if stake_info['has_stake'] else 0
                    })
            
            return inactive
        except Exception:
            return []
    
    def _check_available_stake(self) -> Optional[float]:
        """Check available stake from contract
        Returns amount in DUSK or None
        """
        try:
            command = """curl -X POST -H "Content-Type: application/json" \
  -d '"72883945ac1aa032a88543aacc9e358d1dfef07717094c05296ce675f23078f2"' \
  https://testnet.nodes.dusk.network/on/contracts:0100000000000000000000000000000000000000000000000000000000000000/contract_balance"""
            
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
            
            if result.stdout:
                balance_str = result.stdout.strip()
                try:
                    balance_lux = int(json.loads(balance_str))
                    balance_dusk = balance_lux / 1_000_000_000
                    return balance_dusk
                except (json.JSONDecodeError, ValueError):
                    # Try extracting number from string
                    numbers = re.findall(r'\d+', balance_str)
                    if numbers:
                        balance_lux = int(numbers[0])
                        return balance_lux / 1_000_000_000
            
            return None
        except Exception:
            return None
    
    def _topup_active_provisioner(self, active: Dict, available_stake: float) -> bool:
        """Top-up active provisioner to reach max capacity
        Max capacity = stake_limit - 1001 (to allow 1000 for other provisioner)
        Returns True if top-up was executed, False otherwise
        """
        try:
            stake_limit = self.config.get('stake_limit', 1000000)
            current_stake = active['amount']
            
            # Max capacity for active provisioner (leave 1001 for other provisioner)
            max_capacity = stake_limit - 1001
            
            # Calculate how much more we can add
            room_to_add = max_capacity - current_stake
            
            if room_to_add <= 0:
                # Already at or above max capacity
                return False
            
            # Calculate how much to actually add
            amount_to_add = min(room_to_add, available_stake)
            
            if amount_to_add < 1:
                # Not enough available to add
                return False
            
            print(f"\n\033[1m\033[93m{'─' * 70}\033[0m")
            print(f"\033[1m\033[93m⚙  STAKE TOP-UP TRIGGERED\033[0m")
            print(f"\033[1m\033[93m{'─' * 70}\033[0m\n")
            
            print(f"\033[96mProvisioner index {active['idx']} ({active['prov_id']})\033[0m")
            print(f"\033[96mCurrent stake: {current_stake:,.0f} DUSK\033[0m")
            print(f"\033[96mMax capacity: {max_capacity:,.0f} DUSK\033[0m")
            print(f"\033[96mRoom to add: {room_to_add:,.0f} DUSK\033[0m")
            print(f"\033[96mAvailable: {available_stake:,.2f} DUSK\033[0m")
            print(f"\033[92mAdding: {amount_to_add:,.0f} DUSK\033[0m\n")
            
            # Get provisioner secret key
            stored_keys = self._decrypt_keys(self.encryption_password)
            if not stored_keys:
                print(f"\033[91m✗ Could not load provisioner keys\033[0m\n")
                return False
            
            provisioner_sk = stored_keys[active['prov_id']]['secret_key']
            amount_lux = int(amount_to_add * 1_000_000_000)
            
            # Calculate payload (same as allocate_stake)
            print(f"\033[94mCalculating stake payload...\033[0m\n")
            payload_command = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet calculate-payload-stake-activate \
  --provisioner-sk {provisioner_sk} \
  --amount {amount_lux} \
  --network-id {self.config['network_id']}"""
            
            payload_result, payload_output = self.execute_wallet_command(payload_command)
            
            if not payload_result:
                print(f"\n\033[91m✗ Failed to calculate payload\033[0m\n")
                return False
            
            # Extract payload
            payload_match = re.search(r'"([0-9a-fA-F]+)"', payload_output)
            if not payload_match:
                lines = [line.strip() for line in payload_output.split('\n') if line.strip()]
                if lines:
                    payload = lines[-1].strip().strip('"')
                else:
                    print(f"\n\033[91m✗ Could not extract payload\033[0m\n")
                    return False
            else:
                payload = payload_match.group(1)
            
            print(f"\033[92m✓ Payload generated\033[0m\n")
            
            # Execute stake activation (same as allocate_stake)
            print(f"\033[94mExecuting stake activation...\033[0m\n")
            activate_command = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet contract-call \
  --contract-id {self.config['contract_address']} \
  --fn-name stake_activate \
  --fn-args "{payload}" \
  --gas-limit {self.config['gas_limit']}"""
            
            success, output = self.execute_wallet_command(activate_command)
            
            if success:
                print(f"\n\033[92m{'=' * 70}\033[0m")
                print(f"\033[92m✓ Successfully added {amount_to_add:,.0f} DUSK to provisioner!\033[0m")
                print(f"\033[92m  New total stake: {current_stake + amount_to_add:,.0f} DUSK\033[0m")
                print(f"\033[92m{'=' * 70}\033[0m\n")
                return True
            else:
                print(f"\n\033[91m✗ Failed to add stake\033[0m\n")
                return False
                
        except Exception as e:
            print(f"\033[91m✗ Top-up error: {str(e)}\033[0m\n")
            return False
    
    def _wait_for_block_height(self, target_height: int, log_files: list, timeout_seconds: int = 300) -> bool:
        """Wait until block height reaches target
        Returns True if target reached, False if timeout
        """
        print(f"\033[94mWaiting for block height {target_height}...\033[0m")
        start_time = time.time()
        
        while (time.time() - start_time) < timeout_seconds:
            heights = []
            for log_file in log_files:
                try:
                    with open(log_file, 'r') as f:
                        # Read last 50 lines
                        lines = f.readlines()[-50:]
                        for line in reversed(lines):
                            if 'finalized_block_height' in line:
                                match = re.search(r'finalized_block_height=(\d+)', line)
                                if match:
                                    heights.append(int(match.group(1)))
                                    break
                except FileNotFoundError:
                    pass
            
            if heights:
                current_height = max(heights)
                if current_height >= target_height:
                    print(f"\033[92m✓ Block height {current_height} reached\033[0m\n")
                    return True
                print(f"  Current: {current_height}, Target: {target_height}", end='\r', flush=True)
            
            time.sleep(2)
        
        print(f"\n\033[91m✗ Timeout waiting for block height {target_height}\033[0m\n")
        return False
    
    def _automated_liquidate_and_terminate(self, provisioner: Dict) -> bool:
        """Liquidate and terminate a provisioner automatically
        Executes liquidate immediately followed by terminate (no wait)
        Returns True if successful, False otherwise
        """
        try:
            provisioner_address = provisioner['address']
            prov_id = provisioner['prov_id']
            idx = provisioner['idx']
            
            print(f"\n\033[1m\033[91m{'=' * 70}\033[0m")
            print(f"\033[1m\033[91m🔄  AUTOMATED LIQUIDATION & TERMINATION\033[0m")
            print(f"\033[1m\033[91m{'=' * 70}\033[0m\n")
            
            print(f"\033[96mProvisioner: Index {idx} ({prov_id})\033[0m")
            print(f"\033[96mAddress: {provisioner_address[:50]}...\033[0m\n")
            
            # STEP 1: Liquidate
            print(f"\033[1m\033[96mSTEP 1: Calculating Liquidation Payload\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            liquidate_payload_cmd = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet calculate-payload-liquidate \
  --provisioner {provisioner_address}"""
            
            print(f"\033[92mCalculating liquidation payload...\033[0m\n")
            liquidate_payload_result, liquidate_payload_output = self.execute_wallet_command(liquidate_payload_cmd)
            
            if not liquidate_payload_result:
                print(f"\n\033[91m✗ Failed to calculate liquidation payload\033[0m\n")
                return False
            
            # Extract payload
            payload_match = re.search(r'"([0-9a-fA-F]+)"', liquidate_payload_output)
            if not payload_match:
                lines = [line.strip() for line in liquidate_payload_output.split('\n') if line.strip()]
                if lines:
                    liquidate_payload = lines[-1].strip().strip('"')
                else:
                    print(f"\n\033[91m✗ Could not extract liquidation payload\033[0m\n")
                    return False
            else:
                liquidate_payload = payload_match.group(1)
            
            print(f"\033[92m✓ Liquidation payload generated\033[0m\n")
            
            # Execute liquidation
            print(f"\033[1m\033[96mSTEP 2: Executing Liquidation\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            liquidate_cmd = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet contract-call \
  --contract-id {self.config['contract_address']} \
  --fn-name liquidate \
  --fn-args "{liquidate_payload}" \
  --gas-limit {self.config['gas_limit']}"""
            
            print(f"\033[92mExecuting liquidation...\033[0m\n")
            liquidate_result, _ = self.execute_wallet_command(liquidate_cmd)
            
            if not liquidate_result:
                print(f"\n\033[91m✗ Liquidation failed\033[0m\n")
                return False
            
            print(f"\n\033[92m✓ LIQUIDATION SUCCESSFUL!\033[0m\n")
            
            # STEP 3: Terminate (immediately, no wait)
            print(f"\033[1m\033[96mSTEP 3: Calculating Termination Payload\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            terminate_payload_cmd = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet calculate-payload-terminate \
  --provisioner {provisioner_address}"""
            
            print(f"\033[92mCalculating termination payload...\033[0m\n")
            terminate_payload_result, terminate_payload_output = self.execute_wallet_command(terminate_payload_cmd)
            
            if not terminate_payload_result:
                print(f"\n\033[91m✗ Failed to calculate termination payload\033[0m\n")
                return False
            
            # Extract payload
            payload_match = re.search(r'"([0-9a-fA-F]+)"', terminate_payload_output)
            if not payload_match:
                lines = [line.strip() for line in terminate_payload_output.split('\n') if line.strip()]
                if lines:
                    terminate_payload = lines[-1].strip().strip('"')
                else:
                    print(f"\n\033[91m✗ Could not extract termination payload\033[0m\n")
                    return False
            else:
                terminate_payload = payload_match.group(1)
            
            print(f"\033[92m✓ Termination payload generated\033[0m\n")
            
            # Execute termination
            print(f"\033[1m\033[96mSTEP 4: Executing Termination\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            terminate_cmd = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet contract-call \
  --contract-id {self.config['contract_address']} \
  --fn-name terminate \
  --fn-args "{terminate_payload}" \
  --gas-limit {self.config['gas_limit']}"""
            
            print(f"\033[92mExecuting termination...\033[0m\n")
            terminate_result, _ = self.execute_wallet_command(terminate_cmd)
            
            if not terminate_result:
                print(f"\n\033[91m✗ Termination failed\033[0m\n")
                return False
            
            print(f"\n\033[92m{'=' * 70}\033[0m")
            print(f"\033[92m✓ LIQUIDATION & TERMINATION COMPLETE!\033[0m")
            print(f"\033[92m  Provisioner index {idx} ({prov_id})\033[0m")
            print(f"\033[92m  Status: Completely removed from consensus\033[0m")
            print(f"\033[92m{'=' * 70}\033[0m\n")
            
            return True
            
        except Exception as e:
            print(f"\033[91m✗ Liquidate & terminate error: {str(e)}\033[0m\n")
            import traceback
            traceback.print_exc()
            return False
    
    def _execute_rotation(self, active: Dict, inactive: Dict) -> bool:
        """Execute full rotation sequence
        1. Liquidate & terminate active provisioner
        2. Allocate 1000 DUSK back to that provisioner  
        3. Allocate (limit - 1001) DUSK to inactive provisioner
        Returns True if successful, False otherwise
        """
        try:
            stake_limit = self.config.get('stake_limit', 1000000)
            small_stake = 1000  # DUSK
            large_stake = stake_limit - 1001  # Maximum stake (both must fit under limit)
            
            print(f"\n\033[1m\033[93m{'═' * 70}\033[0m")
            print(f"\033[1m\033[93m🔄  EXECUTING STAKE ROTATION\033[0m")
            print(f"\033[1m\033[93m{'═' * 70}\033[0m\n")
            
            print(f"\033[96mCurrent active: Index {active['idx']} ({active['prov_id']})\033[0m")
            print(f"\033[96mCurrent stake: {active['amount']:,.0f} DUSK\033[0m\n")
            
            print(f"\033[96mWill activate: Index {inactive['idx']} ({inactive['prov_id']})\033[0m\n")
            
            # PHASE 1: Liquidate and terminate active provisioner
            print(f"\033[1m\033[96m{'─' * 70}\033[0m")
            print(f"\033[1m\033[96mPHASE 1: Liquidate & Terminate Active Provisioner\033[0m")
            print(f"\033[1m\033[96m{'─' * 70}\033[0m\n")
            
            if not self._automated_liquidate_and_terminate(active):
                print(f"\033[91m✗ Rotation failed during liquidate & terminate phase\033[0m\n")
                return False
            
            # Check available stake after liquidation
            print(f"\033[1m\033[96m{'─' * 70}\033[0m")
            print(f"\033[1m\033[96mCHECKING AVAILABLE STAKE\033[0m")
            print(f"\033[1m\033[96m{'─' * 70}\033[0m\n")
            
            available_stake = self._check_available_stake()
            if available_stake is None:
                print(f"\033[91m✗ Could not check available stake\033[0m\n")
                return False
            
            print(f"\033[92mAvailable stake: {available_stake:,.2f} DUSK\033[0m\n")
            
            # PHASE 2: Allocate 1000 DUSK back to the just-liquidated provisioner
            print(f"\033[1m\033[96m{'─' * 70}\033[0m")
            print(f"\033[1m\033[96mPHASE 2: Allocate {small_stake:,.0f} DUSK to Index {active['idx']}\033[0m")
            print(f"\033[1m\033[96m{'─' * 70}\033[0m\n")
            
            # Get provisioner secret key
            stored_keys = self._decrypt_keys(self.encryption_password)
            if not stored_keys:
                print(f"\033[91m✗ Could not load provisioner keys\033[0m\n")
                return False
            
            small_stake_lux = int(small_stake * 1_000_000_000)
            
            provisioner_sk_old = stored_keys[active['prov_id']]['secret_key']
            
            print(f"\033[94mCalculating stake payload for {small_stake:,.0f} DUSK...\033[0m\n")
            payload_cmd = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet calculate-payload-stake-activate \
  --provisioner-sk {provisioner_sk_old} \
  --amount {small_stake_lux} \
  --network-id {self.config['network_id']}"""
            
            payload_result, payload_output = self.execute_wallet_command(payload_cmd)
            
            if not payload_result:
                print(f"\n\033[91m✗ Failed to calculate payload\033[0m\n")
                return False
            
            # Extract payload
            payload_match = re.search(r'"([0-9a-fA-F]+)"', payload_output)
            if not payload_match:
                lines = [line.strip() for line in payload_output.split('\n') if line.strip()]
                if lines:
                    payload = lines[-1].strip().strip('"')
                else:
                    print(f"\n\033[91m✗ Could not extract payload\033[0m\n")
                    return False
            else:
                payload = payload_match.group(1)
            
            print(f"\033[92m✓ Payload generated\033[0m\n")
            
            print(f"\033[94mExecuting stake activation...\033[0m\n")
            activate_cmd = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet contract-call \
  --contract-id {self.config['contract_address']} \
  --fn-name stake_activate \
  --fn-args "{payload}" \
  --gas-limit {self.config['gas_limit']}"""
            
            activate_result, _ = self.execute_wallet_command(activate_cmd)
            
            if not activate_result:
                print(f"\n\033[91m✗ Failed to allocate {small_stake:,.0f} DUSK\033[0m\n")
                return False
            
            print(f"\n\033[92m✓ Allocated {small_stake:,.0f} DUSK to index {active['idx']}\033[0m\n")
            
            # PHASE 3: Top-up the inactive provisioner (from 1000 to 998999)
            print(f"\033[1m\033[96m{'─' * 70}\033[0m")
            print(f"\033[1m\033[96mPHASE 3: Top-up Index {inactive['idx']} to {large_stake:,.0f} DUSK\033[0m")
            print(f"\033[1m\033[96m{'─' * 70}\033[0m\n")
            
            # Calculate how much to ADD (not the total amount!)
            current_inactive_stake = inactive.get('amount', 0)
            amount_to_add = large_stake - current_inactive_stake
            
            print(f"\033[96mCurrent stake: {current_inactive_stake:,.0f} DUSK\033[0m")
            print(f"\033[96mTarget stake: {large_stake:,.0f} DUSK\033[0m")
            print(f"\033[96mAmount to add: {amount_to_add:,.0f} DUSK\033[0m\n")
            
            if amount_to_add <= 0:
                print(f"\033[93m⚠ Inactive provisioner already at or above target\033[0m\n")
                print(f"\n\033[1m\033[92m{'═' * 70}\033[0m")
                print(f"\033[1m\033[92m✓ ROTATION COMPLETE!\033[0m")
                print(f"\033[1m\033[92m{'═' * 70}\033[0m\n")
                return True
            
            # Check if we have enough stake available
            if available_stake < amount_to_add:
                print(f"\033[91m✗ Insufficient stake available\033[0m")
                print(f"\033[91m  Need: {amount_to_add:,.0f} DUSK\033[0m")
                print(f"\033[91m  Have: {available_stake:,.2f} DUSK\033[0m\n")
                return False
            
            amount_to_add_lux = int(amount_to_add * 1_000_000_000)
            
            provisioner_sk_new = stored_keys[inactive['prov_id']]['secret_key']
            
            print(f"\033[94mCalculating stake payload for {amount_to_add:,.0f} DUSK...\033[0m\n")
            payload_cmd = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet calculate-payload-stake-activate \
  --provisioner-sk {provisioner_sk_new} \
  --amount {amount_to_add_lux} \
  --network-id {self.config['network_id']}"""
            
            payload_result, payload_output = self.execute_wallet_command(payload_cmd)
            
            if not payload_result:
                print(f"\n\033[91m✗ Failed to calculate payload\033[0m\n")
                return False
            
            # Extract payload
            payload_match = re.search(r'"([0-9a-fA-F]+)"', payload_output)
            if not payload_match:
                lines = [line.strip() for line in payload_output.split('\n') if line.strip()]
                if lines:
                    payload = lines[-1].strip().strip('"')
                else:
                    print(f"\n\033[91m✗ Could not extract payload\033[0m\n")
                    return False
            else:
                payload = payload_match.group(1)
            
            print(f"\033[92m✓ Payload generated\033[0m\n")
            
            print(f"\033[94mExecuting stake activation...\033[0m\n")
            activate_cmd = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet contract-call \
  --contract-id {self.config['contract_address']} \
  --fn-name stake_activate \
  --fn-args "{payload}" \
  --gas-limit {self.config['gas_limit']}"""
            
            activate_result, _ = self.execute_wallet_command(activate_cmd)
            
            if not activate_result:
                print(f"\n\033[91m✗ Failed to add {amount_to_add:,.0f} DUSK\033[0m\n")
                return False
            
            print(f"\n\033[92m✓ Added {amount_to_add:,.0f} DUSK to index {inactive['idx']}\033[0m")
            print(f"\033[92m  New total: {large_stake:,.0f} DUSK\033[0m\n")
            
            # ROTATION COMPLETE
            print(f"\n\033[1m\033[92m{'═' * 70}\033[0m")
            print(f"\033[1m\033[92m✓ ROTATION COMPLETE!\033[0m")
            print(f"\033[1m\033[92m{'═' * 70}\033[0m\n")
            
            print(f"\033[92mFinal stake distribution:\033[0m")
            print(f"\033[92m  Index {active['idx']} ({active['prov_id']}): {small_stake:,.0f} DUSK\033[0m")
            print(f"\033[92m  Index {inactive['idx']} ({inactive['prov_id']}): {large_stake:,.0f} DUSK\033[0m")
            print(f"\033[92m  Total staked: {small_stake + large_stake:,.0f} DUSK (Limit: {stake_limit:,.0f})\033[0m\n")
            
            return True
            
        except Exception as e:
            print(f"\033[91m✗ Rotation error: {str(e)}\033[0m\n")
            import traceback
            traceback.print_exc()
            return False
        """Execute full rotation sequence
        1. Liquidate & terminate active provisioner
        2. Allocate 1000 DUSK back to that provisioner  
        3. Allocate max DUSK to inactive provisioner
        Returns True if successful, False otherwise
        """
        try:
            stake_limit = self.config.get('stake_limit', 1000000)
            
            print(f"\n\033[1m\033[93m{'═' * 70}\033[0m")
            print(f"\033[1m\033[93m🔄  EXECUTING STAKE ROTATION\033[0m")
            print(f"\033[1m\033[93m{'═' * 70}\033[0m\n")
            
            print(f"\033[96mCurrent active: Index {active['idx']} ({active['prov_id']})\033[0m")
            print(f"\033[96mCurrent stake: {active['amount']:,.0f} DUSK\033[0m\n")
            
            print(f"\033[96mWill activate: Index {inactive['idx']} ({inactive['prov_id']})\033[0m\n")
            
            # PHASE 1: Liquidate and terminate active provisioner
            print(f"\033[1m\033[96m{'─' * 70}\033[0m")
            print(f"\033[1m\033[96mPHASE 1: Liquidate & Terminate Active Provisioner\033[0m")
            print(f"\033[1m\033[96m{'─' * 70}\033[0m\n")
            
            if not self._automated_liquidate_and_terminate(active, log_files):
                print(f"\033[91m✗ Rotation failed during liquidate & terminate phase\033[0m\n")
                return False
            
            # Check available stake after liquidation
            print(f"\033[1m\033[96m{'─' * 70}\033[0m")
            print(f"\033[1m\033[96mCHECKING AVAILABLE STAKE\033[0m")
            print(f"\033[1m\033[96m{'─' * 70}\033[0m\n")
            
            available_stake = self._check_available_stake()
            if available_stake is None:
                print(f"\033[91m✗ Could not check available stake\033[0m\n")
                return False
            
            print(f"\033[92mAvailable stake: {available_stake:,.2f} DUSK\033[0m\n")
            
            # PHASE 2: Allocate 1000 DUSK back to the just-liquidated provisioner
            print(f"\033[1m\033[96m{'─' * 70}\033[0m")
            print(f"\033[1m\033[96mPHASE 2: Allocate 1000 DUSK to Index {active['idx']}\033[0m")
            print(f"\033[1m\033[96m{'─' * 70}\033[0m\n")
            
            # Get provisioner secret key
            stored_keys = self._decrypt_keys(self.encryption_password)
            if not stored_keys:
                print(f"\033[91m✗ Could not load provisioner keys\033[0m\n")
                return False
            
            small_stake_amount = 1000  # DUSK
            small_stake_lux = int(small_stake_amount * 1_000_000_000)
            
            provisioner_sk_old = stored_keys[active['prov_id']]['secret_key']
            
            print(f"\033[94mCalculating stake payload for {small_stake_amount:,.0f} DUSK...\033[0m\n")
            payload_cmd = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet calculate-payload-stake-activate \
  --provisioner-sk {provisioner_sk_old} \
  --amount {small_stake_lux} \
  --network-id {self.config['network_id']}"""
            
            payload_result, payload_output = self.execute_wallet_command(payload_cmd)
            
            if not payload_result:
                print(f"\n\033[91m✗ Failed to calculate payload\033[0m\n")
                return False
            
            # Extract payload
            payload_match = re.search(r'"([0-9a-fA-F]+)"', payload_output)
            if not payload_match:
                lines = [line.strip() for line in payload_output.split('\n') if line.strip()]
                if lines:
                    payload = lines[-1].strip().strip('"')
                else:
                    print(f"\n\033[91m✗ Could not extract payload\033[0m\n")
                    return False
            else:
                payload = payload_match.group(1)
            
            print(f"\033[92m✓ Payload generated\033[0m\n")
            
            print(f"\033[94mExecuting stake activation...\033[0m\n")
            activate_cmd = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet contract-call \
  --contract-id {self.config['contract_address']} \
  --fn-name stake_activate \
  --fn-args "{payload}" \
  --gas-limit {self.config['gas_limit']}"""
            
            activate_result, _ = self.execute_wallet_command(activate_cmd)
            
            if not activate_result:
                print(f"\n\033[91m✗ Failed to allocate {small_stake_amount:,.0f} DUSK\033[0m\n")
                return False
            
            print(f"\n\033[92m✓ Allocated {small_stake_amount:,.0f} DUSK to index {active['idx']}\033[0m\n")
            
            # Update available stake
            available_stake -= small_stake_amount
            
            # PHASE 3: Allocate max DUSK to the previously inactive provisioner
            print(f"\033[1m\033[96m{'─' * 70}\033[0m")
            print(f"\033[1m\033[96mPHASE 3: Allocate Maximum DUSK to Index {inactive['idx']}\033[0m")
            print(f"\033[1m\033[96m{'─' * 70}\033[0m\n")
            
            # Calculate how much to allocate (up to stake limit)
            amount_to_allocate = min(stake_limit - 1, available_stake)
            
            if amount_to_allocate < 1:
                print(f"\033[91m✗ No stake available to allocate\033[0m\n")
                return False
            
            amount_to_allocate_lux = int(amount_to_allocate * 1_000_000_000)
            
            provisioner_sk_new = stored_keys[inactive['prov_id']]['secret_key']
            
            print(f"\033[94mCalculating stake payload for {amount_to_allocate:,.0f} DUSK...\033[0m\n")
            payload_cmd = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet calculate-payload-stake-activate \
  --provisioner-sk {provisioner_sk_new} \
  --amount {amount_to_allocate_lux} \
  --network-id {self.config['network_id']}"""
            
            payload_result, payload_output = self.execute_wallet_command(payload_cmd)
            
            if not payload_result:
                print(f"\n\033[91m✗ Failed to calculate payload\033[0m\n")
                return False
            
            # Extract payload
            payload_match = re.search(r'"([0-9a-fA-F]+)"', payload_output)
            if not payload_match:
                lines = [line.strip() for line in payload_output.split('\n') if line.strip()]
                if lines:
                    payload = lines[-1].strip().strip('"')
                else:
                    print(f"\n\033[91m✗ Could not extract payload\033[0m\n")
                    return False
            else:
                payload = payload_match.group(1)
            
            print(f"\033[92m✓ Payload generated\033[0m\n")
            
            print(f"\033[94mExecuting stake activation...\033[0m\n")
            activate_cmd = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet contract-call \
  --contract-id {self.config['contract_address']} \
  --fn-name stake_activate \
  --fn-args "{payload}" \
  --gas-limit {self.config['gas_limit']}"""
            
            activate_result, _ = self.execute_wallet_command(activate_cmd)
            
            if not activate_result:
                print(f"\n\033[91m✗ Failed to allocate {amount_to_allocate:,.0f} DUSK\033[0m\n")
                return False
            
            print(f"\n\033[92m✓ Allocated {amount_to_allocate:,.0f} DUSK to index {inactive['idx']}\033[0m\n")
            
            # ROTATION COMPLETE
            print(f"\n\033[1m\033[92m{'═' * 70}\033[0m")
            print(f"\033[1m\033[92m✓ ROTATION COMPLETE!\033[0m")
            print(f"\033[1m\033[92m{'═' * 70}\033[0m\n")
            
            print(f"\033[92mNew stake distribution:\033[0m")
            print(f"\033[92m  Index {active['idx']} ({active['prov_id']}): {small_stake_amount:,.0f} DUSK\033[0m")
            print(f"\033[92m  Index {inactive['idx']} ({inactive['prov_id']}): {amount_to_allocate:,.0f} DUSK\033[0m\n")
            
            return True
            
        except Exception as e:
            print(f"\033[91m✗ Rotation error: {str(e)}\033[0m\n")
            import traceback
            traceback.print_exc()
            return False
    
    def monitor_epoch_transitions(self):
        """Option 12: Monitor Epoch Transitions (Automated)"""
        # Temporarily exit curses mode
        curses.endwin()
        
        # Define constants first
        EPOCH_BLOCKS = 2160
        TRIGGER_BLOCKS_BEFORE = self.config.get('rotation_trigger_blocks', 50)  # Configurable
        CHECK_BLOCKS_BEFORE = 100  # When to check active provisioner
        CHECK_INTERVAL = 10  # seconds
        TOPUP_CHECK_INTERVAL = 100  # Check for top-up every 100 blocks
        
        print(f"\n\033[94m{'=' * 70}\033[0m")
        print(f"\033[1m\033[96mMONITOR EPOCH TRANSITIONS\033[0m")
        print(f"\033[94m{'=' * 70}\033[0m\n")
        print(f"\033[93mMonitoring epochs every 10 seconds...\033[0m")
        print(f"\033[93mPress 'q' + Enter or Ctrl+C to stop\033[0m")
        print(f"\033[90mRotating between: Instance 1 (idx 0) ↔ Instance 2 (idx 1)\033[0m")
        print(f"\033[90mFallback only: Instance 3 (idx 2)\033[0m")
        print(f"\033[90mRotation trigger: {TRIGGER_BLOCKS_BEFORE} blocks before epoch end\033[0m")
        print(f"\033[90mTop-up check: Every 100 blocks\033[0m\n")
        
        log_files = [
            '/var/log/rusk-1.log',
            '/var/log/rusk-2.log',
            '/var/log/rusk-3.log'
        ]
        
        triggered_epoch = None  # Track which epoch we've already triggered for
        checked_epoch = None  # Track which epoch we've checked stake for
        last_topup_check_height = 0  # Track last height where we checked for top-up
        
        # DEBUG: Check stake detection at startup - EXACT same code as check_stake_info
        print(f"\033[1m\033[93m{'─' * 70}\033[0m")
        print(f"\033[1m\033[93mDEBUG: Initial Stake Check\033[0m")
        print(f"\033[1m\033[93m{'─' * 70}\033[0m\n")
        
        print(f"[DEBUG] Checking encryption password...")
        # Use stored encryption password from session
        if not self.encryption_password:
            print(f"\033[91m✗ Encryption password not available.\033[0m\n")
        else:
            print(f"[DEBUG] Encryption password OK, loading keys...")
            # Load stored provisioners to get their indices
            stored_keys = self._decrypt_keys(self.encryption_password)
            
            if stored_keys is None:
                print(f"\033[91m✗ Could not load stored keys (None returned).\033[0m\n")
            elif not stored_keys:
                print(f"\033[93m⚠ No provisioners stored yet (empty dict).\033[0m\n")
            else:
                print(f"[DEBUG] Loaded {len(stored_keys)} keys, sorting...")
                # Sort provisioners by index
                sorted_provisioners = sorted(stored_keys.items(), key=lambda x: int(x[1].get('index', 0)))
                
                print(f"[DEBUG] Starting provisioner queries...\n")
                # Query each provisioner (only idx 0 and 1)
                for prov_id, data in sorted_provisioners:
                    idx = int(data['index'])  # Convert to int!
                    if idx not in [0, 1]:
                        print(f"[DEBUG] Skipping idx {idx} (not 0 or 1)")
                        continue
                    
                    address = data.get('address', 'N/A')
                    
                    print(f"\033[1m\033[96m{'─' * 70}\033[0m")
                    print(f"\033[96mProvisioner Index {idx}\033[0m")
                    print(f"\033[90m  {prov_id}\033[0m")
                    print(f"\033[90m  Address: {address[:50]}...\033[0m")
                    print(f"\033[1m\033[96m{'─' * 70}\033[0m\n")
                    
                    # Build the command - EXACT same as check_stake_info
                    stake_info_command = f"sozu-beta3-rusk-wallet -w ~/sozu_provisioner -n testnet stake-info --profile-idx {idx}"
                    
                    print(f"\033[92mQuerying stake info (using stored password)...\033[0m\n")
                    
                    # Execute command - EXACT same as check_stake_info
                    success, output = self.execute_wallet_command(stake_info_command)
                    
                    print()
                    
                    if success:
                        if "Eligible stake:" in output:
                            match = re.search(r'Eligible stake:\s*(\d+(?:\.\d+)?)\s*DUSK', output)
                            if match:
                                print(f"  \033[92m✓ Stake info retrieved for index {idx}\033[0m")
                                print(f"  \033[92m✓ HAS STAKE: {match.group(1)} DUSK\033[0m\n")
                            else:
                                print(f"  \033[93m? Found 'Eligible stake:' but couldn't parse amount\033[0m\n")
                        elif "A stake does not exist" in output:
                            print(f"  \033[92m✓ Stake info retrieved for index {idx}\033[0m")
                            print(f"  \033[90m✗ No stake\033[0m\n")
                        else:
                            print(f"  \033[93m? Unknown output format\033[0m\n")
                    else:
                        print(f"  \033[91m✗ Failed to retrieve stake info for index {idx}\033[0m\n")
        
        print(f"\033[1m\033[93m{'─' * 70}\033[0m\n")
        
        # PAUSE so user can see debug output
        input("\033[96mPress Enter to start monitoring...\033[0m")
        print()
        
        try:
            while True:
                # Check if user wants to quit
                import select
                if select.select([sys.stdin], [], [], 0.0)[0]:
                    user_input = sys.stdin.readline().strip().lower()
                    if user_input == 'q':
                        print(f"\n\033[93mStopping monitoring...\033[0m")
                        break
                
                # Get heights from all instances
                heights = []
                for log_file in log_files:
                    height = self._get_block_height_from_log(log_file)
                    if height:
                        heights.append((log_file, height))
                
                if not heights:
                    print(f"\033[91m[{time.strftime('%H:%M:%S')}] ✗ No heights available from any instance\033[0m")
                    time.sleep(CHECK_INTERVAL)
                    continue
                
                # Use highest height
                highest = max(heights, key=lambda x: x[1])
                current_height = highest[1]
                
                # Calculate epoch information
                current_epoch = ((current_height - 1) // EPOCH_BLOCKS) + 1
                epoch_start = (current_epoch - 1) * EPOCH_BLOCKS + 1
                epoch_end = current_epoch * EPOCH_BLOCKS
                blocks_in_epoch = current_height - epoch_start + 1
                blocks_until_end = epoch_end - current_height
                trigger_point = epoch_end - TRIGGER_BLOCKS_BEFORE
                
                # Check sync status
                all_heights = [h[1] for h in heights]
                max_height = max(all_heights)
                min_height = min(all_heights)
                height_diff = max_height - min_height
                
                # Display status
                timestamp = time.strftime('%H:%M:%S')
                print(f"\033[96m[{timestamp}]\033[0m ", end='')
                print(f"Height: \033[92m{current_height}\033[0m | ", end='')
                print(f"Epoch: \033[96m{current_epoch}\033[0m | ", end='')
                print(f"Block {blocks_in_epoch}/{EPOCH_BLOCKS} | ", end='')
                print(f"Until end: \033[93m{blocks_until_end}\033[0m", end='')
                
                # Sync status
                if len(heights) < 3:
                    print(f" | \033[91m⚠ Only {len(heights)}/3 instances\033[0m", end='')
                elif height_diff > 5:
                    print(f" | \033[91m⚠ Sync diff: {height_diff} blocks!\033[0m", end='')
                elif height_diff > 0:
                    print(f" | \033[93m⚠ Sync diff: {height_diff}\033[0m", end='')
                else:
                    print(f" | \033[92m✓ In sync\033[0m", end='')
                
                print()  # Newline
                
                # Calculate trigger and check points
                trigger_point = epoch_end - TRIGGER_BLOCKS_BEFORE
                check_point = epoch_end - CHECK_BLOCKS_BEFORE
                
                # Top-up check: Every 100 blocks, check if we can add more stake to active provisioner
                # This runs throughout the epoch, not just near the end
                if current_height - last_topup_check_height >= TOPUP_CHECK_INTERVAL:
                    active = self._get_active_provisioner()
                    
                    if active:
                        stake_limit = self.config.get('stake_limit', 1000000)
                        current_stake = active['amount']
                        
                        # Check if there's room to add more
                        if current_stake < stake_limit - 1:
                            available_stake = self._check_available_stake()
                            
                            if available_stake and available_stake > 0:
                                # Attempt top-up
                                self._topup_active_provisioner(active, available_stake)
                    
                    # Update last check height
                    last_topup_check_height = current_height
                
                # 100-block checkpoint: Check active provisioner and plan rotation
                if current_height >= check_point and checked_epoch != current_epoch and blocks_until_end <= CHECK_BLOCKS_BEFORE:
                    print(f"\n\033[1m\033[93m{'─' * 70}\033[0m")
                    print(f"\033[1m\033[93m⚙  100-BLOCK CHECKPOINT (Block {current_height}/{epoch_end})\033[0m")
                    print(f"\033[1m\033[93m⚙  Checking active provisioner for rotation planning...\033[0m")
                    print(f"\033[1m\033[93m{'─' * 70}\033[0m\n")
                    
                    # Find active provisioner
                    print(f"\033[96m[1/4] Checking which provisioner currently has stake...\033[0m")
                    active = self._get_active_provisioner()
                    
                    if active:
                        print(f"\033[92m✓ Found active provisioner:\033[0m")
                        print(f"  Index: {active['idx']}")
                        print(f"  ID: {active['prov_id']}")
                        print(f"  Address: {active['address'][:60]}...")
                        print(f"  Stake: {active['amount']:,.0f} DUSK\n")
                        
                        # Check available stake
                        print(f"\033[96m[2/4] Checking available stake in contract...\033[0m")
                        available_stake = self._check_available_stake()
                        
                        if available_stake:
                            print(f"\033[92m✓ Available stake: {available_stake:,.2f} DUSK\033[0m\n")
                            
                            # Get inactive provisioners
                            print(f"\033[96m[3/4] Finding inactive provisioners...\033[0m")
                            inactive = self._get_inactive_provisioners(active['idx'])
                            
                            if inactive:
                                print(f"\033[92m✓ Found {len(inactive)} inactive provisioner(s)\033[0m\n")
                                
                                # Calculate stake to allocate
                                stake_limit = self.config.get('stake_limit', 1000000)
                                # After liquidation, available will increase by active amount
                                future_available = available_stake + active['amount']
                                stake_to_allocate = min(stake_limit - 1, future_available)
                                
                                print(f"\033[96m[4/4] Planning rotation (DRY RUN)...\033[0m\n")
                                
                                # Calculate amounts for the plan
                                small_stake = 1000  # DUSK to put back
                                large_stake = stake_limit - 1001  # Large stake (998999 for 1m limit)
                                
                                print(f"\033[1m\033[95m{'═' * 70}\033[0m")
                                print(f"\033[1m\033[95mROTATION PLAN (DRY RUN - NOT EXECUTING)\033[0m")
                                print(f"\033[1m\033[95m{'═' * 70}\033[0m")
                                
                                print(f"\n\033[93m📋 STEP 1: LIQUIDATE & TERMINATE\033[0m")
                                print(f"  \033[90mWould execute: _automated_liquidate_and_terminate()\033[0m")
                                print(f"  Target: Provisioner index {active['idx']} ({active['prov_id']})")
                                print(f"  Address: {active['address'][:60]}...")
                                print(f"  This will release: {active['amount']:,.0f} DUSK")
                                print(f"  \033[90mNo wait - liquidate then terminate immediately\033[0m")
                                
                                print(f"\n\033[93m📋 STEP 2: CHECK AVAILABLE STAKE\033[0m")
                                print(f"  Current available: {available_stake:,.2f} DUSK")
                                print(f"  After liquidation: {future_available:,.2f} DUSK")
                                
                                print(f"\n\033[93m📋 STEP 3: ALLOCATE 1,000 DUSK BACK\033[0m")
                                print(f"  \033[90mWould execute: allocate_stake()\033[0m")
                                print(f"  Target: Provisioner index {active['idx']} ({active['prov_id']}) ← Just liquidated")
                                print(f"  Address: {active['address'][:60]}...")
                                print(f"  Amount to allocate: {small_stake:,.0f} DUSK")
                                print(f"  Purpose: Keep provisioner ready for next rotation")
                                
                                # Calculate what to add to inactive
                                current_inactive_stake = inactive[0].get('amount', 0)
                                amount_to_add_to_inactive = large_stake - current_inactive_stake
                                
                                print(f"\n\033[93m📋 STEP 4: TOP-UP INACTIVE TO {large_stake:,.0f} DUSK\033[0m")
                                print(f"  \033[90mWould execute: top-up (stake_activate)\033[0m")
                                print(f"  Target: Provisioner index {inactive[0]['idx']} ({inactive[0]['prov_id']})")
                                print(f"  Address: {inactive[0]['address'][:60]}...")
                                print(f"  Current stake: {current_inactive_stake:,.0f} DUSK")
                                print(f"  Target stake: {large_stake:,.0f} DUSK")
                                print(f"  Amount to ADD: {amount_to_add_to_inactive:,.0f} DUSK")
                                print(f"  \033[90mNote: Inactive provisioner is NOT liquidated, only topped up\033[0m")
                                print(f"  Calculation: target - current = {large_stake:,.0f} - {current_inactive_stake:,.0f} = {amount_to_add_to_inactive:,.0f}")
                                
                                print(f"\n\033[1m\033[93m📊 FINAL DISTRIBUTION AFTER ROTATION:\033[0m")
                                print(f"  Provisioner index {active['idx']}: {small_stake:,.0f} DUSK")
                                print(f"  Provisioner index {inactive[0]['idx']}: {large_stake:,.0f} DUSK ← New active")
                                print(f"  Total staked: {small_stake + large_stake:,.0f} DUSK (under limit: {stake_limit:,.0f})")

                                
                                print(f"\n\033[1m\033[95m{'═' * 70}\033[0m")
                                print(f"\033[1m\033[92m✓ Rotation plan ready - will execute at {TRIGGER_BLOCKS_BEFORE}-block trigger\033[0m")
                                print(f"\033[1m\033[95m{'═' * 70}\033[0m\n")
                            else:
                                print(f"\033[91m✗ No inactive provisioners found\033[0m\n")
                        else:
                            print(f"\033[91m✗ Could not check available stake\033[0m\n")
                    else:
                        print(f"\033[93m⚠ No active provisioner found (no stake allocated)\033[0m\n")
                    
                    # Mark this epoch as checked
                    checked_epoch = current_epoch
                
                # Rotation trigger: Execute rotation
                if current_height >= trigger_point and triggered_epoch != current_epoch:
                    print(f"\n\033[1m\033[91m{'!' * 70}\033[0m")
                    print(f"\033[1m\033[91m⚠  EPOCH END APPROACHING! (Block {current_height}/{epoch_end})\033[0m")
                    print(f"\033[1m\033[91m⚠  {blocks_until_end} blocks until epoch {current_epoch} ends!\033[0m")
                    print(f"\033[1m\033[91m{'!' * 70}\033[0m\n")
                    
                    print(f"\033[1m\033[93m>>> EXECUTING ROTATION NOW <<<\033[0m\n")
                    
                    # Get current active and inactive provisioners
                    active = self._get_active_provisioner()
                    if not active:
                        print(f"\033[91m✗ Cannot execute rotation: No active provisioner found\033[0m\n")
                        triggered_epoch = current_epoch
                        continue
                    
                    inactive_list = self._get_inactive_provisioners(active['idx'])
                    if not inactive_list:
                        print(f"\033[91m✗ Cannot execute rotation: No inactive provisioner found\033[0m\n")
                        triggered_epoch = current_epoch
                        continue
                    
                    inactive = inactive_list[0]  # Take first inactive
                    
                    # Execute the rotation
                    rotation_success = self._execute_rotation(active, inactive)
                    
                    if rotation_success:
                        print(f"\n\033[1m\033[92m{'═' * 70}\033[0m")
                        print(f"\033[1m\033[92m✓ ROTATION EXECUTED SUCCESSFULLY FOR EPOCH {current_epoch}!\033[0m")
                        print(f"\033[1m\033[92m{'═' * 70}\033[0m\n")
                    else:
                        print(f"\n\033[1m\033[91m{'═' * 70}\033[0m")
                        print(f"\033[1m\033[91m✗ ROTATION FAILED FOR EPOCH {current_epoch}\033[0m")
                        print(f"\033[1m\033[91m{'═' * 70}\033[0m\n")
                    
                    # Mark this epoch as triggered
                    triggered_epoch = current_epoch
                
                # Wait before next check
                time.sleep(CHECK_INTERVAL)
        
        except KeyboardInterrupt:
            print(f"\n\n\033[93mMonitoring stopped by user (Ctrl+C)\033[0m")
        except Exception as e:
            print(f"\n\033[91m✗ Unexpected error: {str(e)}\033[0m")
            import traceback
            traceback.print_exc()
        
        input("\nPress Enter to continue...")
        self._reinit_curses()
    
    def show_configuration(self):
        """Option 8: Configuration"""
        config_menu_items = [
            "Edit Network ID",
            "Edit Contract Address",
            "Edit Gas Limit",
            "Edit Operator Address",
            "Edit Stake Limit",
            "Edit Rotation Trigger Blocks",
            "Set/Update Wallet Password",
            "Reset to Defaults",
            "Return to Main Menu"
        ]
        
        selected_idx = 0
        
        while True:
            self.stdscr.clear()
            height, width = self.stdscr.getmaxyx()
            
            # Title
            title = "CONFIGURATION"
            self.stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
            self.stdscr.addstr(1, (width - len(title)) // 2, title)
            self.stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
            
            # Current configuration display
            y_pos = 3
            wallet_password_status = "✓ Set" if self.config.get('wallet_password_encrypted') else "✗ Not set"
            config_color = 2 if self.config.get('wallet_password_encrypted') else 5
            
            self.stdscr.attron(curses.color_pair(2))
            self.stdscr.addstr(y_pos, 2, "Current Configuration:")
            self.stdscr.attroff(curses.color_pair(2))
            y_pos += 1
            
            self.stdscr.addstr(y_pos, 2, f"Network ID:         {self.config['network_id']}")
            y_pos += 1
            self.stdscr.addstr(y_pos, 2, f"Contract Address:   {self.config['contract_address'][:50]}...")
            y_pos += 1
            self.stdscr.addstr(y_pos, 2, f"Gas Limit:          {self.config['gas_limit']:,} LUX")
            y_pos += 1
            operator_addr = self.config['operator_address'] if self.config['operator_address'] else '(not set)'
            self.stdscr.addstr(y_pos, 2, f"Operator Address:   {operator_addr[:50]}")
            y_pos += 1
            self.stdscr.addstr(y_pos, 2, f"Stake Limit:        {self.config.get('stake_limit', 1000000):,} DUSK")
            y_pos += 1
            self.stdscr.addstr(y_pos, 2, f"Rotation Trigger:   {self.config.get('rotation_trigger_blocks', 50)} blocks")
            y_pos += 1
            self.stdscr.attron(curses.color_pair(config_color))
            self.stdscr.addstr(y_pos, 2, f"Wallet Password:    {wallet_password_status}")
            self.stdscr.attroff(curses.color_pair(config_color))
            y_pos += 2
            
            # Menu items
            self.stdscr.attron(curses.color_pair(2))
            self.stdscr.addstr(y_pos, 2, "Use ↑/↓ to navigate, Enter to select:")
            self.stdscr.attroff(curses.color_pair(2))
            y_pos += 2
            
            for idx, item in enumerate(config_menu_items):
                if idx == selected_idx:
                    self.stdscr.attron(curses.color_pair(1) | curses.A_REVERSE)
                    self.stdscr.addstr(y_pos + idx, 4, f"→ {item}")
                    self.stdscr.attroff(curses.color_pair(1) | curses.A_REVERSE)
                else:
                    self.stdscr.addstr(y_pos + idx, 4, f"  {item}")
            
            self.stdscr.refresh()
            
            # Handle input
            key = self.stdscr.getch()
            
            if key == curses.KEY_UP:
                selected_idx = (selected_idx - 1) % len(config_menu_items)
            elif key == curses.KEY_DOWN:
                selected_idx = (selected_idx + 1) % len(config_menu_items)
            elif key in [curses.KEY_ENTER, ord('\n'), ord('\r')]:
                if selected_idx == 8:  # Return to Main Menu
                    break
                else:
                    self._handle_config_option(selected_idx + 1)
    
    def _handle_config_option(self, option: int):
        """Handle configuration menu option"""
        # Temporarily exit curses mode
        curses.endwin()
        
        if option == 1:  # Edit Network ID
            new_value = input(f"\n\033[96mEnter new Network ID (current: {self.config['network_id']}): \033[0m").strip()
            try:
                self.config['network_id'] = int(new_value)
                self._save_config()
                print(f"\033[92m✓ Network ID updated to {self.config['network_id']}\033[0m")
            except ValueError:
                print(f"\033[91m✗ Invalid value. Must be a number.\033[0m")
            input("\nPress Enter to continue...")
        
        elif option == 2:  # Edit Contract Address
            new_value = input(f"\n\033[96mEnter new Contract Address:\033[0m\n").strip()
            if new_value:
                self.config['contract_address'] = new_value
                self._save_config()
                print(f"\033[92m✓ Contract Address updated\033[0m")
            else:
                print(f"\033[91m✗ Contract Address cannot be empty\033[0m")
            input("\nPress Enter to continue...")
        
        elif option == 3:  # Edit Gas Limit
            new_value = input(f"\n\033[96mEnter new Gas Limit in LUX (current: {self.config['gas_limit']:,}): \033[0m").strip()
            try:
                gas_limit = int(new_value)
                if gas_limit <= 0:
                    print(f"\033[91m✗ Gas limit must be greater than 0\033[0m")
                else:
                    self.config['gas_limit'] = gas_limit
                    self._save_config()
                    print(f"\033[92m✓ Gas Limit updated to {self.config['gas_limit']:,} LUX\033[0m")
            except ValueError:
                print(f"\033[91m✗ Invalid value. Must be a number.\033[0m")
            input("\nPress Enter to continue...")
        
        elif option == 4:  # Edit Operator Address
            current = self.config['operator_address'] if self.config['operator_address'] else '(not set)'
            new_value = input(f"\n\033[96mEnter Operator Address (current: {current}):\033[0m\n").strip()
            if new_value:
                self.config['operator_address'] = new_value
                self._save_config()
                print(f"\033[92m✓ Operator Address updated\033[0m")
            else:
                print(f"\033[93mOperator Address not changed\033[0m")
            input("\nPress Enter to continue...")
        
        elif option == 5:  # Edit Stake Limit
            new_value = input(f"\n\033[96mEnter new Stake Limit in DUSK (current: {self.config.get('stake_limit', 1000000):,}): \033[0m").strip()
            try:
                stake_limit = int(new_value)
                if stake_limit <= 0:
                    print(f"\033[91m✗ Stake limit must be greater than 0\033[0m")
                else:
                    self.config['stake_limit'] = stake_limit
                    self._save_config()
                    print(f"\033[92m✓ Stake Limit updated to {self.config['stake_limit']:,} DUSK\033[0m")
            except ValueError:
                print(f"\033[91m✗ Invalid value. Must be a number.\033[0m")
            input("\nPress Enter to continue...")
        
        elif option == 6:  # Edit Rotation Trigger Blocks
            new_value = input(f"\n\033[96mEnter Rotation Trigger (blocks before epoch end, current: {self.config.get('rotation_trigger_blocks', 50)}): \033[0m").strip()
            try:
                trigger_blocks = int(new_value)
                if trigger_blocks <= 0 or trigger_blocks >= 2160:
                    print(f"\033[91m✗ Rotation trigger must be between 1 and 2159 blocks\033[0m")
                else:
                    self.config['rotation_trigger_blocks'] = trigger_blocks
                    self._save_config()
                    print(f"\033[92m✓ Rotation Trigger updated to {self.config['rotation_trigger_blocks']} blocks\033[0m")
            except ValueError:
                print(f"\033[91m✗ Invalid value. Must be a number.\033[0m")
            input("\nPress Enter to continue...")
        
        elif option == 7:  # Set/Update Wallet Password
            print(f"\n\033[1m\033[96mSet/Update Wallet Password\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            print(f"\033[93mThis password will be encrypted and stored in config.\033[0m")
            print(f"\033[93mYou will be prompted for the encryption password at startup.\033[0m")
            print(f"\033[93mOnce decrypted, all wallet operations will be automated.\033[0m\n")
            
            wallet_password = getpass.getpass("Enter wallet password: ")
            confirm_password = getpass.getpass("Confirm wallet password: ")
            
            if wallet_password != confirm_password:
                print(f"\033[91m✗ Passwords do not match\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            encryption_password = getpass.getpass("\nEnter encryption password (to encrypt wallet password): ")
            confirm_encryption = getpass.getpass("Confirm encryption password: ")
            
            if encryption_password != confirm_encryption:
                print(f"\033[91m✗ Encryption passwords do not match\033[0m")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            try:
                # Encrypt the wallet password
                key = self._get_encryption_key(encryption_password)
                fernet = Fernet(key)
                encrypted_password = fernet.encrypt(wallet_password.encode())
                
                # Store as base64 string in config
                self.config['wallet_password_encrypted'] = base64.b64encode(encrypted_password).decode()
                self._save_config()
                
                # Update runtime password
                self.wallet_password_decrypted = wallet_password
                
                print(f"\n\033[92m{'=' * 70}\033[0m")
                print(f"\033[92m✓ Wallet password encrypted and saved successfully!\033[0m")
                print(f"\033[92m✓ All future wallet operations will be automated.\033[0m")
                print(f"\033[92m{'=' * 70}\033[0m")
            except Exception as e:
                print(f"\033[91m✗ Failed to encrypt password: {str(e)}\033[0m")
            input("\nPress Enter to continue...")
        
        elif option == 8:  # Reset to Defaults
            confirm = input(f"\n\033[93mReset to default testnet values? (yes/no): \033[0m").strip().lower()
            if confirm in ['yes', 'y']:
                self.config['network_id'] = 2
                self.config['contract_address'] = "72883945ac1aa032a88543aacc9e358d1dfef07717094c05296ce675f23078f2"
                self.config['gas_limit'] = 2000000
                self.config['operator_address'] = ""
                self.config['stake_limit'] = 1000000
                self.config['rotation_trigger_blocks'] = 50
                # Don't reset wallet password
                self._save_config()
                print(f"\033[92m✓ Configuration reset to defaults (wallet password preserved)\033[0m")
            else:
                print(f"\033[93mReset cancelled\033[0m")
            input("\nPress Enter to continue...")
        
        # Reinitialize curses
        self._reinit_curses()


def main(stdscr):
    """Entry point for the curses application"""
    # Enable keypad mode
    stdscr.keypad(True)
    
    # Create and run the manager
    manager = ProvisionerManager(stdscr)
    manager.show_menu()
    
    # Exit message
    stdscr.clear()
    height, width = stdscr.getmaxyx()
    msg = "Thank you for using Provisioner Manager!"
    stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
    stdscr.addstr(height // 2, (width - len(msg)) // 2, msg)
    stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)
    stdscr.refresh()
    stdscr.getch()


if __name__ == "__main__":
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        print("\n\nApplication terminated by user.\n")
        sys.exit(0)
    except Exception as e:
        print(f"\nFatal error: {str(e)}\n")
        sys.exit(1)
