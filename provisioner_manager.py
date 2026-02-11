#!/usr/bin/env python3
"""
Provisioner Management CLI Tool - Version 2.1.0
A command-line interface for managing provisioners with arrow key navigation.

Version: 2.1.0
Release Date: 2026-02-11
Author: Dusk Network Infrastructure Team

New in v2.1.0:
- FEATURE: Telegram configuration menu in Configuration section
  - Enable/disable from within the script
  - Set bot token and chat ID
  - Test Telegram with built-in test message
  - Configure which notification types to receive
  - Complete setup guide in menu
- FEATURE: Debug output for all Telegram send attempts
  - Shows every send attempt with [TELEGRAM] prefix
  - Success includes message ID
  - Failures show exact HTTP error and response
  - Network issues clearly identified
- IMPROVEMENT: No need to manually edit config.json for Telegram
- IMPROVEMENT: Can test Telegram without restarting script

New in v2.0.0:
- MAJOR CHANGE: 2-node active rotation system (idx 0 ↔ idx 1 only)
- Node 3 (idx 2) is pure standby - stays at 0 DUSK unless emergency
- Max stake per node increased to 999K (from 998K)
- Emergency failover: automatically activates idx 2 if idx 0 or 1 fails
- Telegram alerts for emergency scenarios requiring manual intervention
- Simplified rotation logic - cleaner and more predictable
- Node 3 stays synced and ready to step in instantly

ROTATION PATTERN:
Normal operation ping-pongs between idx 0 and idx 1:
  Before: idx 0 maturing (1K), idx 1 active (998K), idx 2 inactive (0)
  Window: idx 0 maturing (999K), idx 1 active (1K), idx 2 inactive (0)
  After:  idx 0 active (999K), idx 1 maturing (1K), idx 2 inactive (0)

Emergency: If idx 0 or 1 crashes and can't restart:
  - Liquidate/deactivate failed node
  - Top up remaining node to 999K
  - Allocate 1K to idx 2 (standby activation)
  - Send Telegram alert for manual intervention

New in v1.8.0:
- FIX: Recovery mode no longer triggers during normal bootstrap
- FIX: Rotation crash when no active node (externally killed mid-epoch)
- FIX: Active nodes now topped up after restart (accepts 10% penalty)
- FEATURE: Slashed stake limit enforced (2% of stake_limit max)
- FIX: Per-node maximum enforced in all execution functions
- FIX: Bootstrap now uses dynamic calculation instead of hardcoded values
- IMPROVEMENT: Status labels - "initial stake" (0 trans) vs "maturing" (1 trans)
- FIX: Removed -1 safety buffers - exact capacity now shown (1000 instead of 999)
- FIX: Allocation skips nodes in "initial stake" - only allocates to empty nodes
- FIX: UnboundLocalError crash when all inactive nodes have stake
- FIX: CRITICAL - Epoch calculation off by 1 (blocks 0-2159 are Epoch 0)
- FIX: CRITICAL - Auto-recovery for 2 active nodes (script crash during rotation)
- FIX: CRITICAL - Slashed stake now counted in capacity calculations
- FIX: CRITICAL - Two-active-nodes check now runs before bootstrap check
- FIX: CRITICAL - Nodes with 0 DUSK now included in inactive categorization
- FEATURE: Transition logger - logs 100 blocks before/after each epoch transition

New in v1.7.8:
- MAJOR CHANGE: 3-node pipeline system (indices 0, 1, 2 all used)
- CRITICAL: Never allow both provisioners active in same epoch
- IMPROVEMENT: JSON updated every rotation check (real-time state awareness)
- FEATURE: Bootstrap logic with staggered allocations
- FEATURE: Automatic recovery from external provisioner kills
- FIX: Correct use of deactivate (inactive/maturing) vs liquidate (active)
- Pipeline stages: Inactive (0 trans) → Maturing (1 trans) → Active (2+ trans)

New in v1.7.7:
- FEATURE: Rotation check interval is now configurable (default: 10 seconds)
- FEATURE: Health check monitors all 3 rusk nodes with auto-restart (>5 blocks behind)
- IMPROVEMENT: Top-up pauses during rotation window to avoid conflicts
- FEATURE: Anomaly detection for externally terminated provisioners
- FEATURE: Automatic recovery when rotation pattern is broken
- Added "Edit Rotation Check Interval" to Configuration menu

New in v1.7.6:
- IMPROVEMENT: Top-up check interval is now configurable (default: 30 seconds)
- IMPROVEMENT: Status line shows blocks until next epoch transition
- Added "Edit Top-up Check Interval" to Configuration menu

New in v1.7.5:
- CRITICAL FIX: Only rotate between index 0 and index 1 (NOT index 2)
- Index 2 (third provisioner) is fallback only - ignored during normal operations
- All allocation/rotation logic now filters for idx 0 and 1 only
- Enhanced debug showing which indices are being considered

New in v1.7.4:
- CRITICAL FIX: Update stake state immediately after allocations/top-ups
- Prevents duplicate allocations to the same provisioner
- State now refreshes after EVERY successful allocation, not just every 100 blocks
- Enhanced debug showing when state is updated

New in v1.7.3:
- CRITICAL FIX: Respect TOTAL stake limit across ALL provisioners
- Calculate remaining capacity before every allocation/top-up
- Only allocate what fits within total limit (e.g., 1,000 DUSK if 998,999 already staked)
- Enhanced debug output showing total staked and remaining capacity

New in v1.7.2:
- AUTOMATED ROTATION with stake maturity intelligence
- Continuous monitoring loop with 10-second block checks
- Top-up loop (30-second checks) for maturing provisioners - NO PENALTY!
- Only rotate TO provisioners with 1 transition seen (penalty-free)
- Bootstrap handling: Auto-allocate to inactive provisioners
- Persistent stake checking: Allocate as soon as ≥1000 DUSK available
- JSON state updates after every rotation
- Comprehensive DEBUG output for every decision and action

New in v1.7.1:
- COMPLETE REWORK of "Monitor Epoch Transitions" function
- Now tracks stake maturity status for all provisioners
- Captures initial state: inactive, maturing (0 or 1 transitions), or active (2+ transitions)
- Saves detailed stake state to JSON file
- Displays comprehensive summary with stake amounts and transition counts
- Foundation for future automated rotation improvements

New in v1.7:
- ROTATION SYSTEM REDESIGNED for optimal 2-epoch stake maturation
- Rotation happens EVERY EPOCH (2160 blocks) instead of every 2 epochs
- Top-up on MATURING nodes (1 transition) = NO 10% penalty!
- Automatic slashed stake monitoring after every top-up
- Warning system when inactive stake exceeds 2% operator limit
- Explanation: Stakes need 2 epoch transitions to mature (2161-4320 blocks)
- Strategy: Always top-up nodes with <2 transitions to avoid penalty

New in v1.6:
- Fixed: Withdraw operator rewards now uses LUX (not DUSK) for unstake amount

New in v1.5:
- Added: Withdraw Operator Rewards feature
- Query balance, convert hex→decimal, withdraw with 1 DUSK buffer
- Fixed: Rotation logic for correct stake distribution
- Fixed: Active/inactive detection based on stake amount

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
import requests  # For Telegram notifications
from typing import Optional, List, Dict
from pathlib import Path
from collections import deque
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import getpass


# ============================================================================
# TELEGRAM NOTIFIER
# ============================================================================

class TelegramNotifier:
    """Send notifications via Telegram Bot API"""
    
    def __init__(self, bot_token: str, chat_id: str, enabled: bool = True, notify_config: dict = None):
        """Initialize Telegram notifier"""
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.enabled = enabled
        self.api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        self.notify_config = notify_config or {
            'epoch_transitions': True,
            'rotations': True,
            'critical_errors': True,
            'health_warnings': True,
            'recovery_actions': True
        }
    
    def send(self, message: str, silent: bool = False) -> bool:
        """Send a message via Telegram"""
        if not self.enabled:
            print(f"\033[90m[TELEGRAM] Disabled, skipping send\033[0m")
            return False
        
        # Extract first line of message for debug
        first_line = message.split('\n')[0][:50]
        print(f"\033[96m[TELEGRAM] Sending: {first_line}...\033[0m")
        
        try:
            payload = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'Markdown',
                'disable_notification': silent
            }
            
            response = requests.post(self.api_url, json=payload, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                msg_id = result.get('result', {}).get('message_id', 'unknown')
                print(f"\033[92m[TELEGRAM] ✓ Success! Message ID: {msg_id}\033[0m")
                return True
            else:
                print(f"\033[91m[TELEGRAM] ✗ Failed! HTTP {response.status_code}\033[0m")
                print(f"\033[93m[TELEGRAM] Response: {response.text[:200]}\033[0m")
                return False
                
        except requests.exceptions.Timeout:
            print(f"\033[91m[TELEGRAM] ✗ Timeout after 10 seconds\033[0m")
            return False
        except requests.exceptions.RequestException as e:
            print(f"\033[91m[TELEGRAM] ✗ Network error: {str(e)[:100]}\033[0m")
            return False
        except Exception as e:
            print(f"\033[91m[TELEGRAM] ✗ Error: {str(e)[:100]}\033[0m")
            return False
    
    def send_epoch_transition(self, epoch: int, height: int, state: dict):
        """Notify on epoch transition"""
        if not self.notify_config.get('epoch_transitions', True):
            return
        
        active_count = sum(1 for p in state.values() if p.get('epoch_transitions_seen', 0) >= 2)
        maturing_count = sum(1 for p in state.values() if p.get('epoch_transitions_seen', 0) == 1)
        inactive_count = sum(1 for p in state.values() if p.get('eligible_stake', 0) > 0 and p.get('epoch_transitions_seen', 0) == 0)
        
        message = f"""🔄 *Epoch Transition*

Epoch: `{epoch}`
Block: `{height:,}`

Pipeline:
• Active: {active_count}
• Maturing: {maturing_count}
• Inactive: {inactive_count}

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""
        
        self.send(message, silent=True)
    
    def send_rotation_started(self, maturing_idx: int, active_idx: int, maturing_stake: int, active_stake: int):
        """Notify when rotation starts"""
        if not self.notify_config.get('rotations', True):
            return
        
        message = f"""⚡ *Rotation Started*

Liquidating: idx {active_idx} ({active_stake:,} DUSK)
Promoting: idx {maturing_idx} ({maturing_stake:,} DUSK)

Time: {datetime.now().strftime('%H:%M:%S')}"""
        
        self.send(message)
    
    def send_rotation_complete(self, new_active_idx: int, stake: int, success: bool = True):
        """Notify when rotation completes"""
        if not self.notify_config.get('rotations', True):
            return
        
        if success:
            message = f"""✅ *Rotation Complete*

New active: idx {new_active_idx}
Stake: {stake:,} DUSK

Time: {datetime.now().strftime('%H:%M:%S')}"""
        else:
            message = f"""❌ *Rotation Failed*

Target: idx {new_active_idx}
Check logs for details

Time: {datetime.now().strftime('%H:%M:%S')}"""
        
        self.send(message)
    
    def send_topup(self, idx: int, amount: int, current_stake: int, new_stake: int):
        """Notify when topping up a maturing node"""
        if not self.notify_config.get('rotations', True):  # Use rotations config for top-ups
            return
        
        message = f"""💰 *Top-up Complete*

Node: idx {idx}
Added: {amount:,} DUSK
Before: {current_stake:,} DUSK
After: {new_stake:,} DUSK

Time: {datetime.now().strftime('%H:%M:%S')}"""
        
        self.send(message, silent=True)  # Silent notification
    
    def send_critical_error(self, error_type: str, details: str):
        """Notify on critical errors"""
        if not self.notify_config.get('critical_errors', True):
            return
        
        message = f"""🚨 *CRITICAL ERROR*

Type: {error_type}

{details}

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""
        
        self.send(message)
    
    def send_recovery_action(self, recovery_type: str, details: str):
        """Notify on recovery actions"""
        if not self.notify_config.get('recovery_actions', True):
            return
        
        message = f"""🔧 *Recovery Action*

Type: {recovery_type}

{details}

Time: {datetime.now().strftime('%H:%M:%S')}"""
        
        self.send(message)
    
    def send_health_warning(self, node_id: str, issue: str, resolved: bool = False):
        """Notify on health check issues"""
        if not self.notify_config.get('health_warnings', True):
            return
        
        if resolved:
            emoji = "✅"
            title = "Health Resolved"
        else:
            emoji = "⚠️"
            title = "Health Warning"
        
        message = f"""{emoji} *{title}*

Node: {node_id}
Issue: {issue}

Time: {datetime.now().strftime('%H:%M:%S')}"""
        
        self.send(message)
    
    def send_node_stuck(self, node_id: str, blocks_behind: int, restart_success: bool):
        """Notify when node is stuck"""
        if not self.notify_config.get('health_warnings', True):
            return
        
        status = "✅ Restarted" if restart_success else "❌ Still Stuck"
        
        message = f"""🔴 *Node Stuck*

Node: {node_id}
Behind: {blocks_behind} blocks
Status: {status}

Time: {datetime.now().strftime('%H:%M:%S')}"""
        
        self.send(message)


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
        
        # Initialize Telegram notifier
        telegram_config = self.config.get('telegram', {})
        if telegram_config.get('enabled', False):
            self.telegram = TelegramNotifier(
                bot_token=telegram_config.get('bot_token', ''),
                chat_id=telegram_config.get('chat_id', ''),
                enabled=True,
                notify_config=telegram_config.get('notify_on', {})
            )
        else:
            self.telegram = None
        
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
            "Withdraw Operator Rewards",
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
            self.withdraw_operator_rewards()
        elif selection == 11:
            self.check_stake_info()
        elif selection == 12:
            self.check_block_heights()
        elif selection == 13:
            self.monitor_epoch_transitions()
        elif selection == 14:
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
            "rotation_trigger_blocks": 50,  # Blocks before epoch end to trigger rotation
            "rotation_check_interval": 10,  # Seconds between rotation checks
            "topup_check_interval": 30,  # Seconds between top-up checks
            "telegram": {
                "enabled": False,  # Enable Telegram notifications
                "bot_token": "",  # Get from @BotFather
                "chat_id": "",  # Get from @userinfobot
                "notify_on": {
                    "epoch_transitions": True,
                    "rotations": True,
                    "critical_errors": True,
                    "health_warnings": True,
                    "recovery_actions": True
                }
            }
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
    
    def withdraw_operator_rewards(self):
        """Option 11: Withdraw Operator Rewards"""
        # Temporarily exit curses mode
        curses.endwin()
        
        print(f"\n\033[94m{'=' * 70}\033[0m")
        print(f"\033[1m\033[96mWITHDRAW OPERATOR REWARDS\033[0m")
        print(f"\033[94m{'=' * 70}\033[0m\n")
        
        try:
            # Get operator address from config
            operator_address = self.config.get('operator_address')
            if not operator_address:
                print(f"\033[91m✗ Operator address not configured\033[0m")
                print(f"\033[93mPlease set operator_address in Configuration menu\033[0m\n")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            contract_address = self.config.get('contract_address')
            if not contract_address:
                print(f"\033[91m✗ Contract address not configured\033[0m\n")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # STEP 1: Calculate balance payload
            print(f"\033[1m\033[96mSTEP 1: Calculating Balance Payload\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            payload_command = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet calculate-payload-balance-of \
  --public-key {operator_address}"""
            
            if self.wallet_password_decrypted:
                print(f"\033[92mExecuting payload calculation (using stored password)...\033[0m\n")
            else:
                print(f"\033[94mExecuting payload calculation...\033[0m")
                print(f"\033[93mNote: You will be prompted for your wallet password.\033[0m\n")
            
            success, output = self.execute_wallet_command(payload_command)
            
            if not success:
                print(f"\n\033[91m✗ Failed to calculate balance payload\033[0m\n")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # Extract payload (remove quotes)
            payload_match = re.search(r'"([0-9a-fA-F]+)"', output)
            if not payload_match:
                lines = [line.strip() for line in output.split('\n') if line.strip()]
                if lines:
                    balance_payload = lines[-1].strip().strip('"')
                else:
                    print(f"\n\033[91m✗ Could not extract balance payload\033[0m\n")
                    input("\nPress Enter to continue...")
                    self._reinit_curses()
                    return
            else:
                balance_payload = payload_match.group(1)
            
            print(f"\033[92m✓ Balance payload generated\033[0m")
            print(f"\033[90m  Payload: {balance_payload[:32]}...{balance_payload[-32:]}\033[0m\n")
            
            # STEP 2: Query balance from contract
            print(f"\033[1m\033[96mSTEP 2: Querying Balance from Contract\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            curl_command = f"curl -s -X POST -d '0x{balance_payload}' https://testnet.nodes.dusk.network/on/contracts:{contract_address}/balance_of"
            
            print(f"\033[94mQuerying contract...\033[0m\n")
            
            result = subprocess.run(
                curl_command,
                shell=True,
                check=True,
                capture_output=True,
                text=True
            )
            
            if not result.stdout:
                print(f"\033[91m✗ No response from contract\033[0m\n")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # Extract hex balance (remove newlines and trailing text)
            hex_balance = result.stdout.strip().split('\n')[0].strip()
            # Remove any trailing text after the hex (like "root@...")
            hex_balance = hex_balance.split('root@')[0].strip()
            
            if not re.match(r'^[0-9a-fA-F]+$', hex_balance):
                print(f"\033[91m✗ Invalid hex balance received: {hex_balance}\033[0m\n")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            print(f"\033[92m✓ Balance received from contract\033[0m")
            print(f"\033[90m  Hex: {hex_balance}\033[0m\n")
            
            # STEP 3: Convert hex to decimal (Little-Endian)
            print(f"\033[1m\033[96mSTEP 3: Converting Hex to Decimal\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            # Parse as little-endian 64-bit integer
            # Extract bytes in pairs
            bytes_list = []
            for i in range(0, min(len(hex_balance), 16), 2):
                bytes_list.append(int(hex_balance[i:i+2], 16))
            
            # Convert to decimal (little-endian)
            balance_lux = 0
            for i, byte in enumerate(bytes_list):
                balance_lux += byte << (i * 8)
            
            balance_dusk = balance_lux / 1_000_000_000
            
            print(f"\033[92m✓ Conversion complete\033[0m")
            print(f"\033[96m  Balance (LUX):  {balance_lux:,}\033[0m")
            print(f"\033[96m  Balance (DUSK): {balance_dusk:,.9f}\033[0m\n")
            
            if balance_lux == 0:
                print(f"\033[93m⚠ No rewards available to withdraw\033[0m\n")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # Calculate withdrawable amount (full DUSK minus 1 DUSK buffer)
            withdrawable_dusk = int(balance_dusk) - 1
            
            if withdrawable_dusk <= 0:
                print(f"\033[93m⚠ Insufficient balance to withdraw (need >1 DUSK)\033[0m\n")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            print(f"\033[1m\033[93m{'─' * 70}\033[0m")
            print(f"\033[1m\033[93mWITHDRAWAL CALCULATION\033[0m")
            print(f"\033[1m\033[93m{'─' * 70}\033[0m")
            print(f"\033[96mAvailable:    {balance_dusk:,.2f} DUSK\033[0m")
            print(f"\033[96mBuffer:       1 DUSK\033[0m")
            print(f"\033[92mWithdrawable: {withdrawable_dusk:,} DUSK\033[0m")
            print(f"\033[1m\033[93m{'─' * 70}\033[0m\n")
            
            # Confirm withdrawal
            confirm = input(f"\033[93mProceed with withdrawal of {withdrawable_dusk:,} DUSK? (yes/no): \033[0m").strip().lower()
            if confirm not in ['yes', 'y']:
                print(f"\033[93mWithdrawal cancelled.\033[0m\n")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # STEP 4: Withdraw rewards
            print(f"\n\033[1m\033[96mSTEP 4: Withdrawing Rewards\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            
            # 4a: Calculate unstake payload
            # IMPORTANT: unstake-amount must be in LUX, not DUSK!
            withdrawable_lux = int(withdrawable_dusk * 1_000_000_000)
            
            print(f"\033[94mCalculating unstake payload for {withdrawable_dusk:,} DUSK ({withdrawable_lux:,} LUX)...\033[0m\n")
            
            unstake_payload_command = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet calculate-payload-sozu-unstake \
  --unstake-amount {withdrawable_lux}"""
            
            success, output = self.execute_wallet_command(unstake_payload_command)
            
            if not success:
                print(f"\n\033[91m✗ Failed to calculate unstake payload\033[0m\n")
                input("\nPress Enter to continue...")
                self._reinit_curses()
                return
            
            # Extract unstake payload
            unstake_payload_match = re.search(r'"([0-9a-fA-F]+)"', output)
            if not unstake_payload_match:
                lines = [line.strip() for line in output.split('\n') if line.strip()]
                if lines:
                    unstake_payload = lines[-1].strip().strip('"')
                else:
                    print(f"\n\033[91m✗ Could not extract unstake payload\033[0m\n")
                    input("\nPress Enter to continue...")
                    self._reinit_curses()
                    return
            else:
                unstake_payload = unstake_payload_match.group(1)
            
            print(f"\033[92m✓ Unstake payload generated\033[0m\n")
            
            # 4b: Execute contract call
            print(f"\033[94mExecuting withdrawal...\033[0m\n")
            
            withdraw_command = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet contract-call \
  --contract-id {contract_address} \
  --fn-name sozu_unstake \
  --fn-args "{unstake_payload}" \
  --gas-limit 2000000"""
            
            success, _ = self.execute_wallet_command(withdraw_command)
            
            print()
            if success:
                print(f"\033[92m{'=' * 70}\033[0m")
                print(f"\033[92m✓ WITHDRAWAL SUCCESSFUL!\033[0m")
                print(f"\033[92m  Withdrawn: {withdrawable_dusk:,} DUSK\033[0m")
                print(f"\033[92m  Remaining buffer: 1 DUSK\033[0m")
                print(f"\033[92m{'=' * 70}\033[0m")
            else:
                print(f"\033[91m{'=' * 70}\033[0m")
                print(f"\033[91m✗ Withdrawal failed\033[0m")
                print(f"\033[91m{'=' * 70}\033[0m")
        
        except subprocess.CalledProcessError as e:
            print(f"\n\033[91m✗ Command failed:\033[0m")
            if e.stderr:
                print(e.stderr)
        except Exception as e:
            print(f"\n\033[91m✗ Unexpected error: {str(e)}\033[0m")
            import traceback
            traceback.print_exc()
        
        input("\nPress Enter to continue...")
        self._reinit_curses()
    
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
        Returns dict with 'has_stake', 'amount', 'slashed_stake', and 'output'
        """
        try:
            stake_info_command = f"sozu-beta3-rusk-wallet -w ~/sozu_provisioner -n testnet stake-info --profile-idx {idx}"
            success, output = self.execute_wallet_command(stake_info_command)
            
            # Debug output
            # print(f"\n[DEBUG] idx={idx}, success={success}, output_length={len(output) if output else 0}")
            # if output:
            #     print(f"[DEBUG] First 200 chars: {output[:200]}")
            
            result = {
                'has_stake': False,
                'amount': 0,
                'slashed_stake': 0,
                'output': output if output else "No output"
            }
            
            if success and output:
                # Parse output for "Eligible stake: <amount> DUSK"
                if "Eligible stake:" in output:
                    # Extract amount
                    match = re.search(r'Eligible stake:\s*(\d+(?:\.\d+)?)\s*DUSK', output)
                    if match:
                        result['has_stake'] = True
                        result['amount'] = float(match.group(1))
                    
                    # Extract slashed stake (reclaimable)
                    slashed_match = re.search(r'Reclaimable slashed stake:\s*(\d+(?:\.\d+)?)\s*DUSK', output)
                    if slashed_match:
                        result['slashed_stake'] = float(slashed_match.group(1))
                    
                    return result
                    
                elif "A stake does not exist for this key" in output:
                    return result
            
            # Check output even if success=False (might still have useful info)
            if output:
                if "Eligible stake:" in output:
                    match = re.search(r'Eligible stake:\s*(\d+(?:\.\d+)?)\s*DUSK', output)
                    if match:
                        result['has_stake'] = True
                        result['amount'] = float(match.group(1))
                    
                    slashed_match = re.search(r'Reclaimable slashed stake:\s*(\d+(?:\.\d+)?)\s*DUSK', output)
                    if slashed_match:
                        result['slashed_stake'] = float(slashed_match.group(1))
                    
                    return result
                    
                elif "A stake does not exist for this key" in output:
                    return result
            
            return result
            
        except Exception as e:
            return {
                'has_stake': False,
                'amount': 0,
                'slashed_stake': 0,
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
        
        IMPORTANT: When topping up an ACTIVE node (>=2 transitions), 10% of the 
        top-up amount becomes inactive (penalty). This is checked after every top-up.
        
        When topping up a MATURING node (<2 transitions), there is NO penalty!
        
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
                
                # Check slashed stake after top-up (10% penalty if node is active)
                print(f"\033[94mChecking for inactive stake (slashed/penalty)...\033[0m\n")
                stake_info = self._check_provisioner_stake(active['idx'])
                slashed_stake = stake_info.get('slashed_stake', 0)
                
                if slashed_stake > 0:
                    # Calculate 2% limit
                    operator_limit = self.config.get('stake_limit', 1000000)
                    max_slashed = operator_limit * 0.02  # 2% of operator limit
                    percentage = (slashed_stake / operator_limit) * 100
                    
                    print(f"\033[93m⚠  INACTIVE STAKE DETECTED\033[0m")
                    print(f"\033[96m  Reclaimable slashed stake: {slashed_stake:,.2f} DUSK\033[0m")
                    print(f"\033[96m  Operator limit: {operator_limit:,} DUSK\033[0m")
                    print(f"\033[96m  Percentage: {percentage:.2f}%\033[0m")
                    print(f"\033[96m  Max allowed: {max_slashed:,.0f} DUSK (2%)\033[0m\n")
                    
                    if slashed_stake > max_slashed:
                        print(f"\033[91m✗ WARNING: Inactive stake exceeds 2% limit!\033[0m")
                        print(f"\033[91m  This may prevent provisioner from being active.\033[0m")
                        print(f"\033[91m  Consider liquidating & terminating to reclaim stake.\033[0m\n")
                    else:
                        print(f"\033[92m✓ Inactive stake is within acceptable limits\033[0m\n")
                else:
                    print(f"\033[92m✓ No inactive stake detected\033[0m\n")
                
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
            prov_id = provisioner['provisioner_id']
            idx = provisioner['index']
            
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
        """Execute full rotation sequence (EVERY EPOCH)
        
        Rotation happens EVERY epoch (2160 blocks), triggered 50 blocks before end.
        
        The 'inactive' node has 1000 DUSK staked with 1 transition (maturing).
        When we top-up this maturing node, there is NO 10% penalty because it's not yet active!
        
        Steps:
        1. Liquidate & terminate active provisioner (the one with large stake)
        2. Allocate 1000 DUSK back to that provisioner (starts maturation)
        3. Top-up the maturing provisioner from 1000 → (limit-1001) DUSK
           - No penalty because node only has 1 transition (not active yet)
           - After next epoch transition, this node becomes fully active
        
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
            
            # Telegram notification - rotation started
            if self.telegram:
                self.telegram.send_rotation_started(
                    inactive['idx'],
                    active['idx'],
                    inactive['amount'],
                    active['amount']
                )
            
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
        """Option 12: Monitor epoch transitions - Automated rotation with 3-node pipeline"""
        # Exit curses for raw terminal output
        curses.endwin()
        
        EPOCH_BLOCKS = 2160
        ROTATION_CHECK_INTERVAL = self.config.get('rotation_check_interval', 10)  # seconds - check for rotation triggers
        TOPUP_CHECK_INTERVAL = self.config.get('topup_check_interval', 30)  # seconds - check for top-up opportunities
        
        print(f"\n\033[94m{'=' * 70}\033[0m")
        print(f"\033[1m\033[96mAUTOMATED EPOCH MONITORING & ROTATION (3-Node Pipeline)\033[0m")
        print(f"\033[94m{'=' * 70}\033[0m\n")
        print(f"\033[93m🔄 3-Node Pipeline: Inactive → Maturing → Active\033[0m")
        print(f"\033[93m⚡ Only ONE active provisioner per epoch (guaranteed)\033[0m")
        print(f"\033[93m📊 Real-time JSON updates every rotation check\033[0m")
        print(f"\033[93m🎯 Pipeline rotation: idx 0 → idx 1 → idx 2 → idx 0...\033[0m")
        print(f"\033[93m🏥 Health monitoring with auto-restart (>5 blocks behind)\033[0m")
        print(f"\033[93m🔧 Auto-recovery from external kills\033[0m\n")
        print(f"\033[90mRotation check: Every {ROTATION_CHECK_INTERVAL} seconds\033[0m")
        print(f"\033[90mTop-up check: Every {TOPUP_CHECK_INTERVAL} seconds\033[0m")
        print(f"\033[90mPress Ctrl+C to stop\033[0m\n")
        
        log_files = [
            '/var/log/rusk-1.log',
            '/var/log/rusk-2.log',
            '/var/log/rusk-3.log'
        ]
        
        state_file = self.storage_dir / "stake_state.json"
        last_rotation_epoch = None
        last_topup_check = 0
        
        # TRANSITION LOGGER: Track last 100 blocks before/after epoch transitions
        transition_log_buffer = deque(maxlen=100)  # Circular buffer for pre-transition logs
        transition_logging_active = False  # True when logging post-transition
        transition_log_file = None
        transition_blocks_logged = 0
        last_logged_epoch = None
        
        # Load or create initial state
        print(f"\033[1m\033[96m{'─' * 70}\033[0m")
        print(f"\033[1m\033[96mINITIALIZATION\033[0m")
        print(f"\033[1m\033[96m{'─' * 70}\033[0m\n")
        
        stake_db = self._load_or_create_stake_state(state_file)
        
        print(f"\n\033[92m✓ Ready to monitor!\033[0m\n")
        input("Press Enter to start monitoring...")
        print()
        
        try:
            # Helper class to tee output to both console and log file
            class TeeOutput:
                def __init__(self, log_file):
                    self.terminal = sys.stdout
                    self.log_file = log_file
                
                def write(self, message):
                    self.terminal.write(message)
                    if self.log_file:
                        try:
                            # Strip ANSI color codes for cleaner log file
                            clean_msg = re.sub(r'\033\[[0-9;]+m', '', message)
                            self.log_file.write(clean_msg)
                        except:
                            pass
                
                def flush(self):
                    self.terminal.flush()
                    if self.log_file:
                        try:
                            self.log_file.flush()
                        except:
                            pass
            
            # Helper function to log messages to both console and transition log
            def log_print(msg, end='\n', flush=False):
                """Print to console and optionally write to transition log file"""
                print(msg, end=end, flush=flush)
                # Also write to transition log if active
                if transition_logging_active and transition_log_file:
                    try:
                        # Strip ANSI color codes for cleaner log file
                        clean_msg = re.sub(r'\033\[[0-9;]+m', '', str(msg))
                        transition_log_file.write(clean_msg + end)
                        if flush:
                            transition_log_file.flush()
                    except:
                        pass  # Don't let logging failures break the main loop
            
            # Save original stdout
            original_stdout = sys.stdout
            tee_output = None
            
            while True:
                # Get current heights from all nodes
                heights = []
                node_heights = {}
                for i, log_file in enumerate(log_files, 1):
                    height = self._get_block_height_from_log(log_file)
                    if height:
                        heights.append((log_file, height))
                        node_heights[i] = height
                
                if not heights:
                    print(f"\033[91m[{time.strftime('%H:%M:%S')}] ✗ No heights available\033[0m")
                    time.sleep(ROTATION_CHECK_INTERVAL)
                    continue
                
                # Health check: Detect and restart stuck nodes (>5 blocks behind)
                highest_height = max(node_heights.values())
                for node_id, height in node_heights.items():
                    blocks_behind = highest_height - height
                    
                    if blocks_behind > 5:
                        print(f"\n\033[91m[HEALTH] ⚠️ Node {node_id} stuck at {height:,} ({blocks_behind} blocks behind!)\033[0m")
                        print(f"\033[93m[HEALTH] 🔄 Restarting rusk-{node_id}...\033[0m")
                        
                        # Restart the stuck node
                        restart_result = os.system(f'systemctl restart rusk-{node_id}')
                        if restart_result != 0:
                            print(f"\033[91m[HEALTH] ✗ Failed to restart rusk-{node_id}\033[0m")
                            continue
                        
                        # Wait for restart
                        time.sleep(5)
                        
                        # Verify recovery
                        new_height = self._get_block_height_from_log(f'/var/log/rusk-{node_id}.log')
                        restart_success = new_height and new_height > height
                        
                        # Telegram notification - node stuck
                        if self.telegram:
                            self.telegram.send_node_stuck(f"rusk-{node_id}", blocks_behind, restart_success)
                        
                        if restart_success:
                            print(f"\033[92m[HEALTH] ✅ Node {node_id} recovered! New height: {new_height:,}\033[0m\n")
                            node_heights[node_id] = new_height
                        else:
                            print(f"\033[91m[HEALTH] ❌ Node {node_id} still stuck after restart!\033[0m")
                            
                            # Check if this is an active provisioner node
                            # If so, warn that manual intervention may be needed
                            stake_db_check = self._update_stake_state(state_file, current_height)
                            inactive_check, maturing_check, active_check = self._categorize_nodes_by_transitions(stake_db_check)
                            
                            # Check if any active provisioner might be affected
                            if len(active_check) > 0:
                                print(f"\033[91m[HEALTH] ⚠️ CRITICAL: You have an active provisioner!\033[0m")
                                print(f"\033[91m[HEALTH] If the stuck node is running your active provisioner,\033[0m")
                                print(f"\033[91m[HEALTH] it won't earn rewards until recovered.\033[0m")
                                print(f"\033[93m[HEALTH] 💡 If recovery fails, consider:\033[0m")
                                print(f"\033[93m[HEALTH]    1. Manually fix the stuck node, OR\033[0m")
                                print(f"\033[93m[HEALTH]    2. Manually liquidate the active provisioner\033[0m")
                                print(f"\033[93m[HEALTH]    → The maturing node will take over and be topped up\033[0m")
                                print(f"\033[93m[HEALTH]       to {stake_limit - 1000:,.0f} DUSK (penalty-free!)\033[0m\n")
                
                highest = max(heights, key=lambda x: x[1])
                current_height = highest[1]
                current_epoch = current_height // EPOCH_BLOCKS
                
                # Calculate blocks until next epoch transition
                epoch_end = (current_epoch + 1) * EPOCH_BLOCKS  # Start of next epoch
                blocks_until_transition = epoch_end - current_height
                
                # Display current status
                timestamp = time.strftime('%H:%M:%S')
                log_print(f"\033[96m[{timestamp}]\033[0m Height: \033[92m{current_height:,}\033[0m | Epoch: \033[96m{current_epoch}\033[0m | Until transition: \033[93m{blocks_until_transition}\033[0m blocks")
                
                # UPDATE: Refresh state EVERY cycle for real-time awareness
                log_print(f"\033[90m  [STATE] Refreshing JSON...\033[0m", end='')
                stake_db = self._update_stake_state(state_file, current_height)
                log_print(f" ✓")
                
                # TRANSITION LOGGER: Buffer current state for transition debugging
                log_entry = {
                    'timestamp': timestamp,
                    'height': current_height,
                    'epoch': current_epoch,
                    'blocks_until_transition': blocks_until_transition,
                    'state': {
                        prov_id: {
                            'index': prov['index'],
                            'stake': prov['eligible_stake'],
                            'slashed': prov.get('slashed_stake', 0),
                            'transitions': prov['epoch_transitions_seen']
                        }
                        for prov_id, prov in stake_db['provisioners'].items()
                    }
                }
                
                # Detect epoch transition
                if last_logged_epoch is not None and current_epoch != last_logged_epoch:
                    # EPOCH TRANSITION DETECTED!
                    log_print(f"\033[93m  [TRANSITION LOG] Epoch {last_logged_epoch} → {current_epoch} detected!\033[0m")
                    
                    # Telegram notification
                    if self.telegram:
                        self.telegram.send_epoch_transition(current_epoch, current_height, stake_db["provisioners"])
                    
                    # Create transition log file
                    log_filename = f"transition_epoch_{last_logged_epoch}_to_{current_epoch}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
                    log_path = self.storage_dir / log_filename
                    transition_log_file = open(log_path, 'w')
                    
                    # Write header
                    transition_log_file.write(f"="*80 + "\n")
                    transition_log_file.write(f"EPOCH TRANSITION LOG: {last_logged_epoch} → {current_epoch}\n")
                    transition_log_file.write(f"Transition detected at block {current_height}\n")
                    transition_log_file.write(f"Log created: {datetime.now().isoformat()}\n")
                    transition_log_file.write(f"="*80 + "\n\n")
                    
                    # Write buffered pre-transition blocks (last 100 blocks)
                    transition_log_file.write("="*80 + "\n")
                    transition_log_file.write(f"PRE-TRANSITION BLOCKS (last {len(transition_log_buffer)} blocks)\n")
                    transition_log_file.write("="*80 + "\n\n")
                    
                    for buffered_entry in transition_log_buffer:
                        transition_log_file.write(f"[{buffered_entry['timestamp']}] Block {buffered_entry['height']} | Epoch {buffered_entry['epoch']} | Until transition: {buffered_entry['blocks_until_transition']}\n")
                        for prov_id, prov_state in buffered_entry['state'].items():
                            transition_log_file.write(f"  idx {prov_state['index']}: {prov_state['stake']:,} DUSK (slashed: {prov_state['slashed']:,}, trans: {prov_state['transitions']})\n")
                        transition_log_file.write("\n")
                    
                    # Start post-transition logging
                    transition_log_file.write("="*80 + "\n")
                    transition_log_file.write("POST-TRANSITION BLOCKS (next 100 blocks)\n")
                    transition_log_file.write("="*80 + "\n")
                    transition_log_file.write("FULL CONSOLE OUTPUT:\n")
                    transition_log_file.write("="*80 + "\n\n")
                    
                    transition_logging_active = True
                    transition_blocks_logged = 0
                    
                    # Redirect stdout to capture ALL output
                    tee_output = TeeOutput(transition_log_file)
                    sys.stdout = tee_output
                    
                    log_print(f"\033[92m  [TRANSITION LOG] Started logging to {log_filename}\033[0m")
                
                # Update last logged epoch
                last_logged_epoch = current_epoch
                
                # Add current entry to buffer (always)
                transition_log_buffer.append(log_entry)
                
                # If in post-transition logging mode, write to file
                if transition_logging_active:
                    transition_log_file.write(f"[{log_entry['timestamp']}] Block {log_entry['height']} | Epoch {log_entry['epoch']} | Until transition: {log_entry['blocks_until_transition']}\n")
                    for prov_id, prov_state in log_entry['state'].items():
                        transition_log_file.write(f"  idx {prov_state['index']}: {prov_state['stake']:,} DUSK (slashed: {prov_state['slashed']:,}, trans: {prov_state['transitions']})\n")
                    transition_log_file.write("\n")
                    transition_log_file.flush()  # Ensure it's written immediately
                    
                    transition_blocks_logged += 1
                    
                    # Close log after 100 post-transition blocks
                    if transition_blocks_logged >= 100:
                        transition_log_file.write("="*80 + "\n")
                        transition_log_file.write(f"POST-TRANSITION LOGGING COMPLETE (100 blocks logged)\n")
                        transition_log_file.write(f"Log finished: {datetime.now().isoformat()}\n")
                        transition_log_file.write("="*80 + "\n")
                        
                        # Restore original stdout
                        sys.stdout = original_stdout
                        tee_output = None
                        
                        transition_log_file.close()
                        transition_logging_active = False
                        log_print(f"\033[92m  [TRANSITION LOG] Completed! File saved.\033[0m")
                
                # Check for anomalies (externally terminated provisioners)
                anomaly_detected = self._check_for_anomaly(stake_db, current_height)
                if anomaly_detected:
                    stake_db = self._update_stake_state(state_file, current_height)
                    # Log anomaly action
                    if transition_logging_active and transition_log_file:
                        transition_log_file.write(f"[{timestamp}] ⚠️ ANOMALY DETECTED AND HANDLED\n\n")
                        transition_log_file.flush()
                
                # Check for rotation trigger
                rotation_needed, rotation_target = self._check_rotation_trigger(stake_db, current_height, current_epoch, last_rotation_epoch)
                
                if rotation_needed and rotation_target:
                    log_print(f"\n\033[1m\033[91m{'!' * 70}\033[0m")
                    log_print(f"\033[1m\033[91m🔄 ROTATION TRIGGER ACTIVATED!\033[0m")
                    log_print(f"\033[1m\033[91m{'!' * 70}\033[0m\n")
                    
                    # Log rotation action
                    if transition_logging_active and transition_log_file:
                        transition_log_file.write(f"[{timestamp}] 🔄 ROTATION TRIGGERED (target idx {rotation_target['index']})\n\n")
                        transition_log_file.flush()
                    
                    success = self._execute_smart_rotation(stake_db, rotation_target, current_height)
                    
                    if success:
                        last_rotation_epoch = current_epoch
                        stake_db = self._update_stake_state(state_file, current_height)
                        log_print(f"\n\033[92m✓ Rotation complete! State updated.\033[0m\n")
                        
                        # Telegram notification - rotation complete
                        if self.telegram and rotation_target:
                            self.telegram.send_rotation_complete(
                                rotation_target['index'],
                                rotation_target.get('eligible_stake', 0),
                                success=True
                            )
                        
                        # Log rotation result
                        if transition_logging_active and transition_log_file:
                            transition_log_file.write(f"[{timestamp}] ✅ ROTATION COMPLETED\n\n")
                            transition_log_file.flush()
                    else:
                        log_print(f"\n\033[91m✗ Rotation failed!\033[0m\n")
                        
                        # Telegram notification - rotation failed
                        if self.telegram and rotation_target:
                            self.telegram.send_rotation_complete(
                                rotation_target['index'],
                                rotation_target.get('eligible_stake', 0),
                                success=False
                            )
                        
                        # Log rotation failure
                        if transition_logging_active and transition_log_file:
                            transition_log_file.write(f"[{timestamp}] ❌ ROTATION FAILED\n\n")
                            transition_log_file.flush()
                
                # Top-up check (every configured interval)
                # Skip if anomaly was just handled to avoid premature balancing
                if anomaly_detected:
                    log_print(f"\033[90m  [TOPUP] Skipping (anomaly just handled, will balance on next rotation)\033[0m")
                elif time.time() - last_topup_check >= TOPUP_CHECK_INTERVAL:
                    log_print(f"\n\033[93m[DEBUG] Top-up check triggered...\033[0m")
                    # Log topup check
                    if transition_logging_active and transition_log_file:
                        transition_log_file.write(f"[{timestamp}] 💰 TOP-UP CHECK TRIGGERED\n")
                        transition_log_file.flush()
                    stake_db = self._check_and_topup(stake_db, current_height, state_file, rotation_target if rotation_needed else None)
                    last_topup_check = time.time()
                
                # Wait before next check
                time.sleep(ROTATION_CHECK_INTERVAL)
        
        except KeyboardInterrupt:
            print(f"\n\n\033[93m⏹ Monitoring stopped by user (Ctrl+C)\033[0m")
        except Exception as e:
            print(f"\n\033[91m✗ Unexpected error: {str(e)}\033[0m")
            import traceback
            traceback.print_exc()
            # Log crash to transition log if active
            if transition_logging_active and transition_log_file:
                transition_log_file.write(f"\n{'='*80}\n")
                transition_log_file.write(f"💥 SCRIPT CRASHED: {str(e)}\n")
                transition_log_file.write(f"Traceback:\n")
                transition_log_file.write(traceback.format_exc())
                transition_log_file.write(f"{'='*80}\n")
        finally:
            # Restore stdout if it was redirected
            if tee_output is not None:
                sys.stdout = original_stdout
            
            # Close transition log file if still open
            if transition_logging_active and transition_log_file:
                try:
                    transition_log_file.write(f"\n{'='*80}\n")
                    transition_log_file.write(f"LOGGING INTERRUPTED (script stopped)\n")
                    transition_log_file.write(f"Blocks logged: {transition_blocks_logged}/100\n")
                    transition_log_file.write(f"Log finished: {datetime.now().isoformat()}\n")
                    transition_log_file.write(f"{'='*80}\n")
                    transition_log_file.close()
                    print(f"\033[93m  [TRANSITION LOG] File closed (interrupted).\033[0m")
                except:
                    pass
        
        input("\nPress Enter to continue...")
        self._reinit_curses()
    
    def _load_or_create_stake_state(self, state_file):
        """Load existing state or create new one"""
        print(f"\033[94m[INIT] Loading stake state...\033[0m")
        
        if state_file.exists():
            try:
                with open(state_file, 'r') as f:
                    stake_db = json.load(f)
                print(f"\033[92m✓ Loaded existing state from {state_file}\033[0m")
                print(f"\033[90m  Last update: {stake_db.get('timestamp', 'Unknown')}\033[0m")
                return stake_db
            except Exception as e:
                print(f"\033[91m✗ Failed to load state: {e}\033[0m")
                print(f"\033[93m  Creating new state...\033[0m")
        
        # Create new state
        heights = []
        log_files = ['/var/log/rusk-1.log', '/var/log/rusk-2.log', '/var/log/rusk-3.log']
        for log_file in log_files:
            height = self._get_block_height_from_log(log_file)
            if height:
                heights.append((log_file, height))
        
        if not heights:
            print(f"\033[91m✗ Cannot get block height!\033[0m")
            return None
        
        current_height = max(heights, key=lambda x: x[1])[1]
        current_epoch = current_height // 2160
        
        stake_db = {
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "current_block": current_height,
            "current_epoch": current_epoch,
            "provisioners": {}
        }
        
        # Query all provisioners
        stored_keys = self._decrypt_keys(self.encryption_password)
        if not stored_keys:
            print(f"\033[91m✗ No provisioners found!\033[0m")
            return None
        
        sorted_provisioners = sorted(stored_keys.items(), key=lambda x: int(x[1].get('index', 0)))
        
        for prov_id, data in sorted_provisioners:
            idx = int(data['index'])
            if idx > 2:  # Check indices 0, 1, 2 (all 3 nodes)
                continue
            
            address = data.get('address', 'N/A')
            stake_info_command = f"sozu-beta3-rusk-wallet -w ~/sozu_provisioner -n testnet stake-info --profile-idx {idx}"
            success, output = self.execute_wallet_command(stake_info_command)
            
            prov_entry = {
                "index": idx,
                "provisioner_id": prov_id,
                "address": address,
                "status": "unknown",
                "eligible_stake": 0,
                "slashed_stake": 0,
                "stake_active_from_block": None,
                "stake_active_from_epoch": None,
                "epoch_transitions_seen": 0
            }
            
            if success:
                if "A stake does not exist" in output:
                    prov_entry["status"] = "inactive"
                elif "Eligible stake:" in output:
                    eligible_match = re.search(r'Eligible stake:\s*(\d+(?:\.\d+)?)\s*DUSK', output)
                    if eligible_match:
                        prov_entry["eligible_stake"] = float(eligible_match.group(1))
                    
                    slashed_match = re.search(r'Reclaimable slashed stake:\s*(\d+(?:\.\d+)?)\s*DUSK', output)
                    if slashed_match:
                        prov_entry["slashed_stake"] = float(slashed_match.group(1))
                    
                    active_match = re.search(r'Stake active from block #(\d+) \(Epoch (\d+)\)', output)
                    if active_match:
                        stake_active_block = int(active_match.group(1))
                        stake_active_epoch = int(active_match.group(2))
                        prov_entry["stake_active_from_block"] = stake_active_block
                        prov_entry["stake_active_from_epoch"] = stake_active_epoch
                        
                        blocks_until_active = stake_active_block - current_height
                        
                        if blocks_until_active >= 2160:
                            prov_entry["status"] = "initial stake"  # Just allocated, 0 transitions
                            prov_entry["epoch_transitions_seen"] = 0
                        elif blocks_until_active > 0:
                            prov_entry["status"] = "maturing"  # 1 transition, will activate next epoch
                            prov_entry["epoch_transitions_seen"] = 1
                        else:
                            prov_entry["status"] = "active"
                            blocks_since_active = current_height - stake_active_block
                            prov_entry["epoch_transitions_seen"] = 2 + (blocks_since_active // 2160)
            
            stake_db["provisioners"][str(idx)] = prov_entry
            print(f"\033[90m  idx {idx}: {prov_entry['status']} ({prov_entry['eligible_stake']:,.0f} DUSK, {prov_entry['epoch_transitions_seen']} transitions)\033[0m")
        
        # Save initial state
        with open(state_file, 'w') as f:
            json.dump(stake_db, f, indent=2)
        
        print(f"\033[92m✓ Created new state\033[0m")
        return stake_db
    
    def _update_stake_state(self, state_file, current_height):
        """Re-query and update stake state"""
        print(f"\033[94m  [UPDATE] Re-querying stake info...\033[0m")
        
        current_epoch = current_height // 2160
        stake_db = {
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "current_block": current_height,
            "current_epoch": current_epoch,
            "provisioners": {}
        }
        
        stored_keys = self._decrypt_keys(self.encryption_password)
        sorted_provisioners = sorted(stored_keys.items(), key=lambda x: int(x[1].get('index', 0)))
        
        for prov_id, data in sorted_provisioners:
            idx = int(data['index'])
            if idx > 2:  # Check indices 0, 1, 2 (all 3 nodes)
                continue
            
            address = data.get('address', 'N/A')
            stake_info_command = f"sozu-beta3-rusk-wallet -w ~/sozu_provisioner -n testnet stake-info --profile-idx {idx}"
            success, output = self.execute_wallet_command(stake_info_command)
            
            prov_entry = {
                "index": idx,
                "provisioner_id": prov_id,
                "address": address,
                "status": "unknown",
                "eligible_stake": 0,
                "slashed_stake": 0,
                "stake_active_from_block": None,
                "stake_active_from_epoch": None,
                "epoch_transitions_seen": 0
            }
            
            if success:
                if "A stake does not exist" in output:
                    prov_entry["status"] = "inactive"
                elif "Eligible stake:" in output:
                    eligible_match = re.search(r'Eligible stake:\s*(\d+(?:\.\d+)?)\s*DUSK', output)
                    if eligible_match:
                        prov_entry["eligible_stake"] = float(eligible_match.group(1))
                    
                    slashed_match = re.search(r'Reclaimable slashed stake:\s*(\d+(?:\.\d+)?)\s*DUSK', output)
                    if slashed_match:
                        prov_entry["slashed_stake"] = float(slashed_match.group(1))
                    
                    active_match = re.search(r'Stake active from block #(\d+) \(Epoch (\d+)\)', output)
                    if active_match:
                        stake_active_block = int(active_match.group(1))
                        stake_active_epoch = int(active_match.group(2))
                        prov_entry["stake_active_from_block"] = stake_active_block
                        prov_entry["stake_active_from_epoch"] = stake_active_epoch
                        
                        blocks_until_active = stake_active_block - current_height
                        
                        if blocks_until_active >= 2160:
                            prov_entry["status"] = "initial stake"  # Just allocated, 0 transitions
                            prov_entry["epoch_transitions_seen"] = 0
                        elif blocks_until_active > 0:
                            prov_entry["status"] = "maturing"  # 1 transition, will activate next epoch
                            prov_entry["epoch_transitions_seen"] = 1
                        else:
                            prov_entry["status"] = "active"
                            blocks_since_active = current_height - stake_active_block
                            prov_entry["epoch_transitions_seen"] = 2 + (blocks_since_active // 2160)
            
            stake_db["provisioners"][str(idx)] = prov_entry
        
        with open(state_file, 'w') as f:
            json.dump(stake_db, f, indent=2)
        
        print(f"\033[92m  ✓ State updated\033[0m")
        for idx_str, prov in stake_db["provisioners"].items():
            print(f"\033[90m    idx {prov['index']}: {prov['status']} ({prov['eligible_stake']:,.0f} DUSK, {prov['epoch_transitions_seen']} trans)\033[0m")
        
        return stake_db
    
    def _check_rotation_trigger(self, stake_db, current_height, current_epoch, last_rotation_epoch):
        """Check if rotation should be triggered (2-node ping-pong: idx 0 ↔ idx 1)"""
        print(f"\033[90m  [CHECK] Rotation trigger...\033[0m", end='')
        
        # Skip if already rotated this epoch
        if last_rotation_epoch == current_epoch:
            print(f" ⏭ Already rotated this epoch")
            return False, None
        
        rotation_trigger_blocks = self.config.get('rotation_trigger_blocks', 50)
        
        # Use categorization for 3-node pipeline
        inactive, maturing, active = self._categorize_nodes_by_transitions(stake_db)
        
        # Must have a maturing provisioner with 1 transition
        if len(maturing) == 0:
            print(f" ❌ No maturing provisioner")
            return False, None
        
        maturing_prov = maturing[0]  # Should only be one
        
        # Check if we're within trigger window
        rotation_block = maturing_prov["stake_active_from_block"] - rotation_trigger_blocks
        
        if current_height >= rotation_block:
            print(f" ✅ TRIGGERED!")
            print(f"\033[93m    Current: {current_height:,} | Trigger: {rotation_block:,} | Will be active: {maturing_prov['stake_active_from_block']:,}\033[0m")
            print(f"\033[93m    Maturing node: idx {maturing_prov['index']} (will take over)\033[0m")
            return True, maturing_prov
        
        blocks_until_trigger = rotation_block - current_height
        print(f" ⏳ {blocks_until_trigger} blocks until trigger")
        return False, None
    
    def _execute_smart_rotation(self, stake_db, target_prov, current_height):
        """Execute rotation: ping-pong between idx 0 and idx 1 only (idx 2 stays at 0)"""
        print(f"\n\033[1m\033[95m{'═' * 70}\033[0m")
        print(f"\033[1m\033[95mEXECUTING SMART ROTATION (2-Node Ping-Pong)\033[0m")
        print(f"\033[1m\033[95m{'═' * 70}\033[0m\n")
        
        # Use categorization to find active node
        inactive, maturing, active = self._categorize_nodes_by_transitions(stake_db)
        
        # FIX: If no active node (externally killed), just top-up maturing node
        if len(active) == 0:
            print(f"\033[93m⚠️  No active provisioner found (externally killed?)\033[0m")
            print(f"\033[93m   Skipping liquidation, will top-up maturing node to max\033[0m\n")
            
            if len(maturing) == 0:
                print(f"\033[91m✗ No maturing provisioner either! Cannot recover.\033[0m")
                return False
            
            maturing_prov = maturing[0]
            
            print(f"\033[93m[RECOVERY] Top-up maturing provisioner (will become active)\033[0m")
            print(f"\033[90m  Index: {maturing_prov['index']}\033[0m")
            print(f"\033[90m  Current stake: {maturing_prov['eligible_stake']:,.0f} DUSK\033[0m\n")
            
            # Check available stake
            available_stake = self._check_available_stake()
            if available_stake is None or available_stake < 1000:
                print(f"\033[91m✗ Insufficient stake ({available_stake if available_stake else 0:,.2f} < 1000)\033[0m")
                return False
            
            stake_limit = self.config.get('stake_limit', 1000000)
            max_per_node = stake_limit - 1000  # 999K for 2-node system
            current_stake = maturing_prov["eligible_stake"]
            desired_to_add = max_per_node - current_stake
            
            # Calculate capacity (include slashed stake!)
            total_staked = sum(prov["eligible_stake"] + prov.get("slashed_stake", 0) for prov in stake_db["provisioners"].values())
            remaining_capacity = stake_limit - total_staked
            
            amount_to_add = min(int(available_stake), int(remaining_capacity), int(desired_to_add))
            
            print(f"\033[90m  Max per node: {max_per_node:,.0f} DUSK\033[0m")
            print(f"\033[90m  Desired to add: {desired_to_add:,.0f} DUSK\033[0m")
            print(f"\033[90m  Available: {available_stake:,.2f} DUSK\033[0m")
            print(f"\033[90m  Will add: {amount_to_add:,.0f} DUSK\033[0m\n")
            
            if amount_to_add < 1000:
                print(f"\033[91m✗ Cannot add sufficient stake ({amount_to_add:,.0f} < 1000)\033[0m")
                return False
            
            success = self._execute_topup(maturing_prov, amount_to_add)
            if success:
                print(f"\n\033[92m✓ Recovery top-up complete! Maturing node ready to take over.\033[0m\n")
                return True
            else:
                print(f"\n\033[91m✗ Recovery top-up failed!\033[0m\n")
                return False
        
        # Normal rotation - active node exists
        active_prov = active[0]
        
        # 2-NODE PING-PONG: Allocate to the OTHER node (0↔1)
        # If active is idx 0, allocate to idx 1
        # If active is idx 1, allocate to idx 0
        # idx 2 stays at 0 DUSK (standby only)
        current_active_idx = active_prov['index']
        if current_active_idx == 0:
            next_index = 1
        elif current_active_idx == 1:
            next_index = 0
        else:
            # Shouldn't happen in 2-node system, but handle it
            print(f"\033[91m✗ Active node is idx {current_active_idx} - expected 0 or 1!\033[0m")
            print(f"\033[93m   Defaulting to idx 0\033[0m")
            next_index = 0
        
        print(f"\033[96m[2-NODE] Ping-pong: idx {current_active_idx} → idx {next_index}\033[0m\n")
        
        # Get the next node (for re-allocation)
        next_node = None
        for idx_str, prov in stake_db["provisioners"].items():
            if prov["index"] == next_index:
                next_node = prov
                break
        
        if not next_node:
            print(f"\033[91m✗ Could not find node idx {next_index}!\033[0m")
            return False
        
        print(f"\033[93m[STEP 1] Liquidate & Terminate active provisioner\033[0m")
        print(f"\033[90m  Killing: idx {active_prov['index']}\033[0m")
        print(f"\033[90m  Current stake: {active_prov['eligible_stake']:,.0f} DUSK\033[0m")
        print(f"\033[90m  Will re-allocate 1K to idx {next_index} after kill\033[0m\n")
        
        # Get provisioner keys
        stored_keys = self._decrypt_keys(self.encryption_password)
        active_prov_id = active_prov["provisioner_id"]
        
        # Execute liquidation
        liquidate_success = self._automated_liquidate_and_terminate(active_prov)
        
        if not liquidate_success:
            print(f"\033[91m✗ Liquidation failed!\033[0m")
            return False
        
        print(f"\033[92m✓ Liquidation complete\033[0m\n")
        
        # Check available stake
        print(f"\033[93m[STEP 2] Check available stake\033[0m")
        available_stake = self._check_available_stake()
        if available_stake is None:
            print(f"\033[91m✗ Could not check available stake\033[0m")
            return False
        
        print(f"\033[92m✓ Available: {available_stake:,.2f} DUSK\033[0m\n")
        
        # Allocate 1000 to killed node (rebuilds pipeline)
        print(f"\033[93m[STEP 3] Allocate 1,000 DUSK back to killed node (idx {next_index})\033[0m")
        print(f"\033[90m  This restarts the pipeline for next rotation\033[0m\n")
        
        if available_stake < 1000:
            print(f"\033[91m✗ Insufficient stake ({available_stake:,.2f} < 1000)\033[0m")
            return False
        
        small_stake_lux = 1000 * 1_000_000_000
        next_prov_id = next_node["provisioner_id"]
        provisioner_sk_next = stored_keys[next_prov_id]['secret_key']
        
        payload_cmd = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet calculate-payload-stake-activate \
  --provisioner-sk {provisioner_sk_next} \
  --amount {small_stake_lux} \
  --network-id {self.config['network_id']}"""
        
        payload_result, payload_output = self.execute_wallet_command(payload_cmd)
        if not payload_result:
            print(f"\033[91m✗ Failed to calculate payload\033[0m")
            return False
        
        payload_match = re.search(r'"([0-9a-fA-F]+)"', payload_output)
        if not payload_match:
            lines = [line.strip() for line in payload_output.split('\n') if line.strip()]
            payload = lines[-1].strip().strip('"') if lines else None
        else:
            payload = payload_match.group(1)
        
        if not payload:
            print(f"\033[91m✗ Could not extract payload\033[0m")
            return False
        
        activate_cmd = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet contract-call \
  --contract-id {self.config['contract_address']} \
  --fn-name stake_activate \
  --fn-args "{payload}" \
  --gas-limit {self.config['gas_limit']}"""
        
        activate_result, _ = self.execute_wallet_command(activate_cmd)
        if not activate_result:
            print(f"\033[91m✗ Failed to allocate 1,000 DUSK\033[0m")
            return False
        
        print(f"\033[92m✓ Allocated 1,000 DUSK to idx {next_index}\033[0m\n")
        available_stake -= 1000
        
        # Top-up target provisioner
        stake_limit = self.config.get('stake_limit', 1000000)
        
        # CRITICAL: Max per node = stake_limit - 1000 (leaves 1000 for each other node)
        max_per_node = stake_limit - 1000  # 999,000 for 1M limit
        current_target_stake = target_prov["eligible_stake"]
        
        # How much can we add to reach the per-node max?
        desired_to_add = max_per_node - current_target_stake
        
        # Calculate what other nodes have staked (for capacity check)
        other_nodes_stake = 1000  # Just allocated 1000 to killed node
        for idx_str, prov in stake_db["provisioners"].items():
            if prov["index"] != target_prov["index"] and prov["index"] != active_prov["index"]:
                other_nodes_stake += prov["eligible_stake"]
        
        remaining_capacity = stake_limit - current_target_stake - other_nodes_stake
        
        # Limited by available stake, remaining capacity, and per-node max
        amount_to_add = min(int(available_stake), int(remaining_capacity), int(desired_to_add))
        
        print(f"\033[93m[STEP 4] Top-up target provisioner\033[0m")
        print(f"\033[90m  Index: {target_prov['index']}\033[0m")
        print(f"\033[90m  Current stake: {current_target_stake:,.0f} DUSK\033[0m")
        print(f"\033[90m  Max per node: {max_per_node:,.0f} DUSK\033[0m")
        print(f"\033[90m  Desired to add: {desired_to_add:,.0f} DUSK\033[0m")
        print(f"\033[90m  Available: {available_stake:,.2f} DUSK\033[0m")
        print(f"\033[90m  Remaining capacity: {remaining_capacity:,.0f} DUSK\033[0m")
        print(f"\033[90m  Will add: {amount_to_add:,.0f} DUSK\033[0m\n")
        
        if amount_to_add <= 0:
            print(f"\033[92m✓ Target already at or near max per-node limit\033[0m")
            return True
        
        amount_to_add_lux = amount_to_add * 1_000_000_000
        target_prov_id = target_prov["provisioner_id"]
        provisioner_sk_new = stored_keys[target_prov_id]['secret_key']
        
        payload_cmd = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet calculate-payload-stake-activate \
  --provisioner-sk {provisioner_sk_new} \
  --amount {amount_to_add_lux} \
  --network-id {self.config['network_id']}"""
        
        payload_result, payload_output = self.execute_wallet_command(payload_cmd)
        if not payload_result:
            print(f"\033[91m✗ Failed to calculate payload\033[0m")
            return False
        
        payload_match = re.search(r'"([0-9a-fA-F]+)"', payload_output)
        if not payload_match:
            lines = [line.strip() for line in payload_output.split('\n') if line.strip()]
            payload = lines[-1].strip().strip('"') if lines else None
        else:
            payload = payload_match.group(1)
        
        if not payload:
            print(f"\033[91m✗ Could not extract payload\033[0m")
            return False
        
        activate_cmd = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet contract-call \
  --contract-id {self.config['contract_address']} \
  --fn-name stake_activate \
  --fn-args "{payload}" \
  --gas-limit {self.config['gas_limit']}"""
        
        activate_result, _ = self.execute_wallet_command(activate_cmd)
        if not activate_result:
            print(f"\033[91m✗ Failed to top-up\033[0m")
            return False
        
        print(f"\033[92m✓ Added {amount_to_add:,.0f} DUSK to idx {target_prov['index']}\033[0m")
        
        print(f"\n\033[1m\033[92m{'═' * 70}\033[0m")
        print(f"\033[1m\033[92m✓ ROTATION COMPLETE!\033[0m")
        print(f"\033[1m\033[92m{'═' * 70}\033[0m\n")
        
        return True
    
    def _check_for_anomaly(self, stake_db, current_height):
        """Bootstrap, conflict detection, and recovery for 3-node pipeline system"""
        print(f"\033[90m  [ANOMALY] Checking...\033[0m", end='')
        
        current_epoch = current_height // 2160
        
        # Categorize all 3 nodes
        inactive, maturing, active = self._categorize_nodes_by_transitions(stake_db)
        
        # Get all nodes (including 0 stake)
        all_nodes = {}
        for idx in [0, 1, 2]:
            for idx_str, prov in stake_db["provisioners"].items():
                if prov["index"] == idx:
                    all_nodes[idx] = prov
                    break
        
        # Check available stake
        available_stake = self._check_available_stake()
        
        # ==================== BOOTSTRAP DETECTION ====================
        
        # BOOTSTRAP 1: All 3 nodes at 0 DUSK (initial bootstrap)
        if len(inactive) == 0 and len(maturing) == 0 and len(active) == 0:
            print(f" 🔧 BOOTSTRAP!")
            print(f"\n\033[1m\033[96m{'=' * 70}\033[0m")
            print(f"\033[1m\033[96m🔧 BOOTSTRAP MODE: All nodes at 0 DUSK\033[0m")
            print(f"\033[1m\033[96m{'=' * 70}\033[0m\n")
            print(f"\033[93m  Allocating maximum stake to Node 0 to start pipeline...\033[0m\n")
            
            if available_stake and available_stake >= 1000:
                stake_limit = self.config.get('stake_limit', 1000000)
                max_per_node = stake_limit - 1000  # Leave room for 1 standby node at 1K each
                can_allocate = min(int(available_stake), max_per_node)
                print(f"\033[94m  [BOOTSTRAP] Allocating {can_allocate:,.0f} DUSK to idx 0 (max per node: {max_per_node:,.0f})...\033[0m")
                success = self._execute_allocation(all_nodes[0], can_allocate)
                if success:
                    print(f"\033[92m  ✅ Bootstrap started! Node 0 will be active in 2 epochs.\033[0m\n")
                    return True
            else:
                print(f"\033[91m  ✗ Insufficient stake ({available_stake if available_stake else 0:,.2f} < 1000)\033[0m\n")
            return True
        
        # BOOTSTRAP 2: Node 0 has stake, nodes 1&2 at 0 (waiting for epoch to allocate node 1)
        if len(inactive) == 1 and inactive[0]["index"] == 0 and len(maturing) == 0 and len(active) == 0:
            print(f" 🔧 BOOTSTRAP STAGE 2")
            print(f"\n\033[1m\033[96m{'=' * 70}\033[0m")
            print(f"\033[1m\033[96m🔧 BOOTSTRAP MODE: Node 0 allocated, waiting for next epoch\033[0m")
            print(f"\033[1m\033[96m{'=' * 70}\033[0m\n")
            print(f"\033[93m  Node 0: {inactive[0]['epoch_transitions_seen']} transitions\033[0m")
            print(f"\033[93m  Will allocate to Node 1 in next epoch to avoid conflict.\033[0m\n")
            return False  # Wait for next epoch
        
        # BOOTSTRAP 3: Node 0 maturing (1 trans), allocate to node 1
        if len(inactive) == 0 and len(maturing) == 1 and maturing[0]["index"] == 0 and len(active) == 0:
            print(f" 🔧 BOOTSTRAP STAGE 3")
            print(f"\n\033[1m\033[96m{'=' * 70}\033[0m")
            print(f"\033[1m\033[96m🔧 BOOTSTRAP MODE: Node 0 maturing, allocate to Node 1\033[0m")
            print(f"\033[1m\033[96m{'=' * 70}\033[0m\n")
            
            if available_stake and available_stake >= 1000:
                can_allocate = min(int(available_stake), 1000)
                print(f"\033[94m  [BOOTSTRAP] Allocating {can_allocate:,.0f} DUSK to idx 1...\033[0m")
                success = self._execute_allocation(all_nodes[1], can_allocate)
                if success:
                    print(f"\033[92m  ✅ Node 1 allocated! 2-node rotation ready.\033[0m")
                    print(f"\033[92m     Node 2 (idx 2) stays at 0 DUSK as standby.\033[0m\n")
                    return True
            else:
                print(f"\033[91m  ✗ Insufficient stake ({available_stake if available_stake else 0:,.2f} < 1000)\033[0m\n")
            return True
        
        # ==================== CONFLICT DETECTION ====================
        
        # Check for nodes that will activate in the same epoch (CRITICAL!)
        conflicts = self._find_activation_conflicts(stake_db, current_epoch)
        
        if conflicts:
            print(f" ⚠️ CONFLICT!")
            for epoch, nodes in conflicts.items():
                print(f"\n\033[1m\033[91m{'!' * 70}\033[0m")
                print(f"\033[1m\033[91m⚠️ CONFLICT: {len(nodes)} nodes will activate in epoch {epoch}!\033[0m")
                print(f"\033[1m\033[91m{'!' * 70}\033[0m\n")
                
                for node in nodes:
                    print(f"\033[93m  - Node idx {node['index']}: {node['epoch_transitions_seen']} transitions, {node['eligible_stake']:,.0f} DUSK\033[0m")
                
                # Deactivate the node with fewer transitions or less stake
                nodes_sorted = sorted(nodes, key=lambda n: (n['epoch_transitions_seen'], n['eligible_stake']))
                node_to_remove = nodes_sorted[0]  # Remove the least progressed one
                
                print(f"\n\033[93m  Removing Node idx {node_to_remove['index']} to resolve conflict...\033[0m")
                
                if node_to_remove['epoch_transitions_seen'] >= 2:
                    # Both nodes are active - defer to two-active-nodes recovery below
                    print(f"\033[93m  ⚠️ Both nodes are active - will use two-active-nodes recovery\033[0m\n")
                    # Don't return - fall through to two-active-nodes check
                else:
                    # Inactive or maturing - use deactivate
                    success = self._execute_deactivate(node_to_remove)
                    if success:
                        print(f"\033[92m  ✅ Conflict resolved!\033[0m\n")
                        return True
        
        
        # ==================== RECOVERY FROM EXTERNAL KILLS ====================
        
        # CRITICAL: Check for two active nodes FIRST (before bootstrap check!)
        # This is a critical rule violation that must be fixed immediately
        if len(active) == 2:
            print(f" 🚨 CRITICAL!")
            print(f"\n\033[1m\033[91m{'!' * 70}\033[0m")
            print(f"\033[1m\033[91m🚨 CRITICAL: TWO ACTIVE NODES DETECTED!\033[0m")
            print(f"\033[1m\033[91m{'!' * 70}\033[0m\n")
            print(f"\033[91m  This violates the core rule: only 1 active node allowed!\033[0m")
            print(f"\033[91m  Likely cause: Script crash during rotation window.\033[0m\n")
            
            # Telegram notification - critical error
            if self.telegram:
                self.telegram.send_critical_error(
                    "Two Active Nodes",
                    f"Both idx {active[0]['index']} ({active[0]['epoch_transitions_seen']} trans, {active[0]['eligible_stake']:,.0f} DUSK) "
                    f"and idx {active[1]['index']} ({active[1]['epoch_transitions_seen']} trans, {active[1]['eligible_stake']:,.0f} DUSK) are active!\n"
                    f"Auto-liquidating to restore single active rule."
                )
            
            # Sort by transitions (more = older), then by stake (less = liquidate if equal transitions)
            # This keeps the higher-staked node when both have same transitions
            active_sorted = sorted(active, key=lambda p: (-p["epoch_transitions_seen"], p["eligible_stake"]))
            node_to_liquidate = active_sorted[0]  # Higher trans OR lower stake
            node_to_keep = active_sorted[1]
            
            print(f"\033[93m  Will liquidate: idx {node_to_liquidate['index']} ({node_to_liquidate['epoch_transitions_seen']} trans, {node_to_liquidate['eligible_stake']:,.0f} DUSK)\033[0m")
            print(f"\033[93m  Will keep: idx {node_to_keep['index']} ({node_to_keep['epoch_transitions_seen']} trans, {node_to_keep['eligible_stake']:,.0f} DUSK)\033[0m")
            print(f"\n\033[93m  ⚡ Liquidating node idx {node_to_liquidate['index']}...\033[0m\n")
            
            # Liquidate selected node
            success = self._automated_liquidate_and_terminate(node_to_liquidate)
            if success:
                print(f"\033[92m  ✅ Older active liquidated! Back to 1 active node.\033[0m")
                print(f"\033[92m  Normal rotation will handle balancing in next cycle.\033[0m\n")
                # IMPORTANT: Return True to force state refresh
                # Don't try to top-up anything yet - wait for normal rotation
                return True
            else:
                print(f"\033[91m  ✗ Failed to liquidate! Manual intervention needed.\033[0m\n")
                return True
        
        # CRITICAL: Distinguish between bootstrap, normal operation, and incomplete pipeline
        nodes_with_stake = sum(1 for prov in stake_db["provisioners"].values() if prov["eligible_stake"] > 0)
        
        # TRUE BOOTSTRAP: No active node yet (building initial pipeline)
        if len(active) == 0:
            print(f" ✓ OK (Bootstrap: {nodes_with_stake}/3 nodes staked, building initial pipeline)")
            return False
        
        # NORMAL OPERATION: Have active + maturing (rotation ready!)
        if len(active) > 0 and len(maturing) > 0:
            print(f" ✓ OK (Normal: {nodes_with_stake}/3 nodes staked, rotation ready)")
            return False
        
        # INCOMPLETE PIPELINE: Have active but no maturing (can't rotate yet)
        if len(active) > 0 and len(maturing) == 0:
            print(f" ✓ OK (Incomplete: {nodes_with_stake}/3 nodes staked, rebuilding pipeline)")
            return False
        
        # RECOVERY 1: No active node (active was killed/crashed)
        if len(active) == 0 and len(maturing) > 0:
            print(f" 🔧 RECOVERY")
            print(f"\n\033[1m\033[93m{'!' * 70}\033[0m")
            print(f"\033[1m\033[93m🔧 RECOVERY: No active node detected (killed/crashed)\033[0m")
            print(f"\033[1m\033[93m{'!' * 70}\033[0m\n")
            print(f"\033[93m  Maturing node will take over next epoch.\033[0m")
            print(f"\033[93m  ⚡ CRITICAL: Top-up maturing node NOW (penalty-free!)\\033[0m\n")
            
            # Get the maturing node (should be exactly 1)
            maturing_node = maturing[0]
            
            # Telegram notification - recovery action
            if self.telegram:
                self.telegram.send_recovery_action(
                    "No Active Node",
                    f"Maturing node (idx {maturing_node['index']}) will take over.\n"
                    f"Topping up to 998K DUSK (penalty-free!)"
                )
            
            current_stake = maturing_node["eligible_stake"]
            
            # Calculate max we can add (penalty-free since maturing!)
            stake_limit = self.config.get('stake_limit', 1000000)
            max_per_node = stake_limit - 1000  # Leave 1K for each other node
            target_stake = max_per_node
            to_add = target_stake - current_stake
            
            print(f"\033[93m  Maturing node: idx {maturing_node['index']}\033[0m")
            print(f"\033[93m  Current: {current_stake:,.0f} DUSK\033[0m")
            print(f"\033[93m  Target: {target_stake:,.0f} DUSK\033[0m")
            print(f"\033[93m  Adding: {to_add:,.0f} DUSK\033[0m")
            print(f"\033[92m  ✓ NO PENALTY (maturing node = 1 transition)\033[0m\n")
            
            # Check available stake
            available_stake = self._check_available_stake()
            if available_stake and available_stake >= to_add:
                print(f"\033[94m  [RECOVERY] Topping up maturing node to {target_stake:,.0f} DUSK...\033[0m")
                success = self._execute_topup(maturing_node, to_add)
                if success:
                    print(f"\033[92m  ✅ Maturing node topped up! Will be active at full capacity next epoch.\033[0m\n")
                    return True
                else:
                    print(f"\033[91m  ✗ Top-up failed!\033[0m\n")
                    return False
            else:
                print(f"\033[91m  ✗ Insufficient stake ({available_stake if available_stake else 0:,.2f} < {to_add:,.0f})\033[0m")
                print(f"\033[93m  Maturing node will take over but with low stake.\033[0m\n")
                return False
        
        # RECOVERY 2: Missing stages in pipeline
        expected_stages = 3  # Should have: 1 inactive, 1 maturing, 1 active
        actual_stages = len(inactive) + len(maturing) + len(active)
        
        if actual_stages < expected_stages and actual_stages > 0:
            print(f" 🔧 INCOMPLETE")
            print(f"\n\033[1m\033[93m{'!' * 70}\033[0m")
            print(f"\033[1m\033[93m🔧 INCOMPLETE PIPELINE: {actual_stages}/3 stages filled\033[0m")
            print(f"\033[1m\033[93m{'!' * 70}\033[0m\n")
            print(f"\033[93m  Inactive: {len(inactive)}, Maturing: {len(maturing)}, Active: {len(active)}\033[0m")
            print(f"\033[93m  Will rebuild pipeline through normal allocation logic.\033[0m\n")
            return False
        
        print(f" ✓ OK")
        return False
    
    def _check_and_topup(self, stake_db, current_height, state_file, rotation_target=None):
        """Check for top-up opportunities and execute if beneficial"""
        print(f"\033[94m  [TOPUP] Checking opportunities...\033[0m")
        
        # PAUSE during rotation window to avoid conflicts
        if rotation_target:
            rotation_trigger_blocks = self.config.get('rotation_trigger_blocks', 50)
            activation_block = rotation_target["stake_active_from_block"]
            trigger_block = activation_block - rotation_trigger_blocks
            blocks_until_trigger = trigger_block - current_height
            
            # If we're within the rotation window, skip top-up
            if blocks_until_trigger <= rotation_trigger_blocks and blocks_until_trigger >= 0:
                print(f"\033[93m    ⏸ Skipping top-up (in rotation window: {blocks_until_trigger} blocks until trigger)\033[0m")
                return stake_db
        
        # Check available stake
        available_stake = self._check_available_stake()
        if available_stake is None or available_stake < 1000:
            print(f"\033[90m    Available: {available_stake if available_stake else 0:,.2f} DUSK (< 1000, skip)\033[0m")
            return stake_db
        
        print(f"\033[92m    Available in contract: {available_stake:,.2f} DUSK\033[0m")
        
        # Calculate TOTAL committed across ALL provisioners (eligible + slashed)
        # Slashed stake counts against the total limit!
        total_staked = sum(prov["eligible_stake"] + prov.get("slashed_stake", 0) for prov in stake_db["provisioners"].values())
        stake_limit = self.config.get('stake_limit', 1000000)
        remaining_capacity = stake_limit - total_staked
        
        print(f"\033[90m    Total committed across all provs: {total_staked:,.0f} DUSK (eligible + slashed)\033[0m")
        print(f"\033[90m    Stake limit: {stake_limit:,.0f} DUSK\033[0m")
        print(f"\033[90m    Remaining capacity: {remaining_capacity:,.0f} DUSK\033[0m")
        
        if remaining_capacity < 1000:
            print(f"\033[93m    ⚠ No capacity for allocation (remaining: {remaining_capacity:,.0f} DUSK)\033[0m")
            return stake_db
        
        # Use categorization for 3-node pipeline
        inactive, maturing, active = self._categorize_nodes_by_transitions(stake_db)
        
        print(f"\033[90m    Pipeline: {len(inactive)} inactive, {len(maturing)} maturing, {len(active)} active\033[0m")
        
        # Priority 0: Top-up ACTIVE provisioner (accepts 10% penalty, better than no active)
        if len(active) > 0:
            active_prov = active[0]
            current_stake = active_prov["eligible_stake"]
            
            # CRITICAL: Max per node = stake_limit - 1000
            max_per_node = stake_limit - 1000
            max_can_add = max_per_node - current_stake
            
            # CRITICAL: Check slashed stake constraint (2% of stake_limit)
            total_slashed = sum(prov["slashed_stake"] for prov in stake_db["provisioners"].values())
            max_slashed_total = stake_limit * 0.02  # 2% of stake limit
            slashed_headroom = max_slashed_total - total_slashed
            
            if slashed_headroom < 0:
                slashed_headroom = 0
            
            # Topping up active node creates 10% slashed stake
            # We need: total_slashed + (amount * 0.10) <= max_slashed_total
            # Therefore: amount <= slashed_headroom / 0.10
            max_by_slashed = slashed_headroom / 0.10
            
            if max_can_add > 0 and slashed_headroom > 0:
                # Can add as much as available, capacity, per-node max, AND slashed constraint
                can_add = min(int(available_stake), int(remaining_capacity), int(max_can_add), int(max_by_slashed))
                
                if can_add >= 1000:
                    print(f"\033[93m    → Top-up ACTIVE prov idx {active_prov['index']} (accepts 10% penalty)\033[0m")
                    print(f"\033[90m      Current: {current_stake:,.0f} | Max per node: {max_per_node:,.0f}\033[0m")
                    print(f"\033[90m      Slashed: {total_slashed:,.0f} / {max_slashed_total:,.0f} (max 2% of {stake_limit:,.0f})\033[0m")
                    print(f"\033[90m      Will create ~{can_add * 0.10:,.0f} slashed | Can add: {can_add:,.0f}\033[0m")
                    success = self._execute_topup(active_prov, can_add)
                    if success:
                        # Update state immediately after successful top-up
                        print(f"\033[94m      [UPDATE] Refreshing state after top-up...\033[0m")
                        stake_db = self._update_stake_state(state_file, current_height)
                    return stake_db
                elif slashed_headroom < 1000:
                    print(f"\033[90m    Active prov exists but slashed limit reached ({total_slashed:,.0f} / {max_slashed_total:,.0f})\033[0m")
                else:
                    print(f"\033[90m    Active prov exists but insufficient capacity to top-up\033[0m")
            elif slashed_headroom <= 0:
                print(f"\033[90m    Active prov exists but slashed limit reached ({total_slashed:,.0f} >= {max_slashed_total:,.0f})\033[0m")
            elif max_can_add <= 0:
                print(f"\033[90m    Active prov idx {active_prov['index']} already at max ({current_stake:,.0f} >= {max_per_node:,.0f})\033[0m")
        
        # Priority 1: Top-up maturing provisioner with 1 transition
        if len(maturing) > 0:
            maturing_prov = maturing[0]  # Should only be one
            current_stake = maturing_prov["eligible_stake"]
            
            # CRITICAL: Max per node = stake_limit - 1000 (leaves 1000 for each other node)
            max_per_node = stake_limit - 1000
            max_can_add = max_per_node - current_stake
            
            if max_can_add <= 0:
                print(f"\033[90m    Maturing prov idx {maturing_prov['index']} already at max ({current_stake:,.0f} >= {max_per_node:,.0f})\033[0m")
            else:
                # Can add as much as available, within capacity, and within per-node max
                can_add = min(int(available_stake), int(remaining_capacity), int(max_can_add))
                
                if can_add >= 1000:
                    print(f"\033[93m    → Top-up maturing prov idx {maturing_prov['index']}\033[0m")
                    print(f"\033[90m      Current: {current_stake:,.0f} | Max per node: {max_per_node:,.0f} | Can add: {can_add:,.0f}\033[0m")
                    success = self._execute_topup(maturing_prov, can_add)
                    if success:
                        # Update state immediately after successful top-up
                        print(f"\033[94m      [UPDATE] Refreshing state after top-up...\033[0m")
                        stake_db = self._update_stake_state(state_file, current_height)
                    return stake_db
                else:
                    print(f"\033[90m    Maturing prov idx {maturing_prov['index']} exists but insufficient capacity to top-up\033[0m")
        
        # Priority 2: Allocate to inactive provisioner (but check for conflicts!)
        if len(inactive) > 0:
            # Sort by index to allocate in sequence
            inactive_sorted = sorted(inactive, key=lambda p: p["index"])
            
            conflict = False  # Initialize before loop
            
            # Try to find one that won't conflict AND has 0 stake
            for inactive_prov in inactive_sorted:
                # CRITICAL: Skip nodes that already have stake (in "initial stake" state)
                # Only allocate to truly empty nodes (0 DUSK)
                if inactive_prov["eligible_stake"] > 0:
                    continue
                
                # Check: will this node activate in same epoch as another?
                current_epoch = current_height // 2160
                
                # This node would activate in current_epoch + 2
                this_activation_epoch = current_epoch + 2
                
                # Check if anyone else is activating then
                conflict = False  # Reset for this candidate
                for prov in stake_db["provisioners"].values():
                    if prov["index"] == inactive_prov["index"]:
                        continue
                    if prov["eligible_stake"] > 0:
                        trans = prov["epoch_transitions_seen"]
                        epochs_until = 2 - trans
                        other_activation = current_epoch + epochs_until
                        
                        if other_activation == this_activation_epoch:
                            conflict = True
                            print(f"\033[90m      Skipping idx {inactive_prov['index']} - would conflict with idx {prov['index']} in epoch {this_activation_epoch}\033[0m")
                            break
                
                if not conflict:
                    # Safe to allocate
                    can_allocate = min(int(available_stake), int(remaining_capacity), 1000)
                    
                    if can_allocate >= 1000:
                        print(f"\033[93m    → Allocate to inactive prov idx {inactive_prov['index']} (start maturing!)\033[0m")
                        print(f"\033[90m      Amount: {can_allocate:,.0f} DUSK\033[0m")
                        success = self._execute_allocation(inactive_prov, can_allocate)
                        if success:
                            # Update state immediately after successful allocation
                            print(f"\033[94m      [UPDATE] Refreshing state after allocation...\033[0m")
                            stake_db = self._update_stake_state(state_file, current_height)
                        return stake_db
                    else:
                        print(f"\033[90m    Insufficient capacity for allocation ({can_allocate:,.0f} < 1000)\033[0m")
                        break
            
            if conflict:
                print(f"\033[90m    All inactive nodes would create conflicts - waiting\033[0m")
        
        else:
            print(f"\033[90m    No allocation opportunities (all nodes in use)\033[0m")
        
        return stake_db
    
    def _execute_topup(self, prov, amount):
        """Execute top-up for a provisioner"""
        # SAFETY CHECK: Ensure we don't exceed per-node maximum
        stake_limit = self.config.get('stake_limit', 1000000)
        max_per_node = stake_limit - 1000  # Leave 1K for each of the other 2 nodes
        current_stake = prov["eligible_stake"]
        new_total = current_stake + amount
        
        if new_total > max_per_node:
            print(f"\033[91m      [SAFETY] ✗ Top-up rejected: would exceed per-node max!\033[0m")
            print(f"\033[91m         Current: {current_stake:,.0f} | Adding: {amount:,.0f} | Would be: {new_total:,.0f} | Max: {max_per_node:,.0f}\033[0m")
            return False
        
        print(f"\033[94m      [EXEC] Topping up {amount:,.0f} DUSK...\033[0m")
        print(f"\033[90m         New total will be: {new_total:,.0f} / {max_per_node:,.0f} (per-node max)\033[0m")
        
        stored_keys = self._decrypt_keys(self.encryption_password)
        prov_id = prov["provisioner_id"]
        provisioner_sk = stored_keys[prov_id]['secret_key']
        
        amount_lux = amount * 1_000_000_000
        
        payload_cmd = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet calculate-payload-stake-activate \
  --provisioner-sk {provisioner_sk} \
  --amount {amount_lux} \
  --network-id {self.config['network_id']}"""
        
        payload_result, payload_output = self.execute_wallet_command(payload_cmd)
        if not payload_result:
            print(f"\033[91m      ✗ Payload failed\033[0m")
            return False
        
        payload_match = re.search(r'"([0-9a-fA-F]+)"', payload_output)
        if not payload_match:
            lines = [line.strip() for line in payload_output.split('\n') if line.strip()]
            payload = lines[-1].strip().strip('"') if lines else None
        else:
            payload = payload_match.group(1)
        
        if not payload:
            print(f"\033[91m      ✗ No payload\033[0m")
            return False
        
        activate_cmd = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet contract-call \
  --contract-id {self.config['contract_address']} \
  --fn-name stake_activate \
  --fn-args "{payload}" \
  --gas-limit {self.config['gas_limit']}"""
        
        activate_result, _ = self.execute_wallet_command(activate_cmd)
        if activate_result:
            print(f"\033[92m      ✓ Top-up complete!\033[0m")
            
            # Send Telegram notification
            if self.telegram:
                self.telegram.send_topup(
                    idx=prov['index'],
                    amount=amount,
                    current_stake=current_stake,
                    new_stake=new_total
                )
            
            return True
        else:
            print(f"\033[91m      ✗ Activation failed\033[0m")
            return False
    
    def _categorize_nodes_by_transitions(self, stake_db):
        """Categorize all 3 nodes by transition count for pipeline management"""
        inactive = []   # 0 transitions
        maturing = []   # 1 transition
        active = []     # 2+ transitions
        
        for idx_str, prov in stake_db["provisioners"].items():
            if prov["index"] not in [0, 1, 2]:
                continue
            
            trans = prov["epoch_transitions_seen"]
            
            # Categorize by transitions (including nodes with 0 stake)
            if trans == 0:
                inactive.append(prov)
            elif trans == 1:
                maturing.append(prov)
            else:  # trans >= 2
                active.append(prov)
        
        return inactive, maturing, active
    
    def _find_activation_conflicts(self, stake_db, current_epoch):
        """Find nodes that will activate in the same epoch (CRITICAL BUG!)"""
        activation_map = {}
        
        for idx_str, prov in stake_db["provisioners"].items():
            if prov["index"] not in [0, 1, 2]:
                continue
            
            if prov["eligible_stake"] > 0:
                trans = prov["epoch_transitions_seen"]
                epochs_until_active = 2 - trans
                
                if epochs_until_active >= 0:
                    activation_epoch = current_epoch + epochs_until_active
                    
                    if activation_epoch not in activation_map:
                        activation_map[activation_epoch] = []
                    activation_map[activation_epoch].append(prov)
        
        # Return conflicts (epochs with >1 node)
        conflicts = {}
        for epoch, nodes in activation_map.items():
            if len(nodes) > 1:
                conflicts[epoch] = nodes
        
        return conflicts
    
    def _execute_deactivate(self, prov):
        """Deactivate an inactive or maturing provisioner (makes stake immediately available)"""
        print(f"\033[93m      [DEACTIVATE] Removing stake from idx {prov['index']} (transitions: {prov['epoch_transitions_seen']})...\033[0m")
        
        # Get the address from stored keys (same as manual function)
        stored_keys = self._decrypt_keys(self.encryption_password)
        prov_id = prov["provisioner_id"]
        
        # The manual function uses data['address'], not the prov_id key!
        provisioner_address = stored_keys[prov_id]['address']
        
        # STEP 1: Calculate deactivation payload (EXACTLY like manual function)
        print(f"\033[94m      [STEP 1] Calculating deactivation payload...\033[0m")
        payload_command = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet calculate-payload-stake-deactivate \
  --provisioner {provisioner_address}"""
        
        payload_result, payload_output = self.execute_wallet_command(payload_command)
        if not payload_result:
            print(f"\033[91m      ✗ Payload calculation failed\033[0m")
            return False
        
        # Extract payload (EXACTLY like manual function)
        payload_match = re.search(r'"([0-9a-fA-F]+)"', payload_output)
        if not payload_match:
            lines = [line.strip() for line in payload_output.split('\n') if line.strip()]
            payload = lines[-1].strip().strip('"') if lines else None
        else:
            payload = payload_match.group(1)
        
        if not payload:
            print(f"\033[91m      ✗ Could not extract payload\033[0m")
            return False
        
        print(f"\033[92m      ✓ Payload generated\033[0m")
        
        # STEP 2: Execute stake deactivation (EXACTLY like manual function)
        print(f"\033[94m      [STEP 2] Executing stake deactivation...\033[0m")
        deactivate_command = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet contract-call \
  --contract-id {self.config['contract_address']} \
  --fn-name stake_deactivate \
  --fn-args "{payload}" \
  --gas-limit {self.config['gas_limit']}"""
        
        deactivate_result, _ = self.execute_wallet_command(deactivate_command)
        if deactivate_result:
            print(f"\033[92m      ✓ Stake deactivated (now available in contract)\033[0m")
            return True
        else:
            print(f"\033[91m      ✗ Deactivation failed\033[0m")
            return False
    
    def _execute_allocation(self, prov, amount):
        """Execute initial allocation to inactive provisioner"""
        # SAFETY CHECK: Ensure we don't exceed per-node maximum
        stake_limit = self.config.get('stake_limit', 1000000)
        max_per_node = stake_limit - 1000  # Leave 1K for each of the other 2 nodes
        current_stake = prov["eligible_stake"]
        new_total = current_stake + amount
        
        if new_total > max_per_node:
            print(f"\033[91m      [SAFETY] ✗ Allocation rejected: would exceed per-node max!\033[0m")
            print(f"\033[91m         Current: {current_stake:,.0f} | Adding: {amount:,.0f} | Would be: {new_total:,.0f} | Max: {max_per_node:,.0f}\033[0m")
            return False
        
        print(f"\033[94m      [EXEC] Allocating {amount:,.0f} DUSK...\033[0m")
        print(f"\033[90m         New total will be: {new_total:,.0f} / {max_per_node:,.0f} (per-node max)\033[0m")
        
        stored_keys = self._decrypt_keys(self.encryption_password)
        prov_id = prov["provisioner_id"]
        provisioner_sk = stored_keys[prov_id]['secret_key']
        
        amount_lux = amount * 1_000_000_000
        
        payload_cmd = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet calculate-payload-stake-activate \
  --provisioner-sk {provisioner_sk} \
  --amount {amount_lux} \
  --network-id {self.config['network_id']}"""
        
        payload_result, payload_output = self.execute_wallet_command(payload_cmd)
        if not payload_result:
            print(f"\033[91m      ✗ Payload failed\033[0m")
            return False
        
        payload_match = re.search(r'"([0-9a-fA-F]+)"', payload_output)
        if not payload_match:
            lines = [line.strip() for line in payload_output.split('\n') if line.strip()]
            payload = lines[-1].strip().strip('"') if lines else None
        else:
            payload = payload_match.group(1)
        
        if not payload:
            print(f"\033[91m      ✗ No payload\033[0m")
            return False
        
        activate_cmd = f"""sozu-beta3-rusk-wallet -w ~/sozu_operator -n testnet contract-call \
  --contract-id {self.config['contract_address']} \
  --fn-name stake_activate \
  --fn-args "{payload}" \
  --gas-limit {self.config['gas_limit']}"""
        
        activate_result, _ = self.execute_wallet_command(activate_cmd)
        if activate_result:
            print(f"\033[92m      ✓ Allocation complete! Provisioner now maturing.\033[0m")
            return True
        else:
            print(f"\033[91m      ✗ Activation failed\033[0m")
            return False

    
    def show_configuration(self):
        """Option 8: Configuration"""
        config_menu_items = [
            "Edit Network ID",
            "Edit Contract Address",
            "Edit Gas Limit",
            "Edit Operator Address",
            "Edit Stake Limit",
            "Edit Rotation Trigger Blocks",
            "Edit Rotation Check Interval",
            "Edit Top-up Check Interval",
            "Configure Telegram Notifications",
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
            self.stdscr.addstr(y_pos, 2, f"Rotation Check:     {self.config.get('rotation_check_interval', 10)} seconds")
            y_pos += 1
            self.stdscr.addstr(y_pos, 2, f"Top-up Interval:    {self.config.get('topup_check_interval', 30)} seconds")
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
                if selected_idx == 10:  # Return to Main Menu
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
        
        elif option == 7:  # Edit Rotation Check Interval
            new_value = input(f"\n\033[96mEnter Rotation Check Interval (seconds, current: {self.config.get('rotation_check_interval', 10)}): \033[0m").strip()
            try:
                interval = int(new_value)
                if interval <= 0:
                    print(f"\033[91m✗ Interval must be greater than 0 seconds\033[0m")
                else:
                    self.config['rotation_check_interval'] = interval
                    self._save_config()
                    print(f"\033[92m✓ Rotation Check Interval updated to {self.config['rotation_check_interval']} seconds\033[0m")
            except ValueError:
                print(f"\033[91m✗ Invalid value. Must be a number.\033[0m")
            input("\nPress Enter to continue...")
        
        elif option == 8:  # Edit Top-up Check Interval
            new_value = input(f"\n\033[96mEnter Top-up Check Interval (seconds, current: {self.config.get('topup_check_interval', 30)}): \033[0m").strip()
            try:
                interval = int(new_value)
                if interval <= 0:
                    print(f"\033[91m✗ Interval must be greater than 0 seconds\033[0m")
                else:
                    self.config['topup_check_interval'] = interval
                    self._save_config()
                    print(f"\033[92m✓ Top-up Check Interval updated to {self.config['topup_check_interval']} seconds\033[0m")
            except ValueError:
                print(f"\033[91m✗ Invalid value. Must be a number.\033[0m")
            input("\nPress Enter to continue...")
        
        elif option == 9:  # Configure Telegram Notifications
            self._configure_telegram()
        
        elif option == 10:  # Set/Update Wallet Password
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
        
        elif option == 11:  # Reset to Defaults
            confirm = input(f"\n\033[93mReset to default testnet values? (yes/no): \033[0m").strip().lower()
            if confirm in ['yes', 'y']:
                self.config['network_id'] = 2
                self.config['contract_address'] = "72883945ac1aa032a88543aacc9e358d1dfef07717094c05296ce675f23078f2"
                self.config['gas_limit'] = 2000000
                self.config['operator_address'] = ""
                self.config['stake_limit'] = 1000000
                self.config['rotation_trigger_blocks'] = 50
                self.config['rotation_check_interval'] = 10
                self.config['topup_check_interval'] = 30
                # Don't reset wallet password
                self._save_config()
                print(f"\033[92m✓ Configuration reset to defaults (wallet password preserved)\033[0m")
            else:
                print(f"\033[93mReset cancelled\033[0m")
            input("\nPress Enter to continue...")
        
        # Reinitialize curses
        self._reinit_curses()
    
    def _configure_telegram(self):
        """Configure Telegram notifications"""
        print(f"\n\033[1m\033[96m{'=' * 70}\033[0m")
        print(f"\033[1m\033[96mCONFIGURE TELEGRAM NOTIFICATIONS\033[0m")
        print(f"\033[1m\033[96m{'=' * 70}\033[0m\n")
        
        # Initialize telegram config if it doesn't exist
        if 'telegram' not in self.config:
            self.config['telegram'] = {
                'enabled': False,
                'bot_token': '',
                'chat_id': '',
                'notify_on': {
                    'epoch_transitions': True,
                    'rotations': True,
                    'critical_errors': True,
                    'health_warnings': True,
                    'recovery_actions': True
                }
            }
        
        telegram_config = self.config['telegram']
        
        # Show current status
        print(f"\033[93mCurrent Status:\033[0m")
        print(f"  Enabled: {telegram_config.get('enabled', False)}")
        print(f"  Bot Token: {'*' * 20 if telegram_config.get('bot_token') else '(not set)'}")
        print(f"  Chat ID: {telegram_config.get('chat_id', '(not set)')}\n")
        
        # Menu
        print(f"\033[96mWhat would you like to do?\033[0m")
        print(f"  1. Enable Telegram notifications")
        print(f"  2. Disable Telegram notifications")
        print(f"  3. Set Bot Token")
        print(f"  4. Set Chat ID")
        print(f"  5. Configure notification types")
        print(f"  6. Test Telegram (send test message)")
        print(f"  7. Setup Guide")
        print(f"  8. Return to Configuration Menu\n")
        
        choice = input(f"\033[96mSelect option (1-8): \033[0m").strip()
        
        if choice == '1':
            # Enable
            telegram_config['enabled'] = True
            self._save_config()
            print(f"\n\033[92m✓ Telegram notifications ENABLED\033[0m")
            if not telegram_config.get('bot_token') or not telegram_config.get('chat_id'):
                print(f"\033[93m⚠ Remember to set Bot Token and Chat ID!\033[0m")
        
        elif choice == '2':
            # Disable
            telegram_config['enabled'] = False
            self._save_config()
            print(f"\n\033[93mTelegram notifications DISABLED\033[0m")
        
        elif choice == '3':
            # Set Bot Token
            print(f"\n\033[96mGet your bot token from @BotFather in Telegram\033[0m")
            print(f"\033[90mExample: 123456789:ABCdefGHIjklMNOpqrsTUVwxyz\033[0m\n")
            bot_token = input(f"\033[96mEnter Bot Token: \033[0m").strip()
            if bot_token:
                telegram_config['bot_token'] = bot_token
                self._save_config()
                print(f"\n\033[92m✓ Bot Token saved\033[0m")
            else:
                print(f"\n\033[91m✗ Bot Token cannot be empty\033[0m")
        
        elif choice == '4':
            # Set Chat ID
            print(f"\n\033[96mGet your chat ID from @userinfobot in Telegram\033[0m")
            print(f"\033[90mExample: 123456789\033[0m\n")
            chat_id = input(f"\033[96mEnter Chat ID: \033[0m").strip()
            if chat_id:
                telegram_config['chat_id'] = chat_id
                self._save_config()
                print(f"\n\033[92m✓ Chat ID saved\033[0m")
            else:
                print(f"\n\033[91m✗ Chat ID cannot be empty\033[0m")
        
        elif choice == '5':
            # Configure notification types
            print(f"\n\033[96mConfigure which events trigger notifications:\033[0m\n")
            notify_config = telegram_config.get('notify_on', {})
            
            for key in ['epoch_transitions', 'rotations', 'critical_errors', 'health_warnings', 'recovery_actions']:
                current = notify_config.get(key, True)
                status = "ENABLED" if current else "DISABLED"
                toggle = input(f"  {key.replace('_', ' ').title()} [{status}] - Toggle? (y/n): ").strip().lower()
                if toggle == 'y':
                    notify_config[key] = not current
            
            telegram_config['notify_on'] = notify_config
            self._save_config()
            print(f"\n\033[92m✓ Notification preferences saved\033[0m")
        
        elif choice == '6':
            # Test Telegram
            if not telegram_config.get('enabled'):
                print(f"\n\033[93m⚠ Telegram is disabled. Enable it first!\033[0m")
            elif not telegram_config.get('bot_token') or not telegram_config.get('chat_id'):
                print(f"\n\033[91m✗ Bot Token and Chat ID must be set first!\033[0m")
            else:
                print(f"\n\033[96mSending test message...\033[0m\n")
                try:
                    url = f"https://api.telegram.org/bot{telegram_config['bot_token']}/sendMessage"
                    message = f"""✅ *Test Message*

This is a test from Provisioner Manager v2.1.0

If you received this, Telegram is working correctly!

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""
                    
                    payload = {
                        'chat_id': telegram_config['chat_id'],
                        'text': message,
                        'parse_mode': 'Markdown'
                    }
                    
                    response = requests.post(url, json=payload, timeout=10)
                    
                    if response.status_code == 200:
                        print(f"\033[92m✓ SUCCESS! Check your Telegram for the test message.\033[0m")
                        result = response.json()
                        print(f"\033[90m  Message ID: {result.get('result', {}).get('message_id', 'unknown')}\033[0m")
                    else:
                        print(f"\033[91m✗ FAILED (HTTP {response.status_code})\033[0m")
                        print(f"\033[93m  Response: {response.text}\033[0m")
                except Exception as e:
                    print(f"\033[91m✗ Error: {str(e)}\033[0m")
        
        elif choice == '7':
            # Setup Guide
            print(f"\n\033[1m\033[96mTELEGRAM SETUP GUIDE\033[0m")
            print(f"\033[94m{'─' * 70}\033[0m\n")
            print(f"\033[96mStep 1: Create a Bot\033[0m")
            print(f"  1. Open Telegram and search for @BotFather")
            print(f"  2. Send /newbot")
            print(f"  3. Follow prompts to name your bot")
            print(f"  4. Copy the bot token (looks like: 123456789:ABCdef...)")
            print(f"  5. Use option 3 above to save the bot token\n")
            
            print(f"\033[96mStep 2: Get Your Chat ID\033[0m")
            print(f"  1. Search for @userinfobot in Telegram")
            print(f"  2. Start a chat with it")
            print(f"  3. It will show your Chat ID (a number)")
            print(f"  4. Use option 4 above to save the chat ID\n")
            
            print(f"\033[96mStep 3: Start Chat with Your Bot\033[0m")
            print(f"  1. Search for your bot in Telegram (by name)")
            print(f"  2. Click START")
            print(f"  3. This is REQUIRED or bot can't send you messages!\n")
            
            print(f"\033[96mStep 4: Test\033[0m")
            print(f"  1. Use option 1 to enable Telegram")
            print(f"  2. Use option 6 to send a test message")
            print(f"  3. You should receive the message in Telegram\n")
            
            print(f"\033[93mNote: Bot token and chat ID are stored in config.json\033[0m")
            print(f"\033[93mMake sure config.json has secure permissions (600)\033[0m")
        
        elif choice == '8':
            # Return
            pass
        
        else:
            print(f"\n\033[91m✗ Invalid option\033[0m")
        
        input("\nPress Enter to continue...")


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
    # Telegram health check BEFORE curses starts
    print(f"\n\033[90m[DEBUG] Script starting...\033[0m")
    
    try:
        storage_dir = Path.home() / ".provisioner_manager"
        config_file = storage_dir / "config.json"
        
        print(f"\033[90m[DEBUG] Checking config file: {config_file}\033[0m")
        print(f"\033[90m[DEBUG] Config exists: {config_file.exists()}\033[0m")
        
        if config_file.exists():
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            print(f"\033[90m[DEBUG] Config loaded successfully\033[0m")
            
            telegram_config = config.get('telegram', {})
            print(f"\033[90m[DEBUG] Telegram config present: {bool(telegram_config)}\033[0m")
            print(f"\033[90m[DEBUG] Telegram enabled: {telegram_config.get('enabled', False)}\033[0m")
            
            if telegram_config.get('enabled', False):
                bot_token = telegram_config.get('bot_token', '')
                chat_id = telegram_config.get('chat_id', '')
                
                print(f"\033[90m[DEBUG] Bot token present: {bool(bot_token)}\033[0m")
                print(f"\033[90m[DEBUG] Chat ID present: {bool(chat_id)}\033[0m")
                
                if bot_token and chat_id:
                    print(f"\n\033[94m{'=' * 70}\033[0m")
                    print(f"\033[96mTelegram Health Check\033[0m")
                    print(f"\033[94m{'=' * 70}\033[0m")
                    print(f"\nBot Token: {bot_token[:20]}...")
                    print(f"Chat ID: {chat_id}")
                    
                    message = f"""✅ *Provisioner Manager Started*

Version: 2.1.0
System: 2-Node Rotation (idx 0 ↔ idx 1)
Telegram: Connected

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

You will receive notifications for:
• Epoch transitions (silent)
• Rotations (idx 0 ↔ idx 1)
• Top-ups (maturing nodes)
• Critical errors
• Recovery actions
• Health warnings"""

                    print(f"\nSending test message to Telegram...")
                    
                    try:
                        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
                        payload = {
                            'chat_id': chat_id,
                            'text': message,
                            'parse_mode': 'Markdown',
                            'disable_notification': False
                        }
                        
                        print(f"URL: {url[:50]}...")
                        print(f"Payload keys: {list(payload.keys())}")
                        print(f"Calling requests.post...")
                        
                        response = requests.post(url, json=payload, timeout=10)
                        
                        print(f"\nHTTP Status: {response.status_code}")
                        
                        if response.status_code == 200:
                            print(f"\n\033[92m✓ SUCCESS! Telegram message sent!\033[0m")
                            print(f"\033[92m  Check your Telegram for the startup message.\033[0m")
                            result = response.json()
                            print(f"\033[90m  Message ID: {result.get('result', {}).get('message_id', 'unknown')}\033[0m")
                        else:
                            print(f"\n\033[91m✗ FAILED (HTTP {response.status_code})\033[0m")
                            print(f"\033[93m  Response: {response.text}\033[0m")
                            print(f"\n\033[93mCommon issues:\033[0m")
                            print(f"\033[93m  1. Bot token is incorrect\033[0m")
                            print(f"\033[93m  2. Chat ID is incorrect\033[0m")
                            print(f"\033[93m  3. You haven't started a chat with your bot yet\033[0m")
                            print(f"\033[93m     → Open Telegram, search for your bot, click START\033[0m")
                    except requests.exceptions.RequestException as e:
                        print(f"\n\033[91m✗ NETWORK ERROR!\033[0m")
                        print(f"\033[93m  Error: {str(e)}\033[0m")
                        print(f"\n\033[93mPossible causes:\033[0m")
                        print(f"\033[93m  1. No internet connection\033[0m")
                        print(f"\033[93m  2. Firewall blocking requests\033[0m")
                        print(f"\033[93m  3. Telegram API is down\033[0m")
                    except Exception as e:
                        print(f"\n\033[91m✗ UNEXPECTED ERROR!\033[0m")
                        print(f"\033[93m  Error: {str(e)}\033[0m")
                        import traceback
                        traceback.print_exc()
                    
                    print(f"\033[94m{'=' * 70}\033[0m\n")
                    time.sleep(3)  # Give user time to read the output
                else:
                    print(f"\n\033[93m⚠ Telegram enabled but missing credentials\033[0m")
                    print(f"\033[93m  Bot token: {'Present' if bot_token else 'MISSING'}\033[0m")
                    print(f"\033[93m  Chat ID: {'Present' if chat_id else 'MISSING'}\033[0m")
                    print(f"\033[93m  Please add bot_token and chat_id to config.json\033[0m\n")
                    time.sleep(2)
            else:
                print(f"\n\033[90m[DEBUG] Telegram is disabled in config\033[0m\n")
        else:
            print(f"\n\033[90m[DEBUG] Config file does not exist\033[0m\n")
    except Exception as e:
        print(f"\n\033[91m✗ Health check error: {str(e)}\033[0m\n")
        import traceback
        traceback.print_exc()
        time.sleep(2)
    
    print(f"\033[90m[DEBUG] Starting curses interface...\033[0m\n")
    
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        print("\n\nApplication terminated by user.\n")
        sys.exit(0)
    except Exception as e:
        print(f"\nFatal error: {str(e)}\n")
        sys.exit(1)
