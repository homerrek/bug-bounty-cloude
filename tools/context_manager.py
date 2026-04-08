#!/usr/bin/env python3
"""
context_manager.py — Context window manager for bug hunting sessions.

Manages conversation context, prioritizes critical information,
and provides smart context rotation for long hunting sessions.

Usage:
  python3 tools/context_manager.py --session target.com --add findings/vuln1.md
  python3 tools/context_manager.py --session target.com --status
  python3 tools/context_manager.py --session target.com --export context.json
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from collections import defaultdict, deque

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# Context budget allocation (tokens)
MAX_CONTEXT_TOKENS = 200000
RESERVED_FOR_OUTPUT = 4096
AVAILABLE_CONTEXT = MAX_CONTEXT_TOKENS - RESERVED_FOR_OUTPUT

CONTEXT_ALLOCATION = {
    "system_prompt": 0.05,      # 5% - System instructions
    "hunt_memory": 0.15,         # 15% - Cross-target patterns
    "current_findings": 0.30,    # 30% - Active findings
    "recon_data": 0.25,          # 25% - Reconnaissance output
    "conversation": 0.25,        # 25% - Conversation history
}


class ContextManager:
    def __init__(self, session_name):
        self.session_name = session_name
        self.session_dir = Path(f".context/{session_name}")
        self.session_dir.mkdir(parents=True, exist_ok=True)

        self.context_file = self.session_dir / "context.json"
        self.context = self._load_context()

    def _load_context(self):
        """Load session context from disk"""
        if self.context_file.exists():
            with open(self.context_file, 'r') as f:
                return json.load(f)
        else:
            return {
                "session_name": self.session_name,
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat(),
                "items": [],
                "priorities": defaultdict(list),
                "total_tokens": 0,
                "message_count": 0
            }

    def _save_context(self):
        """Save session context to disk"""
        self.context["updated_at"] = datetime.now().isoformat()
        with open(self.context_file, 'w') as f:
            json.dump(self.context, f, indent=2)

    def add_item(self, content, item_type="finding", priority="medium", metadata=None):
        """Add an item to context"""
        from tools.token_optimizer import estimate_tokens

        tokens = estimate_tokens(content)

        item = {
            "id": len(self.context["items"]) + 1,
            "type": item_type,
            "priority": priority,
            "content": content,
            "tokens": tokens,
            "added_at": datetime.now().isoformat(),
            "metadata": metadata or {}
        }

        self.context["items"].append(item)
        self.context["priorities"][priority].append(item["id"])
        self.context["total_tokens"] += tokens
        self.context["message_count"] += 1

        self._save_context()

        print(f"{GREEN}[ADDED]{RESET} {item_type} ({tokens:,} tokens, priority: {priority})")
        return item["id"]

    def remove_item(self, item_id):
        """Remove an item from context"""
        for item in self.context["items"]:
            if item["id"] == item_id:
                self.context["total_tokens"] -= item["tokens"]
                self.context["items"].remove(item)
                self._save_context()
                print(f"{YELLOW}[REMOVED]{RESET} Item {item_id} ({item['tokens']:,} tokens)")
                return True
        return False

    def prioritize(self):
        """Re-prioritize context items based on age and relevance"""
        print(f"\n{BOLD}Prioritizing Context...{RESET}\n")

        # Age-based deprioritization
        now = datetime.now()
        updated_items = []

        for item in self.context["items"]:
            added_at = datetime.fromisoformat(item["added_at"])
            age_hours = (now - added_at).total_seconds() / 3600

            # Downgrade priority for old items
            if age_hours > 24 and item["priority"] == "critical":
                item["priority"] = "high"
                print(f"  Downgraded item {item['id']} (24h+ old): critical → high")
            elif age_hours > 48 and item["priority"] == "high":
                item["priority"] = "medium"
                print(f"  Downgraded item {item['id']} (48h+ old): high → medium")
            elif age_hours > 72 and item["priority"] == "medium":
                item["priority"] = "low"
                print(f"  Downgraded item {item['id']} (72h+ old): medium → low")

            updated_items.append(item)

        self.context["items"] = updated_items
        self._rebuild_priorities()
        self._save_context()

    def _rebuild_priorities(self):
        """Rebuild priority index"""
        self.context["priorities"] = defaultdict(list)
        for item in self.context["items"]:
            self.context["priorities"][item["priority"]].append(item["id"])

    def compact(self):
        """Compact context by removing low-priority old items"""
        print(f"\n{BOLD}Compacting Context...{RESET}\n")

        # Calculate current usage
        usage_pct = (self.context["total_tokens"] / AVAILABLE_CONTEXT) * 100

        if usage_pct < 70:
            print(f"{GREEN}[OK] Context at {usage_pct:.1f}% - no compaction needed{RESET}")
            return

        print(f"{YELLOW}[WARNING] Context at {usage_pct:.1f}% - compacting...{RESET}\n")

        # Remove low-priority items first
        removed_count = 0
        removed_tokens = 0

        for priority in ["low", "medium"]:
            if usage_pct < 60:
                break

            items_to_remove = []
            for item in self.context["items"]:
                if item["priority"] == priority:
                    items_to_remove.append(item)

            # Remove oldest half
            items_to_remove.sort(key=lambda x: x["added_at"])
            for item in items_to_remove[:len(items_to_remove)//2]:
                self.context["total_tokens"] -= item["tokens"]
                self.context["items"].remove(item)
                removed_count += 1
                removed_tokens += item["tokens"]

            usage_pct = (self.context["total_tokens"] / AVAILABLE_CONTEXT) * 100

        self._rebuild_priorities()
        self._save_context()

        print(f"{GREEN}[COMPACTED]{RESET} Removed {removed_count} items ({removed_tokens:,} tokens)")
        print(f"New usage: {usage_pct:.1f}%")

    def get_status(self):
        """Get context status"""
        usage_pct = (self.context["total_tokens"] / AVAILABLE_CONTEXT) * 100

        print(f"\n{BOLD}Context Status: {self.session_name}{RESET}")
        print(f"Created: {self.context['created_at']}")
        print(f"Updated: {self.context['updated_at']}\n")

        print(f"{BOLD}Token Usage:{RESET}")
        print(f"  Total: {self.context['total_tokens']:,} / {AVAILABLE_CONTEXT:,} ({usage_pct:.1f}%)")

        # Budget breakdown
        print(f"\n{BOLD}Budget Allocation:{RESET}")
        for category, pct in CONTEXT_ALLOCATION.items():
            allocated = int(AVAILABLE_CONTEXT * pct)
            print(f"  {category}: {allocated:,} tokens ({pct*100:.0f}%)")

        # Priority breakdown
        print(f"\n{BOLD}Items by Priority:{RESET}")
        for priority in ["critical", "high", "medium", "low"]:
            count = len([i for i in self.context["items"] if i["priority"] == priority])
            if count > 0:
                color = RED if priority == "critical" else YELLOW if priority == "high" else CYAN
                print(f"  {color}{priority.upper()}{RESET}: {count} items")

        # Type breakdown
        print(f"\n{BOLD}Items by Type:{RESET}")
        types = defaultdict(int)
        for item in self.context["items"]:
            types[item["type"]] += 1
        for item_type, count in sorted(types.items()):
            print(f"  {item_type}: {count}")

    def export(self, output_file):
        """Export context to JSON"""
        with open(output_file, 'w') as f:
            json.dump(self.context, f, indent=2)
        print(f"{GREEN}[EXPORTED]{RESET} {output_file}")

    def summarize(self):
        """Generate a compact summary of context"""
        summary = {
            "session": self.session_name,
            "tokens": self.context["total_tokens"],
            "items": len(self.context["items"]),
            "critical_items": len([i for i in self.context["items"] if i["priority"] == "critical"]),
            "high_items": len([i for i in self.context["items"] if i["priority"] == "high"]),
            "recent_items": []
        }

        # Get 5 most recent items
        sorted_items = sorted(self.context["items"], key=lambda x: x["added_at"], reverse=True)
        for item in sorted_items[:5]:
            summary["recent_items"].append({
                "id": item["id"],
                "type": item["type"],
                "priority": item["priority"],
                "tokens": item["tokens"],
                "preview": item["content"][:100] + "..." if len(item["content"]) > 100 else item["content"]
            })

        return summary


def main():
    parser = argparse.ArgumentParser(description="Context window manager for bug hunting")
    parser.add_argument("--session", required=True, help="Session name (usually target domain)")
    parser.add_argument("--add", help="Add content from file")
    parser.add_argument("--remove", type=int, help="Remove item by ID")
    parser.add_argument("--type", default="finding", help="Item type (finding, recon, note)")
    parser.add_argument("--priority", default="medium", choices=["critical", "high", "medium", "low"])
    parser.add_argument("--status", action="store_true", help="Show context status")
    parser.add_argument("--compact", action="store_true", help="Compact context")
    parser.add_argument("--prioritize", action="store_true", help="Re-prioritize items")
    parser.add_argument("--export", help="Export context to JSON file")
    parser.add_argument("--summary", action="store_true", help="Print compact summary")
    args = parser.parse_args()

    cm = ContextManager(args.session)

    if args.add:
        try:
            with open(args.add, 'r') as f:
                content = f.read()
            cm.add_item(content, item_type=args.type, priority=args.priority)
        except Exception as e:
            print(f"{RED}[ERROR] {e}{RESET}")

    elif args.remove:
        cm.remove_item(args.remove)

    elif args.status:
        cm.get_status()

    elif args.compact:
        cm.compact()

    elif args.prioritize:
        cm.prioritize()

    elif args.export:
        cm.export(args.export)

    elif args.summary:
        summary = cm.summarize()
        print(json.dumps(summary, indent=2))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
