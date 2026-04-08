#!/usr/bin/env python3
"""
token_optimizer.py — Token usage optimizer for Claude Code sessions.

Analyzes content length, prioritizes critical information, and provides
intelligent chunking for large recon outputs to stay within context limits.

Usage:
  python3 tools/token_optimizer.py --analyze recon/target.com/
  python3 tools/token_optimizer.py --chunk recon/target.com/urls.txt --max-tokens 4000
  python3 tools/token_optimizer.py --summarize findings/report.md
"""

import argparse
import json
import os
import sys
from pathlib import Path
from collections import defaultdict

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# Approximate token counts (1 token ≈ 4 characters for English text)
CHARS_PER_TOKEN = 4
MAX_CONTEXT_TOKENS = 200000  # Claude Sonnet 4.5 context window
SAFE_CHUNK_TOKENS = 8000     # Safe chunk size for single operations


def estimate_tokens(text):
    """Estimate token count from text"""
    return len(text) // CHARS_PER_TOKEN


def analyze_directory(directory):
    """Analyze token usage in a directory"""
    print(f"\n{BOLD}Token Usage Analysis{RESET}")
    print(f"Directory: {directory}\n")

    file_stats = []
    total_tokens = 0

    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    tokens = estimate_tokens(content)
                    lines = content.count('\n') + 1

                    file_stats.append({
                        'path': filepath,
                        'tokens': tokens,
                        'lines': lines,
                        'size_kb': os.path.getsize(filepath) / 1024
                    })
                    total_tokens += tokens
            except Exception:
                pass

    # Sort by token count
    file_stats.sort(key=lambda x: x['tokens'], reverse=True)

    # Display top token consumers
    print(f"{BOLD}Top Token Consumers:{RESET}")
    for i, stat in enumerate(file_stats[:10], 1):
        rel_path = os.path.relpath(stat['path'], directory)
        pct = (stat['tokens'] / total_tokens * 100) if total_tokens > 0 else 0
        color = RED if stat['tokens'] > SAFE_CHUNK_TOKENS else YELLOW if stat['tokens'] > 2000 else GREEN
        print(f"{i:2}. {color}{rel_path}{RESET}")
        print(f"    {stat['tokens']:,} tokens ({pct:.1f}%), {stat['lines']:,} lines, {stat['size_kb']:.1f} KB")

    # Summary
    context_pct = (total_tokens / MAX_CONTEXT_TOKENS * 100) if MAX_CONTEXT_TOKENS > 0 else 0
    print(f"\n{BOLD}Summary:{RESET}")
    print(f"  Total files: {len(file_stats)}")
    print(f"  Total tokens: {total_tokens:,} ({context_pct:.1f}% of context window)")
    print(f"  Average per file: {total_tokens // len(file_stats) if file_stats else 0:,} tokens")

    if total_tokens > MAX_CONTEXT_TOKENS * 0.7:
        print(f"\n{RED}[WARNING] High token usage! Consider chunking or summarization.{RESET}")
    elif total_tokens > MAX_CONTEXT_TOKENS * 0.5:
        print(f"\n{YELLOW}[INFO] Moderate token usage. Monitor for large files.{RESET}")
    else:
        print(f"\n{GREEN}[OK] Token usage within safe limits.{RESET}")

    return file_stats


def chunk_file(filepath, max_tokens):
    """Chunk a large file into smaller pieces"""
    print(f"\n{BOLD}Chunking File{RESET}")
    print(f"Input: {filepath}")
    print(f"Max tokens per chunk: {max_tokens:,}\n")

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        total_tokens = estimate_tokens(content)
        print(f"Total tokens: {total_tokens:,}")

        if total_tokens <= max_tokens:
            print(f"{GREEN}[OK] File is already within limit.{RESET}")
            return

        # Split by lines for cleaner chunks
        lines = content.split('\n')
        chunks = []
        current_chunk = []
        current_tokens = 0

        for line in lines:
            line_tokens = estimate_tokens(line)

            if current_tokens + line_tokens > max_tokens and current_chunk:
                # Save current chunk
                chunks.append('\n'.join(current_chunk))
                current_chunk = [line]
                current_tokens = line_tokens
            else:
                current_chunk.append(line)
                current_tokens += line_tokens

        # Save last chunk
        if current_chunk:
            chunks.append('\n'.join(current_chunk))

        # Write chunks
        base_path = Path(filepath)
        output_dir = base_path.parent / f"{base_path.stem}_chunks"
        output_dir.mkdir(exist_ok=True)

        for i, chunk in enumerate(chunks, 1):
            chunk_path = output_dir / f"chunk_{i:03d}.txt"
            with open(chunk_path, 'w') as f:
                f.write(chunk)
            print(f"{GREEN}[CREATED]{RESET} {chunk_path} ({estimate_tokens(chunk):,} tokens)")

        print(f"\n{BOLD}Summary:{RESET}")
        print(f"  Created {len(chunks)} chunks")
        print(f"  Output directory: {output_dir}")

    except Exception as e:
        print(f"{RED}[ERROR] {e}{RESET}")


def prioritize_content(directory):
    """Prioritize content by relevance for bug hunting"""
    print(f"\n{BOLD}Content Prioritization{RESET}")
    print(f"Directory: {directory}\n")

    priority_rules = {
        'CRITICAL': [
            'credentials', 'api_key', 'secret', 'password', 'token',
            'admin', 'internal', 'dev', 'staging'
        ],
        'HIGH': [
            'endpoint', 'graphql', 'api', 'upload', 'payment',
            'user', 'auth', 'login', 'reset'
        ],
        'MEDIUM': [
            'config', 'swagger', 'openapi', 'wsdl', 'subdomain'
        ],
        'LOW': [
            'static', 'asset', 'image', 'css', 'js'
        ]
    }

    file_priorities = defaultdict(list)

    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            rel_path = os.path.relpath(filepath, directory)

            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().lower()

                priority = 'LOW'
                matches = []

                for level, keywords in priority_rules.items():
                    for keyword in keywords:
                        if keyword in content or keyword in rel_path.lower():
                            if level == 'CRITICAL' or (level == 'HIGH' and priority == 'LOW'):
                                priority = level
                            matches.append(keyword)

                tokens = estimate_tokens(content)
                file_priorities[priority].append({
                    'path': rel_path,
                    'tokens': tokens,
                    'matches': list(set(matches))[:5]  # First 5 unique matches
                })
            except Exception:
                pass

    # Display by priority
    for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        files = file_priorities[level]
        if not files:
            continue

        color = RED if level == 'CRITICAL' else YELLOW if level == 'HIGH' else CYAN
        print(f"\n{color}{BOLD}{level} Priority ({len(files)} files):{RESET}")

        for item in sorted(files, key=lambda x: x['tokens'], reverse=True)[:5]:
            print(f"  {item['path']}")
            print(f"    {item['tokens']:,} tokens")
            if item['matches']:
                print(f"    Matches: {', '.join(item['matches'])}")


def summarize_file(filepath):
    """Generate a token-efficient summary of a file"""
    print(f"\n{BOLD}File Summary{RESET}")
    print(f"Input: {filepath}\n")

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        tokens = estimate_tokens(content)
        lines = content.count('\n') + 1

        print(f"Original: {tokens:,} tokens, {lines:,} lines")

        # Extract key patterns
        patterns = {
            'URLs': [],
            'IPs': [],
            'Domains': [],
            'Endpoints': [],
            'Keywords': []
        }

        import re

        # Simple extraction
        patterns['URLs'] = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', content)[:20]
        patterns['IPs'] = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)[:20]
        patterns['Domains'] = re.findall(r'[a-z0-9.-]+\.[a-z]{2,}', content.lower())[:20]

        # Generate summary
        summary_lines = [
            f"# Summary of {os.path.basename(filepath)}",
            f"",
            f"**Statistics:**",
            f"- Lines: {lines:,}",
            f"- Tokens: {tokens:,}",
            f"",
        ]

        for category, items in patterns.items():
            if items:
                unique_items = list(set(items))[:10]
                summary_lines.append(f"**{category}:** ({len(unique_items)} unique)")
                for item in unique_items:
                    summary_lines.append(f"- {item}")
                summary_lines.append("")

        summary = '\n'.join(summary_lines)
        summary_tokens = estimate_tokens(summary)

        print(f"Summary: {summary_tokens:,} tokens ({(summary_tokens/tokens*100):.1f}% of original)")
        print(f"\n{summary}")

        # Save summary
        summary_path = filepath + '.summary.md'
        with open(summary_path, 'w') as f:
            f.write(summary)

        print(f"\n{GREEN}[SAVED]{RESET} {summary_path}")

    except Exception as e:
        print(f"{RED}[ERROR] {e}{RESET}")


def main():
    parser = argparse.ArgumentParser(description="Token usage optimizer for Claude Code")
    parser.add_argument("--analyze", help="Analyze directory token usage")
    parser.add_argument("--chunk", help="Chunk a large file")
    parser.add_argument("--max-tokens", type=int, default=SAFE_CHUNK_TOKENS, help="Max tokens per chunk")
    parser.add_argument("--prioritize", help="Prioritize content by relevance")
    parser.add_argument("--summarize", help="Generate token-efficient summary")
    parser.add_argument("--json", dest="json_out", action="store_true", help="JSON output")
    args = parser.parse_args()

    if args.analyze:
        analyze_directory(args.analyze)
    elif args.chunk:
        chunk_file(args.chunk, args.max_tokens)
    elif args.prioritize:
        prioritize_content(args.prioritize)
    elif args.summarize:
        summarize_file(args.summarize)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
