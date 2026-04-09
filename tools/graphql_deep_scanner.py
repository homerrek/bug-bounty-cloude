#!/usr/bin/env python3
"""
graphql_deep_scanner.py — Deep GraphQL security scanner.

Tests for introspection, field suggestions, batching attacks, nested queries DoS,
alias-based rate limit bypass, mutation without auth, circular fragments, directive abuse.

Usage:
  python3 tools/graphql_deep_scanner.py --url https://target.com/graphql
  python3 tools/graphql_deep_scanner.py --url https://api.target.com/graphql --header "Authorization: Bearer TOKEN"
"""

import argparse
import json
import time
import urllib.request
import urllib.error
import urllib.parse

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

FINDINGS = []
REQUEST_INTERVAL = 1.0


def _sleep():
    time.sleep(REQUEST_INTERVAL)


def _graphql_request(url, query, headers=None, timeout=15):
    if headers is None:
        headers = {}
    headers.setdefault("User-Agent", "Mozilla/5.0 (compatible; BugBountyScanner/1.0)")
    headers.setdefault("Content-Type", "application/json")

    payload = json.dumps({"query": query}).encode("utf-8")

    try:
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, str(e)


def _add_finding(severity, title, detail, evidence=""):
    f = {"severity": severity, "title": title, "detail": detail, "evidence": evidence}
    FINDINGS.append(f)
    color = RED if severity == "CRITICAL" else YELLOW if severity == "HIGH" else CYAN
    print(f"{color}[{severity}]{RESET} {title}")
    if detail:
        print(f"  {DIM}{detail}{RESET}")
    if evidence:
        print(f"  {BLUE}Evidence: {evidence}{RESET}")


def test_introspection(url, headers):
    """Test if introspection is enabled"""
    print(f"\n{BOLD}[1/8] Testing introspection...{RESET}")
    _sleep()

    introspection_query = """
    {
      __schema {
        types {
          name
          fields {
            name
          }
        }
      }
    }
    """

    status, body = _graphql_request(url, introspection_query, headers)

    if status == 200 and "__schema" in body and "types" in body:
        try:
            data = json.loads(body)
            if "data" in data and "__schema" in data["data"]:
                type_count = len(data["data"]["__schema"]["types"])
                _add_finding("HIGH",
                           "GraphQL introspection enabled",
                           f"Schema exposed with {type_count} types - allows complete API mapping",
                           f"Types found: {type_count}")
                return True
        except json.JSONDecodeError:
            pass

    print(f"{GREEN}Introspection disabled or blocked{RESET}")
    return False


def test_field_suggestions(url, headers):
    """Test if field suggestions leak schema info"""
    print(f"\n{BOLD}[2/8] Testing field suggestions...{RESET}")
    _sleep()

    invalid_query = """
    {
      nonExistentField12345
    }
    """

    status, body = _graphql_request(url, invalid_query, headers)

    if "Did you mean" in body or "similar to" in body or "suggestion" in body.lower():
        _add_finding("MEDIUM",
                   "Field suggestions enabled",
                   "Error messages suggest valid field names - partial schema disclosure",
                   f"Response contains field suggestions")


def test_batch_attack(url, headers):
    """Test batching for rate limit bypass"""
    print(f"\n{BOLD}[3/8] Testing batch query attack...{RESET}")
    _sleep()

    # Create a batch of 20 identical queries
    batch_query = """
    [
      {"query": "{ __typename }"},
      {"query": "{ __typename }"},
      {"query": "{ __typename }"},
      {"query": "{ __typename }"},
      {"query": "{ __typename }"},
      {"query": "{ __typename }"},
      {"query": "{ __typename }"},
      {"query": "{ __typename }"},
      {"query": "{ __typename }"},
      {"query": "{ __typename }"},
      {"query": "{ __typename }"},
      {"query": "{ __typename }"},
      {"query": "{ __typename }"},
      {"query": "{ __typename }"},
      {"query": "{ __typename }"},
      {"query": "{ __typename }"},
      {"query": "{ __typename }"},
      {"query": "{ __typename }"},
      {"query": "{ __typename }"},
      {"query": "{ __typename }"}
    ]
    """

    # Try sending as JSON array
    if headers is None:
        headers = {}
    headers["Content-Type"] = "application/json"

    try:
        req = urllib.request.Request(url, data=batch_query.encode("utf-8"), headers=headers)
        with urllib.request.urlopen(req, timeout=15) as r:
            status = r.status
            body = r.read().decode("utf-8", errors="replace")

            if status == 200 and body.count("__typename") >= 10:
                _add_finding("HIGH",
                           "Batch query attack possible",
                           "GraphQL accepts batched queries - rate limits can be bypassed",
                           f"Successfully executed multiple queries in single request")
    except Exception:
        print(f"{GREEN}Batching blocked or not supported{RESET}")


def test_nested_query_dos(url, headers):
    """Test deeply nested query for DoS"""
    print(f"\n{BOLD}[4/8] Testing nested query DoS...{RESET}")
    _sleep()

    # Create deeply nested query (10 levels)
    nested_query = """
    {
      __schema {
        types {
          fields {
            type {
              fields {
                type {
                  fields {
                    type {
                      fields {
                        type {
                          fields {
                            name
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    """

    start_time = time.time()
    status, body = _graphql_request(url, nested_query, headers)
    elapsed = time.time() - start_time

    if elapsed > 5.0:
        _add_finding("MEDIUM",
                   "Nested query causes slow response",
                   f"Query took {elapsed:.2f}s - potential DoS via query depth",
                   f"Response time: {elapsed:.2f}s")
    elif status == 200:
        print(f"{YELLOW}[INFO] Query completed in {elapsed:.2f}s (no depth limit detected){RESET}")


def test_alias_based_bypass(url, headers):
    """Test alias-based rate limit bypass"""
    print(f"\n{BOLD}[5/8] Testing alias-based rate limit bypass...{RESET}")
    _sleep()

    # Use aliases to make multiple calls to same field
    alias_query = """
    {
      req1: __typename
      req2: __typename
      req3: __typename
      req4: __typename
      req5: __typename
      req6: __typename
      req7: __typename
      req8: __typename
      req9: __typename
      req10: __typename
      req11: __typename
      req12: __typename
      req13: __typename
      req14: __typename
      req15: __typename
      req16: __typename
      req17: __typename
      req18: __typename
      req19: __typename
      req20: __typename
    }
    """

    status, body = _graphql_request(url, alias_query, headers)

    if status == 200 and body.count("req") >= 15:
        _add_finding("MEDIUM",
                   "Alias-based rate limit bypass",
                   "Multiple field aliases accepted - can multiply requests in single query",
                   f"Successfully executed 20 aliased fields")


def test_circular_fragments(url, headers):
    """Test circular fragment for potential DoS"""
    print(f"\n{BOLD}[6/8] Testing circular fragments...{RESET}")
    _sleep()

    circular_query = """
    query {
      __schema {
        ...SchemaFragment
      }
    }

    fragment SchemaFragment on __Schema {
      types {
        ...TypeFragment
      }
    }

    fragment TypeFragment on __Type {
      fields {
        type {
          ...TypeFragment
        }
      }
    }
    """

    start_time = time.time()
    status, body = _graphql_request(url, circular_query, headers)
    elapsed = time.time() - start_time

    if elapsed > 10.0 or status == 0:
        _add_finding("HIGH",
                   "Circular fragment DoS possible",
                   f"Circular fragment caused timeout or very slow response",
                   f"Response time: {elapsed:.2f}s")
    elif status == 200:
        print(f"{GREEN}Circular fragment handled safely{RESET}")


def test_directive_abuse(url, headers):
    """Test directive abuse (@skip, @include)"""
    print(f"\n{BOLD}[7/8] Testing directive abuse...{RESET}")
    _sleep()

    directive_query = """
    query($skip: Boolean = false) {
      __schema @skip(if: $skip) {
        types @skip(if: $skip) {
          name @skip(if: $skip)
        }
      }
    }
    """

    status, body = _graphql_request(url, directive_query, headers)

    if status == 200 and ("types" in body or "schema" in body):
        print(f"{YELLOW}[INFO] Directives accepted (standard behavior){RESET}")


def test_mutation_without_auth(url, headers):
    """Test if mutations work without authentication"""
    print(f"\n{BOLD}[8/8] Testing mutation without auth...{RESET}")
    _sleep()

    # Try a generic mutation probe
    mutation_query = """
    mutation {
      __typename
    }
    """

    # Remove auth headers for this test
    test_headers = {k: v for k, v in (headers or {}).items() if "auth" not in k.lower()}
    test_headers["User-Agent"] = "Mozilla/5.0 (compatible; BugBountyScanner/1.0)"
    test_headers["Content-Type"] = "application/json"

    status, body = _graphql_request(url, mutation_query, test_headers)

    if status == 200:
        _add_finding("CRITICAL",
                   "Mutations work without authentication",
                   "GraphQL accepts mutations without auth - check for privilege escalation",
                   f"Status: {status}")


def main():
    parser = argparse.ArgumentParser(description="Deep GraphQL security scanner")
    parser.add_argument("--url", required=True, help="GraphQL endpoint URL")
    parser.add_argument("--header", action="append", help="Custom header (format: 'Name: Value')")
    parser.add_argument("--rate", type=float, default=1.0, help="Requests per second")
    parser.add_argument("--json", dest="json_out", action="store_true", help="JSON output")
    args = parser.parse_args()

    global REQUEST_INTERVAL
    REQUEST_INTERVAL = 1.0 / args.rate if args.rate > 0 else 1.0

    # Parse custom headers
    headers = {}
    if args.header:
        for header in args.header:
            if ":" in header:
                name, value = header.split(":", 1)
                headers[name.strip()] = value.strip()

    print(f"\n{BOLD}GraphQL Deep Scanner{RESET}")
    print(f"Target: {args.url}\n")

    # Run all tests
    test_introspection(args.url, headers)
    test_field_suggestions(args.url, headers)
    test_batch_attack(args.url, headers)
    test_nested_query_dos(args.url, headers)
    test_alias_based_bypass(args.url, headers)
    test_circular_fragments(args.url, headers)
    test_directive_abuse(args.url, headers)
    test_mutation_without_auth(args.url, headers)

    if args.json_out:
        print(json.dumps({"findings": FINDINGS}, indent=2))
    else:
        print(f"\n{BOLD}Summary: {len(FINDINGS)} finding(s){RESET}")
        if not FINDINGS:
            print(f"{GREEN}No GraphQL vulnerabilities detected.{RESET}")


if __name__ == "__main__":
    main()
