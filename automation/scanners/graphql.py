"""
GraphQL scanner — detect GraphQL endpoints, run introspection,
find dangerous queries and mutations.
"""

import json
import sys
import os
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient
from utils.reporter import Finding

GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/api/graphql", "/api/graphiql",
    "/v1/graphql", "/v2/graphql", "/query", "/gql",
    "/graphql/console", "/playground", "/altair",
    "/explorer", "/api", "/graphql/v1",
]

INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
          ofType {
            name
            kind
          }
        }
        args {
          name
          type {
            name
          }
        }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
"""

# Dangerous mutation names that suggest security-sensitive operations
DANGEROUS_MUTATIONS = [
    "deleteUser", "removeUser", "createAdmin", "updateRole",
    "setPermission", "changePassword", "resetPassword",
    "deleteAccount", "addAdmin", "elevatePrivilege",
    "updateConfig", "modifySettings", "executeCommand",
    "uploadFile", "importData", "runMigration",
    "transferFunds", "createPayment", "modifyBalance",
]

# Fields that might leak sensitive data
SENSITIVE_FIELDS = [
    "password", "passwd", "secret", "token", "apiKey", "api_key",
    "accessToken", "access_token", "refreshToken", "refresh_token",
    "ssn", "social_security", "creditCard", "credit_card",
    "cvv", "bankAccount", "privateKey", "private_key",
    "internalId", "internal_id", "adminFlag", "isAdmin",
    "role", "permission", "salt", "hash", "encryptionKey",
]


def find_graphql_endpoint(base_url, client=None, verbose=True):
    """Try common GraphQL endpoint paths."""
    client = client or HTTPClient(timeout=10)
    found = []

    for path in GRAPHQL_PATHS:
        url = base_url.rstrip("/") + path

        # Try POST with introspection
        resp = client.post(
            url,
            json={"query": "{__typename}"},
            headers={"Content-Type": "application/json"},
        )
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if "data" in data or "errors" in data:
                    found.append(url)
                    if verbose:
                        print(f"    [FOUND] {url}")
                    continue
            except (json.JSONDecodeError, ValueError):
                pass

        # Try GET
        resp = client.get(f"{url}?query={{__typename}}")
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if "data" in data or "errors" in data:
                    found.append(url)
                    if verbose:
                        print(f"    [FOUND] {url} (GET)")
            except (json.JSONDecodeError, ValueError):
                pass

    return found


def run_introspection(endpoint, client=None):
    """Run introspection query to get full schema."""
    client = client or HTTPClient(timeout=30)

    resp = client.post(
        endpoint,
        json={"query": INTROSPECTION_QUERY},
        headers={"Content-Type": "application/json"},
    )

    if resp and resp.status_code == 200:
        try:
            return resp.json()
        except (json.JSONDecodeError, ValueError):
            pass

    # Try GET
    import urllib.parse
    resp = client.get(f"{endpoint}?query={urllib.parse.quote(INTROSPECTION_QUERY)}")
    if resp and resp.status_code == 200:
        try:
            return resp.json()
        except (json.JSONDecodeError, ValueError):
            pass

    return None


def analyze_schema(schema_data):
    """Analyze introspection results for security issues."""
    findings_info = []

    if not schema_data or "data" not in schema_data:
        return findings_info

    schema = schema_data["data"].get("__schema", {})
    types = schema.get("types", [])

    all_fields = []
    all_mutations = []
    sensitive_found = []
    dangerous_found = []

    for type_def in types:
        name = type_def.get("name", "")
        if name.startswith("__"):  # Skip introspection types
            continue

        fields = type_def.get("fields") or []
        for field in fields:
            field_name = field.get("name", "")
            all_fields.append(f"{name}.{field_name}")

            # Check for sensitive fields
            if field_name.lower() in [s.lower() for s in SENSITIVE_FIELDS]:
                sensitive_found.append(f"{name}.{field_name}")

    # Check mutation type
    mutation_type = schema.get("mutationType", {})
    if mutation_type:
        mutation_name = mutation_type.get("name", "")
        for type_def in types:
            if type_def.get("name") == mutation_name:
                for field in (type_def.get("fields") or []):
                    fname = field.get("name", "")
                    all_mutations.append(fname)
                    if fname.lower() in [d.lower() for d in DANGEROUS_MUTATIONS]:
                        dangerous_found.append(fname)

    findings_info.append({
        "total_types": len([t for t in types if not t["name"].startswith("__")]),
        "total_fields": len(all_fields),
        "total_mutations": len(all_mutations),
        "sensitive_fields": sensitive_found,
        "dangerous_mutations": dangerous_found,
        "all_mutations": all_mutations,
    })

    return findings_info


def test_batch_query(endpoint, client=None):
    """Test if batched queries are allowed (DoS risk)."""
    client = client or HTTPClient(timeout=15)

    batch_query = [
        {"query": "{__typename}"},
        {"query": "{__typename}"},
        {"query": "{__typename}"},
    ]

    resp = client.post(
        endpoint,
        json=batch_query,
        headers={"Content-Type": "application/json"},
    )

    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            if isinstance(data, list) and len(data) > 1:
                return True
        except (json.JSONDecodeError, ValueError):
            pass
    return False


def scan(url, verbose=True):
    """Full GraphQL security scan."""
    client = HTTPClient(rate_limit=0.5, timeout=15)
    findings = []

    # Find endpoints
    if verbose:
        print("  Discovering GraphQL endpoints...")
    endpoints = find_graphql_endpoint(url, client, verbose)

    if not endpoints:
        if verbose:
            print("  No GraphQL endpoints found")
        return findings

    for endpoint in endpoints:
        # Test introspection
        if verbose:
            print(f"\n  Testing introspection on {endpoint}...")

        schema = run_introspection(endpoint, client)
        if schema and "data" in schema:
            findings.append(Finding(
                title="GraphQL Introspection Enabled",
                severity="medium",
                description="GraphQL introspection is enabled — full schema is exposed to any user.",
                url=endpoint,
                evidence="Introspection query returned full schema",
                remediation="Disable introspection in production. Use allowlisted queries (persisted queries).",
            ))

            analysis = analyze_schema(schema)
            for info in analysis:
                if verbose:
                    print(f"    Types: {info['total_types']}, Fields: {info['total_fields']}, Mutations: {info['total_mutations']}")

                if info["sensitive_fields"]:
                    findings.append(Finding(
                        title="Sensitive Fields Exposed in GraphQL Schema",
                        severity="high",
                        description="Schema contains fields that may expose sensitive data.",
                        url=endpoint,
                        evidence=f"Sensitive fields: {', '.join(info['sensitive_fields'][:10])}",
                        remediation="Remove sensitive fields from the schema or add proper authorization.",
                    ))
                    if verbose:
                        print(f"    SENSITIVE FIELDS: {', '.join(info['sensitive_fields'][:5])}")

                if info["dangerous_mutations"]:
                    findings.append(Finding(
                        title="Dangerous Mutations in GraphQL Schema",
                        severity="high",
                        description="Schema contains mutations that could allow privilege escalation or data destruction.",
                        url=endpoint,
                        evidence=f"Dangerous mutations: {', '.join(info['dangerous_mutations'][:10])}",
                        remediation="Ensure all dangerous mutations require proper authentication and authorization.",
                    ))
                    if verbose:
                        print(f"    DANGEROUS MUTATIONS: {', '.join(info['dangerous_mutations'][:5])}")

        else:
            if verbose:
                print("    Introspection disabled or returned error")

        # Test batch queries
        if verbose:
            print(f"  Testing batch queries...")
        if test_batch_query(endpoint, client):
            findings.append(Finding(
                title="GraphQL Batch Queries Allowed",
                severity="low",
                description="GraphQL endpoint accepts batched queries — potential for DoS and brute force attacks.",
                url=endpoint,
                evidence="Batch query with 3 queries returned array of results",
                remediation="Limit or disable batch queries. Implement query depth and complexity limits.",
            ))
            if verbose:
                print("    Batch queries: ALLOWED")

    return findings


def scan_multiple(urls, verbose=True):
    all_findings = []
    for url in urls:
        if verbose:
            print(f"\n  [{url}] GraphQL scan...", flush=True)
        all_findings.extend(scan(url, verbose))
    return all_findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python graphql.py <base_url>")
        sys.exit(1)
    url = sys.argv[1]
    if not url.startswith("http"):
        url = f"https://{url}"
    print(f"\n[*] GraphQL scan: {url}\n")
    scan(url)
