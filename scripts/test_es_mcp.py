"""
Test the official Elastic MCP server (@elastic/mcp-server-elasticsearch).

Launches the server as an stdio subprocess via npx, connects to it using the
mcp Python client, verifies all 5 tools are present, then calls:
  - list_indices      → confirm our 3 project indices exist
  - search            → query confirmed_attack_history for a known IP
  - get_mappings      → verify network_live_flows schema
  - get_shards        → cluster shard info
  - esql              → count all documents in confirmed_attack_history

Prerequisites:
  - Node.js + npx installed
  - Elasticsearch running on http://localhost:9200
  - At least 1 document in confirmed_attack_history (run test_verification_agent.py first)

Run: python scripts/test_es_mcp.py
"""

import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"

# v0.3.1 (npm, deprecated) exposes 4 tools; esql was added in v0.4.0 (Docker-only)
EXPECTED_TOOLS = {"list_indices", "get_mappings", "search", "get_shards"}
OUR_INDICES    = {"ands-alerts", "network_live_flows", "confirmed_attack_history"}

failures = 0


def check(label: str, condition: bool, detail: str = "") -> bool:
    global failures
    tag = PASS if condition else FAIL
    if not condition:
        failures += 1
    print(f"  {tag} {label}" + (f"  ({detail})" if detail else ""))
    return condition


def tool_result_text(result) -> str:
    """Extract plain text from an MCP tool result."""
    for block in result.content:
        if hasattr(block, "text"):
            return block.text
    return ""


async def run_tests():
    server_params = StdioServerParameters(
        command="npx",
        args=["@elastic/mcp-server-elasticsearch"],
        env={**os.environ, "ES_URL": "http://localhost:9200"},
    )

    print(f"\n{INFO} Starting official Elastic MCP server via npx ...\n")

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # ---------------------------------------------------------- #
            # 1. Tool discovery                                           #
            # ---------------------------------------------------------- #
            print(f"{INFO} Checking exposed tools")
            tools_response = await session.list_tools()
            found_names = {t.name for t in tools_response.tools}

            for name in sorted(EXPECTED_TOOLS):
                check(f"tool '{name}' present", name in found_names)

            print(f"\n  All tools: {sorted(found_names)}\n")

            # ---------------------------------------------------------- #
            # 2. list_indices — verify our 3 indices exist               #
            # ---------------------------------------------------------- #
            print(f"{INFO} list_indices")
            result = await session.call_tool("list_indices", {})
            text   = tool_result_text(result)
            for idx in OUR_INDICES:
                check(f"index '{idx}' listed", idx in text)
            print()

            # ---------------------------------------------------------- #
            # 3. get_mappings — verify network_live_flows schema          #
            # ---------------------------------------------------------- #
            print(f"{INFO} get_mappings(network_live_flows)")
            result = await session.call_tool(
                "get_mappings", {"index": "network_live_flows"}
            )
            text = tool_result_text(result)
            for field in ("src_ip", "dst_ip", "model_prediction", "confidence"):
                check(f"field '{field}' in mapping", field in text)
            print()

            # ---------------------------------------------------------- #
            # 4. search — query confirmed_attack_history                  #
            # ---------------------------------------------------------- #
            print(f"{INFO} search(confirmed_attack_history)")
            query = {
                "index": "confirmed_attack_history",
                "body": {
                    "size": 3,
                    "query": {"match_all": {}},
                    "sort": [{"@timestamp": {"order": "desc"}}],
                },
            }
            result = await session.call_tool("search", query)
            text   = tool_result_text(result)
            data   = json.loads(text) if text.strip().startswith("{") else {}
            hits   = data.get("hits", {}).get("total", {}).get("value", 0)
            check("search returns hits > 0", hits > 0, f"total hits={hits}")
            check("response has hits.hits",  "hits" in data)
            print()

            # ---------------------------------------------------------- #
            # 5. get_shards                                               #
            # ---------------------------------------------------------- #
            print(f"{INFO} get_shards")
            result = await session.call_tool("get_shards", {})
            text   = tool_result_text(result)
            check("get_shards returns data", len(text) > 10,
                  f"response_len={len(text)}")
            print()

            # ---------------------------------------------------------- #
            # 6. esql — count documents in confirmed_attack_history       #
            # ---------------------------------------------------------- #
            print(f"{INFO} esql — count confirmed_attack_history docs")
            result = await session.call_tool(
                "esql",
                {"query": "FROM confirmed_attack_history | STATS count = COUNT(*)"},
            )
            text = tool_result_text(result)
            check("esql returns result", len(text) > 0)
            check("esql result has count", "count" in text.lower())
            print()

    # ------------------------------------------------------------------ #
    # Summary                                                             #
    # ------------------------------------------------------------------ #
    if failures == 0:
        print(f"{PASS} All checks passed — official Elastic MCP server is working.\n")
    else:
        print(f"{FAIL} {failures} check(s) failed.\n")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(run_tests())
