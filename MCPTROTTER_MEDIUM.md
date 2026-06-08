# Your AI Agent Has a New Attack Surface. Most Security Teams Are Ignoring It.

**MCP is the protocol powering every modern AI agent. Here is what the risks look like, how to test for them, and the tool built to do it automatically.**

---

In September 2025, the first malicious MCP package was published to a public registry. It looked legitimate. It passed basic review. It was installed by developers building AI agents across dozens of companies.

By the time anyone noticed, it had been silently exfiltrating credentials for weeks.

That was not the last one.

Between January and February 2026 alone, researchers filed over **30 CVEs** targeting MCP servers, clients, and tooling. The NSA issued a dedicated advisory. OWASP published its first MCP Top 10. Palo Alto Unit 42 found that with just five connected MCP servers, a single compromised server reached a **78.3% attack success rate**.

The AI agent era has arrived. The security tooling has not caught up.

That is the problem this article is about.

---

## What is MCP and Why Did Everyone Adopt It So Fast?

MCP stands for Model Context Protocol. Anthropic published the specification in late 2024 as an open standard for connecting AI models to tools.

Before MCP, every AI integration was custom-wired. A chatbot connected to Slack via one bespoke API. The same chatbot connected to a database via a completely different one. Developers rebuilt the same plumbing endlessly.

MCP changed that with a single universal interface. One protocol. Any tool. Any AI model.

The adoption was immediate. By mid-2025, Claude, Cursor, Windsurf, LangChain, AutoGen, and hundreds of enterprise agent frameworks all spoke MCP natively. Today, if your company runs an AI agent that does anything — reads documents, queries databases, calls internal APIs, publishes records, sends emails — there is a very good chance an MCP server is sitting somewhere in that pipeline.

And that MCP server is almost certainly not security-tested.

---

## The Problem With MCP From a Security Perspective

MCP is built on JSON-RPC over HTTP. That part is familiar. Web security teams know HTTP.

What is unfamiliar is the *attack surface that did not exist before*.

When an AI model calls an MCP tool, it does not just execute code. It reads the tool's name. It reads the tool's description. It reads the tool's output. All of that text lands in the model's context — the same context that contains the system prompt, the user's instructions, and the agent's decision-making logic.

This creates an attack class that traditional web scanners simply cannot see.

**Prompt injection** is not a SQL injection variant. It does not exploit a type mismatch or a buffer boundary. It exploits the fact that an LLM cannot distinguish between "data" and "instructions" when both arrive in the same context window. An attacker who controls any text the agent reads — a field value, a document, a tool description — can issue instructions to the model itself.

And the model will follow them.

There is more. MCP servers are typically deployed as shared infrastructure. One server, many users. This means the classic web vulnerabilities — IDOR, tenant isolation failures, SSRF — all apply, but now their blast radius includes AI agent behavior, not just raw data access.

A leaked API key from an MCP tool response does not just expose that API. It potentially exposes every action the AI agent can take with that key.

---

## The Risk Map: What Can Actually Go Wrong

Here are the categories that matter most in practice, ordered by how often they appear in real deployments:

**Unauthenticated tool enumeration.** The MCP `tools/list` endpoint is exposed without any credentials. Any attacker on the network can map your entire agent's capability surface before writing a single line of exploit code. This sounds minor. It is not. It is reconnaissance for free.

**Authentication bypass.** Countless MCP implementations treat auth as optional. Tools execute with no token, an expired token, or literally the string `INVALID`. This is not a sophisticated attack. It is a curl command.

**Stored prompt injection.** An attacker writes a malicious payload into any field the AI agent will later read — a notes field, an internal description, a form value. When the agent retrieves that data, the payload fires in its context. The attacker never directly interacts with the AI. This is the attack that hit Supabase's Cursor integration in 2025, exfiltrating sensitive integration tokens from a production environment.

**Tool poisoning and rug pulls.** MCP tool descriptions are treated as trusted instructions by the model. Embed invisible Unicode characters — zero-width spaces, RTL overrides, variation selectors — and you can hide arbitrary instructions that only the model sees. Change a tool's description after the user approved it, and the model now operates under instructions that were never reviewed. Invariant Labs demonstrated working rug-pull attacks against WhatsApp and GitHub MCP servers within months of MCP's release.

**Replay attacks.** JSON-RPC has an `id` field but no nonce, no timestamp, no idempotency key. A captured HTTP request for a destructive tool call — say, publishing a financial form — can be replayed indefinitely. The server has no way to detect it.

**SSRF.** Tools that accept URL parameters will often fetch whatever URL you give them, including `http://169.254.169.254/latest/meta-data/` — the AWS cloud metadata endpoint that hands over IAM credentials to anyone who can reach it.

**Weak sessions.** Some MCP servers issue sequential session IDs. If you know session 1041 exists, session 1042 probably does too. CVE-2025-6515 documented exactly this pattern.

---

## How You Actually Pentest an MCP Server

The methodology is familiar if you have done web application pentesting. The specifics are different.

You start by enumerating the surface: `tools/list`, `resources/list`, `prompts/list`, with and without authentication. You decode any JWT tokens. You probe OAuth metadata endpoints.

Then you test authentication — call tools with no token, an invalid token, an expired token. Decode the JWT and see if the scope claims are actually enforced at the tool level, not just at the gateway.

Then injection: prompt payloads in every string parameter, stored payloads written via write tools and read back via read tools, and — critically — scan every field in every JSON response, not just the `content` field. Real stored injection has fired through error messages, metadata fields, and nested response keys that a naive scanner would never check.

Then protocol: replay identical requests, check session ID entropy across five fresh `initialize` calls, send 30 rapid requests and watch for a 429.

Then infrastructure: CORS headers, security headers, SSRF probes, command injection metacharacters in string parameters, path traversal in file/path parameters.

Finally, dynamic behavior: fetch `tools/list` twice, diff the tool descriptions. Check for duplicate tool names. Check for tool names that differ by a single visually similar character.

Doing this manually against a 25-tool MCP server takes a full day. Doing it carefully and consistently takes more.

---

## Introducing MCPTROTTER

**MCPTROTTER** is a purpose-built pentest tool for MCP servers, part of the **Bugtrotter** security toolkit.

It automates all of the above — 28 checks, covering the full OWASP MCP Top 10 — against any MCP server using Streamable HTTP transport. No Kali Linux required. No Docker. Just Python.

One tool. Any MCP endpoint. Two minutes.

---

### Using MCPTROTTER Without an AI Key

The baseline mode requires nothing except the target URL.

```bash
cd mcppt_tool
python -m mcppt.cli
```

This opens an interactive shell styled like gobuster or ffuf — the kind of interface security people already know.

```
target https://your-mcp-server.com/mcp
noverify
token  eyJ...
scan
findings
report report.md
```

`scan` runs all 28 checks sequentially, streaming live output as each check completes. When it finishes, `findings` shows a colour-coded table: CRITICAL in red, HIGH in yellow, MEDIUM in orange, LOW in cyan.

`report` exports a clean markdown file with finding details, evidence, and severity counts — ready to drop into a pentest report.

For CI/CD pipelines or scripted scans, the one-liner:

```bash
python -m mcppt.cli scan \
  --url https://your-mcp-server.com/mcp \
  --no-verify \
  --output report.md
```

You can also run specific check groups if you want to focus:

```bash
# Injection surface only
python -m mcppt.cli scan --url ... --checks injection,stored,poison_all,tool_poisoning

# Protocol-level only
python -m mcppt.cli scan --url ... --checks replay,session,rate,rug_pull

# Infrastructure only
python -m mcppt.cli scan --url ... --checks headers,ssrf,cmd_injection,path_traversal
```

This alone replaces a full day of manual MCP recon.

---

### Using MCPTROTTER With an AI API Key

Add an AI key and the tool gains an intelligence layer on top of the raw scan results.

Inside the shell, after the scan:

```
ai claude  sk-ant-api03-...
analyze
```

The `analyze` command sends all findings to Claude (or GPT-4o if you prefer OpenAI) and returns three things:

**An attack chain narrative.** Not just a list of findings — a story of how an attacker would chain them together. Which vulnerability is the entry point, which is the pivot, which is the impact. This is what clients and executives actually need to understand risk.

**Top 3 priorities.** Which findings to fix first, with a one-line reason based on exploitability and blast radius — not just CVSS score, which regularly misleads.

**Overall risk rating.** A single CRITICAL / HIGH / MEDIUM / LOW with a one-sentence business-impact justification a non-technical stakeholder can read and act on.

What takes a senior analyst an hour to write takes `analyze` about ten seconds.

---

## MCPTROTTER + Burp Suite: The Full Stack

If you already run Burp Suite in your web application pentest workflow, MCPTROTTER integrates directly with it.

```bash
python -m mcppt.cli scan \
  --url https://your-mcp-server.com/mcp \
  --proxy http://127.0.0.1:8080 \
  --no-verify
```

Every single JSON-RPC call MCPTROTTER makes — all 28 checks, every injection probe, every replay test, every tool enumeration — flows through Burp's proxy.

This is where the combination becomes genuinely powerful.

Burp's HTTP history gives you a complete, timestamped evidence trail of everything MCPTROTTER tested. Every request, every response, logged automatically.

Burp Repeater lets you take any request MCPTROTTER generated — say, the stored injection write call — and iterate on it manually. Change the payload. Change the field. Watch what comes back.

Burp Intruder lets you take the tool call structure MCPTROTTER discovered and fuzz it systematically with wordlists.

Burp's passive scanner runs over all the MCP traffic in the background, catching anything MCPTROTTER's checks do not explicitly cover.

Think of it this way: **Burp Suite is your HTTP microscope. MCPTROTTER is your MCP attack engine.** MCPTROTTER generates high-quality, targeted MCP-specific traffic. Burp captures, replays, and extends every one of those requests.

No other combination gives you this for MCP.

---

## Remediation: The Short Version

For developers and security teams who find findings and need to know what to fix:

**Authentication:** Enforce token validation on *every* tool call. Use RS256/ES256 JWT with a mandatory `exp` claim and a max 24-hour lifetime. Implement tool-level scope claims.

**Prompt injection:** Sanitize all tool outputs before they enter LLM context. Strip `<system>`, `</tool_result>`, and template markers. Apply output guardrails that detect instruction-like patterns.

**Tool descriptions:** Scan for invisible Unicode before deployment. Hash and pin descriptions at first approval. Alert on any change.

**Replay:** Add per-request nonces or timestamps. Reject any request replaying a seen nonce.

**Sessions:** Generate session IDs with CSPRNG, minimum 128-bit entropy. UUID v4 is fine.

**CORS and headers:** Explicit origin allowlist, never `*`. Add `X-Content-Type-Options`, `Referrer-Policy`, `CSP`, and HSTS with `max-age` ≥ 31,536,000.

**Resources endpoint:** Apply identical auth checks to `resources/list` and `resources/read` as to `tools/call`. Validate URIs against an allowlist and reject traversal sequences.

---

## The Bottom Line

MCP is not going away. It is the protocol that makes AI agents useful, and useful AI agents are now a business requirement, not a nice-to-have.

But "useful" and "secure" are not the same thing, and right now there is a gap between how fast MCP is being deployed and how seriously its security is being taken.

OWASP published an MCP Top 10. The NSA issued an advisory. Researchers documented dozens of CVEs. Real production systems have been breached.

The tooling to test for these issues now exists and it takes two minutes to run.

---

## Try It or Reach Out

MCPTROTTER is part of the **Bugtrotter** security toolkit.

If you are running an MCP deployment and want it assessed, if you want MCPTROTTER customised for your specific MCP architecture, or if you just want to talk about what responsible MCP security looks like for your organisation — reach out.

**Gurudeep Mallam — Security Researcher, Bugtrotter**

- GitHub: [github.com/gurudeepmallam-cmd](https://github.com/gurudeepmallam-cmd)
- LinkedIn: [Mallam Gurudeep](https://in.linkedin.com/in/mallam-gurudeep-7734941aa)
- Email: gurudeep.mallam@gmail.com

*MCP is the new attack surface. MCPTROTTER is how you test it.*

---

*MCPTROTTER v2.3 — 28 automated checks — full OWASP MCP Top 10 coverage — works against any MCP server over Streamable HTTP.*
