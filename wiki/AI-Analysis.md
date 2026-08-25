# AI Analysis (optional)

The plugin can generate a natural-language summary/triage note for an alert or case using an LLM provider **you** configure. It is **off by default** and **bring-your-own-key**.

> Read [[Security Model]] before enabling this — it explains exactly what data does and does not leave your network.

## Configure

**Workbench → Settings → AI analysis**:

1. Toggle **Enabled**.
2. Choose a **provider**: OpenAI, DeepSeek, Gemini, or Anthropic.
3. Paste your **API key** (stored server-side; see below).
4. Optionally set a **model** (e.g. `gpt-4o-mini`) and a custom **base URL** (for gateways / self-hosted-compatible endpoints).
5. Save.

## Using it

Open an alert or case flyout → **AI Analysis** tab → **Generate**. The result is stored on the document so it can be viewed later without regenerating.

## Key storage

The API key is held server-side and is not returned to the browser (the field shows a masked placeholder once configured). For at-rest encryption of the stored key, configure the plugin's encryption settings; the Settings tab indicates whether encryption is configured.

## What gets sent

Only a **projected, allowlisted** subset of an alert leaves the network — never the raw document. Comment bodies are never sent (only a count), and long fields such as `full_log` are truncated. See [[Security Model#ai-egress]] for the full boundary.
