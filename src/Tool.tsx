// Envelope: share environment secrets with a teammate through an encrypted, expiring link instead of pasting them in chat.
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useCopy, useStored } from "./lib/store";
import { Section } from "./ui/kit";

const T = "envelope";
type Payload = { label: string; from: string; body: string; created: number; expires: number };
const b64 = (b: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(b as ArrayBuffer))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64 = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
const enc = new TextEncoder(), dec = new TextDecoder();
const INCOMPLETE = "This link is incomplete. Make sure you copied all of it, including the part after #.";

async function keyFrom(pass: string, salt: Uint8Array) {
  const base = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt: salt as BufferSource, iterations: 250000, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
/** Encrypt with AES-256-GCM. The key travels after the # (never sent to any server) unless a passphrase is used. */
async function seal(p: Payload, pass: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12)), salt = crypto.getRandomValues(new Uint8Array(16));
  let key: CryptoKey, raw = "";
  if (pass) key = await keyFrom(pass, salt);
  else { const k = crypto.getRandomValues(new Uint8Array(32)); raw = b64(k); key = await crypto.subtle.importKey("raw", k, "AES-GCM", false, ["encrypt"]); }
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(p)));
  const q = new URLSearchParams({ c: b64(ct), iv: b64(iv), ...(pass ? { s: b64(salt) } : {}), x: String(p.expires) });
  return `${location.origin}/t/envelope?${q}${raw ? "#" + raw : ""}`;
}
async function unseal(c: string, iv: string, keyRaw: string, salt: string | null, pass: string): Promise<Payload> {
  const key = salt ? await keyFrom(pass, unb64(salt)) : await crypto.subtle.importKey("raw", unb64(keyRaw), "AES-GCM", false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) as BufferSource }, key, unb64(c) as BufferSource);
  return JSON.parse(dec.decode(pt));
}
const parseEnv = (body: string) => body.split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#")).map(l => { const i = l.indexOf("="); return i > 0 ? [l.slice(0, i).trim(), l.slice(i + 1).trim().replace(/^["']|["']$/g, "")] : ["", l]; });

function Opened() {
  const [params] = useSearchParams();
  const [pass, setPass] = useState("");
  const [p, setP] = useState<Payload | null>(null);
  const [err, setErr] = useState("");
  const [shown, setShown] = useState<Record<number, boolean>>({});
  const { copy, copied } = useCopy();
  const c = params.get("c") ?? "", iv = params.get("iv") ?? "", salt = params.get("s"), exp = +(params.get("x") ?? 0);
  const expired = exp > 0 && Date.now() > exp;
  // Links without a passphrase open straight away.
  useEffect(() => {
    if (salt || expired) return;
    unseal(c, iv, location.hash.slice(1), null, "").then(setP, () => setErr(INCOMPLETE));
  }, [c, iv, salt, expired]);
  const withPass = async () => { try { setP(await unseal(c, iv, "", salt, pass)); setErr(""); } catch { setErr("Wrong passphrase."); } };
  if (expired) return <section className="panel"><h2>This envelope has expired</h2><p>Ask the sender for a new link.</p></section>;
  if (!p) return <section className="panel stack" style={{ gap: 10, maxWidth: 460 }}><h2>Encrypted envelope</h2>{salt && <><label className="field"><span>Passphrase (the sender told you this separately)</span><input className="input" type="password" value={pass} onChange={e => setPass(e.target.value)} /></label><button className="btn primary" onClick={withPass}>Open</button></>}{err && <p className="pill bad">{err}</p>}</section>;
  const rows = parseEnv(p.body);
  return (
    <section className="panel stack" style={{ gap: 12 }}>
      <p className="eyebrow">From {p.from} · expires {new Date(p.expires).toLocaleString()}</p>
      <h2>{p.label}</h2>
      <div className="stack" style={{ gap: 6 }}>{rows.map(([k, v], i) => (
        <div key={i} className="ev-row"><code>{k || "value"}</code><code className="ev-v">{shown[i] ? v : "•".repeat(Math.min(24, v.length))}</code><button className="btn ghost small" onClick={() => setShown({ ...shown, [i]: !shown[i] })}>{shown[i] ? "Hide" : "Show"}</button><button className="btn small" onClick={() => copy(v)}>Copy</button></div>))}</div>
      <button className="btn" style={{ alignSelf: "flex-start" }} onClick={() => copy(p.body)}>{copied ? "Copied" : "Copy all as .env"}</button>
      <p className="note">Decrypted in your browser. Store these in your password manager or secrets tool, then close this tab.</p>
    </section>
  );
}

export default function Envelope() {
  const [params] = useSearchParams();
  const [from, setFrom] = useStored(T, "from", "Walid");
  const [label, setLabel] = useState("Staging environment for Lina");
  const [body, setBody] = useState("DATABASE_URL=postgres://app:s3cr3t@staging-db:5432/app\nSTRIPE_TEST_KEY=sk_test_example123\nMAPS_API_KEY=example-maps-key");
  const [hours, setHours] = useState(24);
  const [pass, setPass] = useState("");
  const [link, setLink] = useState("");
  const { copy, copied } = useCopy();
  if (params.get("c")) return <><Opened /><style>{css}</style></>;
  const rows = parseEnv(body);
  return (
    <div className="stack">
      <div className="grid2">
        <Section title="What to send">
          <div className="stack" style={{ gap: 10 }}>
            <label className="field"><span>Label</span><input id="ev-l" className="input" value={label} onChange={e => { setLabel(e.target.value); setLink(""); }} /></label>
            <label className="field"><span>Secrets (KEY=value lines, or any text)</span><textarea id="ev-b" className="input" rows={7} value={body} onChange={e => { setBody(e.target.value); setLink(""); }} style={{ fontFamily: "var(--mono)", fontSize: 13 }} /></label>
            <p className="note">{rows.length} values. Encrypted on this device before anything leaves it.</p>
          </div>
        </Section>
        <Section title="How it opens">
          <div className="stack" style={{ gap: 10 }}>
            <label className="field"><span>From</span><input id="ev-f" className="input" value={from} onChange={e => setFrom(e.target.value)} /></label>
            <label className="field"><span>Expires after</span><select id="ev-h" className="input" value={hours} onChange={e => { setHours(+e.target.value); setLink(""); }}>{[1, 4, 24, 72, 168].map(h => <option key={h} value={h}>{h < 24 ? `${h} hour${h > 1 ? "s" : ""}` : `${h / 24} day${h > 24 ? "s" : ""}`}</option>)}</select></label>
            <label className="field"><span>Passphrase (optional, send it by another channel)</span><input id="ev-p" className="input" type="password" value={pass} onChange={e => { setPass(e.target.value); setLink(""); }} /></label>
            <button className="btn primary" onClick={async () => setLink(await seal({ label, from, body, created: Date.now(), expires: Date.now() + hours * 3600000 }, pass))}>Seal the envelope</button>
            {link && <><input className="input note" readOnly value={link} onFocus={e => e.target.select()} aria-label="Envelope link" /><button className="btn" onClick={() => copy(link)}>{copied ? "Copied" : "Copy link"}</button></>}
          </div>
        </Section>
      </div>
      <Section title="How safe is this?">
        <ul style={{ margin: 0, paddingLeft: 18, display: "grid", gap: 6 }}>
          <li>Secrets are encrypted with AES-256-GCM in your browser. No server ever receives them.</li>
          <li>Without a passphrase, the key is the part of the link after <code>#</code>. Browsers never send that part to any server, but anyone holding the full link can open it.</li>
          <li>With a passphrase, the link alone is useless. Send the passphrase by phone or a different app.</li>
          <li>Expiry is checked when the link is opened. There is no server to delete copies, so rotate important secrets after onboarding.</li>
        </ul>
      </Section>
      <style>{css}</style>
    </div>
  );
}
const css = `.ev-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:6px 0;border-bottom:1px solid var(--line)}.ev-row code{font-family:var(--mono);font-size:13px}.ev-v{flex:1;min-width:0;word-break:break-all;background:var(--sunk);padding:4px 8px;border-radius:6px}`;
