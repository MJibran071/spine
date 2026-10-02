// The dashboard page (HTML + CSS + vanilla JS) served by server.ts at `/`.
//
// Why this lives in its own module: the page is ~600 lines of embedded
// CSS/JS and server.ts is transport logic. Keeping it separate keeps both
// readable.
//
// ANIMATION RULES (a polling dashboard is the worst case for motion — a naive
// `innerHTML` repaint every 2s restarts every CSS animation and the page
// visibly strobes):
//   1. `paint()` writes only when the HTML actually changed, so unchanged
//      panels keep their DOM (and their running animations) untouched.
//   2. Tables are diffed per row by signature: only rows whose content changed
//      get the `flash` class, so a probe result landing flashes THAT row.
//   3. Stat values are updated in place (never re-created) and count up with
//      requestAnimationFrame, bumping only when the number moved.
//   4. Logs are appends, not repaints: new lines prepend and slide in.
//   5. `prefers-reduced-motion` disables all of it.
//
// Everything is read-only: no new endpoints, no writes, loopback only.
export const PAGE = `<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Exploit Lab — Live</title>
<script>window.STATE = /*__STATE__*/null; window.STATIC_EXPORT = /*__STATIC__*/false;</script>
<style>
  :root{
    color-scheme: dark;
    --bg:#05070c; --panel:#0e1520cc; --line:#1b2436; --line2:#26344a;
    --fg:#cfd8e3; --dim:#7d8899; --acc:#7cc4ff; --acc2:#4d9dff;
    --ok:#3fb950; --warn:#e3b341; --bad:#ff6b61; --purple:#a371f7;
  }
  *{ box-sizing:border-box; }
  html,body{ height:100%; }
  body{
    margin:0; font:14px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
    background:var(--bg); color:var(--fg); overflow-x:hidden;
  }
  /* ---------- ambient background ---------- */
  .aurora{
    position:fixed; inset:-25vmax; z-index:-2; pointer-events:none; filter:blur(64px); opacity:.6;
    background:
      radial-gradient(38vmax 38vmax at 18% 22%, #1b4bff40, transparent 62%),
      radial-gradient(32vmax 32vmax at 82% 12%, #a371f738, transparent 62%),
      radial-gradient(44vmax 44vmax at 62% 88%, #00cfff26, transparent 64%);
    animation:drift 42s ease-in-out infinite alternate;
  }
  @keyframes drift{
    from{ transform:translate3d(-3%,-2%,0) scale(1.02) rotate(0deg); }
    to  { transform:translate3d(4%,3%,0) scale(1.14) rotate(7deg); }
  }
  .grid{
    position:fixed; inset:0; z-index:-1; pointer-events:none; opacity:.5;
    background-image:
      linear-gradient(#ffffff0f 1px, transparent 1px),
      linear-gradient(90deg,#ffffff0f 1px, transparent 1px);
    background-size:44px 44px;
    -webkit-mask-image:radial-gradient(75% 55% at 50% 0%, #000 25%, transparent 100%);
    mask-image:radial-gradient(75% 55% at 50% 0%, #000 25%, transparent 100%);
    animation:gridpan 26s linear infinite;
  }
  @keyframes gridpan{ to{ background-position:0 44px, 44px 0; } }

  /* ---------- header ---------- */
  header{
    position:sticky; top:0; z-index:20; display:flex; gap:14px; align-items:center; flex-wrap:wrap;
    padding:11px 20px; border-bottom:1px solid var(--line);
    background:linear-gradient(180deg,#05070ce6,#05070c99);
    -webkit-backdrop-filter:blur(12px); backdrop-filter:blur(12px);
  }
  header::after{
    content:""; position:absolute; left:0; right:0; bottom:-1px; height:1px; pointer-events:none;
    background:linear-gradient(90deg,transparent,#4d9dff88,#a371f7bb,#4d9dff88,transparent);
    background-size:200% 100%; animation:sweep 7s linear infinite;
  }
  @keyframes sweep{ from{ background-position:0% 0; } to{ background-position:200% 0; } }
  .mark{
    font-size:15px; font-weight:700; letter-spacing:.14em; margin:0;
    background:linear-gradient(90deg,#7cc4ff,#a371f7,#7cc4ff);
    background-size:220% 100%; -webkit-background-clip:text; background-clip:text; color:transparent;
    animation:sweep 9s linear infinite;
  }
  .muted{ color:var(--dim); font-size:12px; }
  .right{ margin-left:auto; display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
  .pill{
    padding:2px 9px; border-radius:99px; font-size:11px; border:1px solid #30363d;
    white-space:nowrap; transition:color .3s, border-color .3s, background .3s;
  }
  .solved { color:var(--ok);     border-color:#2ea04366; background:#0d1f0d44; }
  .failed { color:var(--bad);    border-color:#f8514966; background:#1f0d0d44; }
  .pending{ color:var(--warn);   border-color:#d2992266; background:#1f1a0d44; }
  .finding{ color:#ff7b72;       border-color:#ff7b7266; background:#1f100d44; }
  .chip   { color:var(--acc);    border-color:#4d9dff44; background:#0d162a5c; }
  .chip-dim{ color:var(--dim);   border-color:#30363d; background:#ffffff08; }
  .chip-vault{ color:#7ee787;    border-color:#2ea04355; background:#0d1f0d55; }
  .chip-lz  { color:var(--purple); border-color:#a371f755; background:#150d2455; }
  .live{ display:inline-flex; align-items:center; gap:7px; }
  .dot{ width:7px; height:7px; border-radius:50%; background:var(--ok); animation:ping 1.9s cubic-bezier(0,0,.2,1) infinite; }
  @keyframes ping{
    0%  { box-shadow:0 0 0 0 #3fb95099; }
    70% { box-shadow:0 0 0 9px #3fb95000; }
    100%{ box-shadow:0 0 0 0 #3fb95000; }
  }
  .dot.warn{ background:var(--warn); animation-duration:1s; }

  /* ---------- layout ---------- */
  main{ padding:16px 20px 56px; max-width:1360px; margin:0 auto; }
  h2{ font-size:12px; text-transform:uppercase; letter-spacing:.08em; color:var(--dim); margin:24px 0 8px; display:flex; align-items:baseline; gap:8px; }
  h2 .hint{ font-size:11px; text-transform:none; letter-spacing:0; color:#5d6878; font-weight:400; }
  .kv{ color:var(--dim); font-size:13px; }
  .empty{ color:var(--dim); font-size:13px; padding:12px 0; }
  a{ color:var(--acc); }

  /* ---------- stats ---------- */
  .stat-row{ display:flex; gap:10px; flex-wrap:wrap; margin-bottom:14px; }
  .stat{
    position:relative; overflow:hidden; min-width:116px; padding:9px 15px 10px;
    border:1px solid var(--line); border-radius:11px;
    background:linear-gradient(180deg,#0e1524e6,#0b101ccc);
    transition:transform .2s ease, border-color .2s ease, box-shadow .25s ease;
    animation:rise .5s cubic-bezier(.2,.8,.2,1) backwards;
  }
  .stat:hover{ transform:translateY(-3px); border-color:#2f4a72; box-shadow:0 14px 32px -18px #4d9dffff; }
  .stat::before{
    content:""; position:absolute; top:0; left:0; height:2px; width:100%;
    background:linear-gradient(90deg,var(--c,#4d9dff),transparent 85%); opacity:.55;
  }
  .stat .val{ font-size:23px; font-weight:600; line-height:1.15; color:var(--c,#7cc4ff); font-variant-numeric:tabular-nums; }
  .stat .lbl{ font-size:10.5px; color:var(--dim); text-transform:uppercase; letter-spacing:.06em; margin-top:1px; }
  .stat .sub{ font-size:10.5px; color:#5d6878; margin-top:2px; }
  .stat.bump{ animation:bump .65s cubic-bezier(.2,.8,.2,1); }
  @keyframes bump{
    0%  { transform:translateY(-3px) scale(1); }
    35% { transform:translateY(-3px) scale(1.05); }
    100%{ transform:translateY(-3px) scale(1); }
  }
  @keyframes rise{ from{ opacity:0; transform:translateY(10px) scale(.98); } to{ opacity:1; transform:none; } }

  /* ---------- tabs ---------- */
  .tabs{ position:relative; display:flex; gap:2px; margin:0 0 18px; border-bottom:1px solid var(--line); overflow-x:auto; }
  .tab{
    flex:0 0 auto; padding:8px 15px; cursor:pointer; border:0; background:none; font-size:13px;
    font-family:inherit; color:var(--dim); border-radius:8px 8px 0 0; white-space:nowrap;
    transition:color .2s ease, background .2s ease;
  }
  .tab:hover{ color:var(--fg); background:#ffffff09; }
  .tab.active{ color:#e6edf3; }
  .tab .n{ font-size:10px; opacity:.75; margin-left:5px; }
  .tab-ind{
    position:absolute; bottom:-1px; left:0; height:2px; width:0; border-radius:2px;
    background:linear-gradient(90deg,#4d9dff,#a371f7); box-shadow:0 0 14px #4d9dffbb;
    transform:translateX(0); transition:transform .34s cubic-bezier(.2,.8,.2,1), width .34s cubic-bezier(.2,.8,.2,1);
  }
  .panel{ display:none; }
  .panel.active{ display:block; animation:panelIn .34s cubic-bezier(.2,.8,.2,1); }
  @keyframes panelIn{ from{ opacity:0; transform:translateY(9px); } to{ opacity:1; transform:none; } }

  /* ---------- tables ---------- */
  table{ width:100%; border-collapse:collapse; }
  td, th{ padding:6px 10px; border-bottom:1px solid #131a26; text-align:left; vertical-align:top; }
  th{ color:var(--dim); font-weight:500; font-size:11px; text-transform:uppercase; letter-spacing:.04em; position:sticky; top:53px; background:#05070ce6; -webkit-backdrop-filter:blur(6px); backdrop-filter:blur(6px); z-index:5; }
  tbody tr{ transition:background .18s ease, transform .18s ease; }
  tbody tr:hover td{ background:#0f1725; }
  tbody tr:hover{ transform:translateX(2px); }
  tbody tr.flash{ animation:flash 1.2s ease; }
  @keyframes flash{ 0%{ background:#4d9dff33; } 100%{ background:transparent; } }
  .addr{ font-size:12px; cursor:pointer; color:var(--acc); position:relative; }
  .addr:hover{ text-decoration:underline; }
  .freshness{ display:inline-block; width:6px; height:6px; border-radius:50%; margin-right:5px; vertical-align:middle; background:#3d4757; }
  .freshness.f{ background:var(--ok); animation:ping 2.4s ease-out infinite; }
  .freshness.w{ background:var(--warn); }
  .nowrap{ white-space:nowrap; }

  /* ---------- signals / findings ---------- */
  .cards{ display:grid; grid-template-columns:repeat(auto-fill,minmax(360px,1fr)); gap:11px; }
  .card{
    position:relative; overflow:hidden; border:1px solid #ff6b6144; border-radius:12px; padding:12px 14px;
    background:linear-gradient(180deg,#1a0d0fdd,#120a0ccc);
    animation:rise .45s cubic-bezier(.2,.8,.2,1) backwards;
    transition:border-color .25s ease, box-shadow .25s ease;
  }
  .card:hover{ border-color:#ff6b6188; box-shadow:0 16px 40px -22px #ff6b61cc; }
  .card::after{
    content:""; position:absolute; inset:-45%; z-index:0; pointer-events:none; opacity:.3;
    background:conic-gradient(from 0deg,#ff6b6100,#ff6b6126,#ff6b6100 55%);
    animation:spin 9s linear infinite;
  }
  @keyframes spin{ to{ transform:rotate(360deg); } }
  .card > *{ position:relative; z-index:1; }
  .card b{ color:#ff7b72; display:block; margin-bottom:4px; }
  .card .profit{ color:var(--ok); font-size:13px; margin-top:6px; }
  .signal-row{
    position:relative; border-left:3px solid var(--warn); border-radius:0 8px 8px 0;
    padding:8px 11px; margin-bottom:8px; background:#14120444;
    animation:rise .35s cubic-bezier(.2,.8,.2,1) backwards;
    transition:background .2s ease, transform .2s ease;
  }
  .signal-row:hover{ background:#1a1a0a66; transform:translateX(2px); }
  .signal-row.high{ border-color:#ff7b72; background:#1a0e0e44; }
  .signal-row .addr-line{ font-size:12px; color:var(--dim); }
  .signal-row .hyp{ font-size:13px; margin-top:3px; color:#c9d1d9; }
  .bar{ height:4px; border-radius:3px; background:#1b2436; overflow:hidden; margin-top:7px; }
  .bar > i{ display:block; height:100%; width:0; border-radius:3px; background:linear-gradient(90deg,#3fb950,#e3b341,#ff6b61); transition:width .85s cubic-bezier(.2,.8,.2,1); }

  /* ---------- badges ---------- */
  .badge{ display:inline-block; padding:1px 7px; border-radius:5px; font-size:11px; margin-right:4px; border:1px solid transparent; }
  .badge-bounty{ background:#d2992222; color:var(--warn); border-color:#d2992244; }
  .badge-conf-high{ background:#3fb95022; color:var(--ok); border-color:#3fb95044; }
  .badge-conf-med { background:#d2992222; color:var(--warn); border-color:#d2992244; }
  .badge-conf-low { background:#8b949e22; color:var(--dim); border-color:#8b949e44; }

  /* ---------- logs ---------- */
  .logbox{
    background:#080c14; border:1px solid var(--line); border-radius:10px; padding:8px 10px;
    height:300px; overflow:auto; font-size:11.5px; line-height:1.75;
  }
  .logline{
    padding:1px 7px; border-left:2px solid #1b2436; border-radius:0 4px 4px 0; margin-bottom:1px;
    white-space:pre-wrap; word-break:break-word; animation:lineIn .4s cubic-bezier(.2,.8,.2,1) backwards;
  }
  .logline .ts{ color:#5d6878; margin-right:7px; }
  .logline .kind{ display:inline-block; min-width:52px; margin-right:6px; color:var(--dim); }
  .logline.k-finding{ border-left-color:#ff6b61; background:#1a0e0e44; }
  .logline.k-finding .kind{ color:#ff7b72; }
  .logline.k-safety{ border-left-color:var(--warn); background:#17130444; }
  .logline.k-safety .kind{ color:var(--warn); }
  .logline.k-scan{ border-left-color:#4d9dff66; }
  .logline.k-fork{ border-left-color:#a371f766; }
  .logline.k-daemon{ border-left-color:#3fb95066; }
  @keyframes lineIn{ from{ opacity:0; transform:translateX(-8px); } to{ opacity:1; transform:none; } }

  /* ---------- memory tab ---------- */
  .logline.k-probe-win{ border-left-color:#3fb950; background:#0d1f0d55; }
  .logline.k-probe-win .kind{ color:var(--ok); }
  .logline.k-probe-fail{ border-left-color:#ff6b61aa; background:#1a0e0e44; }
  .logline.k-probe-fail .kind{ color:#ff7b72; }
  .logline.k-probe-neutral{ border-left-color:#4d9dff55; }
  .logline.k-triage{ border-left-color:#a371f766; }
  .logline.k-triage .kind{ color:var(--purple); }
  .mem-grid{ display:grid; grid-template-columns:minmax(0,1.45fr) minmax(0,1fr); gap:14px; align-items:start; }
  @media (max-width:1040px){ .mem-grid{ grid-template-columns:1fr; } }
  /* Growth sparkline: height is set per bar from data, so the transition IS
     the animation; bars are built once and only their height changes. */
  .spark{ display:flex; align-items:flex-end; gap:3px; height:60px; padding:8px 10px 6px; border:1px solid var(--line); border-radius:11px; background:#0b101ccc; }
  .spark .bar{ flex:1 1 0; min-height:2px; border-radius:3px 3px 0 0; background:linear-gradient(180deg,#7cc4ff,#4d9dff22); transition:height .55s cubic-bezier(.2,.8,.2,1); cursor:default; }
  .spark .bar.now{ background:linear-gradient(180deg,#a371f7,#4d9dff33); box-shadow:0 0 12px #a371f799; }
  .spark .bar.grow{ animation:grow .6s cubic-bezier(.2,.8,.2,1) backwards; }
  @keyframes grow{ from{ transform:scaleY(.08); opacity:.15; } to{ transform:scaleY(1); opacity:1; } }
  /* Rotating halo on a memory stat card (::after is free on .stat). */
  .brain::after{
    content:""; position:absolute; inset:-45%; z-index:0; pointer-events:none; opacity:.28;
    background:conic-gradient(from 0deg,#a371f700,#a371f73a,#7cc4ff00 60%);
    animation:spin 7.5s linear infinite;
  }
  .stat.brain .val, .stat.brain .lbl, .stat.brain .sub{ position:relative; z-index:1; }
  .membar{ height:7px; border-radius:4px; background:#131a26; overflow:hidden; display:flex; margin-top:5px; }
  .membar i{ display:block; height:100%; width:0; transition:width .65s cubic-bezier(.2,.8,.2,1); }
  .membar i.v{ background:linear-gradient(90deg,#ff6b61,#ffa08f); }
  .membar i.e{ background:#7a5c1e; }
  .membar i.h{ background:#2f6f45; }
  .recall-wrap{ position:relative; padding-bottom:4px; }
  /* Working indicator while a recall is in flight: a sweeping bar, not a
     frozen UI (the search never blocks the 2s poll). */
  .recall-wrap.busy::after{
    content:""; position:absolute; left:0; right:0; bottom:0; height:2px;
    background:linear-gradient(90deg,#4d9dff00,#4d9dff,#a371f700); background-size:200% 100%;
    animation:sweep .9s linear infinite;
  }
  .recall-hit{
    border-left:2px solid #a371f766; border-radius:0 7px 7px 0; padding:6px 10px; margin-bottom:6px;
    background:#0d1420aa; font-size:12px; animation:rise .4s cubic-bezier(.2,.8,.2,1) backwards;
  }
  .recall-hit .kind{ color:var(--purple); margin-right:6px; }
  .recall-hit .score{ color:#5d6878; font-size:11px; margin-left:4px; }
  .recall-hit .ts{ color:#5d6878; font-size:11px; }

  /* ---------- controls ---------- */
  .controls{ display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-bottom:10px; }
  input[type="search"], select{
    background:#0b111c; color:var(--fg); border:1px solid var(--line); border-radius:8px;
    padding:6px 10px; font:inherit; font-size:12px; transition:border-color .2s ease, box-shadow .2s ease;
  }
  input[type="search"]:focus, select:focus{ outline:none; border-color:#3b6ea8; box-shadow:0 0 0 3px #4d9dff22; }
  input[type="search"]{ min-width:230px; }
  .btn{
    background:#101a2b; color:var(--fg); border:1px solid var(--line2); border-radius:8px;
    padding:6px 12px; font:inherit; font-size:12px; cursor:pointer;
    transition:background .2s ease, border-color .2s ease, transform .12s ease;
  }
  .btn:hover{ background:#16233a; border-color:#33507a; }
  .btn:active{ transform:scale(.97); }
  .label-x{ font-size:11.5px; color:var(--dim); display:inline-flex; align-items:center; gap:5px; }

  /* ---------- toasts ---------- */
  #toasts{ position:fixed; right:16px; bottom:16px; z-index:60; display:flex; flex-direction:column; gap:8px; align-items:flex-end; }
  .toast{
    max-width:380px; padding:9px 14px; border-radius:10px; font-size:12.5px;
    background:#161b22ee; border:1px solid #30363d; color:var(--fg);
    box-shadow:0 14px 40px -18px #000; animation:toastIn .4s cubic-bezier(.2,.8,.2,1);
  }
  .toast.hot{ border-color:#ff6b6188; background:#1d0f12f2; color:#ffd7d3; }
  .toast.out{ animation:toastOut .35s ease forwards; }
  @keyframes toastIn{ from{ opacity:0; transform:translateX(30px) scale(.96); } to{ opacity:1; transform:none; } }
  @keyframes toastOut{ to{ opacity:0; transform:translateX(30px) scale(.96); } }
  .copy-msg{
    position:fixed; bottom:22px; left:50%; transform:translateX(-50%) translateY(10px);
    background:#161b22; border:1px solid #30363d; border-radius:9px; padding:8px 18px; font-size:13px;
    color:var(--ok); opacity:0; transition:opacity .3s ease, transform .3s ease; pointer-events:none; z-index:70;
  }
  .copy-msg.show{ opacity:1; transform:translateX(-50%) translateY(0); }
  .spin-dot{ display:inline-block; animation:spin 1.6s linear infinite; }

  /* ---------- daemon & live-chain motion ---------- */
  /* Heartbeat dot in the Status cell: a real beat has a sharp thump and a long
     rest, so the keyframes hold most of the cycle quiet instead of a sine blink. */
  .beat-dot{ display:inline-block; width:8px; height:8px; border-radius:50%; background:var(--ok); margin-right:6px; vertical-align:middle; animation:beat 2.4s cubic-bezier(.4,0,.6,1) infinite; }
  .beat-dot.slow{ background:var(--warn); animation-duration:3.6s; }
  .beat-dot.dead{ background:#7d8899; animation:none; }
  @keyframes beat{
    0%  { transform:scale(1);    box-shadow:0 0 0 0 #3fb95099; }
    8%  { transform:scale(1.55); box-shadow:0 0 0 7px #3fb95044; }
    16% { transform:scale(1.05); box-shadow:0 0 0 12px #3fb95000; }
    100%{ transform:scale(1);    box-shadow:0 0 0 0 #3fb95000; }
  }
  /* Chain shard pills: a slow luminance drift so a shard reads as an active
     lane, tinted per chain; unknown chains keep a neutral drift. */
  .chain-pill{
    display:inline-block; margin:1px 3px 1px 0; padding:1px 9px; border-radius:6px; font-size:11px;
    border:1px solid #26344a; background-size:220% 100%; animation:chainShift 5s linear infinite;
    color:#c9d1d9;
  }
  @keyframes chainShift{ from{ background-position:0% 0; } to{ background-position:220% 0; } }
  .ch-gnosis{ border-color:#4d9dff44; background:linear-gradient(90deg,#0e1b22,#17303c,#0e1b22); color:#66d9e8; }
  .ch-solana{ border-color:#9945ff55; background:linear-gradient(90deg,#150c26,#241338,#150c26); color:#c9a5ff; }
  .ch-tron{ border-color:#eb002844; background:linear-gradient(90deg,#26080c,#3c0d13,#26080c); color:#ff6b61; }
  .ch-unattributed{ border-color:#26344a; background:#10161f; color:#7d8899; }
  .ch-ethereum{ border-color:#4d9dff55; background:linear-gradient(90deg,#0d1a2e,#16294a,#0d1a2e); color:#7cc4ff; }
  .ch-bsc     { border-color:#e3b34155; background:linear-gradient(90deg,#241c08,#3a2d0c,#241c08); color:#e3b341; }
  .ch-polygon { border-color:#a371f755; background:linear-gradient(90deg,#1a1024,#291739,#1a1024); color:#c9a5ff; }
  .ch-base    { border-color:#3fb95055; background:linear-gradient(90deg,#0c1f10,#13301a,#0c1f10); color:#56d364; }
  .ch-arbitrum{ border-color:#2dd4bf55; background:linear-gradient(90deg,#08201d,#0e322d,#08201d); color:#2dd4bf; }
  .ch-robinhood{ border-color:#00c80555; background:linear-gradient(90deg,#0a1f0e,#123a17,#0a1f0e); color:#3fd668; } /* Robinhood brand green */
  .ch-optimism{ border-color:#ff6b6155; background:linear-gradient(90deg,#241010,#3a1a1a,#241010); color:#ff8f88; }
  .ch-avalanche{ border-color:#ff5f5655; background:linear-gradient(90deg,#230d0c,#3a1514,#230d0c); color:#ff7b72; }
  /* Cycle heartbeat bar: one fill per daemon interval, looped by CSS so no
     per-poll math; paused + dimmed when the instance stops beating. */
  .cycle-bar{ height:3px; border-radius:2px; background:#131a26; overflow:hidden; margin-top:4px; min-width:70px; }
  .cycle-bar > i{ display:block; height:100%; width:0; border-radius:2px; background:linear-gradient(90deg,#4d9dff,#a371f7); animation:fillbar linear infinite; }
  .cycle-bar.off > i{ animation-play-state:paused; opacity:.3; }
  @keyframes fillbar{ from{ width:0; } to{ width:100%; } }
  /* Per-daemon watched-pool trend (12 ticks, newest right). */
  .mspark{ display:inline-flex; align-items:flex-end; gap:1px; height:16px; margin-left:7px; vertical-align:middle; }
  .mspark i{ display:block; width:3px; min-height:1px; border-radius:1px 1px 0 0; background:#4d9dff88; transition:height .4s cubic-bezier(.2,.8,.2,1); }
  .mspark i:last-child{ background:#a371f7; }
  /* The scanning sweep: active only while a rotating scan is genuinely recent. */
  .scan-status{ display:flex; align-items:center; gap:10px; border:1px solid var(--line); border-radius:10px; padding:7px 12px; margin:4px 0 12px; background:#0b101ccc; font-size:12px; color:var(--dim); }
  .scan-status .sweep{ position:relative; overflow:hidden; flex:1; height:3px; border-radius:2px; background:#131a26; }
  .scan-status .sweep > i{ position:absolute; top:0; bottom:0; width:34%; border-radius:2px; background:linear-gradient(90deg,#4d9dff00,#4d9dff,#a371f700); background-size:200% 100%; animation:sweep 1.4s linear infinite; }
  .scan-status.idle .sweep > i{ animation-play-state:paused; opacity:.25; }
  .scan-status .lamp{ width:7px; height:7px; border-radius:50%; background:#7d8899; }
  .scan-status.live{ border-color:#4d9dff44; }
  .scan-status.live .lamp{ background:#4d9dff; animation:ping 1.6s ease-out infinite; }
  /* Wire: fork probes pulse their border; kinds without a colour yet get one. */
  .logline.k-osint{ border-left-color:#2dd4bf66; }
  .logline.k-gov{ border-left-color:#e3b34166; }
  .logline.k-lab{ border-left-color:#ff6b6155; }
  .logline.k-fork{ animation:borderPulse 2.2s ease-in-out infinite; }
  @keyframes borderPulse{ 0%,100%{ border-left-color:#a371f733; } 50%{ border-left-color:#a371f7cc; } }
  /* Chain wire: one chip per chain the fleet actually touched in recent
     scan/fork events; a chip pings while its chain is active (<60s). */
  .wire{ display:flex; gap:7px; flex-wrap:wrap; margin:0 0 12px; }
  .wire-ch{
    display:inline-flex; align-items:center; gap:6px; padding:3px 11px; border-radius:7px; font-size:11.5px;
    border:1px solid #26344a; background:#0d1420aa; color:var(--dim);
    transition:border-color .3s ease, color .3s ease, background .3s ease;
  }
  .wire-ch .wdot{ width:6px; height:6px; border-radius:50%; background:#3d4757; }
  .wire-ch.active{ border-color:#4d9dff66; color:#c9d1d9; background:#0f1a2ccc; }
  .wire-ch.active .wdot{ background:#4d9dff; animation:ping 1.6s ease-out infinite; }
  .wire-ch + .wire-ch{ margin-left:0; }

  /* ---------- hacking tab ---------- */
  .hack-grid{ display:grid; grid-template-columns:1.35fr 1fr; gap:14px; align-items:start; }
  @media (max-width: 1100px){ .hack-grid{ grid-template-columns:1fr; } }
  .hack-queue .bar{ max-width:130px; }
  .hack-why{ color:#a8b3c4; }
  .hack-note{ color:var(--dim); font-size:11.5px; margin:2px 0 10px; }

  /* ---------- fleet monitor strip ---------- */
  .mon-strip{
    display:flex; align-items:center; gap:10px; flex-wrap:wrap;
    border:1px solid var(--line); border-radius:10px; padding:8px 12px; margin:4px 0 8px;
    background:#0b101ccc; font-size:12.5px;
  }
  .mon-strip.mon-ok{ border-color:#3fb95044; }
  .mon-strip.mon-bad{ border-color:#ff6b6155; background:#140d0ecc; }
  .mon-strip .lamp{ width:7px; height:7px; border-radius:50%; background:#7d8899; flex:0 0 auto; }
  .mon-strip.mon-ok .lamp{ background:var(--ok); animation:ping 2.4s ease-out infinite; }
  .mon-strip.mon-bad .lamp{ background:var(--bad); animation:ping 1.1s ease-out infinite; }
  .mon-chips{ display:flex; gap:6px; flex-wrap:wrap; margin-left:auto; }
  .mon-note{
    font-size:11.5px; color:var(--warn); background:#17130444; border-left:2px solid #d2992266;
    border-radius:0 4px 4px 0; padding:2px 8px; margin:3px 0; word-break:break-word;
  }
  .mon-table{ margin:6px 0 2px; }
  .mon-table th{ position:static; }
  /* ---------- operator switch (backlog triage ON/OFF) ---------- */
  .switch{
    display:inline-flex; align-items:center; gap:8px; cursor:pointer;
    padding:6px 12px; border:1px solid var(--line2); border-radius:999px;
    background:#0e152066; font-size:12px; letter-spacing:.08em; color:var(--dim);
    transition:border-color .2s, color .2s, box-shadow .2s; user-select:none; white-space:nowrap;
  }
  .switch:hover{ border-color:var(--acc); color:var(--fg); }
  .switch:focus-visible{ outline:1px solid var(--acc); outline-offset:2px; }
  .switch .knob{
    width:26px; height:14px; border-radius:999px; background:#26344a; position:relative; transition:background .2s; flex:none;
  }
  .switch .knob::after{
    content:''; position:absolute; top:2px; left:2px; width:10px; height:10px; border-radius:50%;
    background:#7d8899; transition:left .2s, background .2s;
  }
  .switch.on{ border-color:#3fb95066; color:var(--ok); box-shadow:0 0 12px #3fb95022; }
  .switch.on .knob{ background:#3fb95044; }
  .switch.on .knob::after{ left:14px; background:var(--ok); }
  .switch.busy{ opacity:.55; pointer-events:none; }
  .switch .backlog-pill{
    font-size:10px; padding:1px 7px; border-radius:999px; border:1px solid var(--line2); color:var(--dim);
  }
  .switch.on .backlog-pill{ border-color:#e3b34155; color:var(--warn); }
  @media (prefers-reduced-motion: reduce){
    *, *::before, *::after{ animation:none !important; transition:none !important; }
  }
</style>
</head>
<body>
<div class="aurora"></div>
<div class="grid"></div>
<header>
  <h1 class="mark">⚡ EXPLOIT LAB</h1>
  <span class="pill" id="mode">idle</span>
  <span class="muted" id="uptime"></span>
  <span class="muted" id="kb-header"></span>
  <span class="right">
    <button class="switch" id="backlog-switch" title="Operator switch: when ON, every daemon cycle feeds a bounded slice of shape-unknown watchlist rows into the LLM triage queue and drains it (capacity-gated: keys, daily budget, cooldowns all still apply). Read-only fork probing; nothing broadcasts." aria-pressed="false">
      <span class="knob"></span>
      <span class="sw-label">BACKLOG TRIAGE</span>
      <span class="backlog-pill" id="backlog-pill" style="display:none">—</span>
    </button>
    <span class="live"><span class="dot" id="live-dot"></span><span class="muted" id="conn">connecting</span></span>
    <span class="muted">read-only · 127.0.0.1 · nothing broadcasts</span>
  </span>
</header>
<main>
  <div class="stat-row" id="stats"></div>
  <div class="tabs" id="tabs">
    <button class="tab active" data-tab="overview">Overview</button>
    <button class="tab" data-tab="signals">🔍 Signals<span class="n" id="n-signals"></span></button>
    <button class="tab" data-tab="watchlist">Watchlist<span class="n" id="n-watch"></span></button>
    <button class="tab" data-tab="daemons">🎛 Daemons<span class="n" id="n-daemons"></span></button>
    <button class="tab" data-tab="lab">Lab</button>
    <button class="tab" data-tab="gen">🧬 Generic<span class="n" id="n-gen"></span></button>
    <button class="tab" data-tab="memory">🧠 Memory<span class="n" id="n-memory"></span></button>
    <button class="tab" data-tab="ideas">💡 Ideas<span class="n" id="n-ideas"></span></button>
    <button class="tab" data-tab="hacking">🎯 Hacking<span class="n" id="n-hacking"></span></button>
    <button class="tab" data-tab="activity">Activity</button>
    <span class="tab-ind" id="tab-ind"></span>
  </div>

  <div id="panel-overview" class="panel active">
    <h2>Live Findings <span class="hint">a row here means a fork probe reproduced a drain — nothing was broadcast</span></h2>
    <div class="cards" id="findings"></div>
    <h2>Recent Scans <span class="hint">newest first</span></h2>
    <div class="logbox" id="scan-log"></div>
  </div>

  <div id="panel-signals" class="panel">
    <h2>High-Confidence Triage Signals <span class="hint">confidence ≥ 0.5, technique ≠ none, machine-verified probe</span></h2>
    <div id="signal-list"></div>
  </div>

  <div id="panel-watchlist" class="panel">
    <h2>Mainnet Watchlist <span class="hint">read-only local fork probes</span></h2>
    <div class="controls">
      <input type="search" id="wl-filter" placeholder="filter address / name / shape / result  ( / )"/>
      <select id="wl-sort">
        <option value="recent">Sort: recently probed</option>
        <option value="flags">Sort: findings → bounty → recent</option>
        <option value="name">Sort: name</option>
        <option value="shape">Sort: shape</option>
      </select>
      <label class="label-x"><input type="checkbox" id="wl-hide-unknown"/> hide unclassified</label>
      <span class="muted" id="wl-count"></span>
      <button class="btn" id="wl-more" style="display:none">show more</button>
    </div>
    <table id="watch"><thead><tr><th>Pool</th><th>Name</th><th>Shape</th><th>💰 Bounty</th><th>Last Probe</th><th>Result</th></tr></thead><tbody></tbody></table>
  </div>

  <div id="panel-daemons" class="panel">
    <h2>Fleet Health <span class="hint">the same read-only checks as the monitor CLI — daemons, forks, sidecar, crash log — refreshed every 30s</span></h2>
    <div id="monitor-strip"><div class="empty">monitor loading… first report lands within ~30s</div></div>
    <h2>Running Daemons <span class="hint">fleet-wide across every dashboard; heartbeats older than 5 minutes age out</span></h2>
    <div id="watchdog-status" class="empty" style="margin:4px 0 10px"></div>
    <div class="scan-status idle" id="scan-status">
      <span class="lamp"></span>
      <b id="scan-mode">rotating scan</b>
      <div class="sweep"><i></i></div>
      <span id="scan-status-txt" class="nowrap">waiting for first scan…</span>
    </div>
    <div id="chain-wire" class="wire"></div>
    <table id="daemon-table"><thead><tr><th>Instance</th><th>Status</th><th>Chain Shard</th><th>Cycle</th><th>Uptime</th><th>Interval</th><th>Watched</th><th>PID</th><th>Dashboard</th></tr></thead><tbody></tbody></table>
  </div>

  <div id="panel-lab" class="panel">
    <h2>Lab Challenges</h2>
    <table id="challenges"><thead><tr><th>Challenge</th><th>Status</th><th>Technique</th><th>Attempts</th></tr></thead><tbody></tbody></table>
  </div>

  <div id="panel-gen" class="panel">
    <h2>Generic Invariant Engine <span class="hint">template-free: universal property catalog over the target's own ABI — a violated invariant IS the bug</span></h2>
    <div class="stat-row" id="gen-stats"></div>
    <table id="gen-results"><thead><tr><th>Target</th><th>Shape</th><th>Result</th><th>Violated Invariant</th><th>Checked</th></tr></thead><tbody></tbody></table>
  </div>

  <div id="panel-memory" class="panel">
    <h2>Long-Term Memory <span class="hint">local JSONL store (always on) + mem0 sidecar · every triage verdict, probe outcome and lesson is written here and recalled into later prompts</span></h2>
    <div class="stat-row" id="mem-stats"></div>
    <div class="mem-grid">
      <div>
        <h2>Memory Stream <span class="hint">newest first · appended live, never repainted</span></h2>
        <div class="logbox" id="mem-stream" style="height:330px"></div>
      </div>
      <div>
        <h2>Growth <span class="hint">memories written per hour · last 12h</span></h2>
        <div class="spark" id="mem-spark"></div>
        <h2>Recall <span class="hint">ask the agent what it already knows — read-only</span></h2>
        <div class="recall-wrap" id="mem-recall-wrap">
          <div class="controls" style="margin-bottom:8px">
            <input type="search" id="mem-recall" placeholder="address, technique or shape…"/>
            <button class="btn" id="mem-recall-go">Recall</button>
          </div>
          <div id="mem-results" class="muted">Type a target, technique or shape — recall runs against the agent's own memory store.</div>
        </div>
      </div>
    </div>
    <h2>What The Engine Has Learned <span class="hint">per-shape priors from the generic invariant engine — violated / held / error</span></h2>
    <table id="mem-learning"><thead><tr><th>Shape</th><th style="width:190px">Outcomes</th><th>Held</th><th>Violated</th><th>Errors</th><th>Last note</th></tr></thead><tbody></tbody></table>
    <h2>Proven Violations <span class="hint">a violated invariant IS a finding — these are the exact paths that broke one</span></h2>
    <div id="mem-proven"></div>
    <h2>Learned Dead Ends <span class="hint">derived the hard way once; later cycles skip them instead of re-deriving</span></h2>
    <div id="mem-dead"></div>
    <h2>Self-Learned Techniques <span class="hint">the fleet's own proven drains, captured and generalized into a reusable library — proven facts first, LLM distillations second</span></h2>
    <div id="mem-techniques"></div>
  </div>

  <div id="panel-ideas" class="panel">
    <h2>Attack Ideas <span class="hint">LLM-proposed attack plans for triaged targets — ideas ONLY, never executed; execution always requires a fork-reproduced probe</span></h2>
    <div class="controls">
      <input type="search" id="ideas-filter" placeholder="filter title / target / path…"/>
      <span class="muted" id="ideas-count"></span>
    </div>
    <div id="ideas-list"><div class="empty">loading…</div></div>
  </div>

  <div id="panel-hacking" class="panel">
    <h2>Hacking Right Now <span class="hint">live targeting view — what the fleet is working through this instant; read-only local fork probes, nothing broadcast</span></h2>
    <div class="hack-note" id="hack-summary"></div>
    <div class="hack-grid">
      <div>
        <h2>Attack Queue <span class="hint">the fleet's fork-watch candidates, ranked the way the daemon ranks them — findings, bounty targets and seeds first, then most recently probed; slot N ≈ the next N probes across the fleet (deferred triage retries and untested-hypothesis jumps are not visible from the dashboard)</span></h2>
        <table class="hack-queue"><thead><tr><th>#</th><th>Target</th><th>Name</th><th>Shape</th><th>Bounty</th><th>Chain</th><th>Last Probe</th><th>Result</th></tr></thead><tbody id="hack-queue-body"></tbody></table>
        <div class="hack-note" id="hack-queue-more"></div>
        <h2>Live Targeting Log <span class="hint">scan · fork · vault-loop events, newest first</span></h2>
        <div class="logbox" id="hack-log" style="height:330px"></div>
      </div>
      <div>
        <h2>Vault Loop Queue <span class="hint">dedicated ERC-4626 sweep — stalest first, bounty vaults jump the line, ~6 forks per cycle per daemon</span></h2>
        <div id="hack-vaults"></div>
        <h2>This Dashboard's Scan Shard <span class="hint">the chains this daemon's rotating scanner is currently sweeping</span></h2>
        <div class="wire" id="hack-shard"></div>
        <h2>Recent Activity On Targets <span class="hint">newest first — latest scan/fork event mentioning each target</span></h2>
        <div id="hack-recent"></div>
        <h2>🔥 Verified Drains <span class="hint">fork-reproduced findings — the reason for everything above</span></h2>
        <div id="hack-findings"></div>
      </div>
    </div>
  </div>

  <div id="panel-activity" class="panel">
    <h2>Activity Log <span class="hint">newest first · click a kind pill on a line to copy it</span></h2>
    <div class="logbox" id="log" style="height:420px"></div>
  </div>
</main>
<div id="toasts"></div>
<div class="copy-msg" id="copy-msg">Copied!</div>
<script>
var $ = function(id){ return document.getElementById(id); };
var TABS = ['overview','signals','watchlist','daemons','lab','gen','memory','ideas','hacking','activity'];

function esc(s){ return String(s == null ? '' : s).replace(/[&<>"]/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]; }); }
function fmtT(ts){ return new Date(ts).toLocaleTimeString(); }
function fmtDur(ms){ var s = Math.round(ms/1000); if (s < 60) return s + 's'; var m = Math.round(s/60); if (m < 60) return m + 'm'; return Math.round(m/60) + 'h'; }
function fmtAgo(ts){ return ts ? fmtDur(Date.now() - ts) + ' ago' : 'never'; }
function num(v){ return Number(v || 0); }

/* ---------------- motion-safe painting ---------------- */
/* Write only when the markup actually changed: a repaint would restart every
   CSS animation inside, which is what makes naive polling dashboards strobe. */
var paintCache = new Map();
function paint(el, html){
  if (!el) return;
  if (paintCache.get(el) === html) return;
  paintCache.set(el, html);
  el.innerHTML = html;
}

/* Per-table row signatures: only rows whose content changed get .flash. */
var sigCache = new Map();
function diffRows(tableId, items, keyOf, sigOf, rowHtml){
  var prev = sigCache.get(tableId) || new Map();
  var next = new Map();
  var changed = new Set();
  var html = [];
  for (var i = 0; i < items.length; i++){
    var it = items[i], k = keyOf(it), s = sigOf(it);
    next.set(k, s);
    if (prev.has(k) && prev.get(k) !== s) changed.add(k);
    html.push(rowHtml(it, changed.has(k), i));
  }
  sigCache.set(tableId, next);
  return html.join('');
}

/* Count-up numbers, in place, so the card element (and its animation) lives on. */
function animateNum(el, to){
  if (!el) return;
  var from = Number(el.dataset.v || 0);
  if (el.dataset.init === '1' && from === to) return;
  el.dataset.v = String(to);
  el.dataset.init = '1';
  if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches){ el.textContent = String(to); return; }
  var t0 = performance.now(), dur = 520;
  function frame(now){
    var p = Math.min(1, (now - t0) / dur);
    var eased = 1 - Math.pow(1 - p, 3);
    el.textContent = String(Math.round(from + (to - from) * eased));
    if (p < 1) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}

/* containerId lets a panel own its own stat row (the memory tab) while still
   reusing the in-place count-up + bump behaviour of the header cards. */
function setStat(key, opts, containerId){
  var card = document.querySelector('[data-stat="' + key + '"]');
  if (!card){
    card = document.createElement('div');
    card.className = 'stat';
    card.dataset.stat = key;
    card.innerHTML = '<div class="val"><span class="n">0</span><span class="suf"></span></div><div class="lbl"></div><div class="sub"></div>';
    var host = $(containerId || 'stats');
    var n = host ? host.querySelectorAll('.stat').length : 0;
    card.style.animationDelay = (n * 55) + 'ms';
    if (host) host.appendChild(card);
  }
  var suffix = opts.suffix || '';
  var sufEl = card.querySelector('.suf');
  if (sufEl.textContent !== suffix) sufEl.textContent = suffix;
  card.querySelector('.lbl').textContent = opts.label;
  var subEl = card.querySelector('.sub');
  var sub = opts.sub || '';
  if (subEl.textContent !== sub) subEl.textContent = sub;
  if (opts.color) card.style.setProperty('--c', opts.color);
  var nEl = card.querySelector('.n');
  var before = card.dataset.set === '1' ? Number(nEl.dataset.v || 0) : num(opts.value);
  animateNum(nEl, num(opts.value));
  /* Bump on every real change AFTER the card's first fill — including 0 → 1,
     which is exactly the transition worth celebrating (first finding). */
  if (card.dataset.set === '1' && before !== num(opts.value)){
    card.classList.remove('bump');
    void card.offsetWidth; /* restart the animation */
    card.classList.add('bump');
  }
  card.dataset.set = '1';
}

/* ---------------- logs: append, never repaint ---------------- */
function logNode(e, animate){
  var d = document.createElement('div');
  d.className = 'logline k-' + esc(e.kind);
  if (!animate) d.style.animation = 'none';
  d.innerHTML = '<span class="ts">' + esc(fmtT(e.t)) + '</span><span class="kind">' + esc(e.kind) + '</span>' + esc(e.msg);
  return d;
}
function logKey(e){ return e.t + ':' + e.kind + ':' + e.msg; }
function pushLog(container, events, cap){
  if (!container) return;
  var last = container.dataset.last || '';
  var idx = last ? events.findIndex(function(e){ return logKey(e) === last; }) : events.length - 1;
  if (!last || idx < 0){
    container.textContent = '';
    var seed = events.slice(-cap);
    for (var i = seed.length - 1; i >= 0; i--) container.appendChild(logNode(seed[i], false));
  } else {
    var fresh = events.slice(idx + 1);
    for (var j = fresh.length - 1; j >= 0; j--) container.prepend(logNode(fresh[j], true));
  }
  while (container.childElementCount > cap) container.lastElementChild.remove();
  if (events.length) container.dataset.last = logKey(events[events.length - 1]);
}

/* ---------------- tabs ---------------- */
var activeTab = 'overview';
try { activeTab = localStorage.getItem('lab-tab') || 'overview'; } catch (err) { /* private mode */ }
if (TABS.indexOf(activeTab) < 0) activeTab = 'overview';

function showTab(name, remember){
  if (TABS.indexOf(name) < 0) return;
  activeTab = name;
  var tabs = document.querySelectorAll('#tabs .tab');
  for (var i = 0; i < tabs.length; i++) tabs[i].classList.toggle('active', tabs[i].dataset.tab === name);
  for (var p = 0; p < TABS.length; p++){
    var panel = $('panel-' + TABS[p]);
    if (panel) panel.classList.toggle('active', TABS[p] === name);
  }
  moveIndicator();
  if (remember !== false) { try { localStorage.setItem('lab-tab', name); } catch (err) {} }
  document.documentElement.scrollTop = 0;
}
function moveIndicator(){
  var active = document.querySelector('#tabs .tab.active');
  var ind = $('tab-ind');
  if (!active || !ind) return;
  ind.style.width = active.offsetWidth + 'px';
  ind.style.transform = 'translateX(' + active.offsetLeft + 'px)';
}
document.querySelectorAll('#tabs .tab').forEach(function(t){
  t.addEventListener('click', function(){ showTab(t.dataset.tab); });
});
window.addEventListener('resize', moveIndicator);

/* ---------------- misc ui ---------------- */
/* Operator switch: POST {"on":true|false} to the loopback-only toggle
   endpoint. Idempotent; the daemon picks the flag up from disk next cycle
   (≤45s), and the switch state itself reflects the server's ack. */
var switchBusy = false;
async function toggleBacklog(){
  var btn = $('backlog-switch');
  if (!btn || switchBusy) return;
  switchBusy = true;
  btn.classList.add('busy');
  var wantOn = !btn.classList.contains('on');
  try {
    var res = await fetch('/api/backlog-toggle', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ on: wantOn }),
      cache: 'no-store',
    });
    if (!res.ok) throw new Error('status ' + res.status);
    var j = await res.json();
    if (typeof j.triageBacklog === 'boolean') paintBacklogSwitch(j.triageBacklog, j.backlog || null);
    toast(j.triageBacklog
      ? 'Backlog triage ON — unknown-shape rows enter the LLM triage queue each cycle (capacity-gated).'
      : 'Backlog triage OFF — the scan rotation is back to its default diet.', j.triageBacklog);
  } catch (err) {
    toast('Toggle failed: ' + (err && err.message ? err.message : 'unknown error'), true);
  } finally {
    switchBusy = false;
    btn.classList.remove('busy');
  }
}
function paintBacklogSwitch(on, bl){
  var btn = $('backlog-switch');
  if (!btn) return;
  btn.classList.toggle('on', !!on);
  btn.setAttribute('aria-pressed', on ? 'true' : 'false');
  var pill = $('backlog-pill');
  if (pill && bl) {
    pill.style.display = '';
    if (on) {
      var left = Math.max(0, bl.candidates - bl.queueSize);
      pill.textContent = bl.candidates + ' unknown' + (bl.queueSize > 0 ? ' · ' + bl.queueSize + ' queued' : '') + (left > 0 ? ' · ' + left + ' to go' : '');
      pill.title = 'candidates ' + bl.candidates + ' · queue ' + bl.queueSize + ' · due ' + bl.dueNow + ' · keys ' + bl.keys + ' · budget ' + bl.budget.used + '/' + bl.budget.max + (bl.lastNote ? ' · ' + bl.lastNote : '');
    } else {
      pill.textContent = bl.candidates + ' unknown';
      pill.title = bl.candidates + ' shape-unknown rows on forkable chains. Flip the switch to triage them. Keys ' + bl.keys + ' · budget ' + bl.budget.used + '/' + bl.budget.max;
    }
  }
}
(function wireBacklogSwitch(){
  var btn = $('backlog-switch');
  if (!btn) return;
  btn.addEventListener('click', toggleBacklog);
})();
function copyAddr(addr, ev){
  try { if (ev) ev.stopPropagation(); } catch (err) {}
  var m = $('copy-msg');
  navigator.clipboard?.writeText(addr).then(function(){
    m.classList.add('show');
    setTimeout(function(){ m.classList.remove('show'); }, 1400);
  }).catch(function(){});
}
function toast(msg, hot){
  var box = $('toasts');
  if (!box) return;
  if (box.childElementCount > 3) box.firstElementChild.remove();
  var t = document.createElement('div');
  t.className = 'toast' + (hot ? ' hot' : '');
  t.textContent = msg;
  box.appendChild(t);
  setTimeout(function(){
    t.classList.add('out');
    setTimeout(function(){ t.remove(); }, 380);
  }, hot ? 7000 : 4200);
}
function addrCell(addr){
  var short = addr.length > 20 ? addr.slice(0, 10) + '…' + addr.slice(-6) : addr;
  return '<span class="addr" data-copy="' + esc(addr) + '" title="Click to copy: ' + esc(addr) + '">' + esc(short) + '</span>';
}
/* One delegated handler: rows are replaced on refresh, so per-node listeners
   would leak and silently stop firing on every repaint. */
document.addEventListener('click', function(ev){
  var el = ev.target.closest ? ev.target.closest('[data-copy]') : null;
  if (el) copyAddr(el.dataset.copy, ev);
});
function confBadge(conf){
  var pct = Math.round(conf * 100);
  var cls = conf >= 0.8 ? 'high' : conf >= 0.5 ? 'med' : 'low';
  return '<span class="badge badge-conf-' + cls + '">' + pct + '% conf</span>';
}
function shapeChip(shape){
  var s = String(shape || '');
  if (!s || s === '—') return '<span class="muted">—</span>';
  var cls = s.indexOf('erc-4626') === 0 ? 'chip chip-vault' : s.indexOf('layerzero') === 0 ? 'chip chip-lz' : s.indexOf('unknown') === 0 ? 'chip chip-dim' : 'chip';
  return '<span class="' + cls + '" title="' + esc(s) + '">' + esc(s.slice(0, 34)) + '</span>';
}
function freshnessDot(ts){
  if (!ts) return '<span class="freshness"></span>';
  var age = Date.now() - ts;
  return '<span class="freshness ' + (age < 150000 ? 'f' : age < 3600000 ? 'w' : '') + '"></span>';
}

/* watchlist view state */
var wlCap = 80;
var wlQuery = '';
var wlSort = 'recent';
var wlHideUnknown = false;
function wlControls(){
  var f = $('wl-filter'), s = $('wl-sort'), h = $('wl-hide-unknown');
  /* Read the control INSIDE each handler: binding the value once at setup
     froze the filter to whatever was in the box on boot (the query was read
     before the user ever typed, so the list never filtered). */
  if (f) f.addEventListener('input', function(){ wlQuery = f.value.trim().toLowerCase(); wlCap = 80; renderWatchlist(lastState); });
  if (s) s.addEventListener('change', function(){ wlSort = s.value; renderWatchlist(lastState); });
  if (h) h.addEventListener('change', function(){ wlHideUnknown = h.checked; renderWatchlist(lastState); });
  var more = $('wl-more');
  if (more) more.addEventListener('click', function(){ wlCap += 300; renderWatchlist(lastState); });
}
function watchItems(all){
  var seen = new Set();
  var out = [];
  for (var i = 0; i < all.length; i++){
    var w = all[i];
    var addr = String(w.address || '');
    /* Defense in depth: a display-truncated key is not an address and can
       never be probed — never show it even if an old state.json is served. */
    if (addr.indexOf('…') >= 0 || seen.has(addr)) continue;
    seen.add(addr);
    if (wlHideUnknown && String(w.shape || 'unknown').indexOf('unknown') === 0) continue;
    if (wlQuery){
      var hay = (addr + ' ' + (w.name || '') + ' ' + (w.category || '') + ' ' + (w.shape || '') + ' ' + (w.lastResult || '')).toLowerCase();
      if (hay.indexOf(wlQuery) < 0) continue;
    }
    out.push(w);
  }
  out.sort(function(a, b){
    if (wlSort === 'name') return String(a.name || a.address).localeCompare(String(b.name || b.address));
    if (wlSort === 'shape') return String(a.shape || 'zz').localeCompare(String(b.shape || 'zz'));
    if (wlSort === 'flags'){
      var af = (a.finding ? 2 : 0) + (a.bounty ? 1 : 0), bf = (b.finding ? 2 : 0) + (b.bounty ? 1 : 0);
      if (af !== bf) return bf - af;
    }
    return Number(b.lastProbe || 0) - Number(a.lastProbe || 0);
  });
  return out;
}
function renderWatchlist(state){
  if (!state) return;
  var items = watchItems(Object.values(state.watchlist || {}));
  var shown = items.slice(0, wlCap);
  var html = diffRows('watch', shown, function(w){ return w.address; }, function(w){
    return [w.shape, w.lastResult, w.finding, w.bounty, w.name, w.lastProbe].join('|');
  }, function(w, changed, i){
    var bounty = w.bounty ? '<span class="badge badge-bounty" title="Live Immunefi program">💰 ' + esc(w.bounty) + '</span>' : '<span class="muted">—</span>';
    return '<tr class="' + (changed ? 'flash' : '') + '" style="' + (w.finding ? 'background:#1a0e0e;' : '') + 'animation-delay:' + Math.min(i, 30) * 9 + 'ms">' +
      '<td class="nowrap">' + freshnessDot(w.lastProbe) + addrCell(w.address) + '</td>' +
      '<td style="font-size:12px">' + esc(w.name || '—') + (w.category ? '<div style="font-size:10px;color:#5d6878">' + esc(w.category) + '</div>' : '') + '</td>' +
      '<td>' + shapeChip(w.shape) + '</td>' +
      '<td>' + bounty + '</td>' +
      '<td class="nowrap" style="font-size:12px" title="' + (w.lastProbe ? esc(new Date(w.lastProbe).toLocaleString()) : 'never probed') + '">' + (w.lastProbe ? '<span class="muted">' + fmtAgo(w.lastProbe) + '</span>' : '<span class="muted">never</span>') + '</td>' +
      '<td style="font-size:12px;color:#a8b3c4" title="' + esc(w.lastResult || '') + '">' + (w.finding ? '<span class="pill finding">DRAIN</span> ' : '') + esc(String(w.lastResult || '—').slice(0, 130)) + '</td></tr>';
  });
  paint($('watch').querySelector('tbody'), html);
  var count = $('wl-count');
  if (count) count.textContent = 'showing ' + shown.length + ' of ' + items.length + ' targets';
  var more = $('wl-more');
  if (more){
    var left = items.length - shown.length;
    more.style.display = left > 0 ? '' : 'none';
    more.textContent = 'show more (+' + Math.min(left, 300) + ')';
  }
  var badge = $('n-watch');
  if (badge) badge.textContent = items.length;
}

/* ---------------- attack ideas (ideas-only, never executed) ----------------
   The LLM's ranked "how I'd attack this" plans for triaged targets. Purely a
   reading surface: an idea becomes an executed probe only through the same
   fork-simulation pipeline as everything else. */
function renderIdeas(state){
  if (!state) return;
  var ideas = state.attackIdeas || [];
  var stats = state.ideasStats || null;
  var badge = $('n-ideas');
  if (badge) badge.textContent = ideas.length;
  var filter = $('ideas-filter');
  if (filter && !filter.__wired) {
    filter.__wired = true;
    filter.addEventListener('input', function(){ renderIdeas(lastState); });
  }
  var q = filter ? filter.value.toLowerCase() : '';
  var shown = ideas.filter(function(i){
    if (!q) return true;
    return ((i.title||'') + ' ' + (i.address||'') + ' ' + (i.name||'') + ' ' + (i.attackPath||'')).toLowerCase().indexOf(q) >= 0;
  });
  var html = shown.length ? shown.map(function(i){
    return '<div class="card" style="border-left:3px solid #e3b341">' +
      '<b>#' + Number(i.rank || 1) + ' ' + esc(i.title || 'untitled idea') + '</b>' +
      ' <span class="muted">' + Math.round((Number(i.confidence) || 0) * 100) + '% plausible · ' + esc(fmtAgo(i.t)) + '</span>' +
      '<div style="margin-top:4px;font-size:12px"><b>Target:</b> ' + esc(i.chainId || '') + ':' + addrCell(i.address || '') +
        (i.name ? ' <span class="muted">(' + esc(i.name) + ')</span>' : '') + '</div>' +
      '<div style="font-size:12px;color:#a8b3c4;margin-top:2px"><b>Path:</b> ' + esc(i.attackPath || '') + '</div>' +
      (i.preconditions ? '<div style="font-size:12px;color:#a8b3c4"><b>Needs:</b> ' + esc(i.preconditions) + '</div>' : '') +
      (i.whyHard ? '<div style="font-size:12px;color:#a8b3c4"><b>Blocked by:</b> ' + esc(i.whyHard) + '</div>' : '') +
      '</div>';
  }).join('') : '<div class="empty">No attack ideas yet — the LLM writes these for triaged targets with verified source (needs LAB_LLM_KEY; budget ' + (stats ? stats.budgetLeft : '—') + ' left today).</div>';
  paint($('ideas-list'), html);
  var count = $('ideas-count');
  if (count) count.textContent = shown.length === ideas.length ? ideas.length + ' idea(s) · ' + (stats ? stats.targets : '?') + ' target(s)' : shown.length + ' of ' + ideas.length;
}

/* ---------------- hacking tab (live targeting) ----------------
   A reading surface over the state the fleet already publishes: the daemon's
   fork-watch candidates + its priority factors (daemon.ts: findings, bounty,
   seeded), the dedicated ERC-4626 vault loop (vaultloop.ts: stalest first,
   bounty first), the per-daemon scan shard and the reproduced drains.
   Everything here is derived, nothing is a command path: the tab cannot
   start, stop or retarget anything. */
var HACK_QUEUE_CAP = 60;
var chainNames = ["ethereum","arbitrum","optimism","base","polygon","bsc","avalanche","sonic","gnosis","fantom","celo","evmos","linea","scroll","berachain","blast","hyperevm","robinhood"]; /* daemon.ts CHAIN_NAMES */
function hackChainName(w){
  var key = String((w && w.address) || '');
  var m = key.match(/^([a-z0-9]+):0x/i);
  if (m && chainNames.indexOf(m[1].toLowerCase()) >= 0) return m[1].toLowerCase();
  if (/^0x[0-9a-fA-F]{40}$/.test(key)) return 'ethereum';
  return null;
}
/* Mirror of daemon.ts ownsTarget()'s hash — the modulo shard a target lands
   in, shown as info so the fleet's parallelism is legible. */
function hackShardNum(key, n){
  var h = 0;
  for (var i = 0; i < key.length; i++) h = (h * 31 + key.charCodeAt(i)) >>> 0;
  return n > 0 ? h % n : 0;
}
/* The priority factors the daemon itself uses and the dashboard can see.
   (Retry-deferrals and untested-hypothesis jumps happen server-side and are
   intentionally NOT invented here — see the queue's hint.) */
function hackPriority(w){
  var p = 0;
  if (w.finding) p += 4;
  if (w.bounty) p += 2;
  if (w.seeded) p += 1;
  return p;
}
function renderHacking(s){
  if (!s) return;
  var watch = Object.keys(s.watchlist || {}).map(function(k){ var w = s.watchlist[k]; if (w) w.__key = k; return w; })
    .filter(function(w){ return w && String(w.address || '').indexOf('…') < 0; });
  var probeable = watch.filter(function(w){ return /^0x[0-9a-fA-F]{40}$/.test(w.address) || /^([a-z0-9]+):0x/i.test(w.address); });
  var n = Math.max(1, Object.keys(s.daemons || {}).length);
  var findingCount = (s.findings || []).length;
  var ideas = s.attackIdeas || [];
  var sum = $('hack-summary');
  if (sum) sum.textContent = probeable.length + ' probeable targets · ' + probeable.filter(function(w){ return w.lastProbe; }).length + ' probed so far · ' + n + ' daemon(s) hashing targets into ' + n + ' shard(s) · ' + ideas.length + ' idea(s) → ' + findingCount + ' reproduced drain(s)';
  var queue = probeable.slice().sort(function(a, b){
    var pr = hackPriority(b) - hackPriority(a);
    if (pr !== 0) return pr;
    return Number(b.lastProbe || 0) - Number(a.lastProbe || 0);
  });
  var shown = queue.slice(0, HACK_QUEUE_CAP);
  var keyOf = function(w){ return w.__key || w.address; };
  var html = diffRows('hackq', shown, keyOf, function(w){
    return [hackPriority(w), w.lastProbe, w.shape, w.finding, w.bounty, w.name, w.lastResult].join('|');
  }, function(w, changed, i){
    var b = w.bounty ? '<span class="badge badge-bounty" title="Live Immunefi program">💰 ' + esc(w.bounty) + '</span>' : '<span class="muted">—</span>';
    var tag = w.finding ? '<span class="pill finding">DRAIN</span> ' : w.seeded ? '<span class="pill pending">seed</span> ' : '';
    return '<tr class="' + (changed ? 'flash' : '') + '" style="animation-delay:' + Math.min(i, 30) * 9 + 'ms">' +
      '<td class="muted">' + (i + 1) + '</td>' +
      '<td class="nowrap">' + freshnessDot(w.lastProbe) + addrCell(w.address) + '</td>' +
      '<td style="font-size:12px">' + tag + esc(w.name || '—') + '</td>' +
      '<td>' + shapeChip(w.shape) + '</td>' +
      '<td>' + b + '</td>' +
      '<td class="muted" style="font-size:11.5px">shard ' + hackShardNum(keyOf(w).toLowerCase(), n) + ' · ' + esc(hackChainName(w) || '?') + '</td>' +
      '<td class="nowrap" style="font-size:12px">' + (w.lastProbe ? '<span class="muted">' + fmtAgo(w.lastProbe) + '</span>' : '<span class="muted">never</span>') + '</td>' +
      '<td class="hack-why" style="font-size:12px" title="' + esc(w.lastResult || '') + '">' + esc(String(w.lastResult || '—').slice(0, 110)) + '</td></tr>';
  });
  var qb = $('hack-queue-body');
  if (qb) paint(qb, html.length ? html : '<tr><td colspan="8" class="empty">No probeable targets yet.</td></tr>');
  var more = $('hack-queue-more');
  if (more) more.textContent = queue.length > shown.length ? 'showing first ' + shown.length + ' of ' + queue.length + ' candidates — the full rotation lives in the Watchlist tab' : '';
  var nb = $('n-hacking');
  if (nb) nb.textContent = findingCount || '';

  pushLog($('hack-log'), (s.events || []).filter(function(e){ return e.kind === 'scan' || e.kind === 'fork'; }), 160);

  var vaults = probeable.filter(function(w){ var sh = String(w.shape || ''); return sh.indexOf('4626') >= 0 || sh.toLowerCase().indexOf('vault') >= 0; })
    .sort(function(a, b){
      var d = Number(!!b.bounty) - Number(!!a.bounty);
      if (d !== 0) return d;
      var la = a.lastProbe || 0, lb = b.lastProbe || 0;
      var va = la === 0 ? Number.MAX_SAFE_INTEGER : la, vb = lb === 0 ? Number.MAX_SAFE_INTEGER : lb;
      return va - vb || String(a.address).localeCompare(String(b.address));
    });
  paint($('hack-vaults'), vaults.length === 0
    ? '<div class="empty">No vault-shaped targets yet — the ERC-4626 loop has nothing to sweep.</div>'
    : vaults.slice(0, 14).map(function(v, i){
        return '<div class="recall-hit" style="animation-delay:' + (i * 30) + 'ms;border-left-color:#a371f799">' +
          '<b>' + addrCell(v.address) + '</b>' +
          (v.bounty ? ' <span class="badge badge-bounty">💰</span>' : '') +
          (v.finding ? ' <span class="pill finding">DRAIN</span>' : '') +
          ' <span class="muted" style="font-size:11.5px">' + esc(hackChainName(v) || '?') + ' · ' + (v.lastProbe ? 'probed ' + fmtAgo(v.lastProbe) : 'never probed — sweeps first') + '</span>' +
          '<div style="font-size:11.5px" class="muted">' + esc(v.name || v.shape || '') + '</div></div>';
      }).join('') + (vaults.length > 14 ? '<div class="muted" style="font-size:11.5px">+' + (vaults.length - 14) + ' more vault-shaped target(s)</div>' : ''));

  var mine = null, ids = Object.keys(s.daemons || {});
  for (var mi = 0; mi < ids.length; mi++){ var d = s.daemons[ids[mi]]; if (d && Number(d.uiPort) === Number(window.location.port)) mine = d; }
  paint($('hack-shard'), mine ? String(mine.chains || 'all').split(',').map(function(c){
      return '<span class="wire-ch active"><span class="wdot"></span>' + esc(c.trim()) + '</span>'; }).join('')
    : '<span class="muted" style="font-size:11.5px">shard view needs the live dashboard</span>');

  var per = {};
  var evs = s.events || [];
  for (var j = evs.length - 1; j >= 0 && j >= evs.length - 260; j--){
    var e = evs[j];
    if (e.kind !== 'scan' && e.kind !== 'fork') continue;
    var m = String(e.msg).match(/0x[0-9a-fA-F]{40}/);
    if (!m) continue;
    var k = m[0].toLowerCase();
    if (!per[k]){ per[k] = { address: k, kind: e.kind, t: e.t, msg: e.msg }; }
  }
  var perList = Object.keys(per).map(function(k){ return per[k]; }).sort(function(a, b){ return b.t - a.t; }).slice(0, 8);
  paint($('hack-recent'), perList.length === 0
    ? '<div class="empty">No per-target activity yet.</div>'
    : perList.map(function(p, i){
        return '<div class="recall-hit" style="animation-delay:' + (i * 30) + 'ms">' +
          '<span class="kind">' + esc(p.kind) + '</span><span class="ts">' + fmtT(p.t) + '</span> ' + addrCell(p.address) +
          '<div style="color:#8b949e;font-size:11.5px">' + esc(String(p.msg).slice(0, 150)) + '</div></div>';
      }).join(''));

  paint($('hack-findings'), findingCount === 0
    ? '<div class="empty">No reproduced drain yet — the queue above is what stands between the fleet and one.</div>'
    : (s.findings || []).slice().reverse().map(function(f, i){
        return '<div class="card" style="border-left:3px solid #ff6b61;animation-delay:' + (i * 40) + 'ms"><b>🚨 ' + esc(fmtT(f.t)) + '</b> ' + esc(f.msg) + '</div>';
      }).join(''));
}

/* ---------------- the poll ---------------- */
var lastState = null;
/* null = "no baseline recorded yet" (first paint must not toast old findings).
   '' is a real baseline (the session simply has none yet), so a finding that
   arrives later still fires the alert. */
var seenFinding = null;
var connected = null;
if (window.STATE) seenFinding = (window.STATE.findings || []).map(logKey).join('|');

/* ---------------- daemon & live-chain animation helpers ----------------
   Every animated element here is built ONCE and then only its text/attrs
   change — an innerHTML rewrite each poll would restart every CSS animation
   on the page (the strobe this file exists to prevent). */
var DAEMON_STALE_MS = 300000; // matches the server's registry aging rule

/* Chain shard pills, tinted per chain; unknown chains keep a neutral drift. */
function chainPills(chains){
  return String(chains || 'all').split(',').map(function(c){
    var name = c.trim().toLowerCase();
    return '<span class="chain-pill ch-' + esc(name) + '">' + esc(c.trim()) + '</span>';
  }).join('');
}

/* Per-daemon watched-pool trend (last 12 polls, newest right). Kept across
   polls in a plain object; the tick cadence IS the sampling cadence. */
var watchHist = {};
function miniSpark(id, v){
  var h = watchHist[id] || (watchHist[id] = []);
  if (h.length === 0 || h[h.length - 1] !== v){ h.push(v); while (h.length > 12) h.shift(); }
  var max = Math.max.apply(null, h.concat([1]));
  return '<span class="mspark" title="watched pools, last ' + h.length + ' polls">' +
    h.map(function(x){ return '<i style="height:' + Math.max(1, Math.round(x / max * 14)) + 'px"></i>'; }).join('') + '</span>';
}

/* Scanning sweep: animated only while a rotating-scan event is genuinely
   recent. The scan cadence in this fleet is 2–4 minutes per shard pass, so
   "recent" means 150s — anything longer and the lamp goes dark for real. */
function renderScanStatus(s){
  var el = $('scan-status');
  if (!el) return;
  var wire = (s.events || []).filter(function(e){ return e.kind === 'scan'; });
  var last = wire[0];
  var fresh = !!(last && (Date.now() - last.t < 150000));
  var want = fresh ? 'live' : 'idle';
  if (el.dataset.mode !== want){
    el.dataset.mode = want;
    el.classList.toggle('live', want === 'live');
    el.classList.toggle('idle', want !== 'live');
    var m = $('scan-mode');
    if (m) m.textContent = want === 'live' ? 'rotating scan — running' : 'rotating scan — idle';
  }
  var t = $('scan-status-txt');
  if (t) t.textContent = last ? fmtAgo(last.t) + ' · ' + String(last.msg).slice(0, 90) : 'waiting for first scan…';
}

/* Live-chain wire: one chip per chain seen in recent scan/fork events; a chip
   pings while its chain produced an event in the last 60s. */
var wireKey = '';
/* Chain attribution: the fleet's event text names chains several ways —
   "ethereum:0x…" (scan shard prefix), "eth-mainnet.public…" (endpoint URLs in
   responder events), "gnosis", "solana …". The alias table covers the forms
   actually emitted; the shard-prefix fallback catches new chains, and anything
   else is honestly 'unattributed' rather than dropped. */
var CHAIN_ALIASES = [
  [/eth[-_]?mainnet|\bethereum\b/i, 'ethereum'],
  [/\bbsc\b|\bbnb\b|binance/i, 'bsc'],
  [/polygon|\bmatic\b/i, 'polygon'],
  [/arbitrum/i, 'arbitrum'],
  [/optimism|op[-_]mainnet/i, 'optimism'],
  [/avalanche|\bavax\b/i, 'avalanche'],
  [/gnosis|\bxdai\b/i, 'gnosis'],
  [/\bbase\b/i, 'base'],
  [/solana/i, 'solana'],
  [/\btron\b/i, 'tron'],
  [/fantom|\bopera\b/i, 'fantom'],
];
function chainOf(msg){
  var s = String(msg);
  for (var i = 0; i < CHAIN_ALIASES.length; i++) if (CHAIN_ALIASES[i][0].test(s)) return CHAIN_ALIASES[i][1];
  var m = s.match(/^\s*([a-z][a-z0-9_-]{1,20}):\s*0x/i); // shard-prefix form
  return m ? m[1].toLowerCase() : 'unattributed';
}
function renderChainWire(s){
  var el = $('chain-wire');
  if (!el) return;
  var evs = (s.events || []).filter(function(e){ return e.kind === 'scan' || e.kind === 'fork'; }).slice(0, 26);
  var key = evs.map(function(e){ return e.t; }).join(',');
  if (key === wireKey) return; // nothing new — leave the running pulses alone
  wireKey = key;
  var chains = {};
  for (var i = 0; i < evs.length; i++){
    var ch = chainOf(evs[i].msg);
    (chains[ch] = chains[ch] || []).push(evs[i]);
  }
  el.innerHTML = Object.keys(chains).sort().map(function(ch){
    var latest = chains[ch][0];
    var active = !!(latest && (Date.now() - latest.t < 60000));
    return '<span class="wire-ch ' + (active ? 'active' : '') + '">' +
      '<span class="wdot"></span>' + esc(ch) + '</span>';
  }).join('');
}

/* ---------------- memory tab ---------------- */
function fmtBytes(n){
  n = num(n);
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(1) + ' MB';
}

/* Bars are created once and only their HEIGHT changes: rebuilding them would
   restart the transition and the chart would never visibly grow. */
function renderSpark(hourly){
  var el = $('mem-spark');
  if (!el) return;
  if (el.childElementCount !== hourly.length){
    el.innerHTML = hourly.map(function(){ return '<div class="bar grow"></div>'; }).join('');
    var seeded = el.querySelectorAll('.bar');
    for (var i = 0; i < seeded.length; i++) seeded[i].style.animationDelay = (i * 35) + 'ms';
  }
  var bars = el.querySelectorAll('.bar');
  var max = Math.max.apply(null, hourly.concat([1]));
  for (var j = 0; j < hourly.length && j < bars.length; j++){
    var h = Math.max(2, Math.round(num(hourly[j]) / max * 46)) + 'px';
    if (bars[j].style.height !== h) bars[j].style.height = h;
    bars[j].classList.toggle('now', j === hourly.length - 1);
    bars[j].title = hourly[j] + ' in the hour ending ' + fmtT(Date.now() - (hourly.length - 1 - j) * 3600000);
  }
}

function renderMemory(s){
  var d = s.memoryDetail;
  var local = (d && d.local) || null;
  var learn = (d && d.learning) || null;
  var stats = (d && d.stats) || { local: num(s.memory && s.memory.local), sidecar: 'checking' };
  var total = local ? local.total : stats.local;
  var hourly = (local && local.hourly) || [];
  var lastHour = hourly.length ? num(hourly[hourly.length - 1]) : 0;
  var prevHour = hourly.length > 1 ? num(hourly[hourly.length - 2]) : 0;
  var perfHour = local && local.firstAt ? Math.round(total / Math.max(1, (Date.now() - local.firstAt) / 3600000)) : 0;
  var sidecarUp = String(stats.sidecar) === 'up';
  var kinds = (local && local.kinds) || {};

  setStat('mem-total', { value: total, label: 'Memories', color: total > 0 ? '#3fb950' : '#7d8899', sub: local ? fmtBytes(local.bytes) + ' on disk' : '' }, 'mem-stats');
  setStat('mem-growth', { value: lastHour, label: 'Written This Hour', color: lastHour > 0 ? '#7cc4ff' : '#7d8899', sub: prevHour === lastHour ? 'flat vs last hour' : (lastHour > prevHour ? '▲ up vs ' + prevHour : '▼ down vs ' + prevHour) }, 'mem-stats');
  setStat('mem-rate', { value: perfHour, suffix: '/h', label: 'Lifetime Rate', color: '#7cc4ff' }, 'mem-stats');
  setStat('mem-shapes', { value: learn ? learn.shapes : 0, label: 'Shapes Learned', color: '#a371f7' }, 'mem-stats');
  setStat('mem-proven-n', { value: learn ? learn.violations : 0, label: 'Proven Violations', color: learn && learn.violations > 0 ? '#ff6b61' : '#7cc4ff' }, 'mem-stats');
  setStat('mem-dead-n', { value: learn ? learn.deadends : 0, label: 'Dead Ends Learned', color: learn && learn.deadends > 0 ? '#e3b341' : '#7d8899' }, 'mem-stats');
  setStat('mem-side', { value: sidecarUp ? 1 : 0, suffix: sidecarUp ? '' : ' off', label: 'mem0 Sidecar', color: sidecarUp ? '#3fb950' : '#e3b341', sub: kinds['triage'] ? kinds['triage'] + ' triage verdict(s)' : '' }, 'mem-stats');

  var nm = $('n-memory');
  if (nm) nm.textContent = total || '';

  renderSpark(hourly);

  /* Stream: same append-only path as the activity log, so a new memory slides
     in without disturbing the line above it. */
  if (local && local.recent){
    pushLog($('mem-stream'), local.recent.map(function(r){
      return { t: r.t, kind: r.kind, msg: r.ref ? r.text + '  [' + r.ref + ']' : r.text };
    }), 220);
  } else {
    pushLog($('mem-stream'), [], 220);
  }

  /* Learning table: outcome mix as a proportion bar (red = violated). */
  var priors = (learn && learn.priors) || [];
  var tbody = $('mem-learning') && $('mem-learning').querySelector('tbody');
  if (tbody){
    paint(tbody, priors.length === 0
      ? '<tr><td colspan="6" class="empty">The generic engine has not recorded any shape history yet.</td></tr>'
      : diffRows('memlearn', priors, function(p){ return p.shape; },
          function(p){ return p.held + '/' + p.violated + '/' + p.errors + '/' + p.lastNote; },
          function(p, changed){
            var tot = Math.max(1, p.total);
            var wv = p.violated / tot * 100, we = p.errors / tot * 100, wh = p.held / tot * 100;
            return '<tr class="' + (changed ? 'flash' : '') + '">' +
              '<td>' + shapeChip(p.shape) + '</td>' +
              '<td><div class="membar">' +
                '<i class="v" style="width:' + wv + '%"></i>' +
                '<i class="e" style="width:' + we + '%"></i>' +
                '<i class="h" style="width:' + wh + '%"></i>' +
              '</div></td>' +
              '<td>' + p.held + '</td>' +
              '<td style="color:' + (p.violated ? '#ff7b72' : '#7d8899') + '">' + p.violated + '</td>' +
              '<td style="color:' + (p.errors ? '#e3b341' : '#7d8899') + '">' + p.errors + '</td>' +
              '<td style="font-size:12px;color:#7d8899">' + esc(p.lastNote || '—') + '</td></tr>';
          }));
  }

  var proven = (learn && learn.proven) || [];
  paint($('mem-proven'), proven.length === 0
    ? '<div class="empty">No invariant has been proven violated yet — a row here is a machine-checked bug.</div>'
    : proven.slice(0, 12).map(function(v, i){
        return '<div class="recall-hit" style="animation-delay:' + (i * 40) + 'ms;border-left-color:#ff6b6199">' +
          '<span class="pill finding">VIOLATED</span> ' + esc(v.invariant) + ' <span class="score">· ' + esc(v.shape) + '</span>' +
          '<div style="color:#8b949e;font-size:11.5px">' + (v.path ? esc(v.path) : 'path not recorded') +
          (v.profitWei && v.profitWei !== '0' ? ' · profit ' + esc(v.profitWei) + ' wei' : '') + ' · ' + fmtT(v.when) + '</div></div>';
      }).join(''));

  var dead = (learn && learn.dead) || [];
  paint($('mem-dead'), dead.length === 0
    ? '<div class="empty">No dead ends recorded yet.</div>'
    : dead.slice(0, 10).map(function(x){
        return '<div class="recall-hit" style="border-left-color:#e3b34166">' +
          '<span class="kind" style="color:#e3b341">' + esc(x.shape) + '</span>' +
          '<div style="color:#8b949e;font-size:12px">' + esc(x.condition) + ' <span class="ts">· ' + fmtT(x.when) + '</span></div></div>';
      }).join(''));

  /* Self-learned techniques: the agent's own growing library of proven
     drains (and their LLM generalizations). */
  var tech = (d && d.learned) || { total: 0, distilled: 0, proven: 0, shapes: 0, top: [] };
  setStat('mem-tech', { value: tech.total, label: 'Learned Techniques', color: tech.total > 0 ? '#3fb950' : '#7d8899', sub: tech.distilled > 0 ? tech.distilled + ' generalized' : 'captured from proven drains' }, 'mem-stats');
  var tops = tech.top || [];
  paint($('mem-techniques'), tops.length === 0
    ? '<div class="empty">No techniques learned yet — every proven drain (template win, fuzz discovery, invariant violation) lands here and feeds future hunts.</div>'
    : tops.map(function(t, i){
        var head = t.reuse || t.observation || t.technique;
        var originColor = t.origin === 'distilled' ? '#a371f7' : '#3fb950';
        return '<div class="recall-hit" style="animation-delay:' + (i * 40) + 'ms;border-left-color:' + originColor + '99">' +
          '<span class="pill finding" style="background:' + originColor + '22;color:' + originColor + '">' + esc(t.origin) + '</span>' +
          ' <b>' + esc(head) + '</b>' +
          '<div style="color:#8b949e;font-size:11.5px">' +
            (t.shape ? esc(t.shape.slice(0, 60)) + ' · ' : '') +
            (t.path ? 'path: ' + esc(t.path) + ' · ' : '') +
            (t.profitWei && t.profitWei !== '0' ? 'profit ' + esc(t.profitWei) + ' wei · ' : '') +
            'proven ' + esc(t.wins) + 'x' +
            (t.transferredTo && t.transferredTo.length ? ' · also drained ' + esc(t.transferredTo.slice(0, 2).join(', ')) : '') +
            ' · ' + fmtT(t.last) +
          '</div></div>';
      }).join(''));
}

var recallBusy = false;
async function doRecall(){
  var box = $('mem-recall'), out = $('mem-results'), wrap = $('mem-recall-wrap');
  if (!box || !out) return;
  var q = String(box.value || '').trim();
  if (!q){
    out.innerHTML = '<span class="muted">Type a target, technique or shape — recall runs against the agent memory store.</span>';
    return;
  }
  if (!liveMode){
    out.innerHTML = '<span class="muted">Recall needs the live dashboard — this is a frozen export.</span>';
    return;
  }
  if (recallBusy) return;
  recallBusy = true;
  if (wrap) wrap.classList.add('busy');
  try {
    var res = await fetch('/api/memory?q=' + encodeURIComponent(q), { cache: 'no-store' });
    var j = await res.json();
    var hits = j.results || [];
    out.innerHTML = hits.length === 0
      ? '<span class="muted">Nothing remembered for “' + esc(q) + '”.</span>'
      : hits.map(function(h, i){
          return '<div class="recall-hit" style="animation-delay:' + (i * 45) + 'ms">' +
            '<span class="kind">' + esc(h.kind) + '</span><span class="ts">' + fmtT(h.t) + '</span>' +
            '<span class="score">score ' + Number(h.score).toFixed(2) + '</span><br>' + esc(h.text) + '</div>';
        }).join('');
  } catch (err) {
    out.innerHTML = '<span class="muted">recall failed: ' + esc(err.message) + '</span>';
  } finally {
    recallBusy = false;
    if (wrap) wrap.classList.remove('busy');
  }
}

function setConn(ok){
  if (connected === ok) return;
  connected = ok;
  var c = $('conn'), d = $('live-dot');
  if (c) c.textContent = ok ? 'live · 2s' : 'reconnecting…';
  if (d) d.classList.toggle('warn', !ok);
}

/* liveMode is decided once at boot (see boot()): a dashboard polls, an
   exported snapshot file renders its frozen state. */
var liveMode = false;
async function tick(){
  var s;
  if (liveMode || !window.STATE){
    try {
      var res = await fetch('/api/state', { cache: 'no-store' });
      if (!res.ok) throw new Error('status ' + res.status);
      s = await res.json();
    } catch (err) {
      setConn(false);
      return;
    }
  } else {
    s = window.STATE;
  }
  setConn(true);
  lastState = s;

  /* ---- header ---- */
  var mode = String(s.mode || 'idle');
  $('mode').textContent = mode.split(' ')[0];
  $('mode').title = mode;
  $('uptime').textContent = 'up ' + fmtDur(Date.now() - s.startedAt) + ' · cycle ' + s.cycle;
  $('kb-header').textContent = s.kbWins + ' kb wins';

  /* ---- operator switch (LLM triage backlog) ---- */
  paintBacklogSwitch(s.backlog ? !!s.backlog.enabled : false, s.backlog || null);

  /* ---- stats (in-place, animated) ---- */
  var challenges = Object.values(s.challenges || {});
  var solved = challenges.filter(function(c){ return c.status === 'solved'; }).length;
  var watch = Object.values(s.watchlist || {});
  /* Unprobeable rows (display-truncated leftovers in an old state.json) are
     excluded from the watched count and reported separately — never shown as
     if they were targets. */
  var probeable = watch.filter(function(w){ return String(w.address || '').indexOf('…') < 0; }).length;
  var unprobeable = watch.length - probeable;
  var findings = (s.findings || []).length;
  var gen = s.genEngine || { results: {}, harnessable: 0, discoveries: 0 };
  var scanEvents = (s.events || []).filter(function(e){ return e.kind === 'scan'; }).length;
  var daemons = Object.values(s.daemons || {});
  var bountyCount = watch.filter(function(w){ return w.bounty; }).length;
  var customish = (s.canonStats ? (s.canonStats.forkDelta + s.canonStats.custom) : 0);
  // The Overview card and the Memory tab MUST agree: read the same source.
  // memoryDetail.local.total is the live localmem store (memoryDetail rides
  // on every state payload, live or static). s.memory is stale pre-graphql
  // schema residue that is never written by anything — reading it is why
  // this card used to show 0 while the Memory tab showed the real store.
  var memoryLocal = (s.memoryDetail && s.memoryDetail.local && s.memoryDetail.local.total)
    || (s.memory && s.memory.local) || 0;
  var unclassified = watch.filter(function(w){ return String(w.shape || '').indexOf('unknown') === 0; }).length;

  setStat('solved', { value: solved, suffix: '/' + challenges.length, label: 'Challenges Solved', color: '#7cc4ff', sub: challenges.length ? Math.round(solved / challenges.length * 100) + '% of lab' : '' });
  setStat('watch', { value: probeable, label: 'Watched Pools', color: '#7cc4ff', sub: unprobeable > 0 ? unprobeable + ' unprobeable row(s)' : watch.length + ' rows' });
  setStat('findings', { value: findings, label: 'Findings', color: findings > 0 ? '#ff6b61' : '#3fb950', sub: findings ? 'review now' : 'none yet' });
  setStat('gen', { value: gen.discoveries, suffix: '/' + gen.harnessable, label: 'Generic Violations', color: gen.discoveries > 0 ? '#ff6b61' : '#7cc4ff' });
  setStat('unclassified', { value: unclassified, label: 'Unclassified', color: unclassified > 0 ? '#e3b341' : '#3fb950', sub: probeable ? Math.round(unclassified / probeable * 100) + '% of watched' : '' });
  setStat('scan', { value: scanEvents, label: 'Scan Events', color: '#a371f7' });
  setStat('kb', { value: s.kbWins, label: 'KB Wins', color: '#a371f7' });
  setStat('daemons', { value: daemons.length, label: 'Daemons Live', color: daemons.length > 1 ? '#3fb950' : '#7cc4ff' });
  setStat('bounty', { value: bountyCount, label: '💰 Bounty Targets', color: bountyCount > 0 ? '#e3b341' : '#7d8899' });
  setStat('memory', { value: memoryLocal, label: '🧠 Memories', color: memoryLocal > 0 ? '#3fb950' : '#7d8899' });
  /* FUZZ CAMPAIGN STRIP — accumulating bug-finding pressure, visible. */
  var camp = s.campaignStats || null;
  if (camp) {
    setStat('campaigns', { value: camp.active, suffix: '/' + camp.total, label: '🎯 Fuzz Campaigns', color: camp.total > 0 ? '#a371f7' : '#7d8899', sub: camp.runsSoFar ? camp.runsSoFar.toLocaleString() + ' cumulative runs · ' + camp.verified + ' verified' : 'awaiting first slice' });
  }
  /* SMALL-TVL LANE — the DefiLlama < $1M targeting lane (fresh + unaudited +
     tiny = highest undiscovered-bug base rate). Count = custom/fork-delta
     targets in the funnel (the real bug surface the lane feeds). */
  var funnel = s.funnel || null;
  if (funnel) {
    setStat('funnel', { value: funnel.customish, label: '🧭 Custom Surface', color: funnel.customish > 0 ? '#4d9dff' : '#7d8899', sub: funnel.verified > 0 ? funnel.verified + ' verified violation(s)' : funnel.violated > 0 ? funnel.violated + ' violation(s) pending verify' : funnel.fuzzed > 0 ? funnel.fuzzed + ' campaigns · ' + funnel.runsSoFar.toLocaleString() + ' runs' : 'awaiting campaigns' });
  }
  var memCard = document.querySelector('[data-stat="memory"]');
  if (memCard) memCard.classList.add('brain'); // rotating halo: memory is the live learning loop

  renderMemory(s);
  renderIdeas(s);
  renderHacking(s);

  /* Triage is the analysis path most likely to be silently starved (spent
     budget, revoked key, rate limits). Surface it as a first-class number:
     ok/total today, with the blocking reason named underneath. */
  var tr = s.triage || null;
  var tq = s.triageQueue || null;
  if (tr) {
    var attempted = tr.ok + Object.keys(tr.counts || {}).filter(function(k){ return k !== 'ok'; }).reduce(function(a, k){ return a + tr.counts[k]; }, 0);
    var blocked = attempted - tr.ok;
    var worst = Object.keys(tr.counts || {}).filter(function(k){ return k !== 'ok'; }).sort(function(a, b){ return tr.counts[b] - tr.counts[a]; })[0];
    var reasonText = worst ? worst + ' ×' + tr.counts[worst] : 'none';
    if (tr.cooldownMs > 0) reasonText = 'backoff ' + Math.round(tr.cooldownMs / 1000) + 's';
    if (tr.budget && tr.budget.left === 0) reasonText = 'daily cap reached';
    setStat('triage', {
      value: tr.ok,
      suffix: '/' + attempted,
      label: 'LLM Triage OK',
      color: attempted === 0 ? '#7d8899' : tr.ok / attempted >= 0.5 ? '#3fb950' : tr.ok > 0 ? '#e3b341' : '#ff6b61',
      sub: attempted === 0 ? 'no analyses yet' : Math.round(tr.ok / attempted * 100) + '% · ' + reasonText,
    });
    setStat('triagekeys', { value: tr.keys, label: 'Triage Keys', color: tr.keys > 0 ? '#a371f7' : '#ff6b61', sub: 'budget ' + tr.budget.used + '/' + tr.budget.max });
  }
  if (tq) {
    setStat('triageq', { value: tq.size, label: 'Triage Retry Queue', color: tq.size > 200 ? '#e3b341' : tq.size > 0 ? '#7cc4ff' : '#3fb950', sub: tq.due + ' due now' + (tq.maxAttemptsSeen ? ' · max ' + tq.maxAttemptsSeen + ' tries' : '') });
  }

  /* ---- findings + toast on a NEW one ---- */
  var fkey = (s.findings || []).map(logKey).join('|');
  paint($('findings'), (s.findings || []).length
    ? s.findings.slice().reverse().map(function(f){
        return '<div class="card"><b>🚨 FINDING ' + esc(fmtT(f.t)) + '</b>' + esc(f.msg) +
          (f.data && f.data.profitWei ? '<div class="profit">Profit: ' + esc(f.data.profitWei) + ' wei</div>' : '') +
          '<div style="margin-top:8px"><button class="btn" data-goto="activity">→ activity log</button></div></div>';
      }).join('')
    : '<div class="kv">No findings yet — a probe that reproduces a drain lands here the moment it happens.</div>');
  if (seenFinding !== null && fkey !== seenFinding){
    var newest = (s.findings || [])[(s.findings || []).length - 1];
    if (newest && newest.msg) toast('🚨 ' + newest.msg, true);
  }
  seenFinding = fkey;

  /* ---- logs (append only) ---- */
  var events = s.events || [];
  pushLog($('scan-log'), events.filter(function(e){ return e.kind === 'scan'; }), 120);
  pushLog($('log'), events, 400);

  /* ---- signals ---- */
  var signals = watch.filter(function(w){
    var r = w.lastResult || '';
    // Refusals are NOT signals: a gated vault that reverted every probe
    // identity (or every probe path entirely) is the target working as
    // designed. These rows used to appear on the Signals tab with a DRAIN
    // pill — the exact false positive this filter exists to kill.
    if (/probe reverted|blocked by vault gating|probe error|Compiler run failed/.test(r)) return false;
    // A REFUTED hypothesis is definitionally not a signal: on-chain evidence
    // (or a failed probe) already disproved it, so the row must stop voting
    // on the Signals tab even though its historical conf number stays.
    if (r.indexOf('REFUTED') >= 0) return false;
    // A probe that RAN CLEAN (no violation) is also not a signal: the fleet
    // tested the triage's own hypothesis on the local fork and the target
    // held. The historical conf number stays in the row, but a tested-and-
    // held target voting on Signals made the tab show bugs that are not
    // there (verified live: Compound cETH, conf 0.65, "probe ran clean: no
    // violation observed (NO_VIOLATION)").
    if (/probe ran clean/.test(r)) return false;
    if (w.finding) return true;
    var ci = r.indexOf('conf ');
    if (ci < 0) return false;
    var conf = parseFloat(r.slice(ci + 5));
    if (!(conf >= 0.5)) return false;
    var ti = r.indexOf('LLM triage [');
    if (ti < 0) return false;
    var tech = r.slice(ti + 12).split(',')[0].split(']')[0].trim();
    if (!tech || tech === 'none') return false;
    // A SKIPPED probe never tested the hypothesis at all (funding/gating
    // limits) — it is an untested idea, not a signal; "probe ran" only ever
    // pairs with "ran clean", already excluded above. Only an EXECUTED probe
    // that produced a FINDING marker counts.
    return r.indexOf('probe FINDING') >= 0;
  });
  paint($('signal-list'), signals.length === 0
    ? '<div class="empty">No high-confidence (≥50%) signals yet — scanning ' + probeable + ' targets…</div>'
    : signals.map(function(w){
        var r = w.lastResult || '';
        var ci = r.indexOf('conf ');
        var conf = ci >= 0 ? parseFloat(r.slice(ci + 5)) : 0;
        var ti = r.indexOf('LLM triage [');
        var tech = ti >= 0 ? r.slice(ti + 12).split(',')[0].split(']')[0] : '';
        var hi = r.indexOf(']: ');
        var hyp = hi >= 0 ? r.slice(hi + 3).split('|')[0] : r.slice(0, 140);
        var isHigh = conf >= 0.75 || w.finding;
        return '<div class="signal-row' + (isHigh ? ' high' : '') + '">' +
          '<div>' + addrCell(w.address) +
          (w.name ? '<span class="muted" style="font-size:11px"> ' + esc(w.name) + '</span>' : '') +
          (tech ? '<span class="badge badge-conf-' + (conf >= 0.75 ? 'high' : conf >= 0.5 ? 'med' : 'low') + '">' + esc(tech) + '</span>' : '') +
          confBadge(conf) +
          (w.bounty ? '<span class="badge badge-bounty" title="Live Immunefi program">💰</span>' : '') +
          (w.finding ? '<span class="pill finding">' + (String(w.lastResult || '').indexOf('VERIFIED 2/2') === 0 ? 'DRAIN REPRODUCED' : 'FINDING FLAG') + '</span>' : '') +
          (w.lastProbe ? '<span class="muted" style="float:right;font-size:11px">' + fmtAgo(w.lastProbe) + '</span>' : '') +
          '</div><div class="hyp">' + esc(String(hyp).slice(0, 220)) + '</div>' +
          '<div class="bar"><i style="width:' + Math.round(conf * 100) + '%"></i></div></div>';
      }).join(''));
  var nsig = $('n-signals');
  if (nsig) nsig.textContent = signals.length || '';

  /* ---- watchlist ---- */
  renderWatchlist(s);

  /* ---- daemons ---- */
  var wd = s.watchdog;
  paint($('watchdog-status'), wd && wd.line
    ? '🐕 <span style="font-size:12px;color:' + (String(wd.line).indexOf('ok daemons=') >= 0 ? '#3fb950' : '#e3b341') + '">' + esc(String(wd.line).replace(/^\S+\s+\S+\s+/, '')) + '</span>'
    : '<span style="font-size:12px;color:#7d8899">🐕 watchdog not running — daemons will not auto-restart if one dies</span>');
  var db = $('daemon-table').querySelector('tbody');
  if (daemons.length === 0){
    paint(db, '<tr><td colspan="9" class="empty">No daemon heartbeat in the last 5 minutes — the registry shows live instances only.</td></tr>');
  } else {
    daemons.sort(function(a, b){ return String(a.id).localeCompare(String(b.id)); });
    var stateClass = function(d){
      var age = Date.now() - d.lastBeat;
      return age < 120000 ? 'live' : age < DAEMON_STALE_MS ? 'slow' : 'dead';
    };
    paint(db, diffRows('daemons', daemons, function(d){ return d.id; }, function(d){
      return [d.lastBeat, d.cycle, d.watchlistSize, d.chains, d.uiPort, d.pid, d.startedAt, d.intervalSec, d.mainnetOnly].join('|');
    }, function(d, changed){
      /* Animated cells (status/chains/watched) start EMPTY: they are filled
         in-place below, so a repaint never restarts their animations. */
      return '<tr class="' + (changed ? 'flash' : '') + '" data-daemon="' + esc(d.id) + '">' +
        '<td><b style="color:#7cc4ff">' + esc(d.id) + '</b>' + (d.mainnetOnly ? '<span class="pill pending" style="margin-left:6px">MAINNET</span>' : '') + '</td>' +
        '<td class="d-status"></td>' +
        '<td style="max-width:280px" class="d-chains"></td>' +
        '<td class="d-cycle"><span class="cnum">' + esc(d.cycle) + '</span>' +
          '<div class="cycle-bar"><i style="animation-duration:' + Math.max(2, num(d.intervalSec)) + 's"></i></div></td>' +
        '<td style="font-size:12px">' + fmtDur(Date.now() - d.startedAt) + '</td>' +
        '<td style="font-size:12px">' + esc(d.intervalSec) + 's</td>' +
        '<td class="d-watched"></td>' +
        '<td style="font-size:12px;color:#7d8899">' + esc(d.pid) + '@' + esc(d.host) + '</td>' +
        '<td>' + (d.uiPort ? '<a href="http://127.0.0.1:' + esc(d.uiPort) + '">:' + esc(d.uiPort) + '</a>' : '<span class="muted">—</span>') + '</td></tr>';
    }));
    /* In-place cell updates: the CSS fill-bar loops forever per row, so only
       cells whose content actually changed may be touched. Escalation
       (live→slow→stopped) rebuilds the one cell — and pauses that row's bar. */
    var rows = db.querySelectorAll('tr[data-daemon]');
    for (var ri = 0; ri < rows.length; ri++){
      var row = rows[ri];
      var did = row.getAttribute('data-daemon');
      var d = daemons.find(function(x){ return String(x.id) === did; });
      if (!d) continue;
      var want = stateClass(d);
      if (row.dataset.state !== want){
        row.dataset.state = want;
        var stCell = row.querySelector('.d-status');
        var cbar = row.querySelector('.cycle-bar');
        if (want === 'dead'){
          stCell.innerHTML = '<span class="beat-dot dead"></span><span style="color:#7d8899">stopped</span>';
          if (cbar) cbar.classList.add('off');
        } else {
          stCell.innerHTML = want === 'slow'
            ? '<span class="beat-dot slow"></span><span style="color:var(--warn)">slow</span>'
            : '<span class="beat-dot"></span><span style="color:var(--ok)">live</span>';
          if (cbar) cbar.classList.remove('off');
        }
        var chCell = row.querySelector('.d-chains');
        if (chCell) chCell.innerHTML = chainPills(d.chains);
      }
      var wCell = row.querySelector('.d-watched');
      if (wCell && String(d.watchlistSize) !== wCell.dataset.v){
        wCell.dataset.v = String(d.watchlistSize);
        wCell.innerHTML = esc(d.watchlistSize) + miniSpark(d.id, num(d.watchlistSize));
      }
      var cEl = row.querySelector('.cnum');
      if (cEl && cEl.textContent !== String(d.cycle)) cEl.textContent = String(d.cycle);
    }
  }
  renderScanStatus(s);
  renderChainWire(s);
  renderMonitor(s);
  var nd = $('n-daemons');
  if (nd) nd.textContent = daemons.length || '';

  /* ---- lab challenges ---- */
  paint($('challenges').querySelector('tbody'), Object.values(s.challenges || {}).map(function(c){
    return '<tr><td>' + esc(c.name) + '</td>' +
      '<td><span class="pill ' + esc(c.status) + '">' + esc(c.status) + '</span></td>' +
      '<td style="font-size:12px;color:#7d8899">' + esc(c.technique || '—') + '</td>' +
      '<td>' + esc(c.attempts == null ? '—' : c.attempts) + '</td></tr>';
  }).join(''));

  /* ---- generic engine ---- */
  var genEntries = Object.entries(gen.results || {});
  paint($('gen-stats'),
    '<div class="stat" style="--c:#7cc4ff"><div class="val">' + esc(gen.harnessable) + '</div><div class="lbl">Harnessable Targets</div></div>' +
    '<div class="stat" style="--c:' + (gen.discoveries > 0 ? '#ff6b61' : '#7cc4ff') + '"><div class="val">' + esc(gen.discoveries) + '</div><div class="lbl">Universal Violations</div></div>');
  paint($('gen-results').querySelector('tbody'), genEntries.length === 0
    ? '<tr><td colspan="5" class="empty">No generic harness runs yet — the daemon and the harness CLI record here.</td></tr>'
    : diffRows('gen', genEntries, function(en){ return en[0]; }, function(en){ return en[1].result + '|' + en[1].invariant; }, function(en, changed){
        var name = en[0], r = en[1];
        var badge = r.result === 'discovered' ? '<span class="pill finding">VIOLATION</span>'
          : r.result === 'held' ? '<span class="pill solved">held</span>'
          : r.result === 'error' ? '<span class="pill failed">error</span>'
          : '<span class="pill pending">skipped</span>';
        return '<tr class="' + (changed ? 'flash' : '') + '"' + (r.result === 'discovered' ? ' style="background:#1a0e0e"' : '') + '>' +
          '<td>' + esc(name) + '</td>' +
          '<td>' + shapeChip(r.shape) + '</td>' +
          '<td>' + badge + '</td>' +
          '<td style="font-size:12px;color:' + (r.invariant ? '#ff7b72' : '#7d8899') + '">' + esc(r.invariant || '—') + '</td>' +
          '<td style="font-size:12px">' + (r.t ? fmtT(r.t) : '—') + '</td></tr>';
      }));
  var ng = $('n-gen');
  if (ng) ng.textContent = gen.discoveries || '';
}  /* ---------- fleet monitor strip ---------- */
  /* One summary strip + per-daemon verdict rows from the /api/monitor report.
     Rendered only when the tab is active and the report changed — the paint
     cache handles that. */
  var lastMonKey = '';
  function fmtAge(ms){ return ms == null ? '?' : fmtDur(ms) + ' ago'; }
  function renderMonitor(s){
    var el = $('monitor-strip');
    if (!el) return;
    var m = s.monitor;
    if (!m || !m.report){
      paint(el, '<div class="empty">monitor not available yet — the first fleet report is being gathered (checks every 30s)</div>');
      return;
    }
    var r = m.report;
    var ok = function(b){ return '<span style="color:' + (b ? 'var(--ok)' : 'var(--bad)') + '">' + (b ? '✓' : '✗') + '</span>'; };
    var dead = r.daemons.filter(function(d){ return d.verdict !== 'ok'; });
    var deadForks = r.forks.filter(function(f){ return !f.responds; });
    var key = [r.at, r.healthy, dead.length, deadForks.length, r.sidecar, r.findings.count, r.notes.length].join('|');
    if (key === lastMonKey) return;
    lastMonKey = key;
    var q = r.pipeline && r.pipeline.queue ? r.pipeline.queue : null;
    var resp = r.pipeline && r.pipeline.responder ? r.pipeline.responder : null;
    var tech = r.pipeline && r.pipeline.techniques ? r.pipeline.techniques : null;
    var respFresh = resp && resp.baselineAgeMs != null && resp.baselineAgeMs < 6 * 3600000;
    var html = '<div class="mon-strip ' + (r.healthy ? 'mon-ok' : 'mon-bad') + '">' +
      '<span class="lamp"></span><b>' + (r.healthy ? 'FLEET HEALTHY' : 'FLEET DEGRADED') + '</b>' +
      '<span class="muted"> · ' + fmtAge(Date.now() - r.at) + '</span>' +
      '<span class="mon-chips">' +
        '<span class="chip chip-dim" title="daemons whose verdict is not ok">' + ok(dead.length === 0) + ' daemons ' + (r.daemons.length - dead.length) + '/' + r.daemons.length + '</span>' +
        '<span class="chip chip-dim" title="anvil forks answering eth_chainId">' + ok(deadForks.length === 0) + ' forks ' + (r.forks.length - deadForks.length) + '/' + r.forks.length + '</span>' +
        '<span class="chip chip-dim">' + ok(r.sidecar === 'up') + ' sidecar</span>' +
        '<span class="chip chip-dim" title="first-responder balance watchdog: sweep baseline age (fresh = live-exploit detection online)">' + (resp ? (respFresh ? '<span style="color:var(--ok)">✓</span> responder' : '<span style="color:var(--bad)">✗</span> responder') : '<span style="color:var(--bad)">✗</span> responder') + '</span>' +
        '<span class="chip chip-dim" title="total reproduced drains">' + r.findings.count + ' finding(s)</span>' +
        (tech && tech.total > 0 ? '<span class="chip chip-dim" title="self-learned technique library: captures from proven drains (distilled count in tooltip)">' + tech.total + ' learned' + (tech.distilled > 0 ? ' · ' + tech.distilled + ' distilled' : '') + '</span>' : '') +
        (q ? '<span class="chip chip-dim" title="triage retry queue: due now / waiting">queue ' + q.dueNow + '/' + q.total + '</span>' : '') +
      '</span></div>';
    if (r.notes && r.notes.length){
      html += '<div class="mon-notes">' + r.notes.slice(0, 6).map(function(n){
        return '<div class="mon-note">! ' + esc(String(n).slice(0, 200)) + '</div>';      }).join('') + '</div>';
    }
    if (dead.length){
      html += '<table class="mon-table"><thead><tr><th>Daemon</th><th>Verdict</th><th>Detail</th></tr></thead><tbody>' +
        dead.map(function(d){
          var det = 'pid ' + d.pid + ' · heartbeat ' + (d.heartbeatAgeMs == null ? '?' : Math.round(d.heartbeatAgeMs / 1000) + 's') + ' · cycle ' + d.cycle;
          return '<tr><td>' + esc(d.id) + '</td><td><span class="pill ' + (d.verdict === 'dead' ? 'failed' : 'pending') + '">' + esc(d.verdict) + '</span></td><td style="font-size:12px;color:#a8b3c4">' + esc(det) + '</td></tr>';
        }).join('') + '</tbody></table>';
    }
    paint(el, html);
  }

  /* ---------------- boot ---------------- */
wlControls();
showTab(activeTab, false);
moveIndicator();
(function(){
  var go = $('mem-recall-go');
  if (go) go.addEventListener('click', function(){ doRecall(); });
  var box = $('mem-recall');
  if (box) box.addEventListener('keydown', function(ev){ if (ev.key === 'Enter'){ ev.preventDefault(); doRecall(); } });
})();
document.addEventListener('click', function(ev){
  var b = ev.target.closest ? ev.target.closest('[data-goto]') : null;
  if (b) showTab(b.dataset.goto);
});
document.addEventListener('keydown', function(ev){
  if (ev.target.tagName === 'INPUT' || ev.target.tagName === 'SELECT') {
    if (ev.key === 'Escape'){ ev.target.blur(); if (ev.target.id === 'wl-filter'){ ev.target.value = ''; ev.target.dispatchEvent(new Event('input')); } }
    return;
  }
  if (ev.key === '/'){ var f = $('wl-filter'); if (f){ ev.preventDefault(); showTab('watchlist'); f.focus(); } return; }
  var n = parseInt(ev.key, 10);
  if (n >= 1 && n <= TABS.length) showTab(TABS[n - 1]);
});

/* Boot: a seeded window.STATE is a FIRST PAINT, not a verdict on liveness.
   Both the exported snapshot file and a real dashboard arrive with state
   injected (so the first frame is instant) — the server marks exports
   explicitly, so the page never has to guess (and an export never fires a
   request at an API that is not there). The old page froze in standalone ui
   mode because a seeded state disabled polling entirely. */
async function boot(){
  liveMode = !window.STATIC_EXPORT;
  await tick();
  var live = liveMode;
  if (live){
    setInterval(function(){ if (!document.hidden) tick(); }, 2000);
    document.addEventListener('visibilitychange', function(){ if (!document.hidden) tick(); });
    setInterval(function(){
      if (document.hidden) return;
      var c = $('conn');
      c.textContent = connected ? 'live · 2s' : 'reconnecting…';
    }, 2000);
  } else {
    $('conn').textContent = 'static snapshot';
    var dot = document.getElementById('live-dot');
    if (dot) dot.classList.add('warn');
  }
}
boot();
</script>
</body>
</html>`;
