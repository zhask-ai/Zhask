# Fix badge pattern — "✓ Fixed" / "⚡ Fix available" (13 instances)
s/fixedItems\.has('alerts-'\+(e\.ts||idx)) ? `<span style="font-size:\.68rem;background:rgba(46,213,115,\.15);color:#2ed573;padding:1px 7px;border-radius:3px">✓ Fixed<\/span>` : `<span style="font-size:\.68rem;background:rgba(91,141,239,\.12);color:#5b8def;padding:1px 7px;border-radius:3px;font-weight:600">⚡ Fix available<\/span>`/mkFixBadge('alerts-'+(e.ts||idx))/g

# Click-to-view hints
s/<span style="font-size:\.68rem;color:#4a6080;font-style:italic">click to view detail \&amp; fix<\/span>/${CLICK_HINT}/g

# Launcher module status colors
s/style="color:#ff4757">⏹ Stopped/class="u-text-critical">⏹ Stopped/g
s/style="color:#00e5a0">● LIVE/class="u-text-ok">● LIVE/g

# Simple color swaps in inline styles
s/color:#ff4757/color:var(--critical)/g
s/color:#2ed573/color:var(--ok)/g
s/color:#ffa502/color:var(--warning)/g
s/color:#5b8def/color:var(--accent)/g
s/color:#b0c4de/color:var(--text-mid)/g
s/color:#4a6080/color:var(--text-dim)/g
s/color:#7a93b4/color:var(--text-muted)/g
s/color:#ff8b3d/color:var(--orange)/g
s/color:#a17fe0/color:var(--purple)/g
s/color:#39c5cf/color:var(--cyan)/g
s/color:#eaf0f7/color:var(--text-hi)/g
s/color:#ff9900/color:var(--aws)/g
s/color:#4285f4/color:var(--gcp)/g
s/color:#00a4ef/color:var(--azure)/g
s/color:#ff8b8b/color:var(--critical)/g
s/color:#ff9aa2/color:var(--critical)/g
s/color:#93bbff/color:var(--accent)/g
s/color:#c4a5f5/color:var(--purple)/g
s/color:#67e8f9/color:var(--cyan)/g
s/color:#c4a8ff/color:var(--purple)/g
s/color:#7ae8f9/color:var(--cyan)/g
s/color:#93beff/color:var(--accent)/g
s/color:#ff8899/color:var(--critical)/g

# Background tints using CSS variables
s/background:rgba(255,71,87,\.15)/background:var(--critical-bg)/g
s/background:rgba(255,71,87,\.1)/background:var(--critical-bg)/g
s/background:rgba(255,71,87,\.08)/background:var(--critical-bg)/g
s/background:rgba(91,141,239,\.12)/background:var(--accent-bg)/g
s/background:rgba(91,141,239,\.14)/background:var(--accent-bg)/g
s/background:rgba(91,141,239,\.09)/background:var(--accent-bg)/g
s/background:rgba(91,141,239,\.07)/background:var(--accent-bg)/g
s/background:rgba(91,141,239,\.2)/background:var(--accent-bg)/g
s/background:rgba(46,213,115,\.15)/background:var(--ok-bg)/g
s/background:rgba(46,213,115,\.12)/background:var(--ok-bg)/g
s/background:rgba(46,213,115,\.1)/background:var(--ok-bg)/g
s/background:rgba(161,127,224,\.09)/background:var(--purple-bg)/g
s/background:rgba(57,197,207,\.07)/background:var(--cyan-bg)/g
s/background:rgba(255,255,255,\.06)/background:var(--bg-raised)/g
s/background:rgba(255,255,255,\.04)/background:var(--bg-raised)/g
s/background:rgba(255,255,255,\.12)/background:var(--bg-raised)/g

# Border color replacements
s/border:1px solid rgba(255,71,87,\.3)/border:1px solid rgba(239,68,68,.3)/g
s/border:1px solid rgba(91,141,239,\.3)/border:1px solid var(--border-glow)/g
s/border:1px solid rgba(255,255,255,\.12)/border:1px solid var(--border-subtle)/g
s/border:1px solid rgba(46,213,115,\.3)/border:1px solid rgba(16,185,129,.3)/g
s/border:1px solid rgba(46,213,115,\.35)/border:1px solid rgba(16,185,129,.3)/g

# Box-shadow cleanup
s/box-shadow:0 0 16px rgba(46,213,115,\.35)/box-shadow:0 0 16px rgba(16,185,129,.35)/g

# Gradient cleanup
s/background:linear-gradient(135deg,#2ed573,#5b8def)/background:var(--grad-success)/g
