(function() {
  const pages = [
    { id: "dashboard", label: "Dashboard", icon: "M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6", url: "/" },
    { id: "vuln-scanner", label: "Vuln Scanner", icon: "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z", url: "/vuln-scanner" },
    { id: "network-analyzer", label: "Network", icon: "M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z", url: "/network-analyzer" },
    { id: "map", label: "Geo Map", icon: "M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7", url: "/map" },
    { id: "siem", label: "SIEM Logs", icon: "M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2", url: "/siem" },
    { id: "playbooks", label: "Playbooks", icon: "M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01", url: "/playbooks" },
    { id: "ueba", label: "UEBA", icon: "M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z", url: "/ueba" },
    { id: "hunting", label: "Hunt", icon: "M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z", url: "/hunting" },
  ];
  const currentPage = window.location.pathname.replace("/","") || "dashboard";
  const style = document.createElement("style");
  style.textContent = `
    #sentinel-nav { position:fixed;top:0;left:0;right:0;z-index:9999;background:#161b22;border-bottom:1px solid #30363d;display:flex;align-items:center;padding:0 1.25rem;height:48px; }
    #sentinel-nav .nav-brand { font-size:.9rem;font-weight:700;color:#58a6ff;letter-spacing:.08em;text-decoration:none;margin-right:1.5rem;display:flex;align-items:center;gap:.4rem; }
    #sentinel-nav .nav-brand .dot { width:8px;height:8px;border-radius:50%;background:#3fb950;animation:npulse 2s infinite; }
    @keyframes npulse { 0%,100%{opacity:1}50%{opacity:.4} }
    #sentinel-nav .nav-links { display:flex;gap:.15rem;flex:1; }
    #sentinel-nav .nav-link { display:flex;align-items:center;gap:.35rem;padding:.35rem .75rem;border-radius:6px;font-size:.78rem;font-weight:500;color:#8b949e;text-decoration:none;transition:all .15s;border:1px solid transparent; }
    #sentinel-nav .nav-link:hover { color:#e6edf3;background:#21262d; }
    #sentinel-nav .nav-link.active { color:#58a6ff;background:#0d1f2d;border-color:#58a6ff44; }
    #sentinel-nav .nav-link svg { width:14px;height:14px;flex-shrink:0; }
    #sentinel-nav .nav-right { display:flex;align-items:center;gap:.75rem;margin-left:auto; }
    #sentinel-nav .alert-badge { background:#3d1c1c;color:#ffa198;border:1px solid #f8514966;border-radius:12px;padding:.1rem .5rem;font-size:.7rem;font-weight:700;display:none; }
    #sentinel-nav .alert-badge.visible { display:inline-block; }
    #sentinel-nav .nav-time { font-size:.72rem;color:#8b949e;font-family:monospace; }
    #sentinel-nav .nav-status { font-size:.72rem;color:#3fb950; }
    body { padding-top:60px !important; }
  `;
  document.head.appendChild(style);
  const nav = document.createElement("nav");
  nav.id = "sentinel-nav";
  const links = pages.map(p => {
    const active = (window.location.pathname === p.url) ? "active" : "";
    return `<a class="nav-link ${active}" href="${p.url}"><svg fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="${p.icon}"/></svg>${p.label}</a>`;
  }).join("");
  nav.innerHTML = `<a class="nav-brand" href="/"><span class="dot"></span>SENTINEL SOC</a><div class="nav-links">${links}</div><div class="nav-right"><span class="alert-badge" id="nav-alert-count">0</span><span class="nav-status">&#9679; LIVE</span><span class="nav-time" id="nav-time"></span></div>`;
  document.body.insertBefore(nav, document.body.firstChild);
  function updateTime() { document.getElementById("nav-time").textContent = new Date().toUTCString().slice(17,25)+" UTC"; }
  updateTime(); setInterval(updateTime, 1000);
})();





