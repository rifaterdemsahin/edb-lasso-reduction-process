// Global Search Component for EDB Lasso Reduction Process Portal

const SEARCH_INDEX = [
  {
    title: "Architecture & Excalidraw Mind Map",
    category: "Architecture",
    url: "architecture.html",
    description: "Visual mind map and enterprise debugging session lifecycle between DB teams and EDB Support.",
    keywords: ["architecture", "excalidraw", "mind map", "diagram", "lifecycle", "enterprise debugging", "rca", "session", "edb support", "flow"]
  },
  {
    title: "Create EDB Lasso Tarball (CLI & UI Guide)",
    category: "Guide",
    url: "create-lasso-tarball.html",
    description: "How to generate EDB Lasso .tar.gz diagnostic bundle from CLI and UI, expectations, and gotchas.",
    keywords: ["create", "tarball", "tar.gz", "generate", "lasso cli", "expectations", "gotchas", "bloat", "permissions", "offline", "bundle"]
  },
  {
    title: "Stage 01: Ingestion & Unpack",
    category: "Stages",
    url: "stage-01-ingestion-unpack.html",
    description: "Extracts EDB Lasso tarball (.tar.gz) or output directory without altering raw file permissions.",
    keywords: ["stage 1", "unpack", "extract", "tar", "tar.gz", "ingestion", "permissions", "safeguards", "checksum"]
  },
  {
    title: "Stage 02: Credential Stripping",
    category: "Stages",
    url: "stage-02-credential-stripping.html",
    description: "Identifies and masks passwords in conninfo, MD5 hashes, SCRAM-SHA-256 tokens, API keys, and customer tokens.",
    keywords: ["stage 2", "credentials", "passwords", "conninfo", "md5", "scram", "scram-sha-256", "tokens", "aws", "edb_customer_token", "api_key", "secret"]
  },
  {
    title: "Stage 03: Deterministic IP Mapping",
    category: "Stages",
    url: "stage-03-deterministic-ip-mapping.html",
    description: "Maps internal IP addresses (e.g. 10.0.12.45) to consistent aliases (PSEUDO_IP_NODE_01) preserving cluster topology.",
    keywords: ["stage 3", "ip mapping", "pseudonymization", "network", "pseudo_ip", "subnets", "cluster topology", "replication", "barman", "standby"]
  },
  {
    title: "Stage 04: Audit Manifest & Repack",
    category: "Stages",
    url: "stage-04-audit-manifest-repack.html",
    description: "Generates lasso_reduction_manifest.json detailing redaction tallies and produces a sanitized archive.",
    keywords: ["stage 4", "manifest", "audit", "repack", "lasso_reduction_manifest.json", "tarball", "compliance", "pci-dss", "soc2"]
  },
  {
    title: "Side-by-Side Comparison",
    category: "Tools",
    url: "comparison.html",
    description: "Interactive visual side-by-side diff comparison between raw Lasso artifacts and sanitized outputs.",
    keywords: ["comparison", "side by side", "diff", "before after", "visualizer", "compare", "raw vs redacted"]
  },
  {
    title: "Overview: What is EDB Lasso?",
    category: "Documentation",
    url: "index.html#about",
    description: "Multi-platform diagnostic tool developed by EnterpriseDB for PostgreSQL troubleshooting.",
    keywords: ["edb lasso", "overview", "flight recorder", "black box", "troubleshooting", "enterprisedb", "postgres"]
  },
  {
    title: "Four Pillars of EDB Lasso",
    category: "Documentation",
    url: "index.html#why-lasso",
    description: "Standardized troubleshooting, production-safe, zero data extraction, and holistic ecosystem visibility.",
    keywords: ["four pillars", "standardizes", "production safe", "zero data extraction", "barman", "repmgr", "efm"]
  },
  {
    title: "Interactive Reduction Sandbox",
    category: "Tools",
    url: "index.html#sandbox",
    description: "Real-time in-browser redaction sandbox and token masking simulator with sample configs.",
    keywords: ["sandbox", "simulator", "live", "try", "testing", "playground"]
  },
  {
    title: "CLI Guide & Automation",
    category: "Guide",
    url: "index.html#cli-guide",
    description: "Command-line usage for python3 lasso_redact.py across directories and .tar.gz archives.",
    keywords: ["cli", "python", "terminal", "automation", "lasso_redact.py", "script"]
  },
  {
    title: "Marp Presentation: Operational SOP (WHY, WHAT, HOW)",
    category: "Presentation",
    url: "presentation.html",
    description: "Executive and operational presentation explaining why, what, and how the reduction engine works, with code evolution deep dive.",
    keywords: ["marp", "presentation", "sop", "slides", "why", "what", "how", "operational procedure", "code", "architecture"]
  }
];

// Initialize Search Modal
document.addEventListener('DOMContentLoaded', () => {
  const searchInput = document.getElementById('globalSearchInput');
  const searchModal = document.getElementById('searchModal');
  const searchModalInput = document.getElementById('searchModalInput');
  const searchResults = document.getElementById('searchResults');
  const closeSearchModal = document.getElementById('closeSearchModal');

  if (!searchModal) return;

  function openModal() {
    searchModal.classList.remove('hidden');
    searchModalInput.value = searchInput ? searchInput.value : '';
    searchModalInput.focus();
    renderResults(searchModalInput.value);
  }

  function closeModal() {
    searchModal.classList.add('hidden');
    if (searchInput) searchInput.value = '';
  }

  if (searchInput) {
    searchInput.addEventListener('click', openModal);
    searchInput.addEventListener('focus', openModal);
  }

  if (closeSearchModal) {
    closeSearchModal.addEventListener('click', closeModal);
  }

  searchModal.addEventListener('click', (e) => {
    if (e.target === searchModal) closeModal();
  });

  // Shortcut key Cmd+K or Ctrl+K or /
  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      openModal();
    } else if (e.key === '/' && document.activeElement !== searchInput && document.activeElement !== searchModalInput) {
      e.preventDefault();
      openModal();
    } else if (e.key === 'Escape' && !searchModal.classList.contains('hidden')) {
      closeModal();
    }
  });

  if (searchModalInput) {
    searchModalInput.addEventListener('input', (e) => {
      renderResults(e.target.value);
    });
  }

  function renderResults(query) {
    const q = (query || '').trim().toLowerCase();
    searchResults.innerHTML = '';

    const matched = SEARCH_INDEX.filter(item => {
      if (!q) return true;
      return item.title.toLowerCase().includes(q) ||
             item.description.toLowerCase().includes(q) ||
             item.category.toLowerCase().includes(q) ||
             item.keywords.some(k => k.includes(q));
    });

    if (matched.length === 0) {
      searchResults.innerHTML = `
        <div class="py-8 text-center text-slate-400">
          <i class="fa-solid fa-magnifying-glass text-2xl mb-2 text-slate-500"></i>
          <p>No results found for "<span class="text-white font-semibold">${query}</span>"</p>
          <p class="text-xs text-slate-500 mt-1">Try searching for "credentials", "IP", "unpack", "manifest", or "comparison".</p>
        </div>
      `;
      return;
    }

    matched.forEach((item, index) => {
      const a = document.createElement('a');
      a.href = item.url;
      a.className = "flex items-start justify-between p-3 rounded-xl hover:bg-slate-800 transition group border border-transparent hover:border-slate-700";
      a.innerHTML = `
        <div class="flex items-start space-x-3">
          <div class="w-8 h-8 rounded-lg bg-edb/20 text-edb-light flex items-center justify-center shrink-0 mt-0.5 group-hover:bg-edb group-hover:text-white transition">
            <i class="fa-solid fa-arrow-right text-xs"></i>
          </div>
          <div>
            <div class="flex items-center space-x-2">
              <span class="text-sm font-bold text-white group-hover:text-cyan-300 transition">${item.title}</span>
              <span class="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 group-hover:bg-slate-700">${item.category}</span>
            </div>
            <p class="text-xs text-slate-400 mt-1">${item.description}</p>
          </div>
        </div>
      `;
      searchResults.appendChild(a);
    });
  }
});
