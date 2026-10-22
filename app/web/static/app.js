(() => {
  const searchInput = document.getElementById("service-search");
  const filterButtons = document.querySelectorAll(".filter-pill");
  const cards = document.querySelectorAll(".service-card");

  let activeCategory = "all";

  function applyFilters() {
    const query = (searchInput ? searchInput.value : "").trim().toLowerCase();
    cards.forEach((card) => {
      const cat = (card.getAttribute("data-category") || "").toLowerCase();
      const text = (card.getAttribute("data-search") || "").toLowerCase();
      const matchCat = activeCategory === "all" || cat === activeCategory;
      const matchQuery = !query || text.includes(query);
      if (matchCat && matchQuery) {
        card.classList.remove("hidden");
      } else {
        card.classList.add("hidden");
      }
    });
  }

  if (searchInput) {
    searchInput.addEventListener("input", applyFilters);
    window.addEventListener("keydown", (e) => {
      if (e.key === "/" && document.activeElement !== searchInput && !["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName)) {
        e.preventDefault();
        searchInput.focus();
      } else if (e.key === "Escape" && document.activeElement === searchInput) {
        searchInput.value = "";
        searchInput.blur();
        applyFilters();
      }
    });
  }

  filterButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      filterButtons.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      activeCategory = (btn.getAttribute("data-filter") || "all").toLowerCase();
      applyFilters();
    });
  });

  // Live background health-check polling every 15 seconds
  async function refreshHealthStatus() {
    try {
      const res = await fetch("/api/catalog", { headers: { "Accept": "application/json" } });
      if (!res.ok) return;
      const items = await res.json();
      if (!Array.isArray(items)) return;

      let upCount = 0;
      items.forEach((item) => {
        if (item.status_state === "up" && !item.maintenance_mode) {
          upCount++;
        }
        const pill = document.querySelector(`[data-status-for="${item.id}"]`);
        const label = document.querySelector(`[data-status-label="${item.id}"]`);
        if (!pill || !label) return;

        pill.className = "status-pill";
        if (item.maintenance_mode) {
          pill.classList.add("status-degraded");
          label.textContent = "Maintenance";
        } else {
          const st = item.status_state || "unknown";
          pill.classList.add("status-" + st);
          label.textContent = `${st} • ${item.latency_ms || 0}ms`;
        }
      });

      const onlineCounter = document.getElementById("online-counter");
      if (onlineCounter) {
        onlineCounter.textContent = `${upCount} / ${items.length} Online`;
      }
    } catch (_) {
      // Fail silently on transient network hiccups
    }
  }

  if (cards.length > 0) {
    setInterval(refreshHealthStatus, 15000);
  }
})();
