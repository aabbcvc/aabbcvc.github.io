/* Ctrl-Alt-Intel — site interactivity (no dependencies) */
(function () {
  "use strict";

  /* ---------- Theme toggle ---------- */
  var toggle = document.getElementById("themeToggle");
  if (toggle) {
    toggle.addEventListener("click", function () {
      var current = document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
      var next = current === "light" ? "dark" : "light";
      document.documentElement.setAttribute("data-theme", next);
      try { localStorage.setItem("cai-theme", next); } catch (e) {}
    });
  }

  /* ---------- Header shadow + back-to-top ---------- */
  var header = document.getElementById("siteHeader");
  var backToTop = document.getElementById("backToTop");
  var progressBar = document.getElementById("progressBar");
  var postContent = document.getElementById("postContent");

  function onScroll() {
    var y = window.scrollY || window.pageYOffset;
    if (header) header.classList.toggle("is-scrolled", y > 8);
    if (backToTop) backToTop.classList.toggle("is-visible", y > 600);
    if (progressBar && postContent) {
      var rect = postContent.getBoundingClientRect();
      var total = rect.height - window.innerHeight;
      var read = Math.min(Math.max(-rect.top, 0), Math.max(total, 1));
      progressBar.style.width = (total > 0 ? (read / total) * 100 : 0) + "%";
    }
  }
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  if (backToTop) {
    backToTop.addEventListener("click", function () {
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }

  /* ---------- Mobile menu ---------- */
  var burger = document.getElementById("navBurger");
  if (burger && header) {
    burger.addEventListener("click", function () {
      var open = header.classList.toggle("menu-open");
      burger.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  /* ---------- Reveal on scroll ---------- */
  var revealEls = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window && revealEls.length) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          io.unobserve(entry.target);
        }
      });
    }, { rootMargin: "0px 0px -8% 0px", threshold: 0.05 });
    revealEls.forEach(function (el) { io.observe(el); });
  } else {
    revealEls.forEach(function (el) { el.classList.add("is-visible"); });
  }

  /* ---------- Carousel ---------- */
  document.querySelectorAll("[data-carousel]").forEach(function (section) {
    var track = section.querySelector(".carousel");
    var prev = section.querySelector("[data-carousel-prev]");
    var next = section.querySelector("[data-carousel-next]");
    if (!track) return;
    var step = function () {
      var card = track.querySelector(".post-card");
      return card ? card.offsetWidth + 18 : 340;
    };
    if (prev) prev.addEventListener("click", function () { track.scrollBy({ left: -step(), behavior: "smooth" }); });
    if (next) next.addEventListener("click", function () { track.scrollBy({ left: step(), behavior: "smooth" }); });
  });

  /* ---------- Live search / tag filter ---------- */
  var searchInput = document.getElementById("postSearch");
  var filterScope = document.getElementById("postList");
  var noResults = document.getElementById("noResults");
  var chipHost = document.getElementById("tagChips");
  var activeTag = "";

  function items() {
    return filterScope ? Array.prototype.slice.call(filterScope.querySelectorAll("[data-title]")) : [];
  }

  function applyFilter() {
    var q = (searchInput && searchInput.value || "").trim().toLowerCase();
    var visible = 0;
    items().forEach(function (el) {
      var haystack = (el.getAttribute("data-title") || "") + " " + (el.getAttribute("data-tags") || "");
      var tagOk = !activeTag || (el.getAttribute("data-tags") || "").split(",").indexOf(activeTag) !== -1;
      var match = tagOk && (!q || haystack.indexOf(q) !== -1);
      el.style.display = match ? "" : "none";
      if (match) visible++;
    });
    if (noResults) noResults.hidden = visible !== 0;
  }

  if (filterScope) {
    if (searchInput) {
      searchInput.addEventListener("input", applyFilter);
      // "/" focuses search
      document.addEventListener("keydown", function (e) {
        if (e.key === "/" && document.activeElement !== searchInput &&
            !/^(input|textarea|select)$/i.test(document.activeElement.tagName)) {
          e.preventDefault();
          searchInput.focus();
        }
        if (e.key === "Escape" && document.activeElement === searchInput) {
          searchInput.value = "";
          applyFilter();
          searchInput.blur();
        }
      });
    }

    // Build tag chips from card metadata (top 10 by frequency)
    if (chipHost) {
      var counts = {};
      items().forEach(function (el) {
        (el.getAttribute("data-tags") || "").split(",").forEach(function (t) {
          t = t.trim();
          if (t) counts[t] = (counts[t] || 0) + 1;
        });
      });
      Object.keys(counts)
        .sort(function (a, b) { return counts[b] - counts[a] || a.localeCompare(b); })
        .slice(0, 10)
        .forEach(function (tag) {
          var btn = document.createElement("button");
          btn.type = "button";
          btn.className = "chip";
          btn.textContent = tag;
          btn.addEventListener("click", function () {
            activeTag = activeTag === tag ? "" : tag;
            chipHost.querySelectorAll(".chip").forEach(function (c) {
              c.classList.toggle("is-active", c.textContent === activeTag);
            });
            applyFilter();
          });
          chipHost.appendChild(btn);
        });
    }
  }

  /* ---------- Post enhancements ---------- */
  if (postContent) {
    // Wrap tables for horizontal scrolling
    postContent.querySelectorAll("table").forEach(function (table) {
      if (table.parentElement && table.parentElement.classList.contains("table-wrap")) return;
      var wrap = document.createElement("div");
      wrap.className = "table-wrap";
      table.parentNode.insertBefore(wrap, table);
      wrap.appendChild(table);
    });

    // Heading anchor links
    postContent.querySelectorAll("h2[id], h3[id], h4[id]").forEach(function (h) {
      var a = document.createElement("a");
      a.className = "heading-anchor";
      a.href = "#" + h.id;
      a.textContent = "#";
      a.setAttribute("aria-label", "Link to this section");
      h.appendChild(a);
    });

    // Copy buttons and expand/collapse controls on code blocks
    postContent.querySelectorAll("pre").forEach(function (pre, index) {
      var block = pre.closest("div.highlighter-rouge, figure.highlight");

      // Kramdown normally provides one of the wrappers above. Keep indented or
      // hand-authored Markdown code blocks consistent if it does not.
      if (!block) {
        block = document.createElement("div");
        block.className = "code-block";
        pre.parentNode.insertBefore(block, pre);
        block.appendChild(pre);
      }

      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "code-copy";
      btn.textContent = "copy";
      btn.addEventListener("click", function () {
        var text = pre.innerText.replace(/\n$/, "");
        (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject())
          .then(function () {
            btn.textContent = "copied!";
            btn.classList.add("is-copied");
            setTimeout(function () {
              btn.textContent = "copy";
              btn.classList.remove("is-copied");
            }, 1800);
          })
          .catch(function () {});
      });
      block.appendChild(btn);

      // Keep shorter examples fully visible. Longer snippets begin as a
      // preview and can be opened without navigating away from the post.
      if (pre.scrollHeight > 360) {
        var codeId = "post-code-" + (index + 1);
        var toggleRow = document.createElement("div");
        var toggle = document.createElement("button");

        pre.id = pre.id || codeId;
        block.classList.add("code-collapsible", "is-collapsed");
        toggleRow.className = "code-toggle-row";
        toggle.type = "button";
        toggle.className = "code-toggle";
        toggle.textContent = "expand code";
        toggle.setAttribute("aria-controls", pre.id);
        toggle.setAttribute("aria-expanded", "false");

        toggle.addEventListener("click", function () {
          var isCollapsed = block.classList.toggle("is-collapsed");
          toggle.textContent = isCollapsed ? "expand code" : "collapse code";
          toggle.setAttribute("aria-expanded", String(!isCollapsed));

          // If a reader collapses from the end of a very long snippet, keep
          // the shortened block in view instead of leaving them below it.
          if (isCollapsed && block.getBoundingClientRect().bottom < 0) {
            block.scrollIntoView({ block: "center" });
          }
        });

        toggleRow.appendChild(toggle);
        block.appendChild(toggleRow);
      }
    });

    // Table of contents (h2/h3) + scrollspy
    var tocWrap = document.getElementById("postToc");
    var tocNav = document.getElementById("tocNav");
    var shell = document.getElementById("postShell");
    var headings = Array.prototype.slice.call(postContent.querySelectorAll("h2[id], h3[id]"));
    if (tocWrap && tocNav && shell && headings.length >= 2) {
      shell.classList.add("has-toc");
      tocWrap.hidden = false;
      var links = headings.map(function (h) {
        var a = document.createElement("a");
        a.href = "#" + h.id;
        a.textContent = h.textContent.replace(/#$/, "").trim();
        a.className = h.tagName === "H3" ? "toc-h3" : "toc-h2";
        tocNav.appendChild(a);
        return a;
      });

      var setActive = function (id) {
        links.forEach(function (a) {
          a.classList.toggle("is-active", a.getAttribute("href") === "#" + id);
        });
      };

      if ("IntersectionObserver" in window) {
        var visibleIds = new Set();
        var spy = new IntersectionObserver(function (entries) {
          entries.forEach(function (entry) {
            if (entry.isIntersecting) visibleIds.add(entry.target.id);
            else visibleIds.delete(entry.target.id);
          });
          for (var i = 0; i < headings.length; i++) {
            if (visibleIds.has(headings[i].id)) { setActive(headings[i].id); return; }
          }
        }, { rootMargin: "-80px 0px -66% 0px" });
        headings.forEach(function (h) { spy.observe(h); });
      }
    }
  }

  /* ---------- Footer year ---------- */
  var yearEl = document.getElementById("footerYear");
  if (yearEl) yearEl.textContent = new Date().getFullYear();
})();
