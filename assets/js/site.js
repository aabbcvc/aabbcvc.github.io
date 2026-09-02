(function () {
  "use strict";

  var header = document.getElementById("siteHeader");
  function updateHeader() {
    if (header) header.classList.toggle("is-scrolled", window.scrollY > 8);
  }
  window.addEventListener("scroll", updateHeader, { passive: true });
  updateHeader();

  var year = document.getElementById("footerYear");
  if (year) year.textContent = new Date().getFullYear();

  var reveals = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window) {
    var revealObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          revealObserver.unobserve(entry.target);
        }
      });
    }, { rootMargin: "0px 0px -6% 0px", threshold: 0.04 });
    reveals.forEach(function (element) { revealObserver.observe(element); });
  } else {
    reveals.forEach(function (element) { element.classList.add("is-visible"); });
  }

  var content = document.getElementById("postContent");
  if (!content) return;

  content.querySelectorAll("table").forEach(function (table) {
    if (table.parentElement && table.parentElement.classList.contains("table-wrap")) return;
    var wrap = document.createElement("div");
    wrap.className = "table-wrap";
    table.parentNode.insertBefore(wrap, table);
    wrap.appendChild(table);
  });

  content.querySelectorAll("h2[id], h3[id]").forEach(function (heading) {
    var anchor = document.createElement("a");
    anchor.className = "heading-anchor";
    anchor.href = "#" + heading.id;
    anchor.textContent = "#";
    anchor.setAttribute("aria-label", "Link to this section");
    heading.appendChild(anchor);
  });

  content.querySelectorAll("pre").forEach(function (pre) {
    var block = pre.closest(".highlighter-rouge, figure.highlight, .code-block");
    if (!block) {
      block = document.createElement("div");
      block.className = "code-block";
      pre.parentNode.insertBefore(block, pre);
      block.appendChild(pre);
    }
    var button = document.createElement("button");
    button.type = "button";
    button.className = "code-copy";
    button.textContent = "copy";
    button.addEventListener("click", function () {
      if (!navigator.clipboard) return;
      navigator.clipboard.writeText(pre.innerText).then(function () {
        button.textContent = "copied";
        setTimeout(function () { button.textContent = "copy"; }, 1400);
      });
    });
    block.appendChild(button);
  });

  var toc = document.getElementById("postToc");
  var tocNav = document.getElementById("tocNav");
  var headings = Array.prototype.slice.call(content.querySelectorAll("h2[id], h3[id]"));
  if (!toc || !tocNav || headings.length < 2) return;
  toc.hidden = false;
  var links = headings.map(function (heading) {
    var link = document.createElement("a");
    link.href = "#" + heading.id;
    link.textContent = heading.textContent.replace(/#$/, "").trim();
    link.className = heading.tagName === "H3" ? "toc-h3" : "toc-h2";
    tocNav.appendChild(link);
    return link;
  });
  if ("IntersectionObserver" in window) {
    var spy = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        links.forEach(function (link) {
          link.classList.toggle("is-active", link.hash === "#" + entry.target.id);
        });
      });
    }, { rootMargin: "-80px 0px -70% 0px" });
    headings.forEach(function (heading) { spy.observe(heading); });
  }
})();
