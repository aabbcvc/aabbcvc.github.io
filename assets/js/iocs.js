(function () {
  "use strict";
  var root = document.getElementById("iocExplorer");
  if (!root) return;
  var list = document.getElementById("iocList");
  var status = document.getElementById("iocStatus");
  var form = document.getElementById("iocFilters");
  var fields = {q: document.getElementById("iocSearch"), type: document.getElementById("iocType"), tag: document.getElementById("iocTag"), source: document.getElementById("iocSource"), classification: document.getElementById("iocClassification")};
  var publications = [], filtered = [], page = 0, pageSize = 40;
  var previous = document.getElementById("iocPrevious"), next = document.getElementById("iocNext");
  var exports = Array.from(root.querySelectorAll("[data-export]"));

  function el(tag, text, className) {
    var node = document.createElement(tag);
    if (text != null) node.textContent = text;
    if (className) node.className = className;
    return node;
  }
  function refang(value) {
    return value.replace(/\[\.\]|\(\.\)/g, ".").replace(/\[:\]/g, ":").replace(/\[@\]/g, "@").replace(/^hxxp/i, "http");
  }
  function externalLink(label, url) {
    var a = el("a", label); a.href = url; a.target = "_blank"; a.rel = "noopener noreferrer"; return a;
  }
  function options(select, values) {
    Array.from(new Set(values)).sort(function (a, b) { return a.localeCompare(b); }).forEach(function (value) {
      var option = el("option", value); option.value = value; select.appendChild(option);
    });
  }
  function lookupLinks(indicator) {
    var value = indicator.value, type = indicator.type, host;
    if (type === "URL" || type === "IP:port") {
      try {
        host = new URL(value.includes("://") ? value : "https://" + value).hostname.replace(/^\[|\]$/g, "");
        value = host;
        type = host.includes(":") ? "IPv6" : /^\d+\.\d+\.\d+\.\d+$/.test(host) ? "IPv4" : "Domain";
      } catch (_) { return []; }
    }
    var encoded = encodeURIComponent(value);
    if (type === "IPv4" || type === "IPv6") return [
      ["VirusTotal", "https://www.virustotal.com/gui/ip-address/" + encoded],
      ["Hunt.io", "https://portal.hunt.io/ip/" + encoded],
      ["AbuseIPDB", "https://www.abuseipdb.com/check/" + encoded]
    ];
    if (type === "Domain") return [
      ["VirusTotal", "https://www.virustotal.com/gui/domain/" + encoded],
      ["Hunt.io", "https://portal.hunt.io/domain/" + encoded]
    ];
    if (["MD5", "SHA1", "SHA256"].includes(type)) return [["VirusTotal", "https://www.virustotal.com/gui/file/" + encoded]];
    return [];
  }
  async function copy(value, button) {
    try {
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(value);
      else {
        var area = el("textarea"); area.value = value; area.className = "copy-buffer"; document.body.appendChild(area); area.select();
        var copied = document.execCommand("copy"); area.remove(); if (!copied) throw new Error("Clipboard unavailable");
      }
      button.textContent = "Copied";
    } catch (_) { button.textContent = "Select to copy"; }
    setTimeout(function () { button.textContent = "Copy"; }, 1800);
  }
  function renderIndicator(indicator) {
    var article = el("article", null, "ioc-row");
    var details = el("details", null, "ioc-detail");
    var summary = el("summary");
    var title = el("span", null, "ioc-summary-title");
    title.append(el("code", indicator.display), el("span", indicator.type, "ioc-type"));
    summary.append(title, el("span", indicator.observations[0].context, "ioc-summary-context"), el("span", indicator.observations.length + " observation" + (indicator.observations.length === 1 ? "" : "s") + " · View context", "ioc-summary-count"));
    details.appendChild(summary);
    var body = el("div", null, "ioc-detail-body");
    var normalized = el("p", null, "ioc-normalized"); normalized.append(el("span", "Refanged value "), el("code", indicator.value)); body.appendChild(normalized);
    indicator.observations.forEach(function (observation) {
      var item = el("section", null, "ioc-observation");
      var source = el("a", observation.title, "ioc-source-link"); source.href = observation.url + "#iocs";
      item.append(source, el("p", "Published " + observation.published + " · " + observation.classification + " · Confidence: " + observation.confidence, "ioc-source-meta"), el("p", observation.context));
      var tags = el("div", null, "publication-tags");
      observation.tags.forEach(function (tag) {
        var button = el("button", tag, "tag"); button.type = "button";
        button.addEventListener("click", function () { fields.tag.value = tag; applyFilters(); }); tags.appendChild(button);
      });
      item.appendChild(tags); body.appendChild(item);
    });
    var permalink = el("a", "Link to this indicator", "ioc-source-link");
    var params = new URLSearchParams({q: indicator.value, type: indicator.type});
    permalink.href = window.location.pathname + "?" + params; body.appendChild(permalink);
    details.appendChild(body); article.appendChild(details);
    var actions = el("div", null, "ioc-actions");
    var copyButton = el("button", "Copy"); copyButton.type = "button"; copyButton.setAttribute("aria-label", "Copy refanged " + indicator.value);
    copyButton.addEventListener("click", function () { copy(indicator.value, copyButton); }); actions.appendChild(copyButton);
    var links = lookupLinks(indicator);
    if (links.length) {
      var lookup = el("details", null, "ioc-lookup");
      var toggle = el("summary", "Look up"); toggle.setAttribute("aria-label", "Look up " + indicator.value); lookup.appendChild(toggle);
      var menu = el("div", null, "ioc-lookup-menu");
      links.forEach(function (link) { menu.appendChild(externalLink(link[0], link[1])); });
      lookup.appendChild(menu); actions.appendChild(lookup);
    }
    article.appendChild(actions);
    if (filtered.length === 1) details.open = true;
    return article;
  }
  function render() {
    list.replaceChildren();
    var total = filtered.reduce(function (n, item) { return n + item.observations.length; }, 0);
    status.textContent = filtered.length + " unique indicators · " + total + " observations";
    if (!filtered.length) list.appendChild(el("p", "No indicators match these filters. Try another search or reset the filters.", "archive-empty"));
    var fragment = document.createDocumentFragment();
    filtered.slice(page * pageSize, (page + 1) * pageSize).forEach(function (indicator) { fragment.appendChild(renderIndicator(indicator)); });
    list.appendChild(fragment);
    exports.forEach(function (button) { button.disabled = !filtered.length; });
    document.getElementById("iocPagination").hidden = filtered.length <= pageSize;
    previous.disabled = page === 0; next.disabled = (page + 1) * pageSize >= filtered.length;
    document.getElementById("iocPage").textContent = "Page " + (page + 1) + " of " + Math.max(1, Math.ceil(filtered.length / pageSize));
  }
  function applyFilters(saveUrl) {
    page = 0;
    var terms = refang(fields.q.value.trim()).toLowerCase().split(/\s+/).filter(Boolean);
    var groups = new Map();
    publications.forEach(function (post) {
      if (fields.source.value && post.url !== fields.source.value) return;
      if (fields.tag.value && !post.tags.includes(fields.tag.value)) return;
      (post.indicators || []).forEach(function (ioc) {
        if (fields.type.value && ioc.type !== fields.type.value) return;
        if (fields.classification.value && ioc.classification !== fields.classification.value) return;
        var haystack = refang([ioc.value, ioc.display, ioc.context, post.title, post.tags.join(" "), ioc.type, ioc.classification].join(" ")).toLowerCase();
        if (!terms.every(function (term) { return haystack.includes(term); })) return;
        var key = ioc.type + "\u0000" + ioc.value;
        if (!groups.has(key)) groups.set(key, {value: ioc.value, display: ioc.display, type: ioc.type, observations: []});
        var observation = {title: post.title, url: post.url, published: post.published, tags: post.tags, context: ioc.context, confidence: ioc.confidence, classification: ioc.classification};
        var observations = groups.get(key).observations;
        if (!observations.some(function (existing) { return JSON.stringify(existing) === JSON.stringify(observation); })) observations.push(observation);
      });
    });
    filtered = Array.from(groups.values()); render();
    if (saveUrl !== false) {
      var params = new URLSearchParams();
      Object.keys(fields).forEach(function (key) { if (fields[key].value) params.set(key, fields[key].value); });
      window.history.replaceState(null, "", window.location.pathname + (params.size ? "?" + params : ""));
    }
  }
  function csvCell(value) {
    value = String(value == null ? "" : value);
    // Quoting alone does not prevent spreadsheet formula interpretation.
    if (/^[\s]*[=+\-@\t\r]/.test(value)) value = "'" + value;
    return '"' + value.replace(/"/g, '""') + '"';
  }
  function download(format) {
    var content, mime;
    if (format === "json") { content = JSON.stringify(filtered, null, 2) + "\n"; mime = "application/json"; }
    if (format === "txt") { content = Array.from(new Set(filtered.map(function (ioc) { return ioc.value; }))).join("\n") + "\n"; mime = "text/plain"; }
    if (format === "csv") {
      var rows = [["indicator", "type", "context", "classification", "confidence", "source_title", "source_url", "published", "tags"]];
      filtered.forEach(function (ioc) { ioc.observations.forEach(function (o) { rows.push([ioc.value, ioc.type, o.context, o.classification, o.confidence, o.title, new URL(o.url + "#iocs", window.location.href).href, o.published, o.tags.join("; ")]); }); });
      content = "\uFEFF" + rows.map(function (row) { return row.map(csvCell).join(","); }).join("\r\n") + "\r\n"; mime = "text/csv";
    }
    var url = URL.createObjectURL(new Blob([content], {type: mime + ";charset=utf-8"}));
    var link = el("a"); link.href = url; link.download = "ctrl-alt-intel-iocs." + format; document.body.appendChild(link); link.click(); link.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }
  form.addEventListener("submit", function (event) { event.preventDefault(); applyFilters(); });
  form.addEventListener("input", function () { applyFilters(); });
  form.addEventListener("reset", function () { setTimeout(function () { applyFilters(); }, 0); });
  previous.addEventListener("click", function () { page--; render(); list.scrollIntoView({block: "start"}); });
  next.addEventListener("click", function () { page++; render(); list.scrollIntoView({block: "start"}); });
  exports.forEach(function (button) { button.addEventListener("click", function () { download(button.dataset.export); }); });
  root.addEventListener("keydown", function (event) {
    if (event.key !== "Escape") return;
    root.querySelectorAll(".ioc-lookup[open]").forEach(function (details) { details.open = false; details.querySelector("summary").focus(); });
  });
  fetch(root.dataset.index).then(function (response) {
    if (!response.ok) throw new Error("Index unavailable"); return response.json();
  }).then(function (data) {
    publications = data.filter(function (post) { return Array.isArray(post.indicators) && post.indicators.length; });
    var indicators = publications.flatMap(function (post) { return post.indicators; });
    options(fields.type, indicators.map(function (ioc) { return ioc.type; }));
    options(fields.tag, publications.flatMap(function (post) { return post.tags; }));
    options(fields.classification, indicators.map(function (ioc) { return ioc.classification; }));
    publications.forEach(function (post) { var option = el("option", post.title); option.value = post.url; fields.source.appendChild(option); });
    var initial = new URLSearchParams(window.location.search);
    Object.keys(fields).forEach(function (key) { if (initial.has(key)) fields[key].value = initial.get(key); });
    applyFilters(false);
  }).catch(function () {
    status.textContent = "The indicator index could not be loaded. Reload this page to try again.";
    var link = el("a", "Open the JSON index", "ioc-source-link"); link.href = root.dataset.index; list.replaceChildren(link);
  });
})();
