/* The River site: language toggle (ES/EN), hero terminal animation, footer clock,
   demo videos that play only while visible (never with reduced motion).
   No network calls, no tracking. Everything degrades to static Spanish content. */
(function () {
  "use strict";
  var KEY = "the-river-lang";
  var root = document.documentElement;

  function stored() {
    try { return window.localStorage.getItem(KEY); } catch (e) { return null; }
  }
  function store(lang) {
    try { window.localStorage.setItem(KEY, lang); } catch (e) { /* private mode etc. */ }
  }

  function applyLang(lang) {
    if (lang !== "en") lang = "es";
    root.lang = lang;
    var t = root.getAttribute("data-title-" + lang);
    if (t) document.title = t;
    var btns = document.querySelectorAll("[data-lang-toggle]");
    for (var i = 0; i < btns.length; i++) {
      // Mirrors the client: the button shows the language you switch TO.
      btns[i].textContent = lang === "es" ? "EN" : "ES";
      btns[i].setAttribute("aria-label", lang === "es" ? "Switch to English" : "Cambiar a español");
      btns[i].setAttribute("lang", lang === "es" ? "en" : "es");
    }
    document.dispatchEvent(new CustomEvent("river:lang", { detail: lang }));
  }

  // Apply as early as possible (script is loaded in <head>) to avoid a flash.
  var initial = stored();
  if (initial === "en" || initial === "es") root.lang = initial;

  var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function pad(n) { return (n < 10 ? "0" : "") + n; }
  var DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  function tickClocks() {
    var d = new Date();
    var dt = DAYS[d.getDay()] + " " + MONTHS[d.getMonth()] + " " + pad(d.getDate());
    var hms = pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
    var els = document.querySelectorAll("[data-clock]");
    for (var i = 0; i < els.length; i++) {
      var ye = els[i].querySelector(".ye"), cy = els[i].querySelector(".cy");
      if (ye) ye.textContent = dt;
      if (cy) cy.textContent = " " + hms;
    }
  }

  function initTerminal() {
    var term = document.querySelector("[data-term]");
    if (!term || reduceMotion) return;
    var lines = term.querySelectorAll(".term-feed p");
    var input = term.querySelector("[data-term-typed]");
    if (!lines.length || !input) return;
    term.classList.add("anim");

    var timers = [];
    function later(fn, ms) { timers.push(window.setTimeout(fn, ms)); }
    function clearTimers() { while (timers.length) window.clearTimeout(timers.pop()); }

    function run() {
      clearTimers();
      input.textContent = "";
      var i, idx = 0, t = 300;
      for (i = 0; i < lines.length; i++) lines[i].classList.remove("on");
      function step() {
        if (idx >= lines.length) { later(run, 6000); return; }
        var line = lines[idx++];
        var text = line.getAttribute("data-type-" + root.lang) || line.getAttribute("data-type");
        if (text) {
          var c = 0;
          (function typeChar() {
            input.textContent = text.slice(0, c);
            if (c++ < text.length) { later(typeChar, 55 + Math.random() * 60); return; }
            later(function () { input.textContent = ""; line.classList.add("on"); later(step, 700); }, 450);
          })();
        } else {
          line.classList.add("on");
          later(step, line.hasAttribute("data-history") ? 220 : 1300);
        }
      }
      later(step, t);
    }
    document.addEventListener("river:lang", run);
    run();
  }


  // Real demo recordings (video[data-demo]): muted loops that play only while
  // on screen. With prefers-reduced-motion (or no IntersectionObserver) they
  // never autoplay: the poster stays and the native controls start them.
  function initDemoVideos() {
    var vids = document.querySelectorAll("video[data-demo]");
    if (!vids.length) return;
    var i;
    for (i = 0; i < vids.length; i++) vids[i].controls = true;
    if (reduceMotion || !("IntersectionObserver" in window)) return;
    var io = new IntersectionObserver(function (entries) {
      for (var j = 0; j < entries.length; j++) {
        var v = entries[j].target;
        if (entries[j].isIntersecting && entries[j].intersectionRatio >= 0.5) {
          if (v.dataset.userPaused === "1") continue;
          var p = v.play();
          if (p && p.catch) p.catch(function () { /* autoplay refused: poster + controls remain */ });
        } else if (!v.paused) {
          v.dataset.autoPause = "1";
          v.pause();
        }
      }
    }, { threshold: [0, 0.5] });
    for (i = 0; i < vids.length; i++) {
      (function (v) {
        // Respect a pause the user makes with the controls; resume autoplay once they press play.
        v.addEventListener("pause", function () {
          if (v.dataset.autoPause === "1") { v.dataset.autoPause = ""; return; }
          v.dataset.userPaused = "1";
        });
        v.addEventListener("play", function () { v.dataset.userPaused = ""; });
        io.observe(v);
      })(vids[i]);
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    applyLang(root.lang);
    var btns = document.querySelectorAll("[data-lang-toggle]");
    for (var i = 0; i < btns.length; i++) {
      btns[i].addEventListener("click", function () {
        var next = root.lang === "es" ? "en" : "es";
        store(next);
        applyLang(next);
      });
    }
    tickClocks();
    window.setInterval(tickClocks, 1000);
    initTerminal();
    initDemoVideos();
  });
})();
