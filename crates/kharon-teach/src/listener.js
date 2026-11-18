// kharon-teach page listener. Runs at document start in every frame.
//
// It reports what a person did (which element, what kind of event, and the
// text of a text-entry control) through the one binding the recorder added.
// It keeps no state except an element counter, and leaves no global.
(() => {
  "use strict";
  try {
    const BINDING = "__kharonTeach";
    const GUARD = Symbol.for("kharon-teach.listener");
    if (Object.prototype.hasOwnProperty.call(document, GUARD)) return;
    Object.defineProperty(document, GUARD, { value: true, enumerable: false });

    const MAX_STR = 2048;
    const MAX_VALUE = 4096;
    const MAX_SELECTORS = 5;
    const TEXTISH = ["text", "email", "password", "tel", "number", "search", "url"];

    const cut = (s) => (s === null || s === undefined ? null : String(s).slice(0, MAX_STR));
    const ids = new WeakMap();
    let counter = 0;
    let documentId = "";
    try {
      const bytes = new Uint8Array(8);
      crypto.getRandomValues(bytes);
      documentId = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    } catch (_) {
      documentId = String(Math.random()).slice(2) + String(Date.now());
    }

    const send = (report) => {
      try {
        const bind = window[BINDING];
        if (typeof bind === "function") bind(JSON.stringify(report));
      } catch (_) {
        /* never throw into the page */
      }
    };

    const isTop = () => {
      try {
        return window.top === window;
      } catch (_) {
        return false;
      }
    };

    const elementId = (el) => {
      let n = ids.get(el);
      if (n === undefined) {
        n = ++counter;
        ids.set(el, n);
      }
      return n;
    };

    const attrEscape = (s) => String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"');

    const structural = (el, scope) => {
      const parts = [];
      let node = el;
      for (let depth = 0; node && node.nodeType === 1 && depth < 6; depth++) {
        const tag = node.tagName.toLowerCase();
        let part = tag;
        const parent = node.parentElement;
        if (parent) {
          const same = Array.from(parent.children).filter((c) => c.tagName === node.tagName);
          if (same.length > 1) part += ":nth-of-type(" + (same.indexOf(node) + 1) + ")";
        }
        parts.unshift(part);
        const candidate = parts.join(" > ");
        try {
          if (scope.querySelector(candidate) === el) return candidate;
        } catch (_) {
          /* try a longer path */
        }
        node = parent;
      }
      return null;
    };

    const selectorsFor = (el, typed) => {
      const out = [];
      let root = null;
      try {
        root = el.getRootNode();
      } catch (_) {
        root = document;
      }
      const inShadow = typeof ShadowRoot !== "undefined" && root instanceof ShadowRoot;
      const scope = inShadow ? root : document;
      const add = (s, unique) => {
        if (!s || s.length > MAX_STR || out.includes(s)) return;
        // A value this short is contained in an ordinary selector by chance.
        if (typed && typed.length >= 3 && s.includes(typed)) return;
        try {
          if (scope.querySelector(s) !== el) return;
          if (unique && scope.querySelectorAll(s).length !== 1) return;
          out.push(s);
        } catch (_) {
          /* an invalid candidate is dropped */
        }
      };
      const tag = el.tagName.toLowerCase();
      if (el.id) add("#" + CSS.escape(el.id));
      const name = el.getAttribute("name");
      if (name) add(tag + '[name="' + attrEscape(name) + '"]');
      const auto = el.getAttribute("autocomplete");
      if (auto) add(tag + '[autocomplete="' + attrEscape(auto) + '"]');
      const type = el.getAttribute("type");
      if (type) add(tag + '[type="' + attrEscape(type) + '"]', true);
      add(structural(el, scope));
      return { selectors: out.slice(0, MAX_SELECTORS), inShadow };
    };

    const formInfo = (form) => {
      if (!form) return null;
      let index = 0;
      try {
        index = Math.max(0, Array.prototype.indexOf.call(document.forms, form));
      } catch (_) {
        index = 0;
      }
      return {
        index,
        action: cut(form.action),
        method: String(form.method || "get").toLowerCase(),
      };
    };

    const textEntry = (el) => {
      const tag = el.tagName.toLowerCase();
      if (tag === "textarea") return true;
      if (tag !== "input") return false;
      const type = String(el.type || "text").toLowerCase();
      return TEXTISH.includes(type);
    };

    const describe = (el, typed) => {
      const tag = el.tagName.toLowerCase();
      const isInput = tag === "input";
      const sel = selectorsFor(el, typed);
      const form = tag === "form" ? el : el.form || null;
      return {
        element_id: elementId(el),
        tag,
        input_type: isInput ? String(el.type || "text").toLowerCase() : null,
        id: cut(el.id || null),
        name: cut(el.getAttribute("name")),
        autocomplete: cut(el.getAttribute("autocomplete")),
        placeholder: cut(el.getAttribute("placeholder")),
        aria_label: cut(el.getAttribute("aria-label")),
        is_password_now: isInput && String(el.type).toLowerCase() === "password",
        form: formInfo(form),
        selectors: sel.selectors,
        in_shadow_root: sel.inShadow,
      };
    };

    const originOf = (e) => {
      let t = null;
      try {
        const path = e.composedPath ? e.composedPath() : [];
        t = path.length > 0 ? path[0] : e.target;
      } catch (_) {
        t = e.target;
      }
      return t && t.nodeType === 1 ? t : null;
    };

    const report = (kind, el, withValue) => {
      let value = null;
      if (withValue && textEntry(el)) {
        const v = String(el.value === undefined ? "" : el.value);
        if (v.length <= MAX_VALUE) value = v;
      }
      const body = {
        kind,
        document_id: documentId,
        frame_url: cut(location.href) || "",
        is_top: isTop(),
        element: describe(el, value),
      };
      if (value !== null) body.value = value;
      send(body);
    };

    const CLICKABLE = 'button, a, input[type="submit"], input[type="button"], [role="button"]';

    const handlers = {
      input: (e) => {
        const el = originOf(e);
        if (el && el.matches("input, textarea, select")) report("input", el, true);
      },
      change: (e) => {
        const el = originOf(e);
        if (el && el.matches("input, textarea, select")) report("change", el, true);
      },
      click: (e) => {
        const el = originOf(e);
        const hit = el && el.closest ? el.closest(CLICKABLE) : null;
        if (hit) report("click", hit, false);
      },
      submit: (e) => {
        const el = originOf(e);
        if (el && el.tagName.toLowerCase() === "form") report("submit", el, false);
      },
      keydown: (e) => {
        if (e.key !== "Enter") return;
        const el = originOf(e);
        if (el && el.tagName.toLowerCase() === "input") report("enter_key", el, false);
      },
    };

    for (const type of Object.keys(handlers)) {
      const fn = handlers[type];
      document.addEventListener(
        type,
        (e) => {
          try {
            fn(e);
          } catch (_) {
            /* never throw into the page */
          }
        },
        true,
      );
    }

    if (isTop()) send({ hello: true });
  } catch (_) {
    /* never throw into the page */
  }
})();
