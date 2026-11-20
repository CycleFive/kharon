// kharon-teach page listener. Runs at document start in every frame.
//
// It reports what a person did (which element, what kind of event, and the
// text of a text-entry control) through the one binding the recorder added.
// It keeps no state except an element counter, and leaves no global.
(() => {
  "use strict";
  try {
    const BINDING = "__kharonTeach";
    // Replaced by the recorder with a fresh value for each install of this script.
    const NONCE = "__NONCE__";
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

    // Reads go through the prototypes, never through the element: a form's child named
    // "action", "method", "id", "tagName" or "getAttribute" replaces that property on the form.
    const proto = Element.prototype;
    const getAttr = proto.getAttribute;
    const matchesFn = proto.matches;
    const closestFn = proto.closest;
    const getRoot = Node.prototype.getRootNode;
    const getter = (obj, name) => {
      const d = Object.getOwnPropertyDescriptor(obj, name);
      return d && d.get ? d.get : () => undefined;
    };
    const tagGetter = getter(proto, "tagName");
    const formActionGetter = getter(HTMLFormElement.prototype, "action");
    const formMethodGetter = getter(HTMLFormElement.prototype, "method");
    const docFormsGetter = getter(Document.prototype, "forms");
    const attr = (el, name) => getAttr.call(el, name);
    const tagOf = (el) => String(tagGetter.call(el)).toLowerCase();

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
        let part = tagOf(node);
        const parent = node.parentElement;
        if (parent) {
          const same = Array.from(parent.children).filter((c) => tagOf(c) === part);
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

    const textEntry = (el) => {
      const tag = tagOf(el);
      if (tag === "textarea") return true;
      if (tag !== "input") return false;
      return TEXTISH.includes(String(el.type || "text").toLowerCase());
    };

    // What the person has typed into the element now: used to keep it out of the descriptor
    // and the selectors, whether or not this report sends it.
    const typedValue = (el) => {
      try {
        return textEntry(el) ? String(el.value === undefined ? "" : el.value) : "";
      } catch (_) {
        return "";
      }
    };

    // An attribute that holds the typed text (a page that mirrors the field into its own id or
    // name) is not reported and builds no selector.
    const clean = (typed, v) => {
      if (v === null || v === undefined) return null;
      const t = String(v);
      return typed.length > 0 && t.includes(typed) ? null : t;
    };

    const selectorsFor = (el, typed) => {
      const out = [];
      let root = null;
      try {
        root = getRoot.call(el);
      } catch (_) {
        root = document;
      }
      const inShadow = typeof ShadowRoot !== "undefined" && root instanceof ShadowRoot;
      const scope = inShadow ? root : document;
      const add = (s, unique) => {
        if (!s || s.length > MAX_STR || out.includes(s)) return;
        try {
          if (scope.querySelector(s) !== el) return;
          if (unique && scope.querySelectorAll(s).length !== 1) return;
          out.push(s);
        } catch (_) {
          /* an invalid candidate is dropped */
        }
      };
      const tag = tagOf(el);
      const id = clean(typed, attr(el, "id"));
      if (id) add("#" + CSS.escape(id));
      const name = clean(typed, attr(el, "name"));
      if (name) add(tag + '[name="' + attrEscape(name) + '"]');
      const auto = clean(typed, attr(el, "autocomplete"));
      if (auto) add(tag + '[autocomplete="' + attrEscape(auto) + '"]');
      const type = clean(typed, attr(el, "type"));
      if (type) add(tag + '[type="' + attrEscape(type) + '"]', true);
      add(structural(el, scope));
      return { selectors: out.slice(0, MAX_SELECTORS), inShadow };
    };

    const formInfo = (form) => {
      if (!form) return null;
      let index = 0;
      try {
        index = Math.max(0, Array.prototype.indexOf.call(docFormsGetter.call(document), form));
      } catch (_) {
        index = 0;
      }
      let action = null;
      let method = "get";
      try {
        action = cut(formActionGetter.call(form));
        method = String(formMethodGetter.call(form) || "get").toLowerCase();
      } catch (_) {
        /* leave the defaults */
      }
      return { index, action, method };
    };

    const describe = (el) => {
      const tag = tagOf(el);
      const isInput = tag === "input";
      const typed = typedValue(el);
      const sel = selectorsFor(el, typed);
      const form = tag === "form" ? el : el.form || null;
      return {
        element_id: elementId(el),
        tag,
        input_type: isInput ? String(el.type || "text").toLowerCase() : null,
        id: cut(clean(typed, attr(el, "id"))),
        name: cut(clean(typed, attr(el, "name"))),
        autocomplete: cut(clean(typed, attr(el, "autocomplete"))),
        placeholder: cut(clean(typed, attr(el, "placeholder"))),
        aria_label: cut(clean(typed, attr(el, "aria-label"))),
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
        element: describe(el),
      };
      if (value !== null) body.value = value;
      send(body);
    };

    const CLICKABLE = 'button, a, input[type="submit"], input[type="button"], [role="button"]';

    const handlers = {
      input: (e) => {
        const el = originOf(e);
        if (el && matchesFn.call(el, "input, textarea, select")) report("input", el, true);
      },
      change: (e) => {
        const el = originOf(e);
        if (el && matchesFn.call(el, "input, textarea, select")) report("change", el, true);
      },
      click: (e) => {
        const el = originOf(e);
        const hit = el ? closestFn.call(el, CLICKABLE) : null;
        if (hit) report("click", hit, false);
      },
      submit: (e) => {
        const el = originOf(e);
        if (el && tagOf(el) === "form") report("submit", el, false);
      },
      keydown: (e) => {
        if (e.key !== "Enter") return;
        const el = originOf(e);
        if (el && tagOf(el) === "input") report("enter_key", el, false);
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

    if (isTop()) send({ hello: true, nonce: NONCE });
  } catch (_) {
    /* never throw into the page */
  }
})();
