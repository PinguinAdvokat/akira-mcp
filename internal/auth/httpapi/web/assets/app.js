// Akira — встроенный фронтенд auth-сервиса. Одностраничное
// приложение без сборки: маршрутизация по location.hash,
// OAuth-экран для MCP-хостов (без хеша, с query-параметрами),
// работа с API auth-сервиса (JSON), хранение токенов в
// localStorage. Комментарии и интерфейс — на русском.
//
// Безопасность: все пользовательские данные (имена, email, коды,
// URL) вставляются в DOM только через textContent/value, никогда
// через innerHTML — фронтенд работает с чужими (для него) данными
// MCP-клиентов и ответами API.
"use strict";

(function () {
  // ── токены ────────────────────────────────────────────────
  // Пара токенов живёт в localStorage. XSS-поверхности нет
  // (никакого innerHTML с данными, CSP-заголовок отдаёт web.go).

  var TOKEN_KEY = "akira.tokens.v1";

  function loadTokens() {
    try {
      var raw = window.localStorage.getItem(TOKEN_KEY);
      if (!raw) return null;
      var t = JSON.parse(raw);
      if (!t || typeof t.access_token !== "string" || typeof t.refresh_token !== "string") {
        return null;
      }
      return t;
    } catch (e) {
      return null;
    }
  }

  function saveTokens(pair) {
    window.localStorage.setItem(TOKEN_KEY, JSON.stringify(pair));
  }

  function clearTokens() {
    window.localStorage.removeItem(TOKEN_KEY);
  }

  // Приблизительный остаток жизни access-токена (JWT, без
  // проверки подписи — это лишь эвристика для проактивного
  // обновления; авторитет — ответ сервера).
  function accessLeftMs(pair) {
    try {
      var payload = JSON.parse(atobUrl(pair.access_token.split(".")[1]));
      if (typeof payload.exp !== "number") return 0;
      return payload.exp * 1000 - Date.now();
    } catch (e) {
      return 0;
    }
  }

  function atobUrl(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    return atob(s);
  }

  // ── API-клиент ────────────────────────────────────────────
  // Единая точка для запросов к auth-сервису. Относительные пути —
  // фронтенд раздаётся тем же сервисом, что и API (за nginx
  // маршрутизация по пути сохраняется). При 401 c валидным
  // refresh-токеном — одна попытка обновления и повтор запроса.

  var refreshing = null; // singleton-промис: параллельные 401 ждут одну ротацию

  function refreshTokens() {
    if (refreshing) return refreshing;
    var pair = loadTokens();
    if (!pair) return Promise.reject(new Error("no tokens"));
    refreshing = api("/token", {
      method: "POST",
      auth: false,
      body: { grant_type: "refresh_token", refresh_token: pair.refresh_token },
      _skipRefresh: true,
    })
      .then(function (resp) {
        saveTokens(resp);
        return resp;
      })
      .catch(function (err) {
        // Ротация не удалась: старая пара больше не считается
        // действительной — разлогиниваем.
        clearTokens();
        throw err;
      })
      .then(
        function (r) {
          refreshing = null;
          return r;
        },
        function (e) {
          refreshing = null;
          throw e;
        }
      );
    return refreshing;
  }

  /**
   * api(path, opts) → Promise<any>
   * opts: method (по умолчанию GET), body (объект — JSON),
   * auth (Bearer-токен из хранилища), _skipRefresh (внутренний).
   * Ошибки: Error с полями status, code, description.
   */
  function api(path, opts) {
    opts = opts || {};
    var init = {
      method: opts.method || "GET",
      headers: {},
    };
    if (opts.body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opts.body);
    }
    var pair = loadTokens();
    if (opts.auth !== false && pair) {
      init.headers["Authorization"] = "Bearer " + pair.access_token;
    }

    return fetch(path, init).then(function (resp) {
      if (resp.status === 204) return null;
      return resp
        .json()
        .catch(function () { return {}; })
        .then(function (body) {
          if (!resp.ok) {
            var err = new Error(body.error_description || body.error || "HTTP " + resp.status);
            err.status = resp.status;
            err.code = body.error || "";
            err.body = body;
            throw err;
          }
          return body;
        });
    }).catch(function (err) {
      // Сетевой уровень (fetch упал) — понятное сообщение.
      if (err instanceof TypeError) {
        throw new Error("Нет соединения с сервером");
      }
      throw err;
    });
  }

  // request — запрос с авторизацией и авто-refresh на 401.
  function request(path, opts) {
    opts = opts || {};
    return api(path, opts).catch(function (err) {
      if (err.status === 401 && !opts._skipRefresh && loadTokens()) {
        return refreshTokens().then(function () {
          return api(path, opts);
        });
      }
      throw err;
    });
  }

  // ── утилиты ───────────────────────────────────────────────

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(sel));
  }

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (k === "class") node.className = attrs[k];
        else if (k === "text") node.textContent = attrs[k];
        else if (k.slice(0, 2) === "on") node.addEventListener(k.slice(2), attrs[k]);
        else node.setAttribute(k, attrs[k]);
      });
    }
    (children || []).forEach(function (c) {
      if (c == null) return;
      node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return node;
  }

  var toastBox = null;
  function toast(msg, kind) {
    if (!toastBox) toastBox = $("#toasts");
    var t = el("div", { class: "toast" + (kind ? " toast-" + kind : ""), text: msg });
    toastBox.appendChild(t);
    setTimeout(function () {
      t.style.opacity = "0";
      t.style.transition = "opacity .3s";
      setTimeout(function () { t.remove(); }, 350);
    }, 3400);
  }

  // Копирование в буфер с тостом; ввод вручную — надёжнее
  // (navigator.clipboard требует HTTPS или localhost).
  function copyText(text, okMsg) {
    function done() { toast(okMsg || "Скопировано", "ok"); }
    function fail() {
      // Fallback: показать текст в подсказке, чтобы скопировать руками.
      toast("Не удалось скопировать — выделите текст вручную", "error");
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, fail);
    } else {
      // execCommand deprecated, но работает на http-хостах.
      // Стиль — через CSSOM (.style.x), а не атрибут: CSP
      // style-src 'self' без 'unsafe-inline' режет style-атрибуты.
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        var ok = document.execCommand("copy");
        ta.remove();
        if (ok) done(); else fail();
      } catch (e) { fail(); }
    }
  }

  function fmtDate(ts) {
    if (!ts) return "—";
    var d = new Date(ts);
    return d.toLocaleDateString("ru-RU", { day: "numeric", month: "short", year: "numeric" });
  }

  // Публичный адрес этого сервиса: origin без пути и hash.
  // Для команд копирования (MCP URL и т.п.).
  function publicOrigin() {
    return window.location.origin;
  }

  // ── каркас ────────────────────────────────────────────────

  var appRoot = null;

  function brandSVG(size) {
    size = size || 26;
    var wrap = el("span");
    wrap.innerHTML =
      '<svg width="' + size + '" height="' + size + '" viewBox="0 0 64 64" aria-hidden="true">' +
      '<defs><linearGradient id="g' + size + '" x1="0" y1="0" x2="1" y2="1">' +
      '<stop offset="0" stop-color="#7c5cff"/><stop offset="1" stop-color="#4cc2ff"/>' +
      "</linearGradient></defs>" +
      '<rect width="64" height="64" rx="14" fill="#10131c"/>' +
      '<path d="M32 12c-9 0-15 6.5-15 15v25l5-4 5 4 5-4 5 4 5-4 5 4V27c0-8.5-6-15-15-15z" fill="url(#g' + size + ')"/>' +
      '<circle cx="26" cy="27" r="3" fill="#10131c"/>' +
      '<circle cx="38" cy="27" r="3" fill="#10131c"/></svg>';
    return wrap.firstChild;
  }

  // topbar: бренд слева; справа — пользователь (или кнопка входа).
  function topbar(account) {
    var inner = el("div", { class: "topbar-inner wrap" });
    var brand = el("div", { class: "brand" });
    brand.appendChild(brandSVG());
    brand.appendChild(el("span", { text: "Akira" }));
    brand.appendChild(el("span", { class: "beta", text: "mcp" }));
    brand.addEventListener("click", function () {
      if (loadTokens()) location.hash = "#/dashboard";
      else location.hash = "#/login";
    });
    inner.appendChild(brand);
    inner.appendChild(el("div", { class: "spacer" }));

    if (account) {
      var chip = el("div", { class: "user-chip" });
      var avatar = el("div", { class: "avatar", text: (account.username || "?").slice(0, 1).toUpperCase() });
      var name = el("span", { text: account.username });
      var logout = el("button", {
        class: "btn btn-ghost btn-sm",
        text: "Выйти",
        onclick: function (ev) { ev.preventDefault(); logoutFlow(); },
      });
      chip.appendChild(avatar);
      chip.appendChild(name);
      chip.appendChild(logout);
      inner.appendChild(chip);
    }
    var bar = el("div", { class: "topbar" });
    bar.appendChild(inner);
    return bar;
  }

  function logoutFlow() {
    var pair = loadTokens();
    clearTokens();
    if (pair && pair.refresh_token) {
      // revoke — идемпотентен; ошибки (сеть, уже отозван) молчим.
      api("/revoke", {
        method: "POST",
        auth: false,
        body: { refresh_token: pair.refresh_token },
      }).catch(function () {});
    }
    location.hash = "#/login";
    toast("Вы вышли из аккаунта", "ok");
  }

  // spinner-экран при загрузке.
  function renderLoading() {
    setScreen(el("div", { class: "spinner", role: "status", "aria-label": "Загрузка" }));
  }

  function setScreen(node) {
    appRoot.replaceChildren(node);
  }

  // wrapScreen — топбар + содержимое в общий контейнер.
  function wrapScreen(account, content) {
    var wrap = el("div");
    wrap.appendChild(topbar(account));
    var main = el("div", { class: "wrap" });
    main.appendChild(content);
    wrap.appendChild(main);
    setScreen(wrap);
  }

  // ── маршрутизация ─────────────────────────────────────────
  // Хеш-маршруты для обычных страниц; OAuth-экран включается,
  // когда есть query-параметры авторизации (MCP-хост открыл
  // /authorize → сюда) и нет явного хеш-маршрута. Возврат из
  // OAuth-формы — через history.back() к redirect_uri либо ссылка.

  var currentRoute = null;

  function route() {
    var hash = location.hash;
    var query = new URLSearchParams(location.search);

    // OAuth-режим: query содержит response_type/client_id (пришёл
    // из /authorize), хеш-навигации нет.
    if (!hash && query.get("response_type")) {
      currentRoute = "oauth";
      renderOAuth(query);
      return;
    }

    var m = hash.match(/^#\/([a-z-]*)/);
    var name = m ? m[1] : "";
    if (currentRoute === "oauth" && name === "" && !query.get("response_type")) {
      // hash убрали (OAuth завершился) — на главную.
      name = "login";
    }
    currentRoute = name || "root";

    switch (name) {
      case "login": currentRoute = "login"; renderLogin(); break;
      case "register": currentRoute = "register"; renderRegister(); break;
      case "verify": currentRoute = "verify"; renderVerify(); break;
      case "dashboard": currentRoute = "dashboard"; renderDashboard(); break;
      case "logout": logoutFlow(); break;
      default:
        // Корень: авторизован → дашборд, иначе → вход.
        if (loadTokens()) { currentRoute = "dashboard"; renderDashboard(); }
        else { currentRoute = "login"; renderLogin(); }
    }
  }

  // ── экран: вход ───────────────────────────────────────────

  function renderLogin(prefill) {
    if (loadTokens()) { location.hash = "#/dashboard"; return; }

    var card = el("div", { class: "card auth-card" });
    card.appendChild(el("h1", { text: "Вход" }));
    card.appendChild(el("p", { class: "sub", text: "Войдите в аккаунт Akira" }));

    var alertBox = null;

    var fUser = field("Логин или email", "text", "username", {
      autocomplete: "username",
      value: prefill && prefill.username ? prefill.username : "",
    });
    var fPass = field("Пароль", "password", "password", { autocomplete: "current-password" });
    var submit = el("button", { class: "btn block", type: "submit", text: "Войти" });

    var form = el("form", {
      onsubmit: function (ev) {
        ev.preventDefault();
        if (alertBox) alertBox.remove();
        submit.disabled = true;
        submit.textContent = "Входим…";
        api("/token", {
          method: "POST",
          auth: false,
          body: {
            grant_type: "password",
            username: fUser.input.value.trim(),
            password: fPass.input.value,
          },
        })
          .then(function (pair) {
            saveTokens(pair);
            toast("Добро пожаловать!", "ok");
            location.hash = "#/dashboard";
          })
          .catch(function (err) {
            alertBox = alertNode(err.code === "invalid_grant"
              ? "Неверный логин или пароль"
              : err.message, "error");
            card.insertBefore(alertBox, form);
            submit.disabled = false;
            submit.textContent = "Войти";
          });
      },
    });
    form.appendChild(fUser.node);
    form.appendChild(fPass.node);
    form.appendChild(submit);
    card.appendChild(form);

    card.appendChild(el("div", {
      class: "switch-link",
    }, [
      "Нет аккаунта? ",
      el("a", {
        text: "Зарегистрироваться",
        onclick: function (ev) { ev.preventDefault(); location.hash = "#/register"; },
        href: "#/register",
      }),
    ]));

    wrapScreen(null, card);
    fUser.input.focus();
  }

  // ── экран: регистрация ────────────────────────────────────

  function renderRegister() {
    if (loadTokens()) { location.hash = "#/dashboard"; return; }

    var card = el("div", { class: "card auth-card" });
    card.appendChild(el("h1", { text: "Регистрация" }));
    card.appendChild(el("p", { class: "sub", text: "Создайте аккаунт — код подтверждения придёт на email" }));

    var alertBox = null;
    var fUser = field("Логин", "text", "username", { autocomplete: "username" });
    var fMail = field("Email", "email", "email", { autocomplete: "email" });
    var fPass = field("Пароль", "password", "new-password", {
      autocomplete: "new-password",
      hint: "Минимум 8 символов",
    });

    var submit = el("button", { class: "btn block", type: "submit", text: "Зарегистрироваться" });

    var form = el("form", {
      onsubmit: function (ev) {
        ev.preventDefault();
        if (alertBox) alertBox.remove();
        var email = fMail.input.value.trim();
        var pass = fPass.input.value;
        if (pass.length < 8) {
          alertBox = alertNode("Пароль должен быть не короче 8 символов", "error");
          card.insertBefore(alertBox, form);
          return;
        }
        submit.disabled = true;
        submit.textContent = "Отправляем код…";
        api("/register", {
          method: "POST",
          auth: false,
          body: {
            username: fUser.input.value.trim(),
            email: email,
            password: pass,
          },
        })
          .then(function () {
            toast("Код подтверждения отправлен на " + email, "ok");
            location.hash = "#/verify";
            renderVerify({ email: email });
          })
          .catch(function (err) {
            var msg = err.message;
            if (err.code === "user_exists") msg = "Такой логин уже занят";
            else if (err.code === "email_exists") msg = "Этот email уже зарегистрирован";
            alertBox = alertNode(msg, "error");
            card.insertBefore(alertBox, form);
            submit.disabled = false;
            submit.textContent = "Зарегистрироваться";
          });
      },
    });
    form.appendChild(fUser.node);
    form.appendChild(fMail.node);
    form.appendChild(fPass.node);
    form.appendChild(submit);
    card.appendChild(form);

    card.appendChild(el("div", { class: "switch-link" }, [
      "Уже есть аккаунт? ",
      el("a", {
        text: "Войти",
        href: "#/login",
        onclick: function (ev) { ev.preventDefault(); location.hash = "#/login"; },
      }),
    ]));

    wrapScreen(null, card);
    fUser.input.focus();
  }

  // ── экран: подтверждение email ────────────────────────────

  function renderVerify(prefill) {
    if (loadTokens()) { location.hash = "#/dashboard"; return; }

    var email = (prefill && prefill.email) || sessionStorageGet("akira.verify.email") || "";
    var card = el("div", { class: "card auth-card" });
    card.appendChild(el("h1", { text: "Подтверждение email" }));
    card.appendChild(el("p", {
      class: "sub",
      text: email
        ? "Введите код из письма, отправленного на " + email
        : "Введите email и код из письма",
    }));

    var alertBox = null;
    var fMail = field("Email", "email", "email", { value: email, autocomplete: "email" });
    if (email) fMail.input.readOnly = true;

    // 6 отдельных ячеек для кода.
    var codeWrap = el("div", { class: "code-input" });
    var inputs = [];
    for (var i = 0; i < 6; i++) {
      (function (idx) {
        var inp = el("input", {
          type: "text",
          inputmode: "numeric",
          maxlength: "1",
          autocomplete: idx === 0 ? "one-time-code" : "off",
          "aria-label": "Цифра " + (idx + 1),
        });
        inp.addEventListener("input", function () {
          inp.value = inp.value.replace(/\D/g, "").slice(0, 1);
          inp.classList.toggle("filled", !!inp.value);
          if (inp.value && idx < 5) inputs[idx + 1].focus();
          checkAndSubmit();
        });
        inp.addEventListener("keydown", function (ev) {
          if (ev.key === "Backspace" && !inp.value && idx > 0) {
            inputs[idx - 1].focus();
          }
        });
        inp.addEventListener("paste", function (ev) {
          ev.preventDefault();
          var text = (ev.clipboardData || window.clipboardData).getData("text") || "";
          var digits = text.replace(/\D/g, "").slice(0, 6);
          digits.split("").forEach(function (d, j) {
            if (inputs[j]) {
              inputs[j].value = d;
              inputs[j].classList.add("filled");
            }
          });
          var next = inputs[Math.min(digits.length, 5)];
          if (next) next.focus();
          checkAndSubmit();
        });
        inputs.push(inp);
        codeWrap.appendChild(inp);
      })(i);
    }

    var submit = el("button", { class: "btn block", type: "submit", text: "Подтвердить" });

    function codeValue() {
      return inputs.map(function (i) { return i.value; }).join("");
    }

    function checkAndSubmit() {
      if (codeValue().length === 6) doVerify();
    }

    function doVerify() {
      if (alertBox) alertBox.remove();
      submit.disabled = true;
      submit.textContent = "Проверяем…";
      api("/verify", {
        method: "POST",
        auth: false,
        body: { email: fMail.input.value.trim(), code: codeValue() },
      })
        .then(function (pair) {
          sessionStorageRemove("akira.verify.email");
          saveTokens(pair);
          toast("Email подтверждён — добро пожаловать!", "ok");
          location.hash = "#/dashboard";
        })
        .catch(function (err) {
          var msg = err.code === "invalid_code"
            ? "Неверный или истёкший код"
            : err.message;
          alertBox = alertNode(msg, "error");
          card.insertBefore(alertBox, form);
          submit.disabled = false;
          submit.textContent = "Подтвердить";
          inputs.forEach(function (i) { i.value = ""; i.classList.remove("filled"); });
          if (inputs[0]) inputs[0].focus();
        });
    }

    var form = el("form", {
      onsubmit: function (ev) {
        ev.preventDefault();
        if (codeValue().length === 6) doVerify();
      },
    });
    form.appendChild(fMail.node);
    var codeField = el("div", { class: "field" });
    codeField.appendChild(el("label", { text: "Код из письма" }));
    codeField.appendChild(codeWrap);
    form.appendChild(codeField);
    form.appendChild(submit);
    card.appendChild(form);

    // Повторная отправка кода — с защитой от спама (60с).
    var resendState = { left: 0, timer: null };
    var resendBtn = el("button", { class: "btn btn-ghost btn-sm", text: "Отправить код заново" });
    resendBtn.addEventListener("click", function () {
      if (resendState.left > 0) return;
      api("/verify/resend", { method: "POST", auth: false, body: { email: fMail.input.value.trim() } })
        .then(function () {
          toast("Новый код отправлен (если email не подтверждён)", "ok");
          startResendCooldown();
        })
        .catch(function (err) { toast(err.message, "error"); });
    });
    function startResendCooldown() {
      resendState.left = 60;
      resendBtn.disabled = true;
      resendState.timer = setInterval(function () {
        resendState.left--;
        resendBtn.textContent = "Повторно через " + resendState.left + " с";
        if (resendState.left <= 0) {
          clearInterval(resendState.timer);
          resendBtn.disabled = false;
          resendBtn.textContent = "Отправить код заново";
        }
      }, 1000);
    }

    var resendRow = el("div", { class: "switch-link" });
    resendRow.appendChild(resendBtn);
    card.appendChild(resendRow);

    if (email) sessionStorageSet("akira.verify.email", email);

    wrapScreen(null, card);
    if (inputs[0]) inputs[0].focus();
  }

  // ── экран: дашборд ────────────────────────────────────────

  function renderDashboard() {
    if (!loadTokens()) { location.hash = "#/login"; return; }
    renderLoading(); // под topbar будет заменено ниже

    request("/me", {})
      .then(function (me) {
        drawDashboard(me);
      })
      .catch(function (err) {
        if (err.status === 401) {
          // refresh уже пробовали (request) — токены сброшены.
          location.hash = "#/login";
          return;
        }
        wrapScreen(null, el("div", { class: "card auth-card center-screen" }, [
          el("h1", { text: "Не удалось загрузить аккаунт" }),
          el("p", { class: "sub", text: err.message }),
          el("button", {
            class: "btn",
            text: "Повторить",
            onclick: function () { renderDashboard(); },
          }),
        ]));
      });
  }

  function drawDashboard(me) {
    var page = el("div", { class: "page" });

    var head = el("div", { class: "page-head" });
    head.appendChild(el("h2", { text: "Ваш аккаунт" }));
    page.appendChild(head);

    var grid = el("div", { class: "grid" });

    // ── панель: аккаунт и connect_key ──
    var accPanel = el("div", { class: "panel" });
    accPanel.appendChild(el("h3", { text: "Аккаунт" }));
    accPanel.appendChild(el("p", { class: "panel-sub", text: "Данные пользователя и ключ подключения машин" }));

    var kv = el("dl", { class: "kv" });
    kv.appendChild(el("dt", { text: "Логин" }));
    kv.appendChild(el("dd", {}, [el("span", { text: me.username })]));
    kv.appendChild(el("dt", { text: "Email" }));
    kv.appendChild(el("dd", {}, [
      el("span", { text: me.email }),
      me.verified
        ? el("span", { class: "badge badge-ok", text: "подтверждён" })
        : el("span", { class: "badge badge-warn", text: "не подтверждён" }),
    ]));

    // connect_key с кнопкой показать/скрыть, копированием и регенерацией.
    kv.appendChild(el("dt", { text: "connect_key" }));
    var keyVisible = false;
    var keyText = el("span", { class: "key-value", text: "••••••••••" });
    var eyeBtn = el("button", { class: "icon-btn", title: "Показать ключ" });
    eyeBtn.innerHTML =
      '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
    var copyKeyBtn = el("button", { class: "icon-btn", title: "Скопировать ключ" });
    copyKeyBtn.innerHTML =
      '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
    copyKeyBtn.addEventListener("click", function () {
      copyText(me.connect_key || "", "Ключ скопирован");
    });
    eyeBtn.addEventListener("click", function () {
      keyVisible = !keyVisible;
      keyText.textContent = keyVisible ? (me.connect_key || "—") : "••••••••••";
      eyeBtn.style.opacity = keyVisible ? "1" : "";
    });
    kv.appendChild(el("dd", {}, [keyText, eyeBtn, copyKeyBtn]));
    accPanel.appendChild(kv);

    var regenBtn = el("button", { class: "btn btn-danger btn-sm", text: "Перегенерировать ключ" });
    regenBtn.addEventListener("click", function () {
      if (!window.confirm(
        "Сгенерировать новый connect_key? Подключённые машины продолжат работать, " +
        "но после разрыва соединения им понадобится новый ключ."
      )) return;
      regenBtn.disabled = true;
      request("/connect-key/regenerate", { method: "POST" })
        .then(function (resp) {
          me.connect_key = resp.connect_key;
          keyText.textContent = keyVisible ? me.connect_key : "••••••••••";
          toast("Новый ключ сгенерирован", "ok");
          regenBtn.disabled = false;
        })
        .catch(function (err) { toast(err.message, "error"); regenBtn.disabled = false; });
    });
    var regenRow = el("div", { class: "mt-16" });
    regenRow.appendChild(regenBtn);
    accPanel.appendChild(regenRow);

    // Подсказка про ключ.
    accPanel.appendChild(el("p", {
      class: "faint",
      text: "connect_key используется akira-client для подключения машины к вашему аккаунту.",
    }));

    grid.appendChild(accPanel);

    // ── панель: подключение MCP-хостов и машин ──
    grid.appendChild(mcpPanel(me));

    page.appendChild(grid);
    wrapScreen(me, page);
  }

  function mcpPanel(me) {
    var panel = el("div", { class: "panel" });
    panel.appendChild(el("h3", { text: "Подключение" }));
    panel.appendChild(el("p", {
      class: "panel-sub",
      text: "MCP-хосты (Claude, IDE, любые MCP-клиенты) и ваши машины",
    }));

    var steps = el("ol", { class: "steps" });

    // Шаг 1: добавить MCP-сервер в хост.
    var li1 = el("li", { class: "done" });
    li1.appendChild(el("h4", { text: "MCP-сервер уже работает" }));
    li1.appendChild(el("p", {
      text: "Укажите этот URL в настройках вашего MCP-хоста. Авторизация откроется здесь же.",
    }));
    li1.appendChild(copyRow(publicOrigin() + "/mcp", "MCP URL"));
    steps.appendChild(li1);

    // Шаг 2: подключить машину.
    var li2 = el("li");
    li2.appendChild(el("h4", { text: "Подключите машину" }));
    li2.appendChild(el("p", {
      text: "Запустите akira-client на вашей машине с вашим connect_key:",
    }));

    var clientCmd = "go run github.com/PinguinAdvokat/akira-mcp/cmd/akira-client@latest \\\n" +
      "  -server " + publicOrigin().replace(/^https?:\/\//, "") + " \\\n" +
      "  -client-id my-machine \\\n" +
      "  -connect-key <ваш_connect_key>";
    li2.appendChild(copyRow(clientCmd, "команда akira-client", true));
    li2.appendChild(el("p", {
      class: "faint",
      text: "client-id — произвольное имя машины (латиницей, без «:»); -server — адрес этого Akira (порт 80/443 через nginx).",
    }));
    steps.appendChild(li2);

    // Шаг 3: готово.
    var li3 = el("li");
    li3.appendChild(el("h4", { text: "Готово" }));
    li3.appendChild(el("p", {
      text: "После подключения машины доступны хосту через инструменты exec, read_file и write_file. Перечень машин — ресурс akira://machines.",
    }));
    steps.appendChild(li3);

    panel.appendChild(steps);
    return panel;
  }

  function copyRow(text, label, multiline) {
    var row = el("div", { class: "copy-row" });
    var line = el("code", { class: "copy-line", text: text });
    if (multiline) line.style.whiteSpace = "pre";
    line.title = "Нажмите, чтобы скопировать";
    line.addEventListener("click", function () { copyText(text, label + " скопирован"); });
    row.appendChild(line);
    var btn = el("button", { class: "icon-btn", title: "Скопировать " + label });
    btn.innerHTML =
      '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
    btn.addEventListener("click", function () { copyText(text, label + " скопирован"); });
    row.appendChild(btn);
    return row;
  }

  // ── экран: авторизация MCP-хоста (OAuth) ──────────────────
  // Сюда попадает пользователь, которого MCP-хост привёл с
  // /authorize. Форма логина + передача OAuth-параметров в
  // /authorize/confirm. После confirm — переход по location
  // (redirect_uri с кодом): обычно loopback-адрес хоста, который
  // пользователь открыл в браузере; если страница не открывается —
  // ссылка для перехода вручную.

  function renderOAuth(query) {
    // Параметры передаются наизнанку в /authorize/confirm.
    var oauth = {
      response_type: query.get("response_type") || "",
      client_id: query.get("client_id") || "",
      redirect_uri: query.get("redirect_uri") || "",
      scope: query.get("scope") || "",
      state: query.get("state") || "",
      code_challenge: query.get("code_challenge") || "",
      code_challenge_method: query.get("code_challenge_method") || "",
    };

    var card = el("div", { class: "card auth-card" });

    // Бейдж: что авторизуется и куда вернётся MCP-хост
    // (origin из redirect_uri — обычно loopback-адрес хоста).
    var badgeText = "Вход для MCP-клиента";
    try {
      var rOrigin = new URL(oauth.redirect_uri).origin;
      if (rOrigin && rOrigin !== "null") {
        badgeText += " · возврат на " + rOrigin;
      }
    } catch (e) { /* redirect_uri уже провалидирован сервисом */ }
    var badge = el("div", { class: "oauth-badge" });
    badge.innerHTML =
      '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#4cc2ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';
    badge.appendChild(el("span", {}, [document.createTextNode(badgeText)]));
    card.appendChild(badge);

    card.appendChild(el("h1", { text: "Разрешить доступ" }));
    card.appendChild(el("p", {
      class: "sub",
      text: "Приложение MCP запрашивает доступ к вашему аккаунту Akira. Войдите, чтобы подтвердить.",
    }));

    var alertBox = null;
    var fUser = field("Логин или email", "text", "username", { autocomplete: "username" });
    var fPass = field("Пароль", "password", "password", { autocomplete: "current-password" });
    var submit = el("button", { class: "btn block", type: "submit", text: "Разрешить" });

    // Если пользователь уже вошел — префилл логина из /me (без
    // авто-логина: подтверждение доступа — осознанное действие,
    // пароль вводится заново).
    if (loadTokens()) {
      request("/me", { auth: true })
        .then(function (me) {
          if (fUser.input && !fUser.input.value) {
            fUser.input.value = me.username;
            fPass.input.focus();
          }
        })
        .catch(function () { /* не критично */ });
    }

    var form = el("form", {
      onsubmit: function (ev) {
        ev.preventDefault();
        if (alertBox) alertBox.remove();
        submit.disabled = true;
        submit.textContent = "Проверяем…";
        api("/authorize/confirm", {
          method: "POST",
          auth: false,
          body: Object.assign(
            {
              username: fUser.input.value.trim(),
              password: fPass.input.value,
            },
            oauth
          ),
        })
          .then(function (resp) {
            // Успех: экран перехода. Автопереход через 1.5с,
            // плюс кнопка/ссылка (loopback-адрес может не открыться сам).
            wrapScreen(null, oauthSuccess(resp.location));
          })
          .catch(function (err) {
            var msg = err.code === "invalid_grant"
              ? "Неверный логин или пароль"
              : err.code === "invalid_client"
                ? "Неизвестный MCP-клиент — начните подключение заново"
                : err.message;
            alertBox = alertNode(msg, "error");
            card.insertBefore(alertBox, form);
            submit.disabled = false;
            submit.textContent = "Разрешить";
          });
      },
    });
    form.appendChild(fUser.node);
    form.appendChild(fPass.node);
    form.appendChild(submit);
    card.appendChild(form);

    card.appendChild(el("p", { class: "faint" }, [
      "Вход выполняется только для этого клиента; код авторизации одноразовый. ",
    ]));

    wrapScreen(null, card);
    fUser.input.focus();
  }

  function oauthSuccess(location) {
    var card = el("div", { class: "card auth-card" });
    card.appendChild(el("h1", { text: "Готово" }));
    card.appendChild(el("p", {
      class: "sub",
      text: "Доступ разрешён. Возвращаемся к MCP-клиенту…",
    }));

    var openBtn = el("button", { class: "btn block", text: "Вернуться к приложению" });
    openBtn.addEventListener("click", function () {
      window.location.href = location;
    });
    card.appendChild(openBtn);

    card.appendChild(el("p", { class: "faint" }, [
      "Если переход не сработал, ",
      el("a", { href: location, text: "откройте ссылку вручную" }),
      ".",
    ]));

    // Автопереход: loopback-redirect обычно ловит сам хост.
    setTimeout(function () {
      window.location.href = location;
    }, 1500);

    return card;
  }

  // ── помощники форм ────────────────────────────────────────

  // field(label, type, name, opts) → {node, input}
  function field(label, type, name, opts) {
    opts = opts || {};
    var wrap = el("div", { class: "field" });
    var id = "f-" + name + "-" + Math.random().toString(36).slice(2, 7);
    wrap.appendChild(el("label", { for: id, text: label }));
    var input = el("input", {
      type: type,
      id: id,
      name: name,
      autocomplete: opts.autocomplete || "off",
      placeholder: opts.placeholder || "",
    });
    if (opts.value) input.value = opts.value;
    if (opts.readOnly) input.readOnly = true;
    if (type === "email" || name === "username") input.autocapitalize = "none";
    if (name === "code") input.classList.add("mono");
    wrap.appendChild(input);
    if (opts.hint) wrap.appendChild(el("div", { class: "hint", text: opts.hint }));
    return { node: wrap, input: input };
  }

  function alertNode(text, kind) {
    return el("div", { class: "alert alert-" + kind, role: "alert", text: text });
  }

  // sessionStorage-обёртки (могут кинуть в приватных режимах).
  function sessionStorageGet(k) {
    try { return window.sessionStorage.getItem(k); } catch (e) { return null; }
  }
  function sessionStorageSet(k, v) {
    try { window.sessionStorage.setItem(k, v); } catch (e) {}
  }
  function sessionStorageRemove(k) {
    try { window.sessionStorage.removeItem(k); } catch (e) {}
  }

  // ── старт ─────────────────────────────────────────────────

  document.addEventListener("DOMContentLoaded", function () {
    appRoot = $("#app");
    window.addEventListener("hashchange", route);
    route();
  });
})();
