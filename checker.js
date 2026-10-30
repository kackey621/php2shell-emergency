// PHP Version Checker（DOMへの書き込みは textContent のみ。文字列をHTMLとして解釈させる書き込みはしない）
"use strict";

const API_ORIGIN = "https://php-api.skslprd.com";
const RECAPTCHA_SITE_KEY = "6LdGZgguAAAAAHBukGCQe8tZTRZgTQIcSvHAUPL_";
const RECAPTCHA_API = "https://www.google.com/recaptcha/api.js?render=explicit&hl=ja&onload=onRecaptchaReady";
const BOOKING_PREFIX = "https://timerex.net/";

// PHP2Shell（CVE-2026-109618 / CVE-2026-109619）の修正済みバージョン
const FIXED = { "8.5": 12, "8.4": 27, "8.3": 36, "8.2": 35 };

function parseVersion(raw) {
  const s = String(raw || "").trim().replace(/^php\s*[\/:]?\s*v?/i, "").replace(/^v/i, "");
  const m = /^(\d{1,2})\.(\d{1,2})(?:\.(\d{1,3}))?(.*)$/.exec(s);
  if (!m) return null;
  return {
    major: Number(m[1]), minor: Number(m[2]),
    patch: m[3] === undefined ? null : Number(m[3]),
    suffix: m[4].trim(),
    text: s.slice(0, 64),
  };
}

// 判定結果: level は danger / warn / safe / unknown
function judge(raw) {
  const v = parseVersion(raw);
  if (!v) {
    return { level: "unknown", badge: "判定できません", title: "バージョン番号として読み取れませんでした", detail: "「8.3.36」のように、数字とピリオドで入力してください。", notes: [] };
  }
  const branch = `${v.major}.${v.minor}`;
  const distro = /ubuntu|deb|el\d|remi|\+|~/i.test(v.suffix);
  const notes = [];
  if (distro) notes.push(`番号の後ろの「${v.suffix}」は、Linuxディストリビューションのパッケージであることを示します。パッケージでは番号を変えずに修正されている場合があるため、パッケージが10月21日以降に更新されているかをご確認ください。`);

  if (v.major < 5 || (v.major === 5 && v.minor < 4)) {
    return { level: "warn", badge: "要確認", version: v.text, title: "今回の脆弱性の対象より古いバージョンです",
      detail: "PHP2ShellはPHP 5.4以降が対象ですが、このバージョンはサポートが終了してから長い年月がたっており、ほかの深刻な脆弱性が多数残っています。早めのバージョンアップをおすすめします。", notes };
  }
  if (v.major === 5 || v.major === 7 || (v.major === 8 && v.minor <= 1)) {
    return { level: "danger", badge: "危険", version: v.text, title: "公式の修正版がないバージョンです",
      detail: `PHP ${branch} はサポートが終了しており、PHPの開発元からは今回の修正版が提供されていません。PHP 8.2以降の修正済みバージョンへのバージョンアップが必要です。`, notes };
  }
  if (v.major === 8 && FIXED[branch] !== undefined) {
    const need = `${branch}.${FIXED[branch]}`;
    if (v.patch === null) {
      return { level: "unknown", badge: "判定できません", version: v.text, title: "細かい番号まで必要です",
        detail: `PHP ${branch} は ${need} 以上なら修正済みです。「${branch}.○○」の○○の部分まで確認してください。`, notes };
    }
    if (v.patch >= FIXED[branch]) {
      notes.push("修正前の期間に攻撃を受けていた場合、更新しただけでは侵入の跡は消えません。不審なファイルや管理者アカウントがないかも確認しておくと安心です。");
      return { level: "safe", badge: "修正済み", version: v.text, title: "PHP2Shellの修正が含まれるバージョンです",
        detail: `PHP ${need} 以上のため、CVE-2026-109618／CVE-2026-109619 は修正されています。`, notes };
    }
    if (distro) {
      return { level: "warn", badge: "要確認", version: v.text, title: "番号上は修正前ですが、パッケージで修正済みの可能性があります",
        detail: `公式版なら ${need} 以上が必要です。ディストリビューションのパッケージは番号が変わらない場合があるため、パッケージの更新状況で判断する必要があります。`, notes };
    }
    return { level: "danger", badge: "危険", version: v.text, title: "修正前のバージョンです",
      detail: `外部からサーバーを操作されるおそれがあります。PHP ${need} 以上への更新が必要です。`, notes };
  }
  return { level: "unknown", badge: "判定できません", version: v.text, title: "判定基準がないバージョンです",
    detail: "今回の修正情報に含まれていないバージョン番号です。番号に誤りがないかご確認ください。", notes };
}

const needsAction = (result) => result.level === "danger" || result.level === "warn";

// ---- Trusted Types: 読み込んでよいスクリプトURLを reCAPTCHA に限定する ----
let scriptPolicy = null;
if (window.trustedTypes && window.trustedTypes.createPolicy) {
  scriptPolicy = window.trustedTypes.createPolicy("checker", {
    createScriptURL: (u) => { if (u === RECAPTCHA_API) return u; throw new TypeError("許可されていないスクリプトです。"); },
  });
  // reCAPTCHA が内部で読み込むスクリプト（gstatic の reCAPTCHA 配下）だけを許可する
  window.trustedTypes.createPolicy("default", {
    createScriptURL: (u) => { if (/^https:\/\/www\.gstatic\.com\/recaptcha\//.test(u)) return u; throw new TypeError("許可されていないスクリプトです。"); },
  });
}

// ---- 表示 ----
const $ = (id) => document.getElementById(id);

// 予約ボタンの表示条件を保持する（reason: "unknown" | "manual"、version: 手入力の値）
let consultContext = null;

function setBooking(url) {
  const link = $("booking-link");
  if (typeof url === "string" && url.startsWith(BOOKING_PREFIX)) {
    link.setAttribute("href", url);
    link.hidden = false;
  } else {
    link.removeAttribute("href");
    link.hidden = true;
  }
}

function show(result, raw, gate) {
  const section = $("result");
  const card = $("result-card");
  card.classList.remove("is-danger", "is-warn", "is-safe", "is-unknown");
  card.classList.add(`is-${result.level}`);
  $("result-badge").textContent = result.badge;
  $("result-title").textContent = result.title;
  $("result-version").textContent = result.version ? `検出・入力されたバージョン：PHP ${result.version}` : "";
  $("result-detail").textContent = result.detail;

  const list = $("result-notes");
  list.replaceChildren(...(result.notes || []).map((n) => { const li = document.createElement("li"); li.textContent = n; return li; }));

  const rawBox = $("result-raw");
  if (raw) {
    $("raw-powered").textContent = raw.poweredBy || "（送信されていません）";
    $("raw-server").textContent = raw.server || "（送信されていません）";
    rawBox.hidden = false;
  } else {
    rawBox.hidden = true;
  }

  // 予約ボタン: 遠隔確認で「対応が必要」→ そのまま表示 / 手入力・不明 → reCAPTCHA 後に表示 / 修正済み → 表示しない
  setBooking(gate && gate.booking);
  consultContext = gate && gate.consult ? gate.consult : null;
  $("consult").hidden = !consultContext;
  $("consult-btn").hidden = false;
  $("consult-btn").textContent = consultContext && consultContext.reason === "manual" ? "事前面談の予約に進む" : "バージョンがわからないので相談したい";
  $("recaptcha-box").hidden = true;
  $("consult-msg").textContent = "";
  $("result-cta").hidden = !(gate && (gate.booking || gate.consult));

  section.hidden = false;
  section.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
}

function notDetected(data) {
  return {
    level: "unknown", badge: "検出できませんでした",
    title: "このサイトはPHPのバージョンを外部に表示していません",
    detail: "バージョンを隠す設定になっている、PHPを使っていない、CDNなどを経由している、などが考えられます。検出できないことは「安全」という意味ではありません。管理画面で番号を確認できる場合は、下の「バージョン番号を入力して判定」をご利用ください。",
    notes: data && data.host ? [`確認したサイト：${data.host}（応答コード ${data.status}）`] : [],
  };
}

function errorResult(message) {
  return { level: "unknown", badge: "確認できませんでした", title: message, detail: "URLを確かめてもう一度お試しいただくか、下の「バージョン番号を入力して判定」をご利用ください。", notes: [] };
}

const unknownResult = () => ({
  level: "unknown", badge: "ご相談", title: "バージョンがわからない場合もご相談いただけます",
  detail: "ロボットでないことを確認したうえで、事前面談のご予約にお進みいただけます。面談でサーバーの状況を一緒に確認します。", notes: [],
});

async function checkUrl(event) {
  event.preventDefault();
  const input = $("url-input");
  const button = $("url-submit");
  const value = input.value.trim();
  const consultUnknown = { consult: { reason: "unknown" } };
  if (!value) { input.focus(); return; }
  if (value.length > 2048) { show(errorResult("URLが長すぎます。"), null, consultUnknown); return; }

  button.disabled = true;
  const label = button.textContent;
  button.textContent = "確認中…";
  try {
    const res = await fetch(`${API_ORIGIN}/check?url=${encodeURIComponent(value)}`, {
      method: "GET", mode: "cors", credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer",
      signal: AbortSignal.timeout(20000),
    });
    const data = await res.json().catch(() => null);
    if (!data || typeof data !== "object") { show(errorResult("確認用サーバーから正しい応答がありませんでした。"), null, consultUnknown); return; }
    if (!data.ok) { show(errorResult(String(data.error || "確認できませんでした。").slice(0, 200)), null, consultUnknown); return; }
    const raw = { poweredBy: data.poweredBy, server: data.server };
    if (!data.phpVersion) { show(notDetected(data), raw, consultUnknown); return; }
    const result = judge(data.phpVersion);
    if (data.host) result.notes.unshift(`確認したサイト：${String(data.host).slice(0, 253)}`);
    if (needsAction(result)) show(result, raw, { booking: data.booking });
    else if (result.level === "unknown") show(result, raw, consultUnknown);
    else show(result, raw, null);
  } catch (e) {
    show(errorResult(e && e.name === "TimeoutError" ? "確認に時間がかかりすぎたため中断しました。" : "確認用サーバーに接続できませんでした。"), null, consultUnknown);
  } finally {
    button.disabled = false;
    button.textContent = label;
  }
}

function checkManual(event) {
  event.preventDefault();
  const input = $("manual-input");
  const value = input.value.trim();
  if (!value) { input.focus(); return; }
  const result = judge(value);
  if (needsAction(result)) show(result, null, { consult: { reason: "manual", version: value.slice(0, 64) } });
  else if (result.level === "unknown") show(result, null, { consult: { reason: "unknown" } });
  else show(result, null, null);
}

// ---- reCAPTCHA（相談ボタンを押したときにだけ読み込む） ----
let recaptchaState = "idle"; // idle | loading | ready
let widgetId = null;

window.onRecaptchaReady = () => {
  recaptchaState = "ready";
  renderRecaptcha();
};

function renderRecaptcha() {
  if (recaptchaState !== "ready" || !window.grecaptcha) return;
  if (widgetId === null) {
    widgetId = window.grecaptcha.render($("recaptcha"), {
      sitekey: RECAPTCHA_SITE_KEY,
      callback: onRecaptchaPassed,
      "expired-callback": () => { $("consult-msg").textContent = "確認の有効期限が切れました。もう一度チェックしてください。"; },
    });
  } else {
    window.grecaptcha.reset(widgetId);
  }
}

function loadRecaptcha() {
  if (recaptchaState !== "idle") { renderRecaptcha(); return; }
  if (!scriptPolicy) { $("consult-msg").textContent = "お使いのブラウザでは確認画面を表示できません。最新のブラウザでお試しください。"; return; }
  recaptchaState = "loading";
  const s = document.createElement("script");
  s.src = scriptPolicy.createScriptURL(RECAPTCHA_API);
  s.async = true;
  s.onerror = () => { recaptchaState = "idle"; $("consult-msg").textContent = "確認画面を読み込めませんでした。時間をおいてお試しください。"; };
  document.head.appendChild(s);
}

function startConsult() {
  if (!consultContext) return;
  $("consult-btn").hidden = true;
  $("recaptcha-box").hidden = false;
  $("consult-msg").textContent = "";
  loadRecaptcha();
}

async function onRecaptchaPassed(token) {
  const msg = $("consult-msg");
  msg.textContent = "確認しています…";
  try {
    const res = await fetch(`${API_ORIGIN}/booking`, {
      method: "POST", mode: "cors", credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, reason: consultContext.reason, version: consultContext.version }),
      signal: AbortSignal.timeout(20000),
    });
    const data = await res.json().catch(() => null);
    if (data && data.ok && typeof data.booking === "string" && data.booking.startsWith(BOOKING_PREFIX)) {
      setBooking(data.booking);
      $("recaptcha-box").hidden = true;
      msg.textContent = "確認できました。下のボタンから日程をお選びください。";
      $("booking-link").focus();
      return;
    }
    msg.textContent = String((data && data.error) || "確認できませんでした。もう一度お試しください。").slice(0, 200);
  } catch {
    msg.textContent = "確認用サーバーに接続できませんでした。時間をおいてお試しください。";
  }
  if (widgetId !== null && window.grecaptcha) window.grecaptcha.reset(widgetId);
}

document.addEventListener("DOMContentLoaded", () => {
  $("url-form").addEventListener("submit", checkUrl);
  $("manual-form").addEventListener("submit", checkManual);
  $("consult-btn").addEventListener("click", startConsult);
  $("unknown-btn").addEventListener("click", () => show(unknownResult(), null, { consult: { reason: "unknown" } }));
});
