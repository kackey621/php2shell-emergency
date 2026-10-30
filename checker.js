// PHP Version Checker（DOMへの書き込みは textContent のみ。文字列をHTMLとして解釈させる書き込みはしない）
"use strict";

const API_URL = "https://php-api.skslprd.com/check";

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

// ---- 表示 ----
const $ = (id) => document.getElementById(id);

function show(result, raw) {
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
  $("result-cta").hidden = result.level === "safe";
  section.hidden = false;
  section.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
}

function notDetected(data) {
  return {
    level: "unknown", badge: "検出できませんでした",
    title: "このサイトはPHPのバージョンを外部に表示していません",
    detail: "バージョンを隠す設定になっている、PHPを使っていない、CDNなどを経由している、などが考えられます。検出できないことは「安全」という意味ではありません。下の「バージョン番号を入力して判定」で確認してください。",
    notes: data && data.host ? [`確認したサイト：${data.host}（応答コード ${data.status}）`] : [],
  };
}

function errorResult(message) {
  return { level: "unknown", badge: "確認できませんでした", title: message, detail: "URLを確かめてもう一度お試しいただくか、下の「バージョン番号を入力して判定」をご利用ください。", notes: [] };
}

async function checkUrl(event) {
  event.preventDefault();
  const input = $("url-input");
  const button = $("url-submit");
  const value = input.value.trim();
  if (!value) { input.focus(); return; }
  if (value.length > 2048) { show(errorResult("URLが長すぎます。")); return; }

  button.disabled = true;
  const label = button.textContent;
  button.textContent = "確認中…";
  try {
    const res = await fetch(`${API_URL}?url=${encodeURIComponent(value)}`, {
      method: "GET", mode: "cors", credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer",
      signal: AbortSignal.timeout(20000),
    });
    const data = await res.json().catch(() => null);
    if (!data || typeof data !== "object") { show(errorResult("確認用サーバーから正しい応答がありませんでした。")); return; }
    if (!data.ok) { show(errorResult(String(data.error || "確認できませんでした。").slice(0, 200))); return; }
    const raw = { poweredBy: data.poweredBy, server: data.server };
    if (!data.phpVersion) { show(notDetected(data), raw); return; }
    const result = judge(data.phpVersion);
    if (data.host) result.notes.unshift(`確認したサイト：${String(data.host).slice(0, 253)}`);
    show(result, raw);
  } catch (e) {
    show(errorResult(e && e.name === "TimeoutError" ? "確認に時間がかかりすぎたため中断しました。" : "確認用サーバーに接続できませんでした。"));
  } finally {
    button.disabled = false;
    button.textContent = label;
  }
}

function checkManual(event) {
  event.preventDefault();
  const input = $("manual-input");
  if (!input.value.trim()) { input.focus(); return; }
  show(judge(input.value));
}

document.addEventListener("DOMContentLoaded", () => {
  $("url-form").addEventListener("submit", checkUrl);
  $("manual-form").addEventListener("submit", checkManual);
});
