// Learning Lab mobile app. Vanilla JS, no dependencies, works fully offline once loaded.
(() => {
  'use strict';

  const $ = (sel, el = document) => el.querySelector(sel);
  const view = $('#view');
  const toText = html => {
    const t = document.createElement('template');
    t.innerHTML = String(html || '').replace(/<\/(p|li|h\d)>/g, ' </$1>');
    return t.content.textContent.replace(/\s+/g, ' ').trim();
  };
  const esc = s =>String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // ---------- storage (every access guarded: private mode / blocked storage) ----------
  const store = {
    get(k, d = null) { try { const v = localStorage.getItem('ll.' + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
    set(k, v) { try { localStorage.setItem('ll.' + k, JSON.stringify(v)); } catch { /* full or blocked */ } },
    del(k) { try { localStorage.removeItem('ll.' + k); } catch { /* ignore */ } },
  };

  let C = null; // decrypted content: { builtAt, topics, docs, quizzes }
  const topicBySlug = slug => C.topics.find(t => t.slug === slug);
  const quizMeta = id => { for (const t of C.topics) for (const q of t.quizzes) if (q.id === id) return { ...q, topic: t }; return null; };
  const docMeta = id => { for (const t of C.topics) for (const d of t.docs) if (d.id === id) return { ...d, topic: t }; return null; };

  // ---------- crypto: PBKDF2-SHA256 -> AES-256-GCM, gzip inside (matches build.mjs) ----------
  const b64ToBytes = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const bytesToB64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));

  async function deriveKey(passphrase, saltB64, iter) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveBits']);
    return crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: b64ToBytes(saltB64), iterations: iter }, base, 256);
  }

  async function decryptBundle(bundle, rawKey) {
    const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
    const gz = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(bundle.iv) }, key, b64ToBytes(bundle.data));
    const stream = new Blob([gz]).stream().pipeThrough(new DecompressionStream('gzip'));
    return JSON.parse(await new Response(stream).text());
  }

  // ---------- boot ----------
  async function boot() {
    registerServiceWorker();
    let bundle;
    try {
      bundle = await (await fetch('content.json')).json();
    } catch {
      view.innerHTML = `<div class="empty">Couldn't load the content. Open the app once while online so it can save everything for offline use.</div>`;
      return;
    }
    const saved = store.get('key');
    if (saved && saved.salt === bundle.salt && saved.iter === bundle.iter) {
      try { C = await decryptBundle(bundle, b64ToBytes(saved.k)); } catch { C = null; }
    }
    if (C) start(); else showLock(bundle);
  }

  function showLock(bundle) {
    setBar({ title: '' });
    view.innerHTML = `
      <form class="lock" id="lock" autocomplete="off">
        <img class="logo" src="icons/icon-192.png" alt="">
        <h2>Learning Lab</h2>
        <p>Enter your passphrase to unlock your study material on this device. You only need to do this once.</p>
        <input id="pass" type="password" autocapitalize="none" autocorrect="off" spellcheck="false" placeholder="Passphrase" aria-label="Passphrase" required>
        <div class="err" id="err"></div>
        <button class="btn primary block" id="unlock">Unlock</button>
      </form>`;
    $('#lock').addEventListener('submit', async e => {
      e.preventDefault();
      const btn = $('#unlock');
      btn.disabled = true; btn.textContent = 'Unlocking…'; $('#err').textContent = '';
      try {
        // Spaces, dashes and capitals are ignored (must match normalizePassphrase in build.mjs).
        const raw = await deriveKey($('#pass').value.replace(/[\s-]+/g, '').toLowerCase(), bundle.salt, bundle.iter);
        C = await decryptBundle(bundle, raw);
        store.set('key', { k: bytesToB64(raw), salt: bundle.salt, iter: bundle.iter });
        location.hash = '#/';
        start();
      } catch {
        $('#err').textContent = "That passphrase didn't work. Check secrets.json on your PC.";
        btn.disabled = false; btn.textContent = 'Unlock';
      }
    });
  }

  function start() {
    window.addEventListener('hashchange', route);
    route();
    if (navigator.storage?.persist) navigator.storage.persist().catch(() => {});
  }

  // ---------- service worker + update toast ----------
  function registerServiceWorker() {
    if (!('serviceWorker' in navigator)) return;
    navigator.serviceWorker.register('sw.js').then(reg => {
      const offer = w => toast('New content is available.', 'Update', () => { w.postMessage('skipWaiting'); });
      if (reg.waiting && navigator.serviceWorker.controller) offer(reg.waiting);
      reg.addEventListener('updatefound', () => {
        const w = reg.installing;
        w?.addEventListener('statechange', () => {
          if (w.state === 'installed' && navigator.serviceWorker.controller) offer(w);
        });
      });
      // Check for a new build whenever the app comes back to the foreground.
      document.addEventListener('visibilitychange', () => { if (!document.hidden) reg.update().catch(() => {}); });
    }).catch(() => {});
    let reloading = false;
    navigator.serviceWorker.addEventListener('controllerchange', () => {
      if (reloading) return;
      reloading = true;
      location.reload();
    });
  }

  let toastTimer;
  function toast(msg, actionLabel, action, ms = actionLabel ? 0 : 2600) {
    const el = $('#toast');
    el.innerHTML = `<span>${esc(msg)}</span>${actionLabel ? `<button>${esc(actionLabel)}</button>` : ''}`;
    el.hidden = false;
    if (actionLabel) el.querySelector('button').onclick = () => { el.hidden = true; action(); };
    clearTimeout(toastTimer);
    if (ms) toastTimer = setTimeout(() => { el.hidden = true; }, ms);
  }

  // ---------- chrome ----------
  function setBar({ title = '', back = null, actions = [] }) {
    $('#bar-title').textContent = title;
    const b = $('#back');
    b.hidden = !back;
    b.onclick = () => { location.hash = back; };
    const box = $('#bar-actions');
    box.innerHTML = '';
    for (const a of actions) {
      const btn = document.createElement('button');
      btn.className = 'bar-btn';
      btn.setAttribute('aria-label', a.label);
      btn.innerHTML = a.icon || esc(a.label);
      btn.onclick = a.onClick;
      box.appendChild(btn);
    }
  }

  const ICON = {
    gear: '<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true"><circle cx="12" cy="12" r="3.2" fill="none" stroke="currentColor" stroke-width="2"/><path d="M12 2.8v2.4M12 18.8v2.4M4.6 4.6l1.7 1.7M17.7 17.7l1.7 1.7M2.8 12h2.4M18.8 12h2.4M4.6 19.4l1.7-1.7M17.7 6.3l1.7-1.7" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
    list: '<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true"><path d="M8 6h12M8 12h12M8 18h12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="4" cy="6" r="1.3" fill="currentColor"/><circle cx="4" cy="12" r="1.3" fill="currentColor"/><circle cx="4" cy="18" r="1.3" fill="currentColor"/></svg>',
    text: '<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true"><path d="M3 18l5-12 5 12M4.8 14h6.4M15 18l3.2-7.5L21.4 18M16 16h4.4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    chart: '<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true"><path d="M4 20V10M10 20V4M16 20v-7M22 20H2" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
    chev: '<svg class="chev" viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="M9 5l7 7-7 7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  };

  function openSheet(html, onOpen) {
    const sheet = $('#sheet'), bd = $('#sheet-backdrop');
    sheet.innerHTML = `<div class="grab"></div>${html}`;
    sheet.hidden = bd.hidden = false;
    sheet.scrollTop = 0;
    bd.onclick = closeSheet;
    onOpen?.(sheet);
  }
  function closeSheet() { $('#sheet').hidden = $('#sheet-backdrop').hidden = true; }

  // Reading-size preference applies to every document.
  const SIZES = [15, 17, 19, 21];
  const applySize = () => document.documentElement.style.setProperty('--read-size', store.get('readSize', 17) + 'px');
  applySize();

  function openSettings() {
    const size = store.get('readSize', 17);
    const built = C ? new Date(C.builtAt).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '';
    openSheet(`
      <h3>Settings</h3>
      <div class="setting"><span>Text size</span><div class="seg" id="sizes">${SIZES.map(s => `<button data-s="${s}" class="${s === size ? 'on' : ''}" style="font-size:${s - 3}px">A</button>`).join('')}</div></div>
      <div class="setting"><span>Content built</span><span class="pill">${esc(built)}</span></div>
      <div class="setting"><span>Check for new content</span><button class="btn" id="check">Check</button></div>
      <div class="setting"><span>Lock this device</span><button class="btn" id="lockit">Lock</button></div>
      <p class="footer-note">Build ${esc(window.BUILD_ID || '')}. Quiz history is stored only on this phone.</p>`, sheet => {
      sheet.querySelectorAll('#sizes button').forEach(b => b.onclick = () => {
        store.set('readSize', Number(b.dataset.s)); applySize();
        sheet.querySelectorAll('#sizes button').forEach(x => x.classList.toggle('on', x === b));
      });
      $('#check', sheet).onclick = async () => {
        const reg = await navigator.serviceWorker?.getRegistration();
        if (!reg) return toast('Updates need the installed app.');
        if (!navigator.onLine) return toast("You're offline. Try again with a connection.");
        await reg.update().catch(() => {});
        setTimeout(() => { if (!reg.installing && !reg.waiting) toast("You're up to date."); }, 1500);
      };
      $('#lockit', sheet).onclick = () => { store.del('key'); location.hash = '#/'; location.reload(); };
    });
  }

  // ---------- attempts & sessions ----------
  const attempts = () => store.get('attempts', []);
  const attemptsFor = quizId => attempts().filter(a => a.quizId === quizId);
  const lastFull = quizId => attemptsFor(quizId).filter(a => a.mode === 'all').pop();
  const pct = (s, m) => (m ? Math.round((s / m) * 100) : 0);
  const band = p => (p >= 80 ? 'good' : p >= 55 ? 'mid' : 'bad');
  const fmtDate = iso => new Date(iso).toLocaleDateString([], { month: 'short', day: 'numeric' });
  const fmtScore = n => (Number.isInteger(n) ? String(n) : n.toFixed(1));

  function weakSubtopics(filterTopic) {
    const tally = new Map();
    for (const a of attempts()) {
      if (filterTopic && a.topic !== filterTopic) continue;
      const quiz = C.quizzes[a.quizId];
      if (!quiz) continue;
      for (const [num, r] of Object.entries(a.answers)) {
        const q = quiz.questions.find(x => x.num === Number(num));
        if (!q?.subtopic) continue;
        const key = `${a.topic}|${q.subtopic}`;
        const t = tally.get(key) || { topic: a.topic, subtopic: q.subtopic, misses: 0, seen: 0 };
        t.seen++;
        t.misses += 1 - (r.score ?? 0);
        tally.set(key, t);
      }
    }
    return [...tally.values()].filter(t => t.misses > 0).sort((a, b) => b.misses - a.misses);
  }

  // ---------- routing ----------
  let leaveHook = null;
  function route() {
    leaveHook?.(); leaveHook = null;
    closeSheet();
    $('#toast').hidden = $('#toast').querySelector('button') ? $('#toast').hidden : true;
    document.querySelector('.progress-line')?.remove();
    const [path, query] = location.hash.replace(/^#\/?/, '').split('?');
    const [name, ...rest] = path.split('/');
    const arg = decodeURIComponent(rest.join('/'));
    const params = new URLSearchParams(query || '');
    window.scrollTo(0, 0);
    if (name === 't' && topicBySlug(arg)) renderTopic(arg);
    else if (name === 'doc' && C.docs[arg]) renderDoc(arg);
    else if (name === 'quiz' && C.quizzes[arg]) renderQuiz(arg, params);
    else if (name === 'result') renderResult(arg);
    else if (name === 'progress') renderProgress();
    else renderHome();
    view.focus({ preventScroll: true });
  }

  window.addEventListener('scroll', () => $('#bar').classList.toggle('scrolled', window.scrollY > 4), { passive: true });

  // ---------- home ----------
  function renderHome() {
    setBar({ title: 'Learning Lab', actions: [
      { label: 'Progress', icon: ICON.chart, onClick: () => { location.hash = '#/progress'; } },
      { label: 'Settings', icon: ICON.gear, onClick: openSettings },
    ] });
    const all = attempts().filter(a => a.mode === 'all');
    const recent = all.slice(-10);
    const avg = recent.length ? Math.round(recent.reduce((s, a) => s + pct(a.score, a.max), 0) / recent.length) : null;
    const resume = Object.keys(C.quizzes).map(id => ({ id, s: store.get('session.' + id) })).filter(x => x.s && !x.s.done)
      .sort((a, b) => (b.s.updatedAt || '').localeCompare(a.s.updatedAt || ''))[0];
    const lastDoc = store.get('lastDoc');
    const standalone = window.navigator.standalone || matchMedia('(display-mode: standalone)').matches;

    const order = { studying: 0, new: 1, solid: 2 };
    const topics = [...C.topics].sort((a, b) => (order[a.status] ?? 3) - (order[b.status] ?? 3) || (b.started || '').localeCompare(a.started || ''));

    view.innerHTML = `
      <div class="hero"><p>${C.topics.length} topics · ${Object.keys(C.quizzes).length} quizzes</p></div>
      <div class="stats">
        <div class="stat"><b>${all.length}</b><span>quizzes taken</span></div>
        <div class="stat"><b>${avg == null ? '–' : avg + '%'}</b><span>recent average</span></div>
        <div class="stat"><b>${weakSubtopics().length}</b><span>weak spots</span></div>
      </div>
      ${resume || (lastDoc && C.docs[lastDoc.id]) ? `<div class="eyebrow">Pick up where you left off</div>` : ''}
      ${resume ? continueCard(`#/quiz/${encodeURIComponent(resume.id)}${resume.s.mode === 'review' ? '?review=1' : ''}`, quizMeta(resume.id)?.title, `Quiz · question ${resume.s.i + 1} of ${resume.s.order.length}`) : ''}
      ${lastDoc && C.docs[lastDoc.id] ? continueCard(`#/doc/${encodeURIComponent(lastDoc.id)}`, docMeta(lastDoc.id)?.title, `Reading · ${lastDoc.pct || 0}% through`) : ''}
      <div class="eyebrow">Topics</div>
      ${topics.map(topicCard).join('')}
      ${standalone ? '' : `<div class="install-tip">To install on iPhone: tap <b>Share</b> in Safari, then <b>Add to Home Screen</b>. It then works offline.</div>`}`;
  }

  function continueCard(href, title, meta) {
    return `<a class="card" href="${href}"><div class="row"><div class="grow"><h3>${esc(title)}</h3><div class="meta">${esc(meta)}</div></div>${ICON.chev}</div></a>`;
  }

  function topicCard(t) {
    const lessons = t.docs.filter(d => d.kind === 'lesson').length;
    const scores = t.quizzes.map(q => lastFull(q.id)).filter(Boolean);
    const last = scores.sort((a, b) => a.finishedAt.localeCompare(b.finishedAt)).pop();
    const bits = [];
    if (t.docs.some(d => d.kind === 'guide')) bits.push('Study guide');
    if (lessons) bits.push(`${lessons} lesson${lessons > 1 ? 's' : ''}`);
    if (t.quizzes.length) bits.push(`${t.quizzes.length} quiz${t.quizzes.length > 1 ? 'zes' : ''}`);
    const lp = last && pct(last.score, last.max);
    return `<a class="card" href="#/t/${encodeURIComponent(t.slug)}"><div class="row"><div class="grow">
      <h3>${esc(t.title)}</h3>
      <div class="meta"><span class="pill ${esc(t.status)}">${esc(t.status)}</span><span>${bits.join(' · ')}</span>
      ${last ? `<span class="pill ${band(lp)}">Last quiz ${lp}%</span>` : ''}</div>
    </div>${ICON.chev}</div></a>`;
  }

  // ---------- topic ----------
  function renderTopic(slug) {
    const t = topicBySlug(slug);
    setBar({ title: t.title, back: '#/', actions: [{ label: 'Settings', icon: ICON.gear, onClick: openSettings }] });
    const kindLabel = { guide: 'Study guide', lesson: 'Lesson', extra: 'Briefing', sources: 'Sources' };
    const docCard = d => {
      const pos = store.get('pos.' + d.id);
      const read = pos?.pct ? ` · ${pos.pct >= 95 ? 'read' : pos.pct + '% read'}` : '';
      return `<a class="card" href="#/doc/${encodeURIComponent(d.id)}"><div class="row"><div class="grow">
        <h3>${esc(d.title)}</h3><div class="meta">${kindLabel[d.kind]} · ${d.minutes} min${read}</div></div>${ICON.chev}</div></a>`;
    };
    const quizCard = q => {
      const hist = attemptsFor(q.id).filter(a => a.mode === 'all');
      const last = hist[hist.length - 1];
      const best = hist.reduce((m, a) => Math.max(m, pct(a.score, a.max)), 0);
      const sess = store.get('session.' + q.id);
      const inProgress = sess && !sess.done;
      const missed = last ? Object.entries(last.answers).filter(([, r]) => (r.score ?? 0) < 1).length : 0;
      return `<div class="card" style="cursor:default">
        <h3>${esc(q.title)}</h3>
        <div class="meta"><span>${q.count} questions${q.date ? ' · written ' + esc(q.date.slice(0, 10)) : ''}</span>
          ${last ? `<span class="pill ${band(pct(last.score, last.max))}">Last ${pct(last.score, last.max)}%</span>` : ''}
          ${hist.length > 1 ? `<span class="pill">Best ${best}%</span>` : ''}</div>
        <div class="btn-row">
          <a class="btn primary" href="#/quiz/${encodeURIComponent(q.id)}${inProgress && sess.mode === 'review' ? '?review=1' : ''}">${inProgress ? 'Resume' : hist.length ? 'Retake' : 'Start quiz'}</a>
          ${missed && !inProgress ? `<a class="btn" href="#/quiz/${encodeURIComponent(q.id)}?review=1">Redo ${missed} missed</a>` : ''}
        </div>
        ${last ? `<div class="hint"><a href="#/result/${encodeURIComponent(last.id)}">See last results</a></div>` : ''}
      </div>`;
    };
    const weak = weakSubtopics(slug).slice(0, 6);
    const guides = t.docs.filter(d => d.kind === 'guide' || d.kind === 'lesson');
    const extras = t.docs.filter(d => d.kind === 'extra');
    const sources = t.docs.filter(d => d.kind === 'sources');
    view.innerHTML = `
      <div class="hero"><h2>${esc(t.title)}</h2>
        <p><span class="pill ${esc(t.status)}">${esc(t.status)}</span>${t.started ? ` &nbsp;Started ${esc(t.started)}` : ''}</p></div>
      ${guides.length ? `<div class="eyebrow">Read</div>${guides.map(docCard).join('')}` : ''}
      ${t.quizzes.length ? `<div class="eyebrow">Test yourself</div>${t.quizzes.map(quizCard).join('')}` : ''}
      ${weak.length ? `<div class="eyebrow">Weak spots</div><div class="card" style="cursor:default">${weak.map(w => `<div class="meta" style="padding:4px 0">• ${esc(w.subtopic)}</div>`).join('')}</div>` : ''}
      ${extras.length ? `<div class="eyebrow">Briefings</div>${extras.map(docCard).join('')}` : ''}
      ${sources.length ? `<div class="eyebrow">Reference</div>${sources.map(docCard).join('')}` : ''}`;
  }

  // ---------- documents ----------
  function renderDoc(id) {
    const d = docMeta(id);
    const doc = C.docs[id];
    setBar({ title: d.title, back: `#/t/${encodeURIComponent(d.topic.slug)}`, actions: [
      ...(doc.toc.length ? [{ label: 'Contents', icon: ICON.list, onClick: () => openToc(doc) }] : []),
      { label: 'Text size', icon: ICON.text, onClick: cycleSize },
    ] });
    view.innerHTML = `
      <div class="doc-head"><div class="meta">${esc(d.topic.title)} · ${d.minutes} min read</div><h2>${esc(d.title)}</h2></div>
      <article class="reader">${doc.html}</article>
      <div class="btn-row"><a class="btn block" href="#/t/${encodeURIComponent(d.topic.slug)}">Back to ${esc(d.topic.title)}</a></div>`;
    view.querySelectorAll('a[data-anchor]').forEach(a => a.addEventListener('click', e => {
      e.preventDefault();
      document.getElementById(a.dataset.anchor)?.scrollIntoView({ behavior: 'smooth' });
    }));

    const line = document.createElement('div');
    line.className = 'progress-line';
    document.body.appendChild(line);

    // Restore and remember reading position (by fraction, so text size changes don't break it).
    const saved = store.get('pos.' + id);
    const maxScroll = () => Math.max(1, document.documentElement.scrollHeight - innerHeight);
    if (saved?.frac) requestAnimationFrame(() => window.scrollTo(0, saved.frac * maxScroll()));
    let t;
    const onScroll = () => {
      const frac = Math.min(1, window.scrollY / maxScroll());
      line.style.width = (frac * 100).toFixed(1) + '%';
      clearTimeout(t);
      t = setTimeout(() => {
        const p = Math.round(frac * 100);
        const prev = store.get('pos.' + id) || {};
        store.set('pos.' + id, { frac, pct: Math.max(p, prev.pct || 0) });
        store.set('lastDoc', { id, pct: p });
      }, 250);
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
    leaveHook = () => window.removeEventListener('scroll', onScroll);
  }

  function openToc(doc) {
    openSheet(`<h3>Contents</h3><nav class="toc">${doc.toc.map(h => `<a href="#" data-id="${esc(h.id)}" class="d${h.depth}">${esc(h.text)}</a>`).join('')}</nav>`, sheet => {
      sheet.querySelectorAll('a').forEach(a => a.onclick = e => {
        e.preventDefault();
        closeSheet();
        document.getElementById(a.dataset.id)?.scrollIntoView();
      });
    });
  }

  function cycleSize() {
    const frac = window.scrollY / Math.max(1, document.documentElement.scrollHeight - innerHeight);
    const cur = store.get('readSize', 17);
    const next = SIZES[(SIZES.indexOf(cur) + 1) % SIZES.length];
    store.set('readSize', next);
    applySize();
    window.scrollTo(0, frac * Math.max(1, document.documentElement.scrollHeight - innerHeight));
    toast(`Text size ${SIZES.indexOf(next) + 1} of ${SIZES.length}`);
  }

  // ---------- quiz ----------
  const TYPE_LABEL = { mc: 'Multiple choice', fill: 'Fill in the blank', short: 'Short answer', scenario: 'Scenario', calc: 'Calculation' };

  function newSession(quizId, review) {
    const quiz = C.quizzes[quizId];
    let order = quiz.questions.map(q => q.num);
    if (review) {
      const last = lastFull(quizId) || attemptsFor(quizId).pop();
      if (last) order = order.filter(n => (last.answers[n]?.score ?? 0) < 1);
      if (!order.length) order = quiz.questions.map(q => q.num);
    }
    return { order, i: 0, answers: {}, mode: review ? 'review' : 'all', startedAt: new Date().toISOString() };
  }

  function renderQuiz(quizId, params) {
    const meta = quizMeta(quizId);
    const quiz = C.quizzes[quizId];
    const review = params.get('review') === '1';
    const key = 'session.' + quizId;
    let s = store.get(key);
    if (!s || s.done || (s.mode === 'review') !== review) s = newSession(quizId, review);
    const save = () => { s.updatedAt = new Date().toISOString(); store.set(key, s); };
    save();

    setBar({ title: review ? 'Redo missed' : meta.title, back: `#/t/${encodeURIComponent(meta.topic.slug)}` });

    const draw = () => {
      const num = s.order[s.i];
      const q = quiz.questions.find(x => x.num === num);
      const a = s.answers[num] || {};
      const autoGraded = q.type === 'mc' && q.correct;
      const isLast = s.i === s.order.length - 1;
      const graded = a.score != null;

      let body = `
        <div class="q-top">
          <div class="q-track"><div style="width:${(s.i / s.order.length) * 100}%"></div></div>
          <span class="q-count">${s.i + 1} / ${s.order.length}</span>
        </div>
        <div class="q-tags">
          <span class="pill">Q${q.num} · ${TYPE_LABEL[q.type] || 'Question'}</span>
          ${q.difficulty ? `<span class="pill ${q.difficulty.startsWith('hard') ? 'bad' : q.difficulty.startsWith('easy') ? 'good' : 'mid'}">${esc(q.difficulty)}</span>` : ''}
        </div>
        <div class="q-stem reader">${q.stem}</div>`;

      if (q.choices.length) {
        const locked = autoGraded ? a.choice != null : a.revealed;
        body += `<div class="choices ${locked ? 'locked' : ''}">${q.choices.map(c => {
          let cls = '';
          if (autoGraded && a.choice != null) {
            if (c.letter === q.correct) cls = 'correct';
            else if (c.letter === a.choice) cls = 'wrong';
            else cls = 'dim';
          } else if (a.choice === c.letter) cls = 'correct';
          return `<button class="choice ${cls}" data-letter="${c.letter}"><span class="letter">${c.letter}</span><span class="ctext">${c.html}</span></button>`;
        }).join('')}</div>`;
      } else {
        body += `<textarea class="answer" id="ans" placeholder="Type your answer (optional). Thinking it through before revealing helps it stick." ${a.revealed ? 'readonly' : ''}>${esc(a.text || '')}</textarea>`;
      }

      const showKey = autoGraded ? a.choice != null : a.revealed;
      if (showKey) {
        const ok = autoGraded && a.choice === q.correct;
        body += `<div class="key ${autoGraded ? (ok ? 'good' : 'bad') : ''}">
          ${autoGraded ? `<div class="verdict ${ok ? 'good' : 'bad'}">${ok ? 'Correct' : `Not quite. The answer is ${q.correct}.`}</div>` : '<h4>Model answer</h4>'}
          <div class="reader">${q.answer || '<p><em>No answer key entry found for this question.</em></p>'}</div>
          ${q.subtopic ? `<div class="hint" style="text-align:left">Subtopic: ${esc(q.subtopic)}</div>` : ''}
        </div>`;
        if (!autoGraded) {
          body += `<div class="hint">How did you do? Be honest; it drives your weak-spot list.</div>
          <div class="grade-btns">
            <button class="btn good ${a.score === 1 ? 'on' : ''}" data-score="1">Got it</button>
            <button class="btn mid ${a.score === 0.5 ? 'on' : ''}" data-score="0.5">Partly</button>
            <button class="btn bad ${a.score === 0 ? 'on' : ''}" data-score="0">Missed</button>
          </div>`;
        }
      }

      let nav;
      if (!showKey) {
        nav = q.choices.length && autoGraded
          ? `<button class="btn block" id="skip">Skip</button>`
          : `<div class="btn-row" style="margin:0"><button class="btn" id="skip">Skip</button><button class="btn primary" id="reveal">Show answer</button></div>`;
      } else {
        nav = `<button class="btn primary block" id="next" ${graded ? '' : 'disabled'}>${isLast ? 'See results' : 'Next question'}</button>`;
      }
      view.innerHTML = body + `<div class="q-nav">${nav}</div>`;

      // Handlers
      view.querySelectorAll('.choice').forEach(btn => btn.onclick = () => {
        const letter = btn.dataset.letter;
        if (autoGraded) {
          s.answers[num] = { choice: letter, score: letter === q.correct ? 1 : 0 };
          save(); draw();
          if (navigator.vibrate) navigator.vibrate(letter === q.correct ? 15 : [30, 40, 30]);
        } else {
          s.answers[num] = { ...a, choice: letter };
          save(); draw();
        }
      });
      const ta = $('#ans');
      if (ta) ta.oninput = () => { s.answers[num] = { ...(s.answers[num] || {}), text: ta.value }; save(); };
      $('#reveal')?.addEventListener('click', () => {
        s.answers[num] = { ...(s.answers[num] || {}), revealed: true };
        save(); draw();
        view.querySelector('.key')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
      $('#skip')?.addEventListener('click', () => {
        s.answers[num] = { ...(s.answers[num] || {}), skipped: true, score: 0 };
        advance();
      });
      view.querySelectorAll('[data-score]').forEach(b => b.onclick = () => {
        s.answers[num] = { ...(s.answers[num] || {}), score: Number(b.dataset.score) };
        save(); draw();
        $('#next')?.scrollIntoView({ behavior: 'smooth', block: 'end' });
      });
      $('#next')?.addEventListener('click', advance);
      window.scrollTo(0, 0);
    };

    const advance = () => {
      if (s.i < s.order.length - 1) { s.i++; save(); draw(); return; }
      finish();
    };

    const finish = () => {
      const answers = {};
      for (const n of s.order) {
        const a = s.answers[n] || { skipped: true, score: 0 };
        answers[n] = { score: a.score ?? 0, ...(a.choice ? { choice: a.choice } : {}), ...(a.text ? { text: a.text } : {}), ...(a.skipped ? { skipped: true } : {}) };
      }
      const score = Object.values(answers).reduce((t, a) => t + a.score, 0);
      const attempt = {
        id: 'a' + Date.now().toString(36), quizId, topic: meta.topic.slug, mode: s.mode,
        startedAt: s.startedAt, finishedAt: new Date().toISOString(), answers, score, max: s.order.length,
      };
      const all = attempts(); all.push(attempt); store.set('attempts', all);
      store.del(key);
      location.hash = `#/result/${attempt.id}`;
    };

    draw();
  }

  // ---------- results ----------
  function renderResult(attemptId) {
    const a = attempts().find(x => x.id === attemptId);
    if (!a || !C.quizzes[a.quizId]) return renderHome();
    const meta = quizMeta(a.quizId);
    const quiz = C.quizzes[a.quizId];
    const p = pct(a.score, a.max);
    setBar({ title: 'Results', back: `#/t/${encodeURIComponent(meta.topic.slug)}` });
    const missed = Object.entries(a.answers).filter(([, r]) => r.score < 1);
    const subs = [...new Set(missed.map(([n]) => quiz.questions.find(q => q.num === Number(n))?.subtopic).filter(Boolean))];
    const r = 64, circ = 2 * Math.PI * r;
    const color = { good: 'var(--good)', mid: 'var(--warn)', bad: 'var(--bad)' }[band(p)];
    view.innerHTML = `
      <div class="score-ring">
        <svg width="150" height="150" viewBox="0 0 150 150"><circle cx="75" cy="75" r="${r}" fill="none" stroke="var(--surface-2)" stroke-width="12"/>
        <circle cx="75" cy="75" r="${r}" fill="none" stroke="${color}" stroke-width="12" stroke-linecap="round" stroke-dasharray="${circ}" stroke-dashoffset="${circ * (1 - p / 100)}"/></svg>
        <div class="num"><b>${p}%</b><span>${fmtScore(a.score)} of ${a.max}</span></div>
      </div>
      <p style="text-align:center;margin:0 0 4px;font-weight:650">${esc(meta.title)}</p>
      <p class="hint" style="margin-top:0">${a.mode === 'review' ? 'Redo of missed questions · ' : ''}${fmtDate(a.finishedAt)}</p>
      <div class="btn-row">
        <button class="btn primary" id="share">Send to Claude</button>
        ${missed.length ? `<a class="btn" href="#/quiz/${encodeURIComponent(a.quizId)}?review=1">Redo ${missed.length} missed</a>` : ''}
      </div>
      <p class="hint">Sends your score and written answers so Claude can grade them and update your progress log.</p>
      ${subs.length ? `<div class="eyebrow">Worth restudying</div><div class="card" style="cursor:default">${subs.map(s => `<div class="meta" style="padding:3px 0">• ${esc(s)}</div>`).join('')}</div>` : ''}
      <div class="eyebrow">Question by question</div>
      <div id="rows">${Object.entries(a.answers).map(([n, r]) => {
        const q = quiz.questions.find(x => x.num === Number(n));
        const cls = r.skipped ? 'none' : r.score >= 1 ? 'good' : r.score > 0 ? 'mid' : 'bad';
        const sym = r.skipped ? '–' : r.score >= 1 ? '✓' : r.score > 0 ? '½' : '✗';
        const plain = toText(q?.stem);
        return `<div class="result-row" data-n="${n}"><span class="mark ${cls}">${sym}</span><div class="txt">${esc(plain.slice(0, 110))}${plain.length > 110 ? '…' : ''}<small>Q${n} · ${esc(q?.subtopic || TYPE_LABEL[q?.type] || '')}${r.choice ? ` · you chose ${r.choice}` : ''}</small></div></div>`;
      }).join('')}</div>
      <div class="btn-row"><a class="btn block" href="#/t/${encodeURIComponent(meta.topic.slug)}">Back to ${esc(meta.topic.title)}</a></div>`;
    $('#share').onclick = () => shareText(resultText(a), `${meta.topic.title} quiz results`);
    view.querySelectorAll('.result-row').forEach(row => row.onclick = () => {
      const q = quiz.questions.find(x => x.num === Number(row.dataset.n));
      const r = a.answers[row.dataset.n];
      openSheet(`<h3>Q${q.num}</h3><div class="reader">${q.stem}</div>
        ${q.choices.length ? `<div class="reader">${q.choices.map(c => `<p><b>${c.letter}.</b> ${c.html.replace(/<\/?p>/g, '')}${c.letter === q.correct ? ' ✓' : ''}${c.letter === r.choice && c.letter !== q.correct ? ' ← your pick' : ''}</p>`).join('')}</div>` : ''}
        ${r.text ? `<div class="key"><h4>Your answer</h4><div class="reader"><p>${esc(r.text).replace(/\n/g, '<br>')}</p></div></div>` : ''}
        <div class="key"><h4>Answer key</h4><div class="reader">${q.answer}</div></div>`);
    });
  }

  function resultText(a) {
    const meta = quizMeta(a.quizId);
    const quiz = C.quizzes[a.quizId];
    const when = new Date(a.finishedAt);
    const stamp = `${when.toLocaleDateString('en-CA')} ${when.toTimeString().slice(0, 5)}`;
    const lines = [
      'Learning Lab quiz results (from the mobile app). Please log these with progress-tracker, and grade my written answers against the answer key.',
      '',
      `Topic: ${meta.topic.slug} (${meta.topic.title})`,
      `Quiz: topics/${meta.topic.slug}/${meta.file}`,
      `Taken: ${stamp}${a.mode === 'review' ? ' (redo of previously missed questions only)' : ''}`,
      `Score: ${fmtScore(a.score)} / ${a.max} (${pct(a.score, a.max)}%). Multiple choice auto-graded; other questions self-graded.`,
      '',
    ];
    for (const [n, r] of Object.entries(a.answers)) {
      const q = quiz.questions.find(x => x.num === Number(n));
      const verdict = r.skipped ? 'skipped' : q.type === 'mc' && q.correct ? (r.score ? 'correct' : 'wrong') : r.score >= 1 ? 'got it (self)' : r.score > 0 ? 'partial (self)' : 'missed (self)';
      lines.push(`Q${n} [${TYPE_LABEL[q.type] || q.type}${q.subtopic ? '; ' + q.subtopic : ''}]: ${verdict}${r.choice ? `, chose ${r.choice}` : ''}`);
      if (r.text) lines.push(...r.text.trim().split('\n').map(l => '    ' + l));
    }
    return lines.join('\n');
  }

  async function shareText(text, title) {
    try {
      if (navigator.share) { await navigator.share({ title, text }); return; }
    } catch (e) { if (e.name === 'AbortError') return; }
    try { await navigator.clipboard.writeText(text); toast('Copied. Paste it into your Learning session.'); return; } catch { /* fall through */ }
    openSheet(`<h3>Copy results</h3><textarea class="answer" style="min-height:260px" readonly>${esc(text)}</textarea>`, sh => sh.querySelector('textarea').select());
  }

  // ---------- progress ----------
  function renderProgress() {
    setBar({ title: 'Progress', back: '#/' });
    const list = attempts().slice().reverse();
    const weak = weakSubtopics().slice(0, 12);
    view.innerHTML = `
      ${weak.length ? `<div class="eyebrow">Weak spots</div><div class="card" style="cursor:default">${weak.map(w =>
        `<div class="row" style="padding:5px 0"><div class="grow">${esc(w.subtopic)}<div class="meta">${esc(topicBySlug(w.topic)?.title || w.topic)}</div></div><span class="pill bad">${fmtScore(w.misses)} missed</span></div>`).join('')}</div>` : ''}
      <div class="eyebrow">History</div>
      ${list.length ? list.map(a => {
        const m = quizMeta(a.quizId);
        const p = pct(a.score, a.max);
        return `<a class="card" href="#/result/${a.id}"><div class="row"><div class="grow"><h3>${esc(m?.topic.title || a.topic)}</h3>
          <div class="meta">${fmtDate(a.finishedAt)} · ${a.mode === 'review' ? 'redo missed' : 'full quiz'} · ${fmtScore(a.score)}/${a.max}</div></div>
          <span class="pill ${band(p)}">${p}%</span></div></a>`;
      }).join('') : '<div class="empty">No quizzes taken yet. Pick a topic and start one.</div>'}
      ${list.length ? `<div class="btn-row"><button class="btn block" id="exportAll">Send all results to Claude</button></div>` : ''}`;
    $('#exportAll')?.addEventListener('click', () =>
      shareText(attempts().filter(a => C.quizzes[a.quizId]).map(resultText).join('\n\n---\n\n'), 'Learning Lab results'));
  }

  boot();
})();
