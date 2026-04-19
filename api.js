<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Get Key - NTT System</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&family=Oswald:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    :root {
      --primary: #00ff9d; --primary-dark: #00cc7d;
      --bg-dark: #0a0e1a; --bg-darker: #050810;
      --surface: #141824; --text: #e8ecf5; --text-dim: #8892ab;
      --border: #1f2937; --success: #00ff9d; --pending: #fbbf24; --error: #ff4d6d;
    }
    body { font-family: 'IBM Plex Mono', monospace; background: var(--bg-dark); color: var(--text); min-height: 100vh; display: flex; align-items: center; justify-content: center; position: relative; overflow-x: hidden; }
    .bg-grid { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-image: linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px); background-size: 50px 50px; z-index: 0; pointer-events: none; }
    .container { position: relative; z-index: 1; width: 100%; max-width: 500px; padding: 2rem; }
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 2.5rem; box-shadow: 0 20px 60px rgba(0,0,0,0.5); animation: slideUp 0.6s ease; }
    @keyframes slideUp { from { opacity: 0; transform: translateY(30px); } to { opacity: 1; transform: translateY(0); } }
    .title { font-family: 'Oswald', sans-serif; font-size: 2rem; text-align: center; margin-bottom: 0.5rem; background: linear-gradient(135deg, var(--primary), #6366f1); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .subtitle { text-align: center; color: var(--text-dim); font-size: 0.875rem; margin-bottom: 2rem; }
    .steps { display: flex; flex-direction: column; gap: 1rem; margin-bottom: 2rem; }
    .step { background: var(--bg-darker); border: 2px solid var(--border); border-radius: 12px; padding: 1.5rem; display: flex; align-items: center; gap: 1rem; transition: all 0.3s ease; position: relative; overflow: hidden; }
    .step::before { content: ''; position: absolute; top: 0; left: 0; width: 0; height: 100%; background: linear-gradient(90deg, rgba(0,255,157,0.1), transparent); transition: width 0.3s ease; }
    .step.completed::before { width: 100%; }
    .step.completed { border-color: var(--success); }
    .step.active-step { border-color: var(--pending); }
    .step-number { width: 40px; height: 40px; border-radius: 50%; background: var(--surface); border: 2px solid var(--border); display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 1.125rem; flex-shrink: 0; transition: all 0.3s ease; position: relative; z-index: 1; }
    .step.completed .step-number { background: var(--success); border-color: var(--success); color: var(--bg-dark); }
    .step.active-step .step-number { background: var(--pending); border-color: var(--pending); color: var(--bg-dark); }
    .step-content { flex: 1; position: relative; z-index: 1; }
    .step-title { font-weight: 600; margin-bottom: 0.25rem; }
    .step-desc { font-size: 0.875rem; color: var(--text-dim); }
    .step-action { position: relative; z-index: 1; }
    .btn { padding: 0.75rem 1.5rem; border: none; border-radius: 8px; font-family: 'Oswald', sans-serif; font-size: 0.875rem; font-weight: 700; text-transform: uppercase; cursor: pointer; transition: all 0.3s ease; text-decoration: none; display: inline-block; }
    .btn-primary { background: var(--primary); color: var(--bg-dark); }
    .btn-primary:hover { background: var(--primary-dark); transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,255,157,0.4); }
    .btn-primary:disabled { opacity: 0.4; cursor: not-allowed; transform: none !important; }
    .btn-success { background: rgba(0,255,157,0.2); color: var(--success); border: 1px solid var(--success); cursor: default; }
    .checkmark { display: inline-block; margin-right: 0.5rem; }
    .create-key-section { margin-top: 2rem; padding-top: 2rem; border-top: 1px solid var(--border); display: none; }
    .create-key-section.active { display: block; animation: slideUp 0.4s ease; }
    .btn-create { width: 100%; padding: 1.25rem; background: linear-gradient(135deg, var(--primary), #6366f1); color: var(--bg-dark); font-size: 1rem; }
    .btn-create:hover { transform: translateY(-3px); box-shadow: 0 8px 24px rgba(0,255,157,0.5); }
    .key-result { margin-top: 1.5rem; display: none; }
    .key-result.active { display: block; animation: slideUp 0.4s ease; }
    .key-box { background: var(--bg-darker); border: 1px solid var(--success); border-radius: 8px; padding: 1rem; text-align: center; margin-bottom: 1rem; }
    .key-label { font-size: 0.75rem; color: var(--text-dim); margin-bottom: 0.5rem; text-transform: uppercase; letter-spacing: 0.1em; }
    .key-value { font-size: 1.25rem; font-weight: 700; color: var(--success); word-break: break-all; }
    .copy-btn { width: 100%; padding: 0.875rem; background: var(--surface); border: 1px solid var(--border); color: var(--text); }
    .copy-btn:hover { border-color: var(--primary); color: var(--primary); }
    .info-box { background: rgba(0,255,157,0.05); border: 1px solid rgba(0,255,157,0.2); border-radius: 8px; padding: 1rem; margin-top: 1rem; font-size: 0.875rem; color: var(--text-dim); }
    .error-box { background: rgba(255,77,109,0.1); border: 1px solid var(--error); border-radius: 8px; padding: 1rem; margin-top: 1rem; font-size: 0.875rem; color: var(--error); text-align: center; display: none; }
    @media (max-width: 640px) { .container { padding: 1rem; } .card { padding: 1.5rem; } .title { font-size: 1.5rem; } }
  </style>
</head>
<body>
  <div class="bg-grid"></div>
  <div class="container">
    <div class="card">
      <h1 class="title">Get Your Key</h1>
      <p class="subtitle" id="domainDisplay">Loading...</p>

      <div class="steps">
        <div class="step" id="startCard">
          <div class="step-number">S</div>
          <div class="step-content">
            <div class="step-title">Start</div>
            <div class="step-desc">Complete this step first</div>
          </div>
          <div class="step-action">
            <a href="#" class="btn btn-primary" id="startBtn" target="_blank">Start</a>
          </div>
        </div>

        <div class="step" id="step1Card" style="display:none;">
          <div class="step-number">1</div>
          <div class="step-content">
            <div class="step-title">Complete Step 1</div>
            <div class="step-desc">Visit the link and complete the checkpoint</div>
          </div>
          <div class="step-action">
            <button class="btn btn-primary" id="step1Btn" disabled>Start</button>
          </div>
        </div>

        <div class="step" id="step2Card" style="display:none;">
          <div class="step-number">2</div>
          <div class="step-content">
            <div class="step-title">Complete Step 2</div>
            <div class="step-desc">Visit the second link and complete</div>
          </div>
          <div class="step-action">
            <button class="btn btn-primary" id="step2Btn" disabled>Start</button>
          </div>
        </div>
      </div>

      <div class="create-key-section" id="createSection">
        <button class="btn btn-create" id="createKeyBtn">Generate Key</button>
        <div class="key-result" id="keyResult">
          <div class="key-box">
            <div class="key-label">Your Key</div>
            <div class="key-value" id="keyValue">LOADING...</div>
          </div>
          <button class="btn copy-btn" id="copyBtn">Copy Key</button>
          <div class="info-box">
            ✓ Key expires in 24 hours<br>
            ✓ Total keys created: <span id="keyCount">0</span>
          </div>
        </div>
      </div>

      <div class="error-box" id="errorBox"></div>
    </div>
  </div>

  <script type="module">
    import API_BASE from './api-base.js';

    const urlParams = new URLSearchParams(window.location.search);
    const hash      = urlParams.get('hash') || '';

    // domain: từ URL trước, hoặc localStorage khi Linkvertise redirect về không có ?domain
    let domain = urlParams.get('domain') || localStorage.getItem('ntt_domain') || '';

    // Callback types — Linkvertise destination phải dùng các param này:
    // Start:  /key.html?start_done&hash={hash}
    // Step1:  /key.html?step1_done&hash={hash}
    // Step2:  /key.html?step2_done&hash={hash}
    // Nhận cả dạng cũ (?start/?step1/?step2) lẫn dạng mới (?start_done/?step1_done/?step2_done)
    const isStartDone = urlParams.has('start_done') || urlParams.has('start');
    const isStep1Done = urlParams.has('step1_done') || urlParams.has('step1');
    const isStep2Done = urlParams.has('step2_done') || urlParams.has('step2');
    const isCallback  = isStartDone || isStep1Done || isStep2Done;
    const hasValidHash = hash.length > 10;

    let settings = null;
    let hwid     = null;

    function generateHWID() {
      const canvas = document.createElement('canvas');
      const ctx    = canvas.getContext('2d');
      ctx.textBaseline = 'top'; ctx.font = '14px Arial';
      ctx.fillText('NTT fingerprint', 2, 2);
      const fp   = canvas.toDataURL();
      const data = navigator.userAgent + fp + screen.width + screen.height + navigator.language;
      let h = 0;
      for (let i = 0; i < data.length; i++) { h = ((h << 5) - h) + data.charCodeAt(i); h = h & h; }
      return ('HWID_' + Math.abs(h).toString(36).toUpperCase()).slice(0, 50);
    }

    function showError(msg) {
      const b = document.getElementById('errorBox');
      b.textContent = msg; b.style.display = 'block';
    }

    function checkSavedKey() {
      const savedKey    = localStorage.getItem('ntt_generated_key');
      const savedDomain = localStorage.getItem('ntt_key_domain');
      const savedHwid   = localStorage.getItem('ntt_key_hwid');
      const curHwid     = generateHWID();

      // Khác domain hoặc khác hwid → xóa key cũ, không hiện
      if (savedKey && (savedDomain !== domain || savedHwid !== curHwid)) {
        localStorage.removeItem('ntt_generated_key');
        localStorage.removeItem('ntt_key_domain');
        localStorage.removeItem('ntt_key_hwid');
        return false;
      }

      // Đúng domain + đúng hwid → hiện lại key
      if (savedKey && savedDomain === domain && savedHwid === curHwid) {
        document.getElementById('domainDisplay').textContent = domain;
        markStepComplete('start');
        document.getElementById('step1Card').style.display = 'flex';
        markStepComplete(1);
        const section = document.getElementById('createSection');
        section.style.display = 'block';
        section.classList.add('active');
        document.getElementById('createKeyBtn').style.display = 'none';
        document.getElementById('keyValue').textContent = savedKey;
        document.getElementById('keyResult').classList.add('active');
        return true;
      }
      return false;
    }

    async function loadSettings() {
      if (!domain) { showError('No domain specified'); return; }
      try {
        const res  = await fetch(`${API_BASE}/?type=get_settings_by_domain&domain=${encodeURIComponent(domain)}`);
        const data = await res.json();
        if (!data.success) { showError('Domain not found'); return; }

        settings = data.settings;
        document.getElementById('domainDisplay').textContent = settings.website_domain;

        // Start link của hệ thống, destination phải là: /key.html?start_done&hash={hash}
        document.getElementById('startBtn').href = settings.start_link;

        if (settings.ad_steps === 2) document.getElementById('step2Card').style.display = 'flex';

        hwid = localStorage.getItem('ntt_hwid') || generateHWID();
        localStorage.setItem('ntt_hwid', hwid);

        await checkProgress();
        setInterval(checkProgress, 4000);
      } catch { showError('Failed to load settings'); }
    }

    document.getElementById('startBtn').addEventListener('click', () => {
      // Lưu domain + hwid trước khi rời trang sang Linkvertise
      localStorage.setItem('ntt_domain', domain);
      localStorage.setItem('ntt_hwid', hwid || generateHWID());
    });

    async function checkProgress() {
      if (!hwid || !settings) return;
      try {
        const res  = await fetch(`${API_BASE}/?type=progress&hwid=${encodeURIComponent(hwid)}`);
        const data = await res.json();
        if (!data.status) return;

        if (data.start) {
          markStepComplete('start');
        }

        if (data.step1) {
          // step1 done = start cũng done
          markStepComplete('start');
          markStepComplete(1);
          if (settings.ad_steps === 1) {
            showCreateButton();
          } else if (data.step2) {
            markStepComplete(2);
            showCreateButton();
          } else {
            enableStep2();
          }
        } else if (data.start) {
          // start done nhưng chưa step1
          enableStep1();
        }
      } catch {}
    }

    function enableStep1() {
      const card = document.getElementById('step1Card');
      card.style.display = 'flex'; card.classList.add('active-step');
      const btn = document.getElementById('step1Btn');
      btn.disabled = false;
      btn.onclick = () => {
        localStorage.setItem('ntt_domain', domain);
        localStorage.setItem('ntt_hwid', hwid);
        window.open(settings.step1_link, '_blank');
      };
    }

    function enableStep2() {
      const card = document.getElementById('step2Card');
      card.style.display = 'flex'; card.classList.add('active-step');
      const btn = document.getElementById('step2Btn');
      btn.disabled = false;
      btn.onclick = () => {
        localStorage.setItem('ntt_domain', domain);
        localStorage.setItem('ntt_hwid', hwid);
        window.open(settings.step2_link, '_blank');
      };
    }

    function markStepComplete(step) {
      const id   = step === 'start' ? 'startCard' : `step${step}Card`;
      const card = document.getElementById(id);
      card.classList.remove('active-step'); card.classList.add('completed');
      const btn = card.querySelector('.btn');
      btn.className = 'btn btn-success';
      btn.innerHTML = '<span class="checkmark">✓</span> Completed';
      btn.style.pointerEvents = 'none';
    }

    function showCreateButton() {
      const s = document.getElementById('createSection');
      s.style.display = 'block'; s.classList.add('active');
    }

    async function completeStep(step) {
      try {
        const res  = await fetch(`${API_BASE}/?type=complete_step`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ hwid, step, hash, domain }),
        });
        const data = await res.json();
        return data.success;
      } catch { return false; }
    }

    document.getElementById('createKeyBtn').addEventListener('click', async () => {
      const btn = document.getElementById('createKeyBtn');
      btn.disabled = true; btn.textContent = 'Generating...';
      try {
        const res  = await fetch(`${API_BASE}/?type=create_key`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ hwid, domain: settings.website_domain, key_prefix: settings.key_domain }),
        });
        const data = await res.json();
        if (data.success) {
          document.getElementById('keyValue').textContent = data.key;
          document.getElementById('keyCount').textContent = data.total_keys || 1;
          document.getElementById('keyResult').classList.add('active');
          btn.style.display = 'none';
          // Lưu key để không mất khi reload — gắn với hwid + domain
          localStorage.setItem('ntt_generated_key',    data.key);
          localStorage.setItem('ntt_key_domain',       domain);
          localStorage.setItem('ntt_key_hwid',         hwid);
          localStorage.removeItem('ntt_domain');
          localStorage.removeItem('ntt_hwid');
        } else {
          showError(data.error || 'Failed to create key');
          btn.disabled = false; btn.textContent = 'Generate Key';
        }
      } catch {
        showError('Connection error');
        btn.disabled = false; btn.textContent = 'Generate Key';
      }
    });

    document.getElementById('copyBtn').addEventListener('click', () => {
      navigator.clipboard.writeText(document.getElementById('keyValue').textContent).then(() => {
        const btn = document.getElementById('copyBtn');
        btn.textContent = '✓ Copied!';
        setTimeout(() => { btn.textContent = 'Copy Key'; }, 2000);
      });
    });

    // ═══════════════════════════════════════════════════════
    // INIT
    // ═══════════════════════════════════════════════════════
    async function init() {

      // ── Callback từ Linkvertise (có start_done / step1_done / step2_done) ──
      if (isCallback) {
        // domain: ưu tiên từ URL, fallback localStorage (khi admin link không có domain)
        domain = urlParams.get('domain') || localStorage.getItem('ntt_domain') || '';
        hwid   = localStorage.getItem('ntt_hwid') || generateHWID();

        if (!domain) {
          showError('Session lost. Please go back and start over.');
          return;
        }

        if (!hasValidHash) {
          showError('Invalid access detected.');
          setTimeout(() => window.location.replace(`/key.html?domain=${encodeURIComponent(domain)}`), 1500);
          return;
        }

        // Lưu lại để chắc chắn
        localStorage.setItem('ntt_domain', domain);
        localStorage.setItem('ntt_hwid',   hwid);

        const step = isStartDone ? 'start' : isStep1Done ? 1 : 2;
        const ok   = await completeStep(step);

        if (ok) {
          window.location.replace(`/key.html?domain=${encodeURIComponent(domain)}`);
        } else {
          showError('Verification failed. Redirecting...');
          setTimeout(() => window.location.replace(`/key.html?domain=${encodeURIComponent(domain)}`), 2000);
        }
        return;
      }

      // ── Normal flow: ?domain=xxx ─────────────────────────
      if (urlParams.get('domain')) {
        localStorage.setItem('ntt_domain', domain);
      }

      if (!domain) {
        showError('No domain specified. Please use the correct link.');
        return;
      }

      // Nếu đã có key đúng domain + hwid → hiện luôn, không cần load lại
      if (checkSavedKey()) return;

      await loadSettings();
    }

    init();
  </script>
</body>
</html>
