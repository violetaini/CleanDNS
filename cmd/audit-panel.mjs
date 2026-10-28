import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';

const url = process.env.CLEANDNS_AUDIT_URL;
const username = process.env.CLEANDNS_AUDIT_USERNAME;
const password = process.env.CLEANDNS_AUDIT_PASSWORD;
const outputDir = path.resolve(process.env.CLEANDNS_AUDIT_OUTPUT || 'audit-panel');
const chromePath = process.env.CHROME_PATH || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const extraChromeArgs = parseStringArrayEnv('CLEANDNS_AUDIT_CHROME_ARGS_JSON');
const directApi = process.env.CLEANDNS_AUDIT_DIRECT_API === '1';
const allowInsecureCookie = process.env.CLEANDNS_AUDIT_ALLOW_INSECURE_COOKIE === '1';
const themeWrite = process.env.CLEANDNS_AUDIT_THEME_WRITE === '1';
const responseFilterFixture = process.env.CLEANDNS_AUDIT_RESPONSE_FILTER === '1';

if (!url || !username || !password) throw new Error('CLEANDNS_AUDIT_URL, CLEANDNS_AUDIT_USERNAME, and CLEANDNS_AUDIT_PASSWORD are required');
if (!fs.existsSync(chromePath)) throw new Error(`Chrome not found: ${chromePath}`);

async function runAudit() {
fs.mkdirSync(outputDir, { recursive: true });
const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cleandns-audit-chrome-'));
const port = await unusedPort();
const chrome = spawn(chromePath, [
  '--headless=new',
  '--no-sandbox',
  '--disable-gpu',
  '--disable-software-rasterizer',
  '--disable-extensions',
  '--no-first-run',
  '--no-default-browser-check',
  `--remote-debugging-port=${port}`,
  `--user-data-dir=${profileDir}`,
  ...extraChromeArgs,
  'about:blank'
], { stdio: 'ignore', windowsHide: true });

let client;
try {
  await waitFor(async () => (await fetchJson(`http://127.0.0.1:${port}/json/version`))?.webSocketDebuggerUrl, 10_000);
  const target = await fetchJson(`http://127.0.0.1:${port}/json/new?about:blank`, { method: 'PUT' });
  client = await CdpClient.connect(target.webSocketDebuggerUrl);
  await Promise.all([
    client.send('Page.enable'),
    client.send('Runtime.enable'),
    client.send('Log.enable'),
    client.send('Network.enable')
  ]);
  if (allowInsecureCookie) {
    const loginUrl = new URL('/api/login', url);
    const loginResponse = await fetch(loginUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    if (!loginResponse.ok) throw new Error(`audit bootstrap login failed: HTTP ${loginResponse.status}`);
    const session = String(loginResponse.headers.get('set-cookie') || '').match(/cleandns_session=([^;]+)/)?.[1];
    if (!session) throw new Error('audit bootstrap login did not return a session cookie');
    await client.send('Network.setCookie', {
      name: 'cleandns_session',
      value: decodeURIComponent(session),
      url: loginUrl.origin,
      path: '/',
      secure: false,
      httpOnly: true,
      sameSite: 'Lax'
    });
  }
  if (directApi) {
    await client.send('Page.addScriptToEvaluateOnNewDocument', {
      source: `(() => {
        const nativeFetch = window.fetch.bind(window);
        window.fetch = (input, init) => {
          if (typeof input === 'string' && input.startsWith('/')) {
            const hiddenPrefix = '/rpc-7k3n9p2v';
            input = input.startsWith(hiddenPrefix)
              ? '/api' + input.slice(hiddenPrefix.length)
              : input.startsWith('/api/') ? input : '/api' + input;
          }
          return nativeFetch(input, init);
        };
      })();`
    });
  }

  const browserErrors = [];
  client.on('Runtime.exceptionThrown', (event) => browserErrors.push(event.exceptionDetails?.exception?.description || event.exceptionDetails?.text || 'runtime_exception'));
  client.on('Log.entryAdded', (event) => {
    if (event.entry?.level === 'error') browserErrors.push(event.entry.text || 'browser_error');
  });

  await setViewport(client, 1440, 1000, 1, false);
  await navigate(client, url);
  const panelShell = await evaluateValue(client, `({
    ready: Boolean(document.getElementById('loginView') && document.getElementById('appView')),
    location: location.href,
    title: document.title,
    text: document.body?.innerText?.slice(0, 240) || ''
  })`);
  if (!panelShell.ready) {
    throw new Error(`audit did not load the CleanDNS panel: ${JSON.stringify(panelShell)}`);
  }
  if (allowInsecureCookie) {
    const bootstrap = await evaluateValue(client, `(async () => {
      const response = await fetch('/api/session', { credentials: 'same-origin' });
      return {
        status: response.status,
        body: await response.text(),
        loginHidden: document.getElementById('loginView')?.classList.contains('hidden'),
        appHidden: document.getElementById('appView')?.classList.contains('hidden')
      };
    })()`);
    if (bootstrap.status !== 200 || !/"authenticated":true/.test(bootstrap.body)) {
      throw new Error(`audit bootstrap session failed: ${JSON.stringify(bootstrap)}`);
    }
    await sleep(500);
    const bootState = await evaluateValue(client, `({
      appHidden: document.getElementById('appView')?.classList.contains('hidden'),
      loginHidden: document.getElementById('loginView')?.classList.contains('hidden'),
      stateDefined: typeof state !== 'undefined',
      hasStatus: Boolean(typeof state !== 'undefined' && state.status),
      notice: document.getElementById('loginNotice')?.textContent || ''
    })`);
    if (bootState.appHidden && browserErrors.length) {
      throw new Error(`audit panel bootstrap failed: ${JSON.stringify({ bootState, browserErrors })}`);
    }
  }
  if (!allowInsecureCookie) {
    await evaluate(client, `(() => {
      document.getElementById('username').value = ${JSON.stringify(username)};
      document.getElementById('password').value = ${JSON.stringify(password)};
      document.getElementById('loginForm').requestSubmit();
      return true;
    })()`);
  }
  try {
    await waitFor(() => evaluateValue(client, `document.getElementById('appView') && !document.getElementById('appView').classList.contains('hidden')`), 15_000);
    await waitFor(() => evaluateValue(client, `Boolean(typeof state !== 'undefined' && state.status && state.settings)`), 15_000);
  } catch (err) {
    const loginState = await evaluateValue(client, `({
      location: location.href,
      appHidden: document.getElementById('appView')?.classList.contains('hidden'),
      loginHidden: document.getElementById('loginView')?.classList.contains('hidden'),
      notice: document.getElementById('loginNotice')?.textContent || '',
      button: document.getElementById('loginButton')?.textContent || '',
      buttonDisabled: document.getElementById('loginButton')?.disabled === true,
      authenticated: typeof state !== 'undefined' && state.authenticated === true,
      hasStatus: Boolean(typeof state !== 'undefined' && state.status),
      hasSettings: Boolean(typeof state !== 'undefined' && state.settings)
    })`);
    throw new Error(`audit login bootstrap failed: ${JSON.stringify({ loginState, browserErrors, cause: err.message })}`);
  }

  await showSettings(client);
  const desktopSettings = await layoutMetrics(client);
  const desktopAppShell = await evaluateValue(client, `(() => {
    const header = document.querySelector('.topbar-inner').getBoundingClientRect();
    const main = document.querySelector('main').getBoundingClientRect();
    const protection = document.getElementById('headerProtectionStatus');
    const refresh = document.getElementById('refresh');
    return {
      headerWidth: Math.round(header.width),
      mainWidth: Math.round(main.width),
      sameGrid: Math.abs(header.left - main.left) <= 1 && Math.abs(header.right - main.right) <= 1,
      compactWidth: header.width <= 1200,
      protectionVisible: protection.getClientRects().length > 0 && !protection.classList.contains('hidden'),
      refreshHidden: getComputedStyle(refresh).display === 'none'
    };
  })()`);
  const desktopInteraction = await evaluateValue(client, `(async () => {
    const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    const toggleIds = ['protectionEnabled', 'safeBrowsingEnabled', 'parentalEnabled', 'safeSearchEnabled'];
    const providerIds = ['safeSearchBing', 'safeSearchDuckduckgo', 'safeSearchEcosia', 'safeSearchGoogle', 'safeSearchPixabay', 'safeSearchYandex', 'safeSearchYoutube'];
    const initial = Object.fromEntries(toggleIds.map((id) => [id, document.getElementById(id).checked]));
    const initialProviders = Object.fromEntries(providerIds.map((id) => [id, document.getElementById(id).checked]));
    const initialMeta = document.getElementById('safeSearchProvidersMeta').textContent.trim();
    const safeBrowsing = document.getElementById('safeBrowsingEnabled');
    const safeSearch = document.getElementById('safeSearchEnabled');
    const opener = document.getElementById('openSafeSearchConfig');
    const firstProvider = document.getElementById(providerIds[0]);

    safeBrowsing.click();
    const browsingChanged = {
      checked: safeBrowsing.checked,
      dirty: state.settingsDirty,
      payloadMatches: settingsPayload().safeBrowsingEnabled === safeBrowsing.checked,
      saveEnabled: !document.getElementById('saveSettings').disabled
    };
    safeBrowsing.click();

    safeSearch.click();
    const safeSearchChanged = {
      checked: safeSearch.checked,
      dirty: state.settingsDirty,
      payloadMatches: settingsPayload().safeSearch.enabled === safeSearch.checked
    };
    safeSearch.click();

    safeSearch.checked = false;
    safeSearch.dispatchEvent(new Event('change', { bubbles: true }));
    const providersEditableWhenDisabled = providerIds.every((id) => !document.getElementById(id).disabled);
    safeSearch.checked = initial.safeSearchEnabled;
    safeSearch.dispatchEvent(new Event('change', { bubbles: true }));

    opener.focus();
    opener.click();
    await wait(30);
    const cancelDialog = {
      visible: !document.getElementById('safeSearchConfigModal').classList.contains('hidden'),
      title: document.getElementById('safeSearchConfigTitle').textContent.trim(),
      focused: document.activeElement === firstProvider,
      providers: document.querySelectorAll('#safeSearchProviders input').length,
      parentInModal: document.getElementById('safeSearchProviders').closest('#safeSearchConfigModal') !== null
    };
    firstProvider.click();
    cancelDialog.dirtyBeforeCancel = state.settingsDirty;
    document.getElementById('cancelSafeSearchConfig').click();
    await wait(30);
    cancelDialog.restored = providerIds.every((id) => document.getElementById(id).checked === initialProviders[id]);
    cancelDialog.closed = document.getElementById('safeSearchConfigModal').classList.contains('hidden');
    cancelDialog.focusRestored = document.activeElement === opener;
    cancelDialog.dirtyAfterCancel = state.settingsDirty;

    opener.focus();
    opener.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }));
    await wait(30);
    const keyboardOpened = !document.getElementById('safeSearchConfigModal').classList.contains('hidden') && document.activeElement === firstProvider;
    firstProvider.click();
    document.getElementById('applySafeSearchConfig').click();
    await wait(30);
    const applied = {
      closed: document.getElementById('safeSearchConfigModal').classList.contains('hidden'),
      dirty: state.settingsDirty,
      payloadMatches: settingsPayload().safeSearch.bing === firstProvider.checked,
      meta: document.getElementById('safeSearchProvidersMeta').textContent.trim(),
      metaChanged: document.getElementById('safeSearchProvidersMeta').textContent.trim() !== initialMeta,
      focusRestored: document.activeElement === opener
    };

    firstProvider.checked = initialProviders[firstProvider.id];
    firstProvider.dispatchEvent(new Event('change', { bubbles: true }));
    handleSettingsChange();
    opener.scrollIntoView({ block: 'center' });
    const rowRect = opener.getBoundingClientRect();
    const toggleRect = opener.querySelector('.settings-toggle').getBoundingClientRect();
    return {
      initial,
      browsingChanged,
      safeSearchChanged,
      providersEditableWhenDisabled,
      cancelDialog,
      keyboardOpened,
      applied,
      rowCount: document.querySelectorAll('#generalProtectionRows .settings-link-row').length,
      modernToggleCount: toggleIds.filter((id) => document.getElementById(id).closest('.settings-toggle')).length,
      switchLinkColumns: getComputedStyle(opener).gridTemplateColumns.split(/\\s+/).filter(Boolean).length,
      toggleInside: toggleRect.left >= rowRect.left && toggleRect.right <= rowRect.right,
      oldStateAbsent: !document.getElementById('safeSearchState'),
      providersInModal: document.getElementById('safeSearchProviders').closest('#safeSearchConfigModal') !== null,
      restored: toggleIds.every((id) => document.getElementById(id).checked === initial[id])
        && providerIds.every((id) => document.getElementById(id).checked === initialProviders[id])
        && document.getElementById('safeSearchProvidersMeta').textContent.trim() === initialMeta
        && state.settingsDirty === false
    };
  })()`);
  await screenshot(client, path.join(outputDir, 'desktop-general.png'));

  const desktopSafeSearchDialog = await evaluateValue(client, `(async () => {
    const opener = document.getElementById('openSafeSearchConfig');
    opener.focus();
    opener.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 30));
    const modal = document.querySelector('#safeSearchConfigModal .modal').getBoundingClientRect();
    const rows = [...document.querySelectorAll('#safeSearchProviders .safe-search-provider')].map((row) => row.getBoundingClientRect());
    return {
      visible: !document.getElementById('safeSearchConfigModal').classList.contains('hidden'),
      focused: document.activeElement === document.getElementById('safeSearchBing'),
      insideViewport: modal.left >= 0 && modal.right <= innerWidth && modal.top >= 0 && modal.bottom <= innerHeight,
      providers: rows.length,
      rowsInside: rows.every((rect) => rect.left >= modal.left && rect.right <= modal.right)
    };
  })()`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'desktop-safe-search-dialog.png'));
  await evaluate(client, `cancelSafeSearchConfig(); true`);

  const desktopStatsInteraction = await evaluateValue(client, `(async () => {
    const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    selectView('dns', { skipUrl: true });
    selectSettingsSection('stats', { history: 'replace' });
    await loadSettings({ force: true });
    const master = document.getElementById('statsEnabled');
    const ignoredToggle = document.getElementById('statsIgnoredEnabled');
    const retentionPreset = document.getElementById('statsRetentionPreset');
    const retentionInput = document.getElementById('statsRetentionHours');
    const ignoredField = document.getElementById('statsIgnoredDomains');
    const initial = {
      enabled: master.checked,
      ignoredEnabled: ignoredToggle.checked,
      retention: retentionHoursValue('stats'),
      ignored: ignoredField.value
    };

    master.click();
    const masterChanged = {
      enabled: master.checked,
      dirty: state.settingsDirty,
      payloadMatches: settingsPayload().statsEnabled === master.checked,
      retentionDisabled: document.getElementById('openStatsRetention').disabled,
      ignoredRowDisabled: document.getElementById('openStatsIgnoredDomains').classList.contains('is-disabled'),
      ignoredToggleDisabled: ignoredToggle.disabled
    };
    master.click();

    const retentionOpener = document.getElementById('openStatsRetention');
    retentionOpener.focus();
    retentionOpener.click();
    await wait(30);
    const alternate = initial.retention === 168 ? '24' : '168';
    document.querySelector('[data-retention-kind="stats"][data-retention-value="' + alternate + '"]').click();
    const retentionCancel = {
      visible: !document.getElementById('statsRetentionModal').classList.contains('hidden'),
      focusedOption: document.activeElement?.dataset?.retentionKind === 'stats' || document.activeElement === retentionInput,
      dirtyBeforeCancel: state.settingsDirty
    };
    document.getElementById('cancelStatsRetention').click();
    await wait(30);
    retentionCancel.restored = retentionHoursValue('stats') === initial.retention;
    retentionCancel.closed = document.getElementById('statsRetentionModal').classList.contains('hidden');
    retentionCancel.focusRestored = document.activeElement === retentionOpener;
    retentionCancel.dirtyAfterCancel = state.settingsDirty;

    retentionOpener.focus();
    retentionOpener.click();
    await wait(30);
    document.querySelector('[data-retention-kind="stats"][data-retention-value="custom"]').click();
    await wait(20);
    const decreased = Math.max(1, initial.retention - 1);
    retentionInput.value = String(decreased);
    retentionInput.dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('applyStatsRetention').click();
    const decreaseConfirm = {
      applicable: decreased < initial.retention,
      warningVisible: !document.getElementById('statsRetentionDecreaseWarning').classList.contains('hidden'),
      buttonText: document.getElementById('applyStatsRetention').textContent.trim(),
      stillOpen: !document.getElementById('statsRetentionModal').classList.contains('hidden')
    };
    document.getElementById('applyStatsRetention').click();
    await wait(30);
    const retentionApplied = {
      closed: document.getElementById('statsRetentionModal').classList.contains('hidden'),
      dirty: state.settingsDirty,
      payloadMatches: settingsPayload().statsRetentionHours === decreased,
      meta: document.getElementById('statsRetentionMeta').textContent.trim(),
      focusRestored: document.activeElement === retentionOpener
    };
    setRetentionControl('stats', initial.retention);
    handleSettingsChange();

    const ignoredOpener = document.getElementById('openStatsIgnoredDomains');
    ignoredOpener.focus();
    ignoredOpener.click();
    await wait(30);
    ignoredField.value = initial.ignored + (initial.ignored ? '\\n' : '') + 'cancel-stats.audit';
    ignoredField.dispatchEvent(new Event('input', { bubbles: true }));
    const ignoredCancel = {
      visible: !document.getElementById('statsIgnoredModal').classList.contains('hidden'),
      focused: document.activeElement === ignoredField,
      dirtyBeforeCancel: state.settingsDirty
    };
    document.getElementById('cancelStatsIgnored').click();
    await wait(30);
    ignoredCancel.restored = ignoredField.value === initial.ignored;
    ignoredCancel.closed = document.getElementById('statsIgnoredModal').classList.contains('hidden');
    ignoredCancel.focusRestored = document.activeElement === ignoredOpener;
    ignoredCancel.dirtyAfterCancel = state.settingsDirty;

    ignoredOpener.focus();
    ignoredOpener.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }));
    await wait(30);
    ignoredField.value = 'invalid domain!';
    ignoredField.dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('applyStatsIgnored').click();
    const invalidPrevented = !document.getElementById('statsIgnoredModal').classList.contains('hidden') && !ignoredField.checkValidity();
    ignoredField.value = 'stats-audit.example\\nstats-audit.example\\nhttps://probe-stats.example/path';
    ignoredField.dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('applyStatsIgnored').click();
    await wait(30);
    const ignoredApplied = {
      closed: document.getElementById('statsIgnoredModal').classList.contains('hidden'),
      normalized: ignoredField.value === 'stats-audit.example\\nprobe-stats.example',
      dirty: state.settingsDirty,
      payloadMatches: JSON.stringify(settingsPayload().statsIgnoredDomains) === JSON.stringify(['stats-audit.example', 'probe-stats.example']),
      meta: document.getElementById('statsIgnoredMeta').textContent.trim(),
      focusRestored: document.activeElement === ignoredOpener
    };
    ignoredField.value = initial.ignored;
    ignoredField.dispatchEvent(new Event('input', { bubbles: true }));
    ignoredToggle.checked = initial.ignoredEnabled;
    handleSettingsChange();

    document.getElementById('clearStats').focus();
    document.getElementById('clearStats').click();
    await wait(30);
    const clearConfirm = {
      visible: !document.getElementById('dataClearModal').classList.contains('hidden'),
      title: document.getElementById('dataClearTitle').textContent.trim(),
      focused: document.activeElement === document.getElementById('confirmDataClear')
    };
    document.getElementById('cancelDataClear').click();
    await wait(30);
    clearConfirm.closed = document.getElementById('dataClearModal').classList.contains('hidden');
    clearConfirm.focusRestored = document.activeElement === document.getElementById('clearStats');

    document.getElementById('settings-section-stats').scrollIntoView({ block: 'start' });
    return {
      initial,
      masterChanged,
      retentionCancel,
      decreaseConfirm,
      retentionApplied,
      ignoredCancel,
      invalidPrevented,
      ignoredApplied,
      clearConfirm,
      rowCount: document.querySelectorAll('#statsSettingsRows .settings-link-row').length,
      modernToggleCount: ['statsEnabled', 'statsIgnoredEnabled'].filter((id) => document.getElementById(id).closest('.settings-toggle')).length,
      oldModulesAbsent: !document.getElementById('stats-module-ignore') && !document.getElementById('stats-module-summary') && !document.getElementById('statsSettingsSummary') && !document.getElementById('statsSettingsState'),
      restored: master.checked === initial.enabled && ignoredToggle.checked === initial.ignoredEnabled && retentionHoursValue('stats') === initial.retention && ignoredField.value === initial.ignored && state.settingsDirty === false
    };
  })()`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'desktop-stats-settings.png'));

  const desktopStatsRetentionDialog = await evaluateValue(client, `(async () => {
    document.getElementById('openStatsRetention').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const modal = document.querySelector('#statsRetentionModal .modal').getBoundingClientRect();
    const grid = document.getElementById('statsRetentionOptions');
    return {
      visible: !document.getElementById('statsRetentionModal').classList.contains('hidden'),
      insideViewport: modal.left >= 0 && modal.right <= innerWidth && modal.top >= 0 && modal.bottom <= innerHeight,
      options: grid.querySelectorAll('.retention-option').length,
      columns: getComputedStyle(grid).gridTemplateColumns.split(/\\s+/).filter(Boolean).length,
      active: grid.querySelectorAll('.retention-option.active').length,
      focusedOption: document.activeElement?.dataset?.retentionKind === 'stats'
    };
  })()`);
  await screenshot(client, path.join(outputDir, 'desktop-stats-retention-dialog.png'));
  await evaluate(client, `cancelRetentionConfig('stats'); true`);

  const desktopQueryLogInteraction = await evaluateValue(client, `(async () => {
    const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    selectView('dns', { skipUrl: true });
    selectSettingsSection('querylog', { history: 'replace' });
    await loadSettings({ force: true });
    const master = document.getElementById('queryLogEnabled');
    const anonymize = document.getElementById('queryLogAnonymizeClientIp');
    const ignoredToggle = document.getElementById('queryLogIgnoredEnabled');
    const retentionInput = document.getElementById('queryLogRetentionHours');
    const capacity = document.getElementById('queryLogMaxEntries');
    const ignoredField = document.getElementById('queryLogIgnoredDomains');
    const initial = {
      enabled: master.checked,
      anonymize: anonymize.checked,
      ignoredEnabled: ignoredToggle.checked,
      retention: retentionHoursValue('queryLog'),
      capacity: capacity.value,
      ignored: ignoredField.value
    };

    master.click();
    const masterChanged = {
      enabled: master.checked,
      dirty: state.settingsDirty,
      payloadMatches: settingsPayload().queryLogEnabled === master.checked,
      anonymizeDisabled: anonymize.disabled,
      retentionDisabled: document.getElementById('openQueryLogRetention').disabled,
      capacityDisabled: document.getElementById('openQueryLogCapacity').disabled,
      ignoredDisabled: ignoredToggle.disabled && document.getElementById('openQueryLogIgnoredDomains').classList.contains('is-disabled')
    };
    master.click();
    anonymize.click();
    const anonymizeChanged = { checked: anonymize.checked, dirty: state.settingsDirty, payloadMatches: settingsPayload().queryLogAnonymizeClientIp === anonymize.checked };
    anonymize.click();

    const retentionOpener = document.getElementById('openQueryLogRetention');
    retentionOpener.focus();
    retentionOpener.click();
    await wait(30);
    document.querySelector('[data-retention-kind="queryLog"][data-retention-value="custom"]').click();
    await wait(20);
    const decreased = Math.max(1, initial.retention - 1);
    retentionInput.value = String(decreased);
    retentionInput.dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('applyQueryLogRetention').click();
    const decreaseConfirm = {
      applicable: decreased < initial.retention,
      warningVisible: !document.getElementById('queryLogRetentionDecreaseWarning').classList.contains('hidden'),
      buttonText: document.getElementById('applyQueryLogRetention').textContent.trim(),
      stillOpen: !document.getElementById('queryLogRetentionModal').classList.contains('hidden')
    };
    document.getElementById('applyQueryLogRetention').click();
    await wait(30);
    const retentionApplied = {
      closed: document.getElementById('queryLogRetentionModal').classList.contains('hidden'),
      dirty: state.settingsDirty,
      payloadMatches: settingsPayload().queryLogRetentionHours === decreased,
      focusRestored: document.activeElement === retentionOpener
    };
    setRetentionControl('queryLog', initial.retention);
    handleSettingsChange();

    const capacityOpener = document.getElementById('openQueryLogCapacity');
    const changedCapacity = String(Number(initial.capacity) >= 5000 ? Number(initial.capacity) - 20 : Number(initial.capacity) + 20);
    capacityOpener.focus();
    capacityOpener.click();
    await wait(30);
    capacity.value = changedCapacity;
    capacity.dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('cancelQueryLogCapacity').click();
    await wait(30);
    const capacityCancel = { restored: capacity.value === initial.capacity, closed: document.getElementById('queryLogCapacityModal').classList.contains('hidden'), focusRestored: document.activeElement === capacityOpener, dirty: state.settingsDirty };
    capacityOpener.click();
    await wait(20);
    capacity.value = changedCapacity;
    capacity.dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('applyQueryLogCapacity').click();
    await wait(30);
    const capacityApplied = { closed: document.getElementById('queryLogCapacityModal').classList.contains('hidden'), dirty: state.settingsDirty, payloadMatches: settingsPayload().queryLogMaxEntries === Number(changedCapacity), meta: document.getElementById('queryLogCapacityMeta').textContent.trim() };
    capacity.value = initial.capacity;
    capacity.dispatchEvent(new Event('input', { bubbles: true }));

    const ignoredOpener = document.getElementById('openQueryLogIgnoredDomains');
    ignoredOpener.focus();
    ignoredOpener.click();
    await wait(30);
    ignoredField.value = 'log-audit.example\\nlog-audit.example\\nhttps://probe-log.example/path';
    ignoredField.dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('applyQueryLogIgnored').click();
    await wait(30);
    const ignoredApplied = {
      closed: document.getElementById('queryLogIgnoredModal').classList.contains('hidden'),
      normalized: ignoredField.value === 'log-audit.example\\nprobe-log.example',
      dirty: state.settingsDirty,
      payloadMatches: JSON.stringify(settingsPayload().queryLogIgnoredDomains) === JSON.stringify(['log-audit.example', 'probe-log.example']),
      meta: document.getElementById('queryLogIgnoredMeta').textContent.trim(),
      focusRestored: document.activeElement === ignoredOpener
    };
    ignoredField.value = initial.ignored;
    ignoredField.dispatchEvent(new Event('input', { bubbles: true }));
    ignoredToggle.checked = initial.ignoredEnabled;
    handleSettingsChange();

    document.getElementById('clearQueryLogSettings').focus();
    document.getElementById('clearQueryLogSettings').click();
    await wait(30);
    const clearConfirm = {
      visible: !document.getElementById('dataClearModal').classList.contains('hidden'),
      title: document.getElementById('dataClearTitle').textContent.trim(),
      focused: document.activeElement === document.getElementById('confirmDataClear')
    };
    document.getElementById('cancelDataClear').click();
    await wait(30);
    clearConfirm.closed = document.getElementById('dataClearModal').classList.contains('hidden');
    clearConfirm.focusRestored = document.activeElement === document.getElementById('clearQueryLogSettings');

    document.getElementById('settings-section-querylog').scrollIntoView({ block: 'start' });
    return {
      initial,
      masterChanged,
      anonymizeChanged,
      decreaseConfirm,
      retentionApplied,
      capacityCancel,
      capacityApplied,
      ignoredApplied,
      clearConfirm,
      rowCount: document.querySelectorAll('#queryLogSettingsRows .settings-link-row').length,
      modernToggleCount: ['queryLogEnabled', 'queryLogAnonymizeClientIp', 'queryLogIgnoredEnabled'].filter((id) => document.getElementById(id).closest('.settings-toggle')).length,
      oldModulesAbsent: !document.getElementById('querylog-module-privacy') && !document.getElementById('querylog-module-ignore') && !document.getElementById('queryLogRuntimeSummary') && !document.getElementById('queryLogSettingsCount'),
      restored: master.checked === initial.enabled && anonymize.checked === initial.anonymize && ignoredToggle.checked === initial.ignoredEnabled && retentionHoursValue('queryLog') === initial.retention && capacity.value === initial.capacity && ignoredField.value === initial.ignored && state.settingsDirty === false
    };
  })()`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'desktop-query-log-settings.png'));

  const desktopQueryLogDialogs = await evaluateValue(client, `(async () => {
    document.getElementById('openQueryLogRetention').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const retentionModal = document.querySelector('#queryLogRetentionModal .modal').getBoundingClientRect();
    const retention = {
      visible: !document.getElementById('queryLogRetentionModal').classList.contains('hidden'),
      insideViewport: retentionModal.left >= 0 && retentionModal.right <= innerWidth && retentionModal.top >= 0 && retentionModal.bottom <= innerHeight,
      options: document.querySelectorAll('#queryLogRetentionOptions .retention-option').length,
      columns: getComputedStyle(document.getElementById('queryLogRetentionOptions')).gridTemplateColumns.split(/\\s+/).filter(Boolean).length,
      active: document.querySelectorAll('#queryLogRetentionOptions .retention-option.active').length
    };
    cancelRetentionConfig('queryLog');
    document.getElementById('openQueryLogIgnoredDomains').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const ignoredModal = document.querySelector('#queryLogIgnoredModal .modal').getBoundingClientRect();
    const ignored = {
      visible: !document.getElementById('queryLogIgnoredModal').classList.contains('hidden'),
      focused: document.activeElement === document.getElementById('queryLogIgnoredDomains'),
      insideViewport: ignoredModal.left >= 0 && ignoredModal.right <= innerWidth && ignoredModal.top >= 0 && ignoredModal.bottom <= innerHeight,
      textareaInside: document.getElementById('queryLogIgnoredDomains').getBoundingClientRect().right <= ignoredModal.right
    };
    return { retention, ignored };
  })()`);
  await screenshot(client, path.join(outputDir, 'desktop-query-log-ignored-dialog.png'));
  await evaluate(client, `cancelIgnoredDomainsConfig('queryLog'); true`);

  const desktopCacheInteraction = await evaluateValue(client, `(async () => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('dns', { history: 'replace' });
    const toggle = document.getElementById('cacheEnabled');
    const size = document.getElementById('cacheMaxEntries');
    const minTtl = document.getElementById('cacheMinTtl');
    const maxTtl = document.getElementById('cacheMaxTtl');
    const optimistic = document.getElementById('cacheOptimistic');
    const optimisticAnswerTtl = document.getElementById('cacheOptimisticAnswerTtl');
    const optimisticMaxAge = document.getElementById('cacheOptimisticMaxAge');
    const initial = toggle.checked;
    const initialSize = size.value;
    const initialMinTtl = minTtl.value;
    const initialMaxTtl = maxTtl.value;
    const initialOptimistic = optimistic.checked;
    const initialOptimisticAnswerTtl = optimisticAnswerTtl.value;
    const initialOptimisticMaxAge = optimisticMaxAge.value;
    const changedSize = String(Number(initialSize) >= 1000000 ? Number(initialSize) - 1 : Number(initialSize) + 1);

    document.getElementById('openDnsCacheCapacity').focus();
    document.getElementById('openDnsCacheCapacity').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const cancelOpened = {
      visible: !document.getElementById('dnsCacheConfigModal').classList.contains('hidden'),
      focused: document.activeElement === size
    };
    size.value = changedSize;
    size.dispatchEvent(new Event('input', { bubbles: true }));
    cancelOpened.dirty = state.settingsDirty;
    document.getElementById('cancelDnsCacheConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const canceled = {
      restored: size.value === initialSize,
      closed: document.getElementById('dnsCacheConfigModal').classList.contains('hidden'),
      focusRestored: document.activeElement === document.getElementById('openDnsCacheCapacity'),
      dirty: state.settingsDirty
    };

    document.getElementById('openDnsCacheCapacity').focus();
    document.getElementById('openDnsCacheCapacity').click();
    await new Promise((resolve) => setTimeout(resolve, 20));
    size.value = changedSize;
    size.dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('applyDnsCacheConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const applied = {
      value: size.value,
      payloadValue: settingsPayload().cacheMaxEntries,
      dirty: state.settingsDirty,
      closed: document.getElementById('dnsCacheConfigModal').classList.contains('hidden')
    };
    size.value = initialSize;
    size.dispatchEvent(new Event('input', { bubbles: true }));

    const rangeValidation = { applicable: Number(initialMaxTtl) < 86400 };
    if (rangeValidation.applicable) {
      const minOpener = document.getElementById('openDnsCacheMinTtl');
      minOpener.focus();
      minOpener.click();
      await new Promise((resolve) => setTimeout(resolve, 20));
      minTtl.value = String(Number(initialMaxTtl) + 1);
      minTtl.dispatchEvent(new Event('input', { bubbles: true }));
      document.getElementById('applyDnsCacheConfig').click();
      await new Promise((resolve) => setTimeout(resolve, 30));
      rangeValidation.prevented = !document.getElementById('dnsCacheConfigModal').classList.contains('hidden') && !minTtl.checkValidity() && document.activeElement === minTtl;
      document.getElementById('cancelDnsCacheConfig').click();
      await new Promise((resolve) => setTimeout(resolve, 20));
      rangeValidation.restored = minTtl.value === initialMinTtl && document.activeElement === minOpener && state.settingsDirty === false;
    }

    toggle.click();
    const toggleRow = toggle.closest('.settings-link-row').getBoundingClientRect();
    const toggleTrack = toggle.closest('.settings-toggle').querySelector('.settings-toggle-track').getBoundingClientRect();
    const changed = {
      enabled: toggle.checked,
      dirty: state.settingsDirty,
      rowsText: document.getElementById('dnsCacheRows').innerText.replace(/\\s+/g, ' ').trim(),
      modernToggle: toggle.closest('.settings-toggle') !== null,
      toggleInside: toggleTrack.left >= toggleRow.left && toggleTrack.right <= toggleRow.right,
      headerStateAbsent: !document.getElementById('dnsCacheState'),
      sizePreserved: size.value === initialSize,
      optimisticDisabled: optimistic.disabled,
      linksDisabled: ['openDnsCacheCapacity', 'openDnsCacheMinTtl', 'openDnsCacheMaxTtl', 'openDnsCacheAdvanced'].every((id) => document.getElementById(id).disabled),
      payloadEnabled: settingsPayload().cacheEnabled
    };
    toggle.click();
    optimistic.click();
    const optimisticChanged = {
      enabled: optimistic.checked,
      dirty: state.settingsDirty,
      modernToggle: optimistic.closest('.settings-toggle') !== null,
      answerTtlDisabled: optimisticAnswerTtl.disabled,
      maxAgeDisabled: optimisticMaxAge.disabled,
      valuesPreserved: optimisticAnswerTtl.value === initialOptimisticAnswerTtl && optimisticMaxAge.value === initialOptimisticMaxAge,
      payloadEnabled: settingsPayload().cacheOptimistic
    };
    optimistic.click();
    document.getElementById('clearDnsCache').focus();
    document.getElementById('clearDnsCache').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const clearConfirm = {
      visible: !document.getElementById('clearDnsCacheModal').classList.contains('hidden'),
      focused: document.activeElement === document.getElementById('confirmClearDnsCache')
    };
    document.getElementById('cancelClearDnsCache').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    clearConfirm.closed = document.getElementById('clearDnsCacheModal').classList.contains('hidden');
    clearConfirm.focusRestored = document.activeElement === document.getElementById('clearDnsCache');
    return {
      initial,
      initialSize,
      initialMinTtl,
      initialMaxTtl,
      initialOptimistic,
      initialOptimisticAnswerTtl,
      initialOptimisticMaxAge,
      cancelOpened,
      canceled,
      applied,
      rangeValidation,
      changed,
      optimisticChanged,
      clearConfirm,
      restored: toggle.checked === initial && size.value === initialSize && minTtl.value === initialMinTtl && maxTtl.value === initialMaxTtl && optimistic.checked === initialOptimistic && optimisticAnswerTtl.value === initialOptimisticAnswerTtl && optimisticMaxAge.value === initialOptimisticMaxAge && state.settingsDirty === false
    };
  })()`);
  await evaluate(client, `document.getElementById('dns-module-cache').scrollIntoView({ block: 'start' }); true`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'desktop-dns-cache.png'));

  const desktopCacheDialog = await evaluateValue(client, `(async () => {
    document.getElementById('openDnsCacheAdvanced').focus();
    document.getElementById('openDnsCacheAdvanced').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const modal = document.querySelector('#dnsCacheConfigModal .modal').getBoundingClientRect();
    return {
      visible: !document.getElementById('dnsCacheConfigModal').classList.contains('hidden'),
      title: document.getElementById('dnsCacheConfigTitle').textContent,
      focused: document.activeElement === document.getElementById('cacheStaleTtl'),
      insideViewport: modal.left >= 0 && modal.right <= innerWidth && modal.top >= 0 && modal.bottom <= innerHeight,
      fields: document.querySelectorAll('#dnsCacheAdvancedPanel input').length
    };
  })()`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'desktop-dns-cache-dialog.png'));
  await evaluate(client, `cancelDnsCacheConfig(); true`);

  const desktopCacheConfirm = await evaluateValue(client, `(async () => {
    document.getElementById('clearDnsCache').focus();
    document.getElementById('clearDnsCache').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const modal = document.querySelector('#clearDnsCacheModal .modal').getBoundingClientRect();
    return {
      visible: !document.getElementById('clearDnsCacheModal').classList.contains('hidden'),
      focused: document.activeElement === document.getElementById('confirmClearDnsCache'),
      insideViewport: modal.left >= 0 && modal.right <= innerWidth && modal.top >= 0 && modal.bottom <= innerHeight
    };
  })()`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'desktop-dns-cache-confirm.png'));
  await evaluate(client, `closeClearDnsCacheModal(); true`);

  const desktopDnssecInteraction = await evaluateValue(client, `(() => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('dns', { history: 'replace' });
    const toggle = document.getElementById('dnsDnssecEnabled');
    const initial = toggle.checked;
    const signatureBefore = upstreamSettingsSignature();
    toggle.click();
    const changed = {
      enabled: toggle.checked,
      dirty: state.settingsDirty,
      payloadEnabled: settingsPayload().dnsDnssecEnabled,
      rowsText: document.getElementById('dnsServiceRows').innerText.replace(/\\s+/g, ' ').trim(),
      upstreamSignatureChanged: upstreamSettingsSignature() !== signatureBefore
    };
    toggle.click();
    document.getElementById('dns-module-service').scrollIntoView({ block: 'start' });
    return { initial, changed, restored: toggle.checked === initial && state.settingsDirty === false };
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'desktop-dns-service.png'));

  const desktopRefuseAnyInteraction = await evaluateValue(client, `(() => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('dns', { history: 'replace' });
    const toggle = document.getElementById('dnsRefuseAny');
    const initial = toggle.checked;
    toggle.click();
    const changed = {
      enabled: toggle.checked,
      dirty: state.settingsDirty,
      payloadEnabled: settingsPayload().dnsRefuseAny,
      rowsText: document.getElementById('dnsServiceRows').innerText.replace(/\\s+/g, ' ').trim()
    };
    toggle.click();
    document.getElementById('dns-module-service').scrollIntoView({ block: 'start' });
    return { initial, changed, restored: toggle.checked === initial && state.settingsDirty === false };
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'desktop-refuse-any-setting.png'));

  const desktopDnsServiceInteraction = await evaluateValue(client, `(async () => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('dns', { history: 'replace' });
    const rate = document.getElementById('dnsRateLimit');
    const mode = document.getElementById('protectionBlockMode');
    const ttl = document.getElementById('dnsBlockedResponseTtl');
    const cname = document.getElementById('protectionCnameCheck');
    const ipv6 = document.getElementById('dnsIpv6ResolutionEnabled');
    const initial = {
      rate: rate.value,
      mode: mode.value,
      ttl: ttl.value,
      ipv4: document.getElementById('dnsBlockingIpv4').value,
      ipv6Address: document.getElementById('dnsBlockingIpv6').value,
      cname: cname.checked,
      ipv6Enabled: ipv6.checked
    };

    cname.click();
    const cnameChanged = { enabled: cname.checked, dirty: state.settingsDirty, payloadEnabled: settingsPayload().cnameCheck };
    cname.click();
    ipv6.click();
    const ipv6Changed = { enabled: ipv6.checked, dirty: state.settingsDirty, payloadDisableIpv6: settingsPayload().dnsDisableIpv6 };
    ipv6.click();

    const rateOpener = document.getElementById('openDnsRateLimit');
    rateOpener.focus();
    rateOpener.click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const rateDialog = {
      visible: !document.getElementById('dnsServiceConfigModal').classList.contains('hidden'),
      title: document.getElementById('dnsServiceConfigTitle').textContent,
      focused: document.activeElement === rate
    };
    const changedRate = String(Number(initial.rate) >= 1000000 ? Number(initial.rate) - 1 : Number(initial.rate) + 1);
    rate.value = changedRate;
    rate.dispatchEvent(new Event('input', { bubbles: true }));
    rateDialog.dirtyBeforeCancel = state.settingsDirty;
    document.getElementById('cancelDnsServiceConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    rateDialog.cancelRestored = rate.value === initial.rate && state.settingsDirty === false;
    rateDialog.focusRestored = document.activeElement === rateOpener;
    rateOpener.click();
    await new Promise((resolve) => setTimeout(resolve, 20));
    rate.value = changedRate;
    rate.dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('applyDnsServiceConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    rateDialog.applyClosed = document.getElementById('dnsServiceConfigModal').classList.contains('hidden');
    rateDialog.applyDirty = state.settingsDirty;
    rateDialog.payloadMatches = settingsPayload().dnsRateLimit === Number(changedRate);
    rate.value = initial.rate;
    rate.dispatchEvent(new Event('input', { bubbles: true }));

    const blockingOpener = document.getElementById('openDnsBlockingMode');
    blockingOpener.focus();
    blockingOpener.click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const activeMode = document.querySelector('[data-dns-block-mode].active');
    const blockingDialog = {
      visible: !document.getElementById('dnsServiceConfigModal').classList.contains('hidden'),
      title: document.getElementById('dnsServiceConfigTitle').textContent,
      focused: document.activeElement === activeMode,
      options: document.querySelectorAll('[data-dns-block-mode]').length,
      modeValues: [...document.querySelectorAll('[data-dns-block-mode]')].map(card => card.dataset.dnsBlockMode),
      addressInitiallyVisible: !document.getElementById('dnsBlockingAddressDialogFields').classList.contains('hidden')
    };
    activeMode.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true, cancelable: true }));
    blockingDialog.keyboardChanged = mode.value !== initial.mode;
    blockingDialog.addressVisibilityChanged = document.getElementById('dnsBlockingAddressDialogFields').classList.contains('hidden') === (mode.value !== 'custom');
    document.getElementById('cancelDnsServiceConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    blockingDialog.cancelRestored = mode.value === initial.mode && ttl.value === initial.ttl && state.settingsDirty === false;
    blockingDialog.focusRestored = document.activeElement === blockingOpener;

    blockingOpener.click();
    await new Promise((resolve) => setTimeout(resolve, 20));
    document.getElementById('dnsBlockingModeCustom').click();
    const ipv4Field = document.getElementById('dnsBlockingIpv4');
    const ipv6Field = document.getElementById('dnsBlockingIpv6');
    blockingDialog.customMode = {
      fieldsVisible: !document.getElementById('dnsBlockingAddressDialogFields').classList.contains('hidden'),
      inputsEnabled: !ipv4Field.disabled && !ipv6Field.disabled
    };
    ipv4Field.value = 'not-an-ip';
    ipv4Field.dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('applyDnsServiceConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    blockingDialog.customMode.invalidPrevented = !document.getElementById('dnsServiceConfigModal').classList.contains('hidden') && !ipv4Field.checkValidity() && document.activeElement === ipv4Field;
    document.getElementById('cancelDnsServiceConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 20));

    blockingOpener.click();
    await new Promise((resolve) => setTimeout(resolve, 20));
    document.getElementById('dnsBlockingModeNxdomain').click();
    const changedTtl = String(Number(initial.ttl) >= 4294967295 ? Number(initial.ttl) - 1 : Number(initial.ttl) + 1);
    ttl.value = changedTtl;
    ttl.dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('applyDnsServiceConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    blockingDialog.applyClosed = document.getElementById('dnsServiceConfigModal').classList.contains('hidden');
    blockingDialog.applyDirty = state.settingsDirty;
    blockingDialog.payloadMatches = settingsPayload().blockMode === 'nxdomain' && settingsPayload().dnsBlockedResponseTtl === Number(changedTtl);
    blockingDialog.appliedMeta = document.getElementById('dnsBlockingModeMeta').textContent.trim();

    mode.value = initial.mode;
    ttl.value = initial.ttl;
    document.getElementById('dnsBlockingIpv4').value = initial.ipv4;
    document.getElementById('dnsBlockingIpv6').value = initial.ipv6Address;
    handleSettingsChange();
    document.getElementById('dns-module-service').scrollIntoView({ block: 'start' });
    return {
      initial,
      cnameChanged,
      ipv6Changed,
      rateDialog,
      blockingDialog,
      rowCount: document.querySelectorAll('#dnsServiceRows .settings-link-row').length,
      rateMeta: document.getElementById('dnsRateLimitMeta').textContent.trim(),
      allowlistMeta: document.getElementById('dnsRateLimitAllowlistMeta').textContent.trim(),
      subnetIpv4Meta: document.getElementById('dnsRateLimitSubnetIpv4Meta').textContent.trim(),
      subnetIpv6Meta: document.getElementById('dnsRateLimitSubnetIpv6Meta').textContent.trim(),
      blockingMeta: document.getElementById('dnsBlockingModeMeta').textContent.trim(),
      restored: cname.checked === initial.cname && ipv6.checked === initial.ipv6Enabled && rate.value === initial.rate && mode.value === initial.mode && ttl.value === initial.ttl && state.settingsDirty === false
    };
  })()`);
  const desktopDnsServiceDialog = await evaluateValue(client, `(async () => {
    document.getElementById('openDnsBlockingMode').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const modal = document.querySelector('#dnsServiceConfigModal .modal').getBoundingClientRect();
    return {
      visible: !document.getElementById('dnsServiceConfigModal').classList.contains('hidden'),
      focused: document.activeElement === document.querySelector('[data-dns-block-mode].active'),
      insideViewport: modal.left >= 0 && modal.right <= innerWidth && modal.top >= 0 && modal.bottom <= innerHeight,
      optionCount: document.querySelectorAll('[data-dns-block-mode]').length,
      ttlEnabled: !document.getElementById('dnsBlockedResponseTtl').disabled
    };
  })()`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'desktop-dns-service-blocking-dialog.png'));
  await evaluate(client, `cancelDnsServiceConfig(); true`);

  const desktopEcsInteraction = await evaluateValue(client, `(async () => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('dns', { history: 'replace' });
    const enabled = document.getElementById('ecsEnabled');
    const ipv4Prefix = document.getElementById('ecsIpv4Prefix');
    const ipv6Prefix = document.getElementById('ecsIpv6Prefix');
    const defaultIpv4 = document.getElementById('ecsDefaultIpv4');
    const opener = document.getElementById('openEcsConfig');
    const initial = {
      enabled: enabled.checked,
      ipv4Prefix: ipv4Prefix.value,
      ipv6Prefix: ipv6Prefix.value,
      defaultIpv4: defaultIpv4.value
    };

    enabled.click();
    const toggleChanged = {
      enabled: enabled.checked,
      dirty: state.settingsDirty,
      payloadEnabled: settingsPayload().ecsEnabled
    };
    enabled.click();

    opener.focus();
    opener.click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const dialog = {
      visible: !document.getElementById('ecsConfigModal').classList.contains('hidden'),
      title: document.getElementById('ecsConfigTitle').textContent.trim(),
      focused: document.activeElement === ipv4Prefix
    };
    const changedIpv4Prefix = String(Number(initial.ipv4Prefix) >= 32 ? 31 : Number(initial.ipv4Prefix) + 1);
    const changedIpv6Prefix = String(Number(initial.ipv6Prefix) >= 128 ? 127 : Number(initial.ipv6Prefix) + 1);
    const changedDefaultIpv4 = initial.defaultIpv4 === '203.0.113.45' ? '198.51.100.45' : '203.0.113.45';
    ipv4Prefix.value = changedIpv4Prefix;
    ipv6Prefix.value = changedIpv6Prefix;
    defaultIpv4.value = changedDefaultIpv4;
    [ipv4Prefix, ipv6Prefix, defaultIpv4].forEach((field) => field.dispatchEvent(new Event('input', { bubbles: true })));
    dialog.dirtyBeforeCancel = state.settingsDirty;
    document.getElementById('cancelEcsConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    dialog.cancelRestored = ipv4Prefix.value === initial.ipv4Prefix && ipv6Prefix.value === initial.ipv6Prefix && defaultIpv4.value === initial.defaultIpv4 && state.settingsDirty === false;
    dialog.focusRestored = document.activeElement === opener;

    opener.click();
    await new Promise((resolve) => setTimeout(resolve, 20));
    defaultIpv4.value = '999.1.1.1';
    defaultIpv4.dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('applyEcsConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    dialog.invalidPrevented = !document.getElementById('ecsConfigModal').classList.contains('hidden') && !defaultIpv4.checkValidity() && document.activeElement === defaultIpv4;
    document.getElementById('cancelEcsConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 20));

    opener.click();
    await new Promise((resolve) => setTimeout(resolve, 20));
    ipv4Prefix.value = changedIpv4Prefix;
    ipv6Prefix.value = changedIpv6Prefix;
    defaultIpv4.value = changedDefaultIpv4;
    [ipv4Prefix, ipv6Prefix, defaultIpv4].forEach((field) => field.dispatchEvent(new Event('input', { bubbles: true })));
    document.getElementById('applyEcsConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    dialog.applyClosed = document.getElementById('ecsConfigModal').classList.contains('hidden');
    dialog.applyDirty = state.settingsDirty;
    dialog.payloadMatches = settingsPayload().ecsIpv4Prefix === Number(changedIpv4Prefix)
      && settingsPayload().ecsIpv6Prefix === Number(changedIpv6Prefix)
      && settingsPayload().ecsDefaultIpv4 === changedDefaultIpv4;
    dialog.appliedMeta = document.getElementById('ecsPolicyMeta').textContent.trim();

    ipv4Prefix.value = initial.ipv4Prefix;
    ipv6Prefix.value = initial.ipv6Prefix;
    defaultIpv4.value = initial.defaultIpv4;
    [ipv4Prefix, ipv6Prefix, defaultIpv4].forEach((field) => field.dispatchEvent(new Event('input', { bubbles: true })));
    handleSettingsChange();
    document.getElementById('dns-module-ecs').scrollIntoView({ block: 'center' });
    const rowRect = opener.getBoundingClientRect();
    const toggleRect = opener.querySelector('.settings-toggle').getBoundingClientRect();
    return {
      initial,
      toggleChanged,
      dialog,
      rowCount: document.querySelectorAll('#ecsSettingsRows .settings-link-row').length,
      role: opener.getAttribute('role'),
      rowColumns: getComputedStyle(opener).gridTemplateColumns.split(/\\s+/).filter(Boolean).length,
      toggleInside: toggleRect.left >= rowRect.left && toggleRect.right <= rowRect.right,
      meta: document.getElementById('ecsPolicyMeta').textContent.trim(),
      oldSummaryAbsent: !document.getElementById('ecsSummary'),
      restored: enabled.checked === initial.enabled && ipv4Prefix.value === initial.ipv4Prefix && ipv6Prefix.value === initial.ipv6Prefix && defaultIpv4.value === initial.defaultIpv4 && state.settingsDirty === false
    };
  })()`);
  await sleep(120);
  await screenshot(client, path.join(outputDir, 'desktop-dns-ecs.png'));

  const desktopEcsDialog = await evaluateValue(client, `(async () => {
    const opener = document.getElementById('openEcsConfig');
    opener.focus();
    opener.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 30));
    const modal = document.querySelector('#ecsConfigModal .modal').getBoundingClientRect();
    const fields = [...document.querySelectorAll('#ecsConfigModal input')].map((field) => field.getBoundingClientRect());
    return {
      visible: !document.getElementById('ecsConfigModal').classList.contains('hidden'),
      focused: document.activeElement === document.getElementById('ecsIpv4Prefix'),
      insideViewport: modal.left >= 0 && modal.right <= innerWidth && modal.top >= 0 && modal.bottom <= innerHeight,
      fields: fields.length,
      fieldsInside: fields.every((rect) => rect.left >= modal.left && rect.right <= modal.right)
    };
  })()`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'desktop-dns-ecs-dialog.png'));
  await evaluate(client, `cancelEcsConfig(); true`);

  const desktopAccessInteraction = await evaluateValue(client, `(async () => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('dns', { history: 'replace' });
    const allowed = document.getElementById('accessAllowedClients');
    const blocked = document.getElementById('accessBlockedClients');
    const hosts = document.getElementById('accessBlockedHosts');
    const allowedOpener = document.getElementById('openAccessAllowedClients');
    const blockedOpener = document.getElementById('openAccessBlockedClients');
    const hostsOpener = document.getElementById('openAccessBlockedHosts');
    const initial = {
      allowed: allowed.value,
      blocked: blocked.value,
      hosts: hosts.value,
      blockedDisabled: blockedOpener.disabled
    };

    allowedOpener.focus();
    allowedOpener.click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const allowedDialog = {
      visible: !document.getElementById('accessConfigModal').classList.contains('hidden'),
      title: document.getElementById('accessConfigTitle').textContent.trim(),
      focused: document.activeElement === allowed
    };
    allowed.value = '192.0.2.10\\n# audit comment\\n192.0.2.0/24\\n192.0.2.10';
    allowed.dispatchEvent(new Event('input', { bubbles: true }));
    allowedDialog.dirtyBeforeCancel = state.settingsDirty;
    const duplicateBadge = document.querySelector('#accessAllowedHint .warn');
    allowedDialog.duplicateHint = Boolean(duplicateBadge && duplicateBadge.textContent.replace(/\\s+/g, '').includes('1条重复'));
    document.getElementById('cancelAccessConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    allowedDialog.cancelRestored = allowed.value === initial.allowed && state.settingsDirty === false;
    allowedDialog.focusRestored = document.activeElement === allowedOpener;

    allowedOpener.click();
    await new Promise((resolve) => setTimeout(resolve, 20));
    allowed.value = 'not-an-ip';
    allowed.dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('applyAccessConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    allowedDialog.invalidPrevented = !document.getElementById('accessConfigModal').classList.contains('hidden') && !allowed.checkValidity() && document.activeElement === allowed;
    document.getElementById('cancelAccessConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 20));

    allowedOpener.click();
    await new Promise((resolve) => setTimeout(resolve, 20));
    allowed.value = '192.0.2.10\\n# audit comment\\n192.0.2.0/24\\n192.0.2.10';
    allowed.dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('applyAccessConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    allowedDialog.applyClosed = document.getElementById('accessConfigModal').classList.contains('hidden');
    allowedDialog.applyDirty = state.settingsDirty;
    allowedDialog.payloadMatches = JSON.stringify(settingsPayload().accessAllowedClients) === JSON.stringify(['192.0.2.10', '192.0.2.0/24']);
    allowedDialog.appliedMeta = document.getElementById('accessAllowedMeta').textContent.trim();
    allowedDialog.blockedDisabled = blockedOpener.disabled;

    allowed.value = '';
    allowed.dispatchEvent(new Event('input', { bubbles: true }));
    const blockedEnabledWithoutAllow = !blockedOpener.disabled;
    blockedOpener.focus();
    blockedOpener.click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const blockedDialog = {
      visible: !document.getElementById('accessConfigModal').classList.contains('hidden'),
      title: document.getElementById('accessConfigTitle').textContent.trim(),
      focused: document.activeElement === blocked
    };
    document.getElementById('cancelAccessConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 20));
    blockedDialog.focusRestored = document.activeElement === blockedOpener;

    hostsOpener.focus();
    hostsOpener.click();
    await new Promise((resolve) => setTimeout(resolve, 20));
    hosts.value = 'bad host!';
    hosts.dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('applyAccessConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const hostsDialog = {
      invalidPrevented: !document.getElementById('accessConfigModal').classList.contains('hidden') && !hosts.checkValidity() && document.activeElement === hosts
    };
    document.getElementById('cancelAccessConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 20));
    hostsOpener.click();
    await new Promise((resolve) => setTimeout(resolve, 20));
    hosts.value = 'malware.audit.example\\n# audit comment\\nmalware.audit.example';
    hosts.dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('applyAccessConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    hostsDialog.applyClosed = document.getElementById('accessConfigModal').classList.contains('hidden');
    hostsDialog.applyDirty = state.settingsDirty;
    hostsDialog.payloadMatches = JSON.stringify(settingsPayload().accessBlockedHosts) === JSON.stringify(['malware.audit.example']);
    hostsDialog.appliedMeta = document.getElementById('accessHostsMeta').textContent.trim();

    allowed.value = initial.allowed;
    blocked.value = initial.blocked;
    hosts.value = initial.hosts;
    [allowed, blocked, hosts].forEach((field) => field.dispatchEvent(new Event('input', { bubbles: true })));
    clearAccessDialogValidity();
    handleSettingsChange();
    document.getElementById('access-module-summary').scrollIntoView({ block: 'center' });
    return {
      initial,
      allowedDialog,
      blockedDialog,
      hostsDialog,
      blockedEnabledWithoutAllow,
      rowCount: document.querySelectorAll('#accessSettingsRows .settings-link-row').length,
      rowsText: document.getElementById('accessSettingsRows').innerText.replace(/\\s+/g, ' ').trim(),
      oldSummaryAbsent: !document.getElementById('accessModeSummary'),
      oldEditorAbsent: !document.querySelector('.access-editor-grid'),
      restored: allowed.value === initial.allowed && blocked.value === initial.blocked && hosts.value === initial.hosts && blockedOpener.disabled === initial.blockedDisabled && state.settingsDirty === false
    };
  })()`);
  await sleep(120);
  await screenshot(client, path.join(outputDir, 'desktop-dns-access.png'));

  const desktopAccessDialog = await evaluateValue(client, `(async () => {
    document.getElementById('openAccessAllowedClients').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const modal = document.querySelector('#accessConfigModal .modal').getBoundingClientRect();
    const textarea = document.getElementById('accessAllowedClients').getBoundingClientRect();
    return {
      visible: !document.getElementById('accessConfigModal').classList.contains('hidden'),
      focused: document.activeElement === document.getElementById('accessAllowedClients'),
      insideViewport: modal.left >= 0 && modal.right <= innerWidth && modal.top >= 0 && modal.bottom <= innerHeight,
      textareaInside: textarea.left >= modal.left && textarea.right <= modal.right,
      hintItems: document.querySelectorAll('#accessAllowedHint span').length
    };
  })()`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'desktop-dns-access-dialog.png'));
  await evaluate(client, `cancelAccessConfig(); true`);

  const desktopRefuseAnyTest = await evaluateValue(client, `(async () => {
    selectView('filters', { skipUrl: true });
    selectFilterSection('test', '', { history: 'replace' });
    const name = document.getElementById('testName');
    const type = document.getElementById('testType');
    const ip = document.getElementById('testIp');
    const initial = { name: name.value, type: type.value, ip: ip.value };
    window.__auditRefuseAnyForm = initial;
    name.value = 'refuse-any.audit';
    type.value = 'ANY';
    ip.value = '192.0.2.44';
    await runTest();
    document.getElementById('testDecisionPanel').scrollIntoView({ block: 'center' });
    const result = {
      stateText: document.getElementById('testState').textContent.trim(),
      decisionText: document.getElementById('testDecisionPanel').innerText.replace(/\\s+/g, ' ').trim(),
      summaryText: document.getElementById('testSummary').innerText.replace(/\\s+/g, ' ').trim(),
      selectedType: type.value,
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1
    };
    return result;
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'desktop-refuse-any-test.png'));
  await evaluate(client, `(() => {
    const initial = window.__auditRefuseAnyForm || { name: 'example.com', type: 'A', ip: '114.114.114.114' };
    document.getElementById('testName').value = initial.name;
    document.getElementById('testType').value = initial.type;
    document.getElementById('testIp').value = initial.ip;
    delete window.__auditRefuseAnyForm;
    return true;
  })()`);

  const desktopClientReverseDns = await evaluateValue(client, `(async () => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('dns', { history: 'replace' });
    const clientToggle = document.getElementById('clientReverseDnsEnabled');
    const privateToggle = document.getElementById('privateReverseEnabled');
    const whoisToggle = document.getElementById('clientWhoisEnabled');
    const hostsToggle = document.getElementById('clientHostsEnabled');
    const arpToggle = document.getElementById('clientArpEnabled');
    const dhcpToggle = document.getElementById('clientDhcpEnabled');
    const servers = document.getElementById('privateReverseUpstreams');
    const initial = {
      clientEnabled: clientToggle.checked,
      privateEnabled: privateToggle.checked,
      whoisEnabled: whoisToggle.checked,
      hostsEnabled: hostsToggle.checked,
      arpEnabled: arpToggle.checked,
      dhcpEnabled: dhcpToggle.checked,
      servers: servers.value
    };
    clientToggle.click();
    const clientChanged = {
      enabled: clientToggle.checked,
      dirty: state.settingsDirty,
      payloadEnabled: settingsPayload().clientReverseDnsEnabled,
      rowsText: document.getElementById('privateReverseRows').innerText.replace(/\\s+/g, ' ').trim()
    };
    clientToggle.click();
    whoisToggle.click();
    const whoisChanged = {
      enabled: whoisToggle.checked,
      dirty: state.settingsDirty,
      payloadEnabled: settingsPayload().clientWhoisEnabled
    };
    whoisToggle.click();
    hostsToggle.click();
    const hostsChanged = {
      enabled: hostsToggle.checked,
      dirty: state.settingsDirty,
      payloadEnabled: settingsPayload().clientHostsEnabled
    };
    hostsToggle.click();
    privateToggle.click();
    const privateChanged = {
      enabled: privateToggle.checked,
      dirty: state.settingsDirty,
      payloadEnabled: settingsPayload().privateReverseEnabled
    };
    privateToggle.click();

    const opener = document.getElementById('openPrivateReverseServers');
    opener.focus();
    opener.click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const dialog = {
      visible: !document.getElementById('privateReverseServersModal').classList.contains('hidden'),
      focused: document.activeElement === servers,
      title: document.getElementById('privateReverseServersTitle').textContent
    };
    servers.value = initial.servers + '\\n# cancel private reverse audit';
    servers.dispatchEvent(new Event('input', { bubbles: true }));
    dialog.dirtyBeforeCancel = state.settingsDirty;
    document.getElementById('cancelPrivateReverseServers').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    dialog.cancelRestored = servers.value === initial.servers && state.settingsDirty === false;
    dialog.cancelClosed = document.getElementById('privateReverseServersModal').classList.contains('hidden');
    dialog.focusRestored = document.activeElement === opener;

    window.__auditPrivateReverseText = '# Audit private reverse UI\\n192.0.2.53\\n[/168.192.in-addr.arpa/]192.0.2.54';
    opener.click();
    await new Promise((resolve) => setTimeout(resolve, 20));
    servers.value = window.__auditPrivateReverseText;
    servers.dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('applyPrivateReverseServers').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    dialog.applyClosed = document.getElementById('privateReverseServersModal').classList.contains('hidden');
    dialog.applyDirty = state.settingsDirty;
    dialog.payloadMatches = JSON.stringify(settingsPayload().privateReverseUpstreams) === JSON.stringify(splitLines(window.__auditPrivateReverseText));
    dialog.appliedMeta = document.getElementById('privateReverseServersMeta').textContent.trim();

    servers.value = initial.servers;
    servers.dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('dns-module-private-reverse').scrollIntoView({ block: 'start' });
    return {
      initial,
      clientChanged,
      whoisChanged,
      hostsChanged,
      privateChanged,
      dialog,
      rowCount: document.querySelectorAll('#privateReverseRows .settings-link-row').length,
      sourceControlsVisible: [whoisToggle, hostsToggle, arpToggle, dhcpToggle].every((node) => node.getClientRects().length > 0),
      sourcePayloadMatches: settingsPayload().clientWhoisEnabled === initial.whoisEnabled && settingsPayload().clientHostsEnabled === initial.hostsEnabled && settingsPayload().clientArpEnabled === initial.arpEnabled && settingsPayload().clientDhcpEnabled === initial.dhcpEnabled,
      restored: clientToggle.checked === initial.clientEnabled && privateToggle.checked === initial.privateEnabled && whoisToggle.checked === initial.whoisEnabled && hostsToggle.checked === initial.hostsEnabled && arpToggle.checked === initial.arpEnabled && dhcpToggle.checked === initial.dhcpEnabled && servers.value === initial.servers && state.settingsDirty === false
    };
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'desktop-private-reverse-settings.png'));
  const desktopPrivateReverseDialog = await evaluateValue(client, `(async () => {
    document.getElementById('openPrivateReverseServers').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    document.querySelector('#privateReverseServersModal .upstream-syntax').open = true;
    const modal = document.querySelector('#privateReverseServersModal .modal').getBoundingClientRect();
    const textarea = document.getElementById('privateReverseUpstreams').getBoundingClientRect();
    return {
      visible: !document.getElementById('privateReverseServersModal').classList.contains('hidden'),
      focused: document.activeElement === document.getElementById('privateReverseUpstreams'),
      insideViewport: modal.left >= 0 && modal.right <= innerWidth && modal.top >= 0 && modal.bottom <= innerHeight,
      textareaInside: textarea.left >= modal.left && textarea.right <= modal.right,
      syntaxExamples: document.querySelectorAll('#privateReverseServersModal .upstream-syntax-list code').length
    };
  })()`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'desktop-private-reverse-dialog.png'));
  await evaluate(client, `cancelPrivateReverseServers(); true`);

  const desktopUpstreamRouting = await evaluateValue(client, `(async () => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('dns', { history: 'replace' });
    const upstreamField = document.getElementById('upstreams');
    const initialText = upstreamField.value;
    const initialMode = document.getElementById('upstreamMode').value;
    window.__auditOriginalUpstreamText = initialText;
    window.__auditOriginalPrivateReverseText = document.getElementById('privateReverseUpstreams').value;
    const currentAnalysis = analyzeUpstreamConfiguration(splitLines(upstreamField.value));
    const target = currentAnalysis.defaults[0] || currentAnalysis.targets[0];
    if (!target) throw new Error('audit requires a default upstream');
    const auditComment = initialText.includes('# Audit domain routing UI') ? '# Audit domain routing UI alternate' : '# Audit domain routing UI';
    window.__auditUpstreamText = [
      auditComment,
      target,
      '[/example.com/]' + target,
      '[/*.example.com/]' + target,
      '[/www.example.com/]#',
      '[//]' + target
    ].join('\\n');

    const modeOpener = document.getElementById('openDnsUpstreamMode');
    modeOpener.focus();
    modeOpener.click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const activeModeCard = document.querySelector('[data-upstream-mode].active');
    const modeDialog = {
      visible: !document.getElementById('dnsUpstreamConfigModal').classList.contains('hidden'),
      title: document.getElementById('dnsUpstreamConfigTitle').textContent,
      focused: document.activeElement === activeModeCard,
      options: document.querySelectorAll('#dnsUpstreamModePanel [data-upstream-mode]').length
    };
    activeModeCard.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true, cancelable: true }));
    modeDialog.keyboardChanged = document.getElementById('upstreamMode').value !== initialMode;
    document.getElementById('cancelDnsUpstreamConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    modeDialog.canceled = document.getElementById('upstreamMode').value === initialMode && state.settingsDirty === false;
    modeDialog.focusRestored = document.activeElement === modeOpener;

    const serversOpener = document.getElementById('openDnsUpstreamServers');
    serversOpener.focus();
    serversOpener.click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const serverDialog = {
      visible: !document.getElementById('dnsUpstreamConfigModal').classList.contains('hidden'),
      title: document.getElementById('dnsUpstreamConfigTitle').textContent,
      focused: document.activeElement === upstreamField
    };
    upstreamField.value = initialText + '\\n# cancel audit';
    upstreamField.dispatchEvent(new Event('input', { bubbles: true }));
    serverDialog.dirtyBeforeCancel = state.settingsDirty;
    document.getElementById('cancelDnsUpstreamConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    serverDialog.cancelRestored = upstreamField.value === initialText && state.settingsDirty === false;
    serverDialog.cancelClosed = document.getElementById('dnsUpstreamConfigModal').classList.contains('hidden');
    serverDialog.focusRestored = document.activeElement === serversOpener;

    serversOpener.click();
    await new Promise((resolve) => setTimeout(resolve, 20));
    upstreamField.value = window.__auditUpstreamText;
    upstreamField.dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('applyDnsUpstreamConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    serverDialog.applyClosed = document.getElementById('dnsUpstreamConfigModal').classList.contains('hidden');
    serverDialog.applyDirty = state.settingsDirty;
    serverDialog.payloadMatches = JSON.stringify(settingsPayload().upstreams) === JSON.stringify(splitLines(window.__auditUpstreamText));
    window.__auditPrivateReverseTestText = '[/168.192.in-addr.arpa/]' + target;
    document.getElementById('privateReverseUpstreams').value = window.__auditPrivateReverseTestText;
    document.getElementById('privateReverseUpstreams').dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('upstreamPreviewFold').open = true;
    document.getElementById('upstreamTestName').value = 'api.example.com';
    document.getElementById('upstreamTestType').value = 'A';
    renderUpstreamConfigSummary();
    await runUpstreamTest();
    const testFoldOpenedByRun = document.getElementById('upstreamTestFold').open;
    upstreamField.value = window.__auditUpstreamText;
    renderUpstreamConfigSummary();
    await new Promise((resolve) => setTimeout(resolve, 250));
    document.getElementById('upstreamPreviewFold').open = false;
    document.getElementById('upstreamTestFold').open = false;
    document.getElementById('dns-module-upstreams').scrollIntoView({ block: 'start' });
    const analysis = analyzeUpstreamConfiguration(splitLines(document.getElementById('upstreams').value));
    const largePreview = analyzeUpstreamConfiguration([
      target,
      ...Array.from({ length: 120 }, (_, index) => '[/route-' + index + '.audit.test/]' + target)
    ]);
    const module = document.getElementById('dns-module-upstreams').getBoundingClientRect();
    const result = {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      moduleWidth: Math.round(module.width),
      defaults: analysis.defaults.length,
      routes: analysis.routes.length,
      comments: analysis.comments.length,
      targets: analysis.targets.length,
      summaryText: document.getElementById('upstreamSettingsRows').innerText.replace(/\\s+/g, ' ').trim(),
      rowCount: document.querySelectorAll('#upstreamSettingsRows .settings-link-row').length,
      modeMeta: document.getElementById('upstreamModeMeta').textContent.trim(),
      serversMeta: document.getElementById('upstreamServersMeta').textContent.trim(),
      fallbackMeta: document.getElementById('upstreamFallbackMeta').textContent.trim(),
      bootstrapMeta: document.getElementById('upstreamBootstrapMeta').textContent.trim(),
      timeoutMeta: document.getElementById('upstreamTimeoutMeta').textContent.trim(),
      previewText: document.getElementById('upstreamListPreview').innerText.replace(/\s+/g, ' ').trim(),
      syntaxExamples: document.querySelectorAll('.upstream-syntax-list code').length,
      previewEntries: largePreview.entries.length,
      previewEntryCount: largePreview.entryCount,
      doqLabel: upstreamTransportLabel('quic://unfiltered.adguard-dns.com'),
      doqAliasLabel: upstreamTransportLabel('doq://unfiltered.adguard-dns.com'),
      doqSummary: upstreamTransportSummary(['8.8.8.8', 'quic://unfiltered.adguard-dns.com']),
      selectedRoute: state.upstreamTestResult?.selectedRoute || '',
      settingsDirty: state.settingsDirty,
      selectedUpstreams: state.upstreamTestResult?.selectedUpstreams || [],
      testRows: state.upstreamTestResult?.results?.length || 0,
      privateTestRows: (state.upstreamTestResult?.results || []).filter((row) => row.role === 'private-reverse').length,
      testFoldOpenedByRun,
      resultText: document.getElementById('upstreamTestResult').innerText.replace(/\s+/g, ' ').trim(),
      toastCount: document.querySelectorAll('#toastStack .toast').length,
      modeDialog,
      serverDialog
    };
    document.getElementById('toastStack').replaceChildren();
    return result;
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'desktop-upstream-settings.png'));
  const desktopUpstreamDialog = await evaluateValue(client, `(async () => {
    document.getElementById('openDnsUpstreamServers').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    document.querySelector('#dnsUpstreamServersPanel .upstream-syntax').open = true;
    const modal = document.querySelector('#dnsUpstreamConfigModal .modal').getBoundingClientRect();
    const textarea = document.getElementById('upstreams').getBoundingClientRect();
    return {
      visible: !document.getElementById('dnsUpstreamConfigModal').classList.contains('hidden'),
      title: document.getElementById('dnsUpstreamConfigTitle').textContent,
      focused: document.activeElement === document.getElementById('upstreams'),
      insideViewport: modal.left >= 0 && modal.right <= innerWidth && modal.top >= 0 && modal.bottom <= innerHeight,
      textareaInside: textarea.left >= modal.left && textarea.right <= modal.right,
      syntaxExamples: document.querySelectorAll('#dnsUpstreamServersPanel .upstream-syntax-list code').length,
      doqExample: [...document.querySelectorAll('#dnsUpstreamServersPanel .upstream-syntax-list code')].some((node) => node.textContent.trim() === 'quic://unfiltered.adguard-dns.com')
    };
  })()`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'desktop-upstream-server-dialog.png'));
  await evaluate(client, `cancelDnsUpstreamConfig(); document.getElementById('upstreamTestFold').open = true; document.getElementById('upstreamTestFold').scrollIntoView({ block: 'start' }); true`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'desktop-upstream-test.png'));
  await evaluate(client, `(() => {
    document.getElementById('upstreams').value = window.__auditOriginalUpstreamText;
    document.getElementById('privateReverseUpstreams').value = window.__auditOriginalPrivateReverseText;
    document.getElementById('upstreams').dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('privateReverseUpstreams').dispatchEvent(new Event('input', { bubbles: true }));
    handleSettingsChange();
    return true;
  })()`);

  await evaluate(client, `selectView('dashboard', { skipUrl: true }); window.scrollTo(0, 0); true`);
  await sleep(500);
  const desktopDashboard = await layoutMetrics(client);
  await screenshot(client, path.join(outputDir, 'desktop-dashboard.png'));
  const desktopDashboardFidelity = await evaluateValue(client, `(async () => {
    const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    while (state.dashboardLoading) await wait(20);
    const period = document.getElementById('dashboardPeriod');
    const initial = {
      value: period.value,
      options: [...period.options].map((option) => Number(option.value)),
      statusPeriod: state.status.statistics.periodHours,
      apiOptions: [...(state.status.statistics.periodOptions || [])].map(Number)
    };
    const hasSevenDay = initial.options.includes(168);
    const targetPeriod = hasSevenDay ? '168' : initial.value;
    period.value = targetPeriod;
    period.dispatchEvent(new Event('change', { bubbles: true }));
    while (state.dashboardLoading) await wait(20);
    const rankNames = (id) => [...document.querySelectorAll('#' + id + ' .rank-row .rank-name-text')].map((node) => node.textContent.trim());
    const rankCounts = (id) => [...document.querySelectorAll('#' + id + ' .rank-row .rank-value')].map((node) => Number(node.textContent.replace(/[^0-9.]/g, '')) || 0);
    const ordered = (values, direction, compare = (left, right) => left - right) => values.every((value, index) => !index || (direction === 'asc' ? compare(values[index - 1], value) <= 0 : compare(values[index - 1], value) >= 0));
    const sortIds = ['topClients', 'topQueriedDomains', 'topBlockedDomains', 'topUpstreams', 'topUpstreamAvg'];
    const initialSorts = Object.fromEntries(sortIds.map((id) => [id, {
      buttons: document.querySelectorAll('#' + id + ' [data-rank-sort]').length,
      active: document.querySelector('#' + id + ' .rank-sort-button.active')?.dataset.rankSortField || '',
      aria: document.querySelector('#' + id + ' [aria-sort]:not([aria-sort="none"])')?.getAttribute('aria-sort') || ''
    }]));
    const nameButton = document.querySelector('#topClients [data-rank-sort-field="name"]');
    nameButton.focus();
    const nameFocused = document.activeElement === nameButton;
    nameButton.click();
    const namesAsc = rankNames('topClients');
    const nameAscAria = document.querySelector('#topClients [data-rank-sort-field="name"]')?.closest('[aria-sort]')?.getAttribute('aria-sort');
    document.querySelector('#topClients [data-rank-sort-field="name"]').click();
    const namesDesc = rankNames('topClients');
    const nameDescAria = document.querySelector('#topClients [data-rank-sort-field="name"]')?.closest('[aria-sort]')?.getAttribute('aria-sort');
    document.querySelector('#topClients [data-rank-sort-field="count"]').click();
    const countsRestored = rankCounts('topClients');
    const countRestoredAria = document.querySelector('#topClients [data-rank-sort-field="count"]')?.closest('[aria-sort]')?.getAttribute('aria-sort');
    const rankSort = {
      headers: document.querySelectorAll('#view-dashboard .rank-head').length,
      buttons: document.querySelectorAll('#view-dashboard [data-rank-sort]').length,
      eachTableHasTwoButtons: sortIds.every((id) => document.querySelectorAll('#' + id + ' [data-rank-sort]').length === 2),
      defaults: initialSorts,
      nameFocused,
      namesAsc: ordered(namesAsc, 'asc', (left, right) => left.localeCompare(right, undefined, { numeric: true, sensitivity: 'base' })),
      namesDesc: ordered(namesDesc, 'desc', (left, right) => left.localeCompare(right, undefined, { numeric: true, sensitivity: 'base' })),
      nameAscAria,
      nameDescAria,
      countsRestored: ordered(countsRestored, 'desc'),
      countRestoredAria,
      finalField: state.dashboardSort.topClients.field,
      finalDirection: state.dashboardSort.topClients.direction
    };
    const statCards = [...document.querySelectorAll('#dashboardStats .stats-card')].map((node) => node.getBoundingClientRect());
    const panels = [...document.querySelectorAll('#view-dashboard .dashboard-layout > .dashboard-panel')].map((node) => node.getBoundingClientRect());
    const upstreamRows = [...document.querySelectorAll('#topUpstreams .rank-row, #topUpstreamAvg .rank-row')];
    const dots = [...document.querySelectorAll('#topClients .rank-item-dot, #topQueriedDomains .rank-item-dot')];
    return {
      initial,
      hasSevenDay,
      targetPeriod,
      selected: period.value,
      statusPeriod: state.status.statistics.periodHours,
      urlPeriod: new URL(location.href).searchParams.get('period'),
      windowText: document.getElementById('dashboardStatsWindow').textContent.trim(),
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      statCards: statCards.length,
      statCardSameRow: statCards.length === 4 && statCards.every((rect) => Math.abs(rect.top - statCards[0].top) <= 1),
      statCardEqualHeight: statCards.length === 4 && statCards.every((rect) => Math.abs(rect.height - statCards[0].height) <= 1),
      mobileTitlesHidden: [...document.querySelectorAll('.stats-card-mobile-title')].every((node) => getComputedStyle(node).display === 'none'),
      primaryPanels: panels.length,
      panelPairHeightsEqual: panels.length === 6 && [0, 2, 4].every((index) => Math.abs(panels[index].height - panels[index + 1].height) <= 1),
      panelHeight: Math.round(panels[0]?.height || 0),
      duplicateRefreshButtons: document.querySelectorAll('[data-dashboard-refresh]').length,
      counterIcons: document.querySelectorAll('#dashboardCounters .dashboard-stat-icon').length,
      upstreamRows: upstreamRows.length,
      upstreamRowsSeparated: upstreamRows.every((row) => {
        const name = row.querySelector('.rank-name')?.getBoundingClientRect();
        const metric = row.querySelector('.rank-metric')?.getBoundingClientRect();
        return !name || !metric || name.right <= metric.left + 1;
      }),
      rankDotsSpaced: dots.every((dot) => {
        const dotRect = dot.getBoundingClientRect();
        const textRect = dot.nextElementSibling?.getBoundingClientRect();
        return !textRect || textRect.left - dotRect.right >= 6;
      }),
      runningDetailsVisible: document.getElementById('dashboardExtra').getClientRects().length > 0,
      timelineVisible: document.getElementById('dashboardTimeline').getClientRects().length > 0,
      rankSort
    };
  })()`);
  await evaluate(client, `document.querySelector('#topClients [data-rank-sort-field="name"]').click(); document.getElementById('topClients').closest('.dashboard-panel').scrollIntoView({ block: 'start' }); true`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'desktop-dashboard-sorted.png'));
  await evaluate(client, `document.querySelector('#topClients [data-rank-sort-field="count"]').click(); window.scrollTo(0, 0); true`);
  await screenshot(client, path.join(outputDir, 'desktop-dashboard-period-selected.png'));
  Object.assign(desktopDashboardFidelity, await evaluateValue(client, `(async () => {
    const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    const period = document.getElementById('dashboardPeriod');
    period.value = ${JSON.stringify(desktopDashboardFidelity.initial.value)};
    period.dispatchEvent(new Event('change', { bubbles: true }));
    while (state.dashboardLoading) await wait(20);
    document.getElementById('refreshDashboard').click();
    const refreshBusyVisible = state.dashboardLoading && document.getElementById('refreshDashboard').classList.contains('is-loading') && document.getElementById('refreshDashboard').disabled;
    while (state.dashboardLoading) await wait(20);
    return {
      restoredPeriod: period.value,
      restoredStatusPeriod: state.status.statistics.periodHours,
      restoredUrlPeriod: new URL(location.href).searchParams.get('period'),
      refreshBusyVisible,
      refreshRestored: !document.getElementById('refreshDashboard').disabled && !document.getElementById('refreshDashboard').classList.contains('is-loading')
    };
  })()`));

  const desktopOverlays = await evaluateValue(client, `(async () => {
    const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    const press = (key, shiftKey = false) => document.dispatchEvent(new KeyboardEvent('keydown', { key, shiftKey, bubbles: true, cancelable: true }));
    const result = {};

    selectView('filters', { skipUrl: true });
    selectFilterSection('blocklists', '', { history: 'replace' });
    const filterTrigger = document.getElementById('chooseSub');
    filterTrigger.focus();
    filterTrigger.click();
    await wait(40);
    const filterModal = document.getElementById('filterModal');
    const filterFocusable = [...filterModal.querySelectorAll('button, input, select, textarea, a[href], [tabindex]:not([tabindex="-1"])')].filter((node) => node.getClientRects().length && !node.disabled);
    const filterLast = filterFocusable[filterFocusable.length - 1];
    filterLast.focus();
    press('Tab');
    await wait(20);
    const tabWrapped = document.activeElement === filterFocusable[0];
    press('Escape');
    await wait(40);
    result.filter = {
      tabWrapped,
      closed: filterModal.classList.contains('hidden'),
      ariaHidden: filterModal.getAttribute('aria-hidden'),
      bodyUnlocked: !document.body.classList.contains('modal-open'),
      focusRestored: document.activeElement === filterTrigger
    };

    selectFilterSection('rewrites', '', { history: 'replace' });
    const rewriteTrigger = document.getElementById('toggleRewriteEditor');
    rewriteTrigger.focus();
    rewriteTrigger.click();
    await wait(40);
    const rewriteModal = document.getElementById('rewriteQuickAdd');
    const rewriteFocused = document.activeElement === document.getElementById('rewriteDomain');
    document.getElementById('rewriteDomain').value = '*.audit.example';
    const rewriteAnswer = document.getElementById('rewriteValue');
    rewriteAnswer.value = 'target.audit.example';
    rewriteAnswer.dispatchEvent(new Event('input', { bubbles: true }));
    const detectedType = document.getElementById('rewriteDetectedType').textContent.trim();
    press('Escape');
    await wait(40);
    result.rewrite = {
      focused: rewriteFocused,
      typeControlRemoved: !document.getElementById('rewriteType'),
      detectedType,
      wildcardNormalized: normalizeRewriteDomainInput('*.audit.example', true),
      closed: rewriteModal.classList.contains('hidden'),
      bodyUnlocked: !document.body.classList.contains('modal-open'),
      focusRestored: document.activeElement === rewriteTrigger
    };

    const rewriteGlobalToggle = document.getElementById('rewriteGlobalEnabled');
    const originalRewriteGlobal = rewritesGloballyEnabled();
    rewriteGlobalToggle.focus();
    rewriteGlobalToggle.click();
    await wait(40);
    const rewriteGlobalModal = document.getElementById('rewriteGlobalModal');
    const targetRewriteGlobal = !originalRewriteGlobal;
    const cancelState = {
      visible: !rewriteGlobalModal.classList.contains('hidden'),
      focused: document.activeElement === document.getElementById('confirmRewriteGlobal'),
      target: rewriteGlobalTarget,
      switchRestoredBeforeConfirm: rewriteGlobalToggle.checked === originalRewriteGlobal
    };
    document.getElementById('cancelRewriteGlobal').click();
    await wait(40);
    const cancelRestored = rewriteGlobalModal.classList.contains('hidden') && rewriteGlobalToggle.checked === originalRewriteGlobal && document.activeElement === rewriteGlobalToggle;
    const originalRewriteApi = api;
    api = async (path, options = {}) => {
      if (path === '/api/settings' && String(options.method || 'GET').toUpperCase() === 'POST') {
        return { settings: { ...state.settings, rewritesEnabled: targetRewriteGlobal }, status: state.status };
      }
      return originalRewriteApi(path, options);
    };
    rewriteGlobalToggle.click();
    await wait(30);
    document.getElementById('confirmRewriteGlobal').click();
    await wait(80);
    api = originalRewriteApi;
    const applied = rewriteGlobalModal.classList.contains('hidden') && rewritesGloballyEnabled() === targetRewriteGlobal && rewriteGlobalToggle.checked === targetRewriteGlobal;
    state.settings = { ...state.settings, rewritesEnabled: originalRewriteGlobal };
    renderRewriteList();
    clearToasts('ok', 'DNS 重写');
    result.rewriteGlobal = {
      ...cancelState,
      original: originalRewriteGlobal,
      cancelRestored,
      applied,
      restored: rewritesGloballyEnabled() === originalRewriteGlobal && rewriteGlobalToggle.checked === originalRewriteGlobal,
      label: document.getElementById('rewriteGlobalEnabledLabel').textContent.trim()
    };

    selectFilterSection('blocklists', '', { history: 'replace' });
    const subscriptionTrigger = [...document.querySelectorAll('[data-open-subscription-auto-update]')].find((node) => node.getClientRects().length);
    subscriptionTrigger.focus();
    subscriptionTrigger.click();
    await wait(40);
    const subscriptionModal = document.getElementById('subscriptionAutoUpdateModal');
    const subscriptionFocused = document.activeElement === document.getElementById('subscriptionAutoUpdateEnabled');
    press('Escape');
    await wait(40);
    result.subscription = {
      focused: subscriptionFocused,
      closed: subscriptionModal.classList.contains('hidden'),
      focusRestored: document.activeElement === subscriptionTrigger
    };

    const originalApi = api;
    let releaseClientLoad = null;
    let delayedClientLoad = false;
    api = async (path, options = {}) => {
      const method = String(options.method || 'GET').toUpperCase();
      if (!delayedClientLoad && path === '/api/clients' && method === 'GET') {
        delayedClientLoad = true;
        await new Promise((resolve) => { releaseClientLoad = resolve; });
      }
      return originalApi(path, options);
    };
    selectView('dns', { skipUrl: true });
    selectSettingsSection('clients', { history: 'replace' });
    await wait(20);
    const clientTrigger = document.getElementById('toggleClientEditor');
    clientTrigger.focus();
    clientTrigger.click();
    await wait(40);
    const clientFocusedBeforeLoad = document.activeElement === document.getElementById('clientName');
    releaseClientLoad?.();
    await wait(250);
    const clientFocusedAfterLoad = document.activeElement === document.getElementById('clientName');
    const clientOpenAfterLoad = !document.getElementById('clientWorkspace').classList.contains('editor-collapsed');
    document.querySelector('[data-client-editor-tab="upstreams"]').click();
    const upstreams = document.getElementById('clientUpstreams');
    const cacheToggle = document.getElementById('clientUpstreamsCacheEnabled');
    const cacheSize = document.getElementById('clientUpstreamsCacheSize');
    const initialCache = {
      enabled: cacheToggle.checked,
      size: cacheSize.value,
      sizeDisabled: cacheSize.disabled,
      stateText: document.getElementById('clientUpstreamsCacheState').textContent
    };
    upstreams.value = 'udp://1.1.1.1';
    upstreams.dispatchEvent(new Event('input', { bubbles: true }));
    cacheToggle.click();
    cacheSize.value = '1048576';
    cacheSize.dispatchEvent(new Event('input', { bubbles: true }));
    const configuredCache = {
      enabled: cacheToggle.checked,
      size: cacheSize.value,
      sizeDisabled: cacheSize.disabled,
      stateText: document.getElementById('clientUpstreamsCacheState').textContent,
      effective: clientCustomCacheActive({
        upstreams: splitLines(upstreams.value),
        upstreamsCacheEnabled: cacheToggle.checked,
        upstreamsCacheSize: Number(cacheSize.value)
      })
    };
    api = originalApi;
    press('Escape');
    await wait(40);
    let releaseRouteClientLoad = null;
    let delayedRouteClientLoad = false;
    api = async (path, options = {}) => {
      const method = String(options.method || 'GET').toUpperCase();
      if (!delayedRouteClientLoad && path === '/api/clients' && method === 'GET') {
        delayedRouteClientLoad = true;
        await new Promise((resolve) => { releaseRouteClientLoad = resolve; });
      }
      return originalApi(path, options);
    };
    selectSettingsSection('clients', { history: 'replace' });
    await wait(30);
    selectSettingsSection('general', { history: 'replace' });
    releaseRouteClientLoad?.();
    await wait(300);
    const routeIsolation = {
      delayedLoad: delayedRouteClientLoad,
      view: state.view,
      section: state.settingsSection,
      title: document.getElementById('settingsTitle').textContent.trim(),
      description: document.getElementById('settingsDesc').textContent.trim(),
      generalActive: document.getElementById('settings-section-general').classList.contains('active'),
      clientsInactive: !document.getElementById('settings-section-clients').classList.contains('active')
    };
    api = originalApi;
    result.client = {
      delayedLoad: delayedClientLoad,
      focusedBeforeLoad: clientFocusedBeforeLoad,
      focusedAfterLoad: clientFocusedAfterLoad,
      openAfterLoad: clientOpenAfterLoad,
      cacheControls: { initial: initialCache, configured: configuredCache },
      closed: document.getElementById('clientWorkspace').classList.contains('editor-collapsed'),
      focusRestored: document.activeElement === clientTrigger,
      routeIsolation
    };

    selectView('logs', { skipUrl: true });
    if (state.recent[0]) {
      openLogDetail(state.recent[0]);
      await wait(40);
      const logModal = document.getElementById('logDetailModal');
      const logFocused = document.activeElement === document.getElementById('closeLogDetailModal');
      press('Escape');
      await wait(40);
      result.log = { focused: logFocused, closed: logModal.classList.contains('hidden') };
    } else {
      result.log = { skipped: true };
    }

    const settingsCaret = document.querySelector('.nav-group .nav-caret[data-view="dns"]');
    settingsCaret.focus();
    settingsCaret.click();
    await wait(20);
    const settingsGroup = settingsCaret.closest('.nav-group');
    const navMenu = settingsGroup.querySelector('.nav-menu');
    const menuOpened = getComputedStyle(navMenu).display !== 'none';
    document.body.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await wait(20);
    result.desktopNav = {
      menuOpened,
      closedOutside: !settingsGroup.classList.contains('menu-open') && getComputedStyle(navMenu).display === 'none'
    };
    return result;
  })()`);

  await evaluate(client, `(() => {
    selectView('filters', { skipUrl: true });
    selectFilterSection('rewrites', '', { history: 'replace' });
    document.getElementById('rewriteGlobalEnabled').click();
    return true;
  })()`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'desktop-rewrite-global-toggle.png'));
  await evaluate(client, `document.getElementById('cancelRewriteGlobal').click(); true`);

  await evaluate(client, `(() => {
    selectView('filters', { skipUrl: true });
    selectFilterSection('rewrites', '', { history: 'replace' });
    document.getElementById('toggleRewriteEditor').click();
    document.getElementById('rewriteDomain').value = '*.audit.example';
    const answer = document.getElementById('rewriteValue');
    answer.value = 'target.audit.example';
    answer.dispatchEvent(new Event('input', { bubbles: true }));
    return true;
  })()`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'desktop-rewrite-cname.png'));
  await evaluate(client, `document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true })); true`);

  const desktopFilteringCheck = await evaluateValue(client, `(async () => {
    const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    selectView('filters', { skipUrl: true });
    selectFilterSection('custom', '', { history: 'replace' });
    const rulesEditor = document.getElementById('rulesText');
    const originalRules = rulesEditor.value;
    const newline = String.fromCharCode(10);
    const backslash = String.fromCharCode(92);
    rulesEditor.value = originalRules + (originalRules && !originalRules.endsWith(newline) ? newline : '') + [
      'plain.audit.example',
      '192.0.2.10 host.audit.example alias.audit.example',
      '/^(ads|track)[0-9]+' + backslash + '.audit' + backslash + '.example$/'
    ].join(newline) + newline;
    syncRuleMetrics();
    const editorParity = {
      hostsHighlighted: document.querySelectorAll('#rulesHighlight .hosts').length > 0,
      regexHighlighted: document.querySelectorAll('#rulesHighlight .regex').length > 0,
      hostsMetric: document.getElementById('rulesInfo').textContent.includes('Hosts'),
      regexMetric: document.getElementById('rulesInfo').textContent.includes('正则'),
      overviewMentionsTypes: document.getElementById('rulesOverview').textContent.includes('Hosts') && document.getElementById('rulesOverview').textContent.includes('正则'),
      examples: document.querySelectorAll('.rules-examples [data-rule-example]').length,
      hasExactExample: [...document.querySelectorAll('.rules-examples [data-rule-example]')].some((button) => button.dataset.ruleExample === 'ads.example.com'),
      hasMultiHostExample: [...document.querySelectorAll('.rules-examples [data-rule-example]')].some((button) => button.dataset.ruleExample.includes('alias.example.org')),
      hasRegexExample: [...document.querySelectorAll('.rules-examples [data-rule-example]')].some((button) => button.dataset.ruleExample.startsWith('/^'))
    };
    rulesEditor.value = originalRules;
    syncRuleMetrics();
    const candidates = [
      { name: 'hosts-check.audit', type: 'A' },
      { name: 'ipv4.rewrite.test', type: 'A' },
      { name: 'doubleclick.net', type: 'A' }
    ];
    let selected = candidates[0];
    let expected = null;
    for (const candidate of candidates) {
      const checked = await api('/api/filter/check', {
        method: 'POST',
        body: JSON.stringify({ ...candidate, clientIp: '127.0.0.1' })
      });
      selected = candidate;
      expected = checked;
      if (checked.status !== 'not_filtered') break;
    }
    const expectedRules = Array.isArray(expected?.rules) ? expected.rules : [];
    const expectedRewriteRows = expected?.rewrite ? 1 : 0;
    const expectedEvidence = expected?.rewrite?.values?.[0]
      || expectedRules[0]?.text
      || filterCheckReason(expected || {});
    const beforeRecent = state.recent.length;
    const beforeTotal = Number(state.status?.stats?.total || 0);
    document.getElementById('customCheckName').value = selected.name;
    document.getElementById('customCheckType').value = selected.type;
    document.getElementById('customCheckIp').value = '127.0.0.1';
    document.getElementById('runCustomCheck').click();
    const busyVisible = document.getElementById('runCustomCheck').disabled && document.getElementById('runCustomCheck').textContent.trim() === '处理中...';
    const deadline = Date.now() + 10000;
    while (document.getElementById('customCheckState').textContent.trim() === '检查中' && Date.now() < deadline) await wait(25);
    const result = document.getElementById('customCheckResult');
    const rect = result.getBoundingClientRect();
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      insideViewport: rect.left >= 0 && rect.right <= innerWidth + 1,
      state: document.getElementById('customCheckState').textContent.trim(),
      expectedState: filterCheckDecision(expected || {}).label,
      expectedStatus: expected?.status || '',
      sourceLabelRendered: expected?.source !== 'filter-hosts' || result.textContent.includes('Hosts 规则'),
      expectedRuleRows: expectedRules.length,
      expectedRewriteRows,
      hasExpectedEvidence: !expectedEvidence || result.textContent.includes(expectedEvidence),
      resultText: result.textContent.trim(),
      ruleRows: result.querySelectorAll('.custom-check-rule-row').length,
      rewriteRows: result.querySelectorAll('.custom-check-rewrite').length,
      typeOptions: document.getElementById('customCheckType').options.length,
      busyVisible,
      busyRestored: !document.getElementById('runCustomCheck').disabled && document.getElementById('runCustomCheck').textContent.trim() === '检查规则',
      recentUnchanged: state.recent.length === beforeRecent,
      statsUnchanged: Number(state.status?.stats?.total || 0) === beforeTotal,
      editorParity
    };
  })()`);
  await screenshot(client, path.join(outputDir, 'desktop-filtering-check.png'));

  const desktopClientsPersistent = await evaluateValue(client, `(async () => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('clients', { history: 'replace' });
    await loadClients();
    setClientView('persistent');
    window.scrollTo(0, 0);
    const section = document.getElementById('settings-section-clients').getBoundingClientRect();
    const persistentTab = document.querySelector('[data-client-view="persistent"]');
    const runtimeTab = document.querySelector('[data-client-view="runtime"]');
    persistentTab.focus();
    persistentTab.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 20));
    const keyboardSwitched = state.clientView === 'runtime' && document.activeElement === runtimeTab;
    setClientView('persistent');
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      sectionWidth: Math.round(section.width),
      tabs: document.querySelectorAll('[data-client-view]').length,
      activeTab: document.querySelector('[data-client-view].active')?.dataset.clientView || '',
      visiblePanels: [...document.querySelectorAll('[data-client-view-panel]')].filter((node) => !node.hidden && node.getClientRects().length).length,
      keyboardSwitched,
      clientCount: state.clients.length,
      headerCells: document.querySelectorAll('#clientPersistentPanel .client-table thead th').length,
      rowCount: document.querySelectorAll('#clientsList tr').length,
      compactSettings: document.querySelectorAll('#clientsList .client-table-setting').length,
      editorHidden: document.getElementById('clientWorkspace').classList.contains('editor-collapsed'),
      saveDisabled: document.getElementById('saveClients').disabled,
      actionsInside: [...document.querySelectorAll('#clientsList .client-actions-cell')].every((cell) => {
        const cellRect = cell.getBoundingClientRect();
        return [...cell.querySelectorAll('button')].every((button) => {
          const rect = button.getBoundingClientRect();
          return rect.left >= cellRect.left && rect.right <= cellRect.right;
        });
      })
    };
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'desktop-clients-persistent.png'));

  const desktopClientDeleteDialog = await evaluateValue(client, `(async () => {
    const button = document.querySelector('#clientsList [data-client-del]');
    const countBefore = state.clients.length;
    const dirtyBefore = state.clientsDirty;
    button?.focus();
    button?.click();
    await new Promise((resolve) => setTimeout(resolve, 40));
    const modal = document.getElementById('clientDeleteModal');
    const rect = modal.querySelector('.modal').getBoundingClientRect();
    return {
      available: Boolean(button),
      visible: !modal.classList.contains('hidden'),
      focused: document.activeElement === document.getElementById('confirmClientDelete'),
      title: document.getElementById('clientDeleteTitle').textContent.trim(),
      question: document.getElementById('clientDeleteQuestion').textContent.trim(),
      insideViewport: rect.left >= 0 && rect.right <= innerWidth && rect.top >= 0 && rect.bottom <= innerHeight,
      countBefore,
      dirtyBefore
    };
  })()`);
  await screenshot(client, path.join(outputDir, 'desktop-client-delete-dialog.png'));
  Object.assign(desktopClientDeleteDialog, await evaluateValue(client, `(() => {
    const opener = document.activeElement;
    document.getElementById('cancelClientDelete').click();
    return new Promise((resolve) => setTimeout(() => resolve({
      closed: document.getElementById('clientDeleteModal').classList.contains('hidden'),
      countPreserved: state.clients.length === ${desktopClientDeleteDialog.countBefore},
      dirtyPreserved: state.clientsDirty === ${desktopClientDeleteDialog.dirtyBefore},
      focusRestored: document.activeElement !== opener && document.activeElement?.matches?.('[data-client-del]') === true
    }), 40));
  })()`));

  const desktopClientCache = await evaluateValue(client, `(() => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('clients', { history: 'replace' });
    openClientEditor(false);
    setClientEditorTab('upstreams');
    document.getElementById('clientUpstreams').value = 'udp://1.1.1.1';
    document.getElementById('clientUpstreamsCacheEnabled').checked = true;
    document.getElementById('clientUpstreamsCacheSize').value = '1048576';
    renderClientUpstreamControls();
    window.scrollTo(0, 0);
    const rect = document.getElementById('clientQuickAdd').getBoundingClientRect();
    const actions = document.querySelector('#clientQuickAdd .client-editor-actions').getBoundingClientRect();
    const sizeRect = document.getElementById('clientUpstreamsCacheSize').getBoundingClientRect();
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      width: Math.round(rect.width),
      stateText: document.getElementById('clientUpstreamsCacheState').textContent,
      sizeDisabled: document.getElementById('clientUpstreamsCacheSize').disabled,
      mainTabsHidden: document.querySelector('.client-view-tabs').getClientRects().length === 0,
      pageTitle: document.getElementById('settingsTitle').textContent.trim(),
      editorTitle: document.getElementById('clientEditorTitle').textContent.trim(),
      actionsPosition: getComputedStyle(document.querySelector('#clientQuickAdd .client-editor-actions')).position,
      actionsAfterInput: actions.top >= sizeRect.bottom - 1
    };
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'desktop-client-cache.png'));
  await evaluate(client, `closeClientEditor(); true`);

  const desktopRuntimeClients = await evaluateValue(client, `(async () => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('clients', { history: 'replace' });
    await loadClients();
    setClientView('runtime');
    const moduleNode = document.getElementById('runtimeClientModule');
    const rows = [...document.querySelectorAll('#runtimeClientsList .runtime-client-row')];
    const candidate = (state.runtimeClients || []).find((item) => item.known !== true && Number(item.requests || 0) > 0) || (state.runtimeClients || []).find((item) => item.known !== true) || (state.runtimeClients || [])[0];
    const row = candidate ? rows.find((item) => item.textContent.includes(candidate.address)) : rows[0];
    const addButton = row?.querySelector('[data-runtime-client-add]');
    const clientsDirtyBefore = state.clientsDirty;
    let prefillIdentifier = '';
    let editorOpened = false;
    if (addButton) {
      addButton.click();
      prefillIdentifier = document.getElementById('clientIdentifiers').value.trim();
      editorOpened = !document.getElementById('clientWorkspace').classList.contains('editor-collapsed');
      closeClientEditor();
    }
    moduleNode.scrollIntoView({ block: 'start' });
    const rect = moduleNode.getBoundingClientRect();
    const addresses = (state.runtimeClients || []).map((item) => item.address);
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      moduleWidth: Math.round(rect.width),
      runtimeCount: state.runtimeClients?.length || 0,
      rowCount: rows.length,
      headerCells: document.querySelectorAll('#runtimeClientsList .runtime-client-head > span').length,
      addresses,
      rawHostAddresses: addresses.length > 0 && addresses.every((address) => !String(address).includes('/')),
      queryLogAnonymized: state.queryLog?.anonymizeClientIp !== false,
      anonymizedRecent: (state.recent || []).some((item) => String(item.client || '').includes('/')),
      sourceText: row?.querySelector('.runtime-client-source')?.innerText.replace(/\\s+/g, ' ').trim() || '',
      sourceTexts: rows.map((item) => item.querySelector('.runtime-client-source')?.innerText.replace(/\\s+/g, ' ').trim() || ''),
      requests: Number(row?.querySelector('.runtime-client-requests strong')?.textContent.replace(/[^0-9]/g, '') || 0),
      addAvailable: Boolean(addButton),
      editorOpened,
      prefillIdentifier,
      prefillMatchesAddress: Boolean(candidate && prefillIdentifier === candidate.address),
      clientsDirtyPreserved: state.clientsDirty === clientsDirtyBefore,
      activeTab: state.clientView,
      visiblePanels: [...document.querySelectorAll('[data-client-view-panel]')].filter((node) => !node.hidden && node.getClientRects().length).length
    };
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'desktop-runtime-clients.png'));

  const desktopDhcpRuntimeClient = await evaluateValue(client, `(() => {
    window.__cleandnsAuditRuntimeClients = state.runtimeClients;
    window.__cleandnsAuditRuntimeClientExpanded = state.runtimeClientExpanded;
    const address = '192.168.50.101';
    state.runtimeClients = [{
      address,
      name: 'phone.lan',
      note: '',
      clientId: '',
      tags: [],
      known: false,
      source: 'dhcp',
      dhcp: {
        kind: 'dynamic',
        hostname: 'phone.lan',
        mac: '00:11:22:33:44:55',
        expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString()
      },
      requests: 27,
      blocked: 2,
      cached: 11,
      protocols: ['udp'],
      types: ['A', 'AAAA'],
      firstSeenAt: new Date(Date.now() - 10 * 60 * 1000).toISOString(),
      lastSeenAt: new Date().toISOString(),
      queryLogAnonymized: true,
      reverseDns: { enabled: false, status: 'disabled', hostname: '', resolver: '', scope: '', error: '' },
      whois: { enabled: true, status: 'resolved', info: { orgname: 'CleanDNS Audit Network', city: 'Shanghai', country: 'CN' }, server: 'whois.arin.net:43', error: '' }
    }];
    state.runtimeClientExpanded = [address];
    state.runtimeClientPage = 1;
    renderRuntimeClients();
    const row = document.querySelector('#runtimeClientsList .runtime-client-row');
    const source = row?.querySelector('.runtime-client-source');
    const whois = row?.querySelector('.runtime-client-whois');
    const addButton = row?.querySelector('[data-runtime-client-add]');
    const sourceText = source?.innerText.replace(/\\s+/g, ' ').trim() || '';
    const rowRect = row?.getBoundingClientRect();
    const sourceRect = source?.getBoundingClientRect();
    const whoisRect = whois?.getBoundingClientRect();
    addButton?.click();
    const prefill = {
      name: document.getElementById('clientName').value.trim(),
      tags: document.getElementById('clientTags').value.trim(),
      note: document.getElementById('clientNote').value.trim()
    };
    closeClientEditor();
    setClientView('runtime');
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      rowVisible: Boolean(rowRect && rowRect.width > 0 && rowRect.height > 0),
      sourceInside: Boolean(rowRect && sourceRect && sourceRect.left >= rowRect.left && sourceRect.right <= rowRect.right),
      sourceText,
      whoisText: whois?.innerText.replace(/\\s+/g, ' ').trim() || '',
      whoisInside: Boolean(rowRect && whoisRect && whoisRect.left >= rowRect.left && whoisRect.right <= rowRect.right),
      name: row?.querySelector('.runtime-client-main span')?.textContent.trim() || '',
      prefill
    };
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'desktop-runtime-client-dhcp.png'));
  await evaluate(client, `(() => {
    state.runtimeClients = window.__cleandnsAuditRuntimeClients || [];
    state.runtimeClientExpanded = window.__cleandnsAuditRuntimeClientExpanded || [];
    delete window.__cleandnsAuditRuntimeClients;
    delete window.__cleandnsAuditRuntimeClientExpanded;
    renderRuntimeClients();
    return true;
  })()`);

  const desktopDhcp = await evaluateValue(client, `(async () => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('dhcp', { history: 'replace' });
    await loadDhcpStatus({ silent: true, preserveForm: true });
    await checkDhcpConfiguration();
    openDhcpLeaseModal();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const modalFocused = document.activeElement === document.getElementById('dhcpLeaseMac');
    closeDhcpLeaseModal();
    document.getElementById('settings-section-dhcp').scrollIntoView({ block: 'start' });
    const section = document.getElementById('settings-section-dhcp').getBoundingClientRect();
    const dnsField = document.getElementById('dhcpDnsServers').closest('.cache-field').getBoundingClientRect();
    const dnsInput = document.getElementById('dhcpDnsServers').getBoundingClientRect();
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      sectionWidth: Math.round(section.width),
      supported: state.dhcp.supported,
      running: state.dhcp.running,
      interfaceOptions: document.getElementById('dhcpInterfaceName').options.length,
      enableDisabled: document.getElementById('dhcpEnabled').disabled,
      validationErrors: state.dhcp.validation?.errors?.length || 0,
      runtimeText: document.getElementById('dhcpRuntimeBanner').innerText.replace(/\s+/g, ' ').trim(),
      dnsInputWidth: Math.round(dnsInput.width),
      dnsInputHeight: Math.round(dnsInput.height),
      dnsInputInsideField: dnsInput.left >= dnsField.left && dnsInput.right <= dnsField.right,
      modalFocused,
      modalClosed: document.getElementById('dhcpLeaseModal').classList.contains('hidden')
    };
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'desktop-dhcp.png'));
  await evaluate(client, `document.getElementById('dhcpDnsServers').scrollIntoView({ block: 'center' }); true`);
  await sleep(120);
  await screenshot(client, path.join(outputDir, 'desktop-dhcp-dns.png'));

  await evaluate(client, `(async () => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('encryption', { history: 'replace' });
    await loadTlsStatus({ silent: true });
    document.getElementById('encryption-module-protocols').scrollIntoView({ block: 'start' });
    return true;
  })()`);
  await sleep(120);
  await screenshot(client, path.join(outputDir, 'desktop-doq-runtime.png'));

  const desktopEncryptionDialogs = {};
  await evaluate(client, `clearToasts(); window.scrollTo({ top: 0, left: 0, behavior: 'auto' }); true`);
  await sleep(80);
  desktopEncryptionDialogs.menu = await evaluateValue(client, `(() => {
    const toggle = document.getElementById('encryptionActionsToggle');
    toggle.click();
    const menu = document.getElementById('encryptionActionsMenu');
    const rect = menu.getBoundingClientRect();
    return {
      visible: !menu.classList.contains('hidden'),
      expanded: toggle.getAttribute('aria-expanded') === 'true',
      items: menu.querySelectorAll('[role="menuitem"]').length,
      width: Math.round(rect.width),
      height: Math.round(rect.height),
      insideViewport: rect.left >= 0 && rect.right <= innerWidth && rect.top >= 0 && rect.bottom <= innerHeight
    };
  })()`);
  await screenshot(client, path.join(outputDir, 'desktop-encryption-actions.png'));
  desktopEncryptionDialogs.outsideClose = await evaluateValue(client, `(() => {
    document.body.click();
    return document.getElementById('encryptionActionsMenu').classList.contains('hidden') && document.getElementById('encryptionActionsToggle').getAttribute('aria-expanded') === 'false';
  })()`);
  desktopEncryptionDialogs.tls = await evaluateValue(client, `(async () => {
    const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    document.getElementById('encryptionActionsToggle').click();
    document.getElementById('openTlsConfigFromMenu').click();
    await wait(50);
    const backdrop = document.getElementById('tlsConfigModal');
    const modal = backdrop.querySelector('.modal');
    const rect = modal.getBoundingClientRect();
    const result = {
      visible: !backdrop.classList.contains('hidden'),
      insideViewport: rect.left >= 0 && rect.right <= innerWidth && rect.top >= 0 && rect.bottom <= innerHeight,
      focused: document.activeElement === document.getElementById('tlsCertificatePath'),
      certificateMatches: document.getElementById('tlsCertificatePath').value === state.tlsStatus.certificatePath,
      privateKeyMatches: document.getElementById('tlsPrivateKeyPath').value === state.tlsStatus.privateKeyPath,
      source: backdrop.querySelector('.tls-config-source')?.innerText.replace(/\s+/g, ' ').trim() || ''
    };
    return result;
  })()`);
  await screenshot(client, path.join(outputDir, 'desktop-tls-config-dialog.png'));
  desktopEncryptionDialogs.tlsEscape = await evaluateValue(client, `(async () => {
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 40));
    return {
      closed: document.getElementById('tlsConfigModal').classList.contains('hidden'),
      focusRestored: document.activeElement === document.getElementById('openTlsConfig')
    };
  })()`);
  desktopEncryptionDialogs.reset = await evaluateValue(client, `(async () => {
    const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    const before = {
      dohPath: state.settings.dohPath,
      certificatePath: state.tlsStatus.certificatePath,
      privateKeyPath: state.tlsStatus.privateKeyPath,
      dirty: state.settingsDirty
    };
    document.getElementById('encryptionActionsToggle').click();
    document.getElementById('openProtocolReset').click();
    const deadline = Date.now() + 5000;
    while (document.getElementById('confirmProtocolReset').disabled && Date.now() < deadline) await wait(25);
    const backdrop = document.getElementById('protocolResetModal');
    const modal = backdrop.querySelector('.modal');
    const rect = modal.getBoundingClientRect();
    return {
      visible: !backdrop.classList.contains('hidden'),
      insideViewport: rect.left >= 0 && rect.right <= innerWidth && rect.top >= 0 && rect.bottom <= innerHeight,
      rows: document.querySelectorAll('#protocolResetSummary .protocol-reset-row').length,
      confirmEnabled: !document.getElementById('confirmProtocolReset').disabled,
      preserveText: document.getElementById('protocolResetSummary').innerText.replace(/\s+/g, ' ').trim(),
      before,
      unchangedBeforeConfirm: before.dohPath === state.settings.dohPath && before.certificatePath === state.tlsStatus.certificatePath && before.privateKeyPath === state.tlsStatus.privateKeyPath && before.dirty === state.settingsDirty
    };
  })()`);
  await screenshot(client, path.join(outputDir, 'desktop-protocol-reset-dialog.png'));
  desktopEncryptionDialogs.resetClosed = await evaluateValue(client, `(() => {
    document.getElementById('cancelProtocolReset').click();
    return document.getElementById('protocolResetModal').classList.contains('hidden');
  })()`);

  const desktopTls = await evaluateValue(client, `(async () => {
    const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    selectView('dns', { skipUrl: true });
    selectSettingsSection('encryption', { history: 'replace' });
    await loadTlsStatus({ silent: true });
    const validateButton = document.getElementById('validateTlsCertificate');
    validateButton.click();
    const deadline = Date.now() + 5000;
    while (validateButton.disabled && Date.now() < deadline) await wait(25);
    const validateNotice = document.getElementById('settingsNotice').textContent.trim();
    const validateToast = [...document.querySelectorAll('#toastStack .toast')].map((node) => node.textContent.trim()).join(' ');
    const profileResponse = await fetch(apiTarget('/api/apple/doh.mobileconfig'), { credentials: 'same-origin' });
    const profileText = await profileResponse.text();
    const moduleNode = document.getElementById('encryption-module-certificate');
    const detailsNode = document.getElementById('tlsCertificateDetails');
    moduleNode.scrollIntoView({ block: 'start' });
    const moduleRect = moduleNode.getBoundingClientRect();
    const status = state.tlsStatus || {};
    const doq = state.status?.protocols?.doq || {};
    const expectedDoqRuntime = doq.enabled === false ? '已停用' : doq.verified === false ? '待确认' : doq.running ? '运行中' : '未运行';
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      moduleWidth: Math.round(moduleRect.width),
      status: status.status || '',
      validCert: status.validCert === true,
      validKey: status.validKey === true,
      validChain: status.validChain === true,
      validPair: status.validPair === true,
      validHost: status.validHost === true,
      stateText: document.getElementById('tlsCertificateState').textContent.trim(),
      bannerClass: document.getElementById('tlsCertificateBanner').className,
      bannerText: document.getElementById('tlsCertificateBanner').innerText.replace(/\\s+/g, ' ').trim(),
      summaryItems: document.querySelectorAll('#tlsCertificateSummary .settings-summary-item').length,
      detailRows: document.querySelectorAll('#tlsCertificateDetails .tls-detail-row').length,
      detailColumns: getComputedStyle(detailsNode).gridTemplateColumns.split(/\\s+/).filter(Boolean).length,
      validateNotice,
      validateToast,
      validateRestored: !validateButton.disabled && validateButton.querySelector('span').textContent.trim() === '重新验证',
      downloadEnabled: !document.getElementById('downloadDohProfile').disabled,
      noPrivateKeyMaterial: !detailsNode.textContent.includes('BEGIN PRIVATE KEY'),
      doqRuntime: {
        enabled: doq.enabled !== false,
        running: doq.running === true,
        verified: doq.verified === true,
        pid: Number(doq.pid || 0),
        expected: expectedDoqRuntime,
        shown: document.getElementById('doqRuntimeStatus').textContent.replace(/\s+/g, ' ').trim(),
        matches: document.getElementById('doqRuntimeStatus').textContent.includes(expectedDoqRuntime),
        pidVisible: !doq.running || !doq.pid || document.getElementById('doqRuntimeStatus').textContent.includes(String(doq.pid))
      },
      profile: {
        status: profileResponse.status,
        contentType: profileResponse.headers.get('content-type') || '',
        disposition: profileResponse.headers.get('content-disposition') || '',
        hasDohUrl: profileText.includes(state.settings.dohUrl),
        hasDnsPayload: profileText.includes('com.apple.dnsSettings.managed'),
        bytes: profileText.length
      }
    };
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'desktop-tls-certificate.png'));

  const desktopSetupGuide = await evaluateValue(client, `(async () => {
    selectView('status', { skipUrl: true });
    window.scrollTo(0, 0);
    renderSetupGuide(state.status || {});
    const selector = document.getElementById('setupGuideDevice');
    const card = document.getElementById('setupGuideCard');
    const content = document.getElementById('setupGuideContent');
    const original = selector.value;
    const options = [...selector.options].map((option) => option.value);

    selector.value = 'macos';
    selector.dispatchEvent(new Event('change', { bubbles: true }));
    const macosProfile = content.querySelector('[data-setup-profile]');
    const macosDohRow = content.querySelector('.setup-guide-address');
    const dohProtocol = state.status?.protocols?.doh || {};
    const dohEndpoint = String(state.status?.endpoints?.doh || '').trim();
    const dohReady = dohProtocol.enabled !== false && dohProtocol.running !== false && Boolean(dohEndpoint);
    const appleExpectedEnabled = dohReady && state.tlsStatus?.status !== 'invalid';
    const macos = {
      title: content.querySelector('.setup-guide-title strong')?.textContent.trim() || '',
      profileVisible: Boolean(macosProfile),
      profileEnabled: Boolean(macosProfile && !macosProfile.disabled),
      profileExpectedEnabled: appleExpectedEnabled,
      actionCount: content.querySelectorAll('.setup-guide-actions button').length,
      addressCount: content.querySelectorAll('.setup-guide-address').length,
      addressMatches: macosDohRow?.querySelector('code')?.textContent.trim() === (dohReady ? dohEndpoint : '当前已停用')
    };
    renderStatus(state.status);
    macos.preservedAfterStatusRender = selector.value === 'macos' && state.setupGuideDevice === 'macos';

    selector.value = 'ios';
    selector.dispatchEvent(new Event('change', { bubbles: true }));
    const iosProfile = content.querySelector('[data-setup-profile]');
    const ios = {
      title: content.querySelector('.setup-guide-title strong')?.textContent.trim() || '',
      profileVisible: Boolean(iosProfile),
      profileEnabled: Boolean(iosProfile && !iosProfile.disabled),
      profileExpectedEnabled: appleExpectedEnabled,
      actionCount: content.querySelectorAll('.setup-guide-actions button').length,
      addressCount: content.querySelectorAll('.setup-guide-address').length
    };
    renderStatus(state.status);
    ios.preservedAfterStatusRender = selector.value === 'ios' && state.setupGuideDevice === 'ios';

    selector.value = 'encrypted';
    selector.dispatchEvent(new Event('change', { bubbles: true }));
    const doqProtocol = state.status?.protocols?.doq || {};
    const doqEndpoint = String(state.status?.endpoints?.doq || '').trim();
    const doqEnabled = doqProtocol.enabled !== false;
    const doqRunning = doqProtocol.running ?? doqEnabled;
    const doqReady = doqEnabled && doqRunning && doqProtocol.verified !== false && Boolean(doqEndpoint);
    const expected = [
      { label: 'DNS-over-HTTPS', ready: dohReady, value: dohEndpoint },
      { label: 'DNS-over-QUIC', ready: doqReady, value: doqEndpoint }
    ];
    const rows = [...content.querySelectorAll('.setup-guide-address')];
    const rowStates = rows.map((row, index) => {
      const button = row.querySelector('[data-setup-copy]');
      const labelNode = row.querySelector(':scope > span');
      const label = labelNode?.firstChild?.textContent?.trim() || '';
      const value = row.querySelector('code')?.textContent.trim() || '';
      const unavailable = row.classList.contains('unavailable');
      const wanted = expected[index] || {};
      return {
        label,
        value,
        unavailable,
        copyDisabled: Boolean(button?.disabled),
        matches: label === wanted.label && value === (wanted.ready ? wanted.value : '当前已停用') && unavailable === !wanted.ready && Boolean(button?.disabled) === !wanted.ready
      };
    });
    const cardRect = card.getBoundingClientRect();
    const contentRect = content.getBoundingClientRect();
    const selectorRect = selector.getBoundingClientRect();
    const body = card.querySelector('.setup-guide-body');
    const encrypted = {
      title: content.querySelector('.setup-guide-title strong')?.textContent.trim() || '',
      addressCount: rows.length,
      rowStates,
      actionCount: content.querySelectorAll('.setup-guide-actions button').length
    };
    content.querySelector('[data-setup-encryption]').click();
    await new Promise((resolve) => setTimeout(resolve, 40));
    const shortcut = {
      view: state.view,
      section: state.settingsSection,
      settingsVisible: !document.getElementById('settings-section-encryption').classList.contains('hidden') && document.getElementById('settings-section-encryption').classList.contains('active'),
      protocolModuleVisible: Boolean(document.getElementById('encryption-module-protocols')?.getClientRects().length)
    };
    selectView('status', { skipUrl: true });
    state.setupGuideDevice = original;
    renderSetupGuide(state.status || {});
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      initial: original,
      options,
      selectedRestored: selector.value === original,
      bodyColumns: getComputedStyle(body).gridTemplateColumns.split(/\\s+/).filter(Boolean).length,
      cardInside: cardRect.left >= 0 && cardRect.right <= innerWidth + 1,
      selectorInside: selectorRect.left >= cardRect.left && selectorRect.right <= cardRect.right,
      contentInside: contentRect.left >= cardRect.left && contentRect.right <= cardRect.right,
      macos,
      ios,
      encrypted,
      shortcut
    };
  })()`);
  await sleep(120);
  await evaluate(client, `(() => { document.getElementById('toastStack').replaceChildren(); state.setupGuideDevice = 'encrypted'; renderSetupGuide(state.status || {}); window.scrollTo(0, 0); return true; })()`);
  await screenshot(client, path.join(outputDir, 'desktop-setup-guide.png'));
  await evaluate(client, `(() => { state.setupGuideDevice = 'router'; renderSetupGuide(state.status || {}); return true; })()`);

  const desktopThemeInteraction = await evaluateValue(client, `(async () => {
    const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    const canWrite = ${JSON.stringify(themeWrite)};
    const rgb = (value) => (String(value).match(/[\\d.]+/g) || []).slice(0, 3).map(Number);
    const luminance = (value) => {
      const values = rgb(value).map((part) => {
        const channel = part / 255;
        return channel <= .03928 ? channel / 12.92 : Math.pow((channel + .055) / 1.055, 2.4);
      });
      return .2126 * values[0] + .7152 * values[1] + .0722 * values[2];
    };
    const contrast = (foreground, background) => {
      const values = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
      return (values[0] + .05) / (values[1] + .05);
    };
    document.getElementById('toastStack').replaceChildren();
    selectView('dashboard', { skipUrl: true });
    window.scrollTo(0, 0);
    const initial = state.profile?.theme || 'auto';
    const toggle = document.getElementById('accountMenuToggle');
    toggle.click();
    const menu = document.getElementById('accountMenu');
    const opened = !menu.classList.contains('hidden') && toggle.getAttribute('aria-expanded') === 'true';
    const darkButton = document.querySelector('[data-theme-option="dark"]');
    if (canWrite) {
      darkButton.click();
      const deadline = Date.now() + 5000;
      while ((darkButton.disabled || state.profile?.theme !== 'dark') && Date.now() < deadline) await wait(25);
    } else {
      adoptProfile({ ...state.profile, theme: 'dark' });
      setAccountMenu(false);
    }
    const closedAfterSelection = menu.classList.contains('hidden');
    if (closedAfterSelection) toggle.click();
    const persisted = canWrite ? await api('/api/profile') : { theme: state.profile?.theme };
    const bodyStyle = getComputedStyle(document.body);
    const cardStyle = getComputedStyle(document.querySelector('#dashboardStats .stats-card'));
    const headingStyle = getComputedStyle(document.querySelector('#view-dashboard h1'));
    const menuRect = menu.getBoundingClientRect();
    return {
      canWrite,
      initial,
      opened,
      closedAfterSelection,
      preference: document.documentElement.dataset.themePreference,
      resolved: document.documentElement.dataset.theme,
      selected: darkButton.getAttribute('aria-checked'),
      persisted: persisted.theme,
      bodyBackground: bodyStyle.backgroundColor,
      cardBackground: cardStyle.backgroundColor,
      headingColor: headingStyle.color,
      headingContrast: Number(contrast(headingStyle.color, bodyStyle.backgroundColor).toFixed(2)),
      menuInsideViewport: menuRect.left >= 0 && menuRect.right <= innerWidth && menuRect.top >= 0 && menuRect.bottom <= innerHeight
    };
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'desktop-account-menu-dark.png'));
  const desktopThemeClose = await evaluateValue(client, `(() => {
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
    const escapeClosed = document.getElementById('accountMenu').classList.contains('hidden');
    document.getElementById('accountMenuToggle').click();
    document.body.click();
    const outsideClosed = document.getElementById('accountMenu').classList.contains('hidden');
    document.getElementById('toastStack').replaceChildren();
    return { escapeClosed, outsideClosed };
  })()`);
  Object.assign(desktopThemeInteraction, desktopThemeClose);

  const routeAudit = await evaluateValue(client, `(() => {
    const rows = [];
    const channels = (value) => (String(value).match(/\\d+/g) || []).slice(0, 3).map(Number);
    const capture = (route, node) => {
      const surface = node?.querySelector('.card, .settings-module, .section-card, .logs-table-wrap, .table-wrap') || node;
      const surfaceColor = surface ? getComputedStyle(surface).backgroundColor : '';
      const values = channels(surfaceColor);
      rows.push({
        route,
        visible: Boolean(node && !node.classList.contains('hidden') && node.getClientRects().length),
        horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
        scrollWidth: document.documentElement.scrollWidth,
        theme: document.documentElement.dataset.theme,
        surfaceColor,
        darkSurface: values.length === 3 && values.reduce((sum, value) => sum + value, 0) / 3 < 80
      });
    };
    for (const section of ['general', 'stats', 'querylog', 'dns', 'encryption', 'clients', 'dhcp']) {
      selectView('dns', { skipUrl: true });
      selectSettingsSection(section, { history: 'replace' });
      capture('settings/' + section, document.getElementById('settings-section-' + section));
    }
    for (const section of ['blocklists', 'allowlists', 'rewrites', 'services', 'custom', 'test']) {
      selectView('filters', { skipUrl: true });
      selectFilterSection(section, '', { history: 'replace' });
      capture('filters/' + section, document.getElementById('filter-section-' + section));
    }
    for (const view of ['logs', 'status', 'dashboard']) {
      selectView(view, { skipUrl: true });
      capture(view, document.getElementById('view-' + view));
    }
    window.scrollTo(0, 0);
    return rows;
  })()`);
  const routeScrollReset = await evaluateValue(client, `(async () => {
    const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    const scrollDown = () => window.scrollTo(0, Math.min(900, Math.max(1, document.documentElement.scrollHeight - innerHeight)));

    selectView('dashboard', { skipUrl: true });
    scrollDown();
    const viewBefore = Math.round(window.scrollY);
    selectView('logs', { skipUrl: true });
    const viewReset = window.scrollY === 0;

    selectView('dns', { skipUrl: true });
    selectSettingsSection('dhcp', { history: 'replace' });
    scrollDown();
    const settingsBefore = Math.round(window.scrollY);
    selectSettingsSection('dns', { history: 'replace' });
    const settingsReset = window.scrollY === 0;

    selectView('filters', { skipUrl: true });
    selectFilterSection('services', '', { history: 'replace' });
    scrollDown();
    const filtersBefore = Math.round(window.scrollY);
    selectFilterSection('allowlists', '', { history: 'replace' });
    const filtersReset = window.scrollY === 0;

    selectView('dns', { skipUrl: true });
    selectSettingsSection('access', { history: 'replace', instant: true });
    await wait(40);
    const anchorTop = Math.round(document.getElementById('access-module-summary').getBoundingClientRect().top);
    const anchorVisibleBelowHeader = anchorTop >= 58 && anchorTop < innerHeight - 20;
    selectView('dashboard', { skipUrl: true });
    return {
      viewBefore,
      viewReset,
      settingsBefore,
      settingsReset,
      filtersBefore,
      filtersReset,
      anchorTop,
      anchorVisibleBelowHeader
    };
  })()`);
  await screenshot(client, path.join(outputDir, 'desktop-dark-dashboard.png'));
  await evaluate(client, `selectView('dns', { skipUrl: true }); selectSettingsSection('dns', { history: 'replace' }); window.scrollTo(0, 0); true`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'desktop-dark-dns.png'));
  await evaluate(client, `selectView('filters', { skipUrl: true }); selectFilterSection('blocklists', '', { history: 'replace' }); window.scrollTo(0, 0); true`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'desktop-dark-filters.png'));
  const desktopBlockedServicesAutoUpdate = await evaluateValue(client, `(async () => {
    selectView('filters', { skipUrl: true });
    selectFilterSection('services', '', { history: 'replace' });
    await loadBlockedServices();
    window.scrollTo(0, 0);
    const section = document.getElementById('filter-section-services').getBoundingClientRect();
    const control = document.getElementById('blockedServicesCatalogControl').getBoundingClientRect();
    const actions = document.querySelector('#blockedServicesCatalogControl .service-catalog-auto-actions').getBoundingClientRect();
    const controls = ['blockedServicesAutoUpdateEnabled', 'blockedServicesAutoUpdateInterval', 'updateBlockedServicesCatalog'].map((id) => {
      const input = document.getElementById(id);
      const node = id === 'blockedServicesAutoUpdateEnabled' ? input.closest('.settings-toggle') : input;
      const rect = node.getBoundingClientRect();
      return { id, left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom, disabled: input.disabled };
    });
    const meta = document.getElementById('blockedServicesAutoUpdateMeta');
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      sectionInside: section.left >= 0 && section.right <= innerWidth,
      controlInside: control.left >= section.left && control.right <= section.right && control.top >= section.top,
      controlsInside: controls.every((item) => item.left >= actions.left - 1 && item.right <= actions.right + 1 && item.top >= actions.top - 1 && item.bottom <= actions.bottom + 1),
      controlsSeparated: controls.every((item, index) => index === 0 || item.left >= controls[index - 1].right - 1),
      toggleEnabled: !document.getElementById('blockedServicesAutoUpdateEnabled').disabled,
      intervalDisabled: document.getElementById('blockedServicesAutoUpdateInterval').disabled,
      manualUpdateEnabled: !document.getElementById('updateBlockedServicesCatalog').disabled,
      autoDisabled: !document.getElementById('blockedServicesAutoUpdateEnabled').checked,
      metaText: meta.textContent.trim(),
      catalogRows: state.blockedServices.catalog.length
    };
  })()`);
  await sleep(120);
  await screenshot(client, path.join(outputDir, 'desktop-blocked-services-auto-update.png'));
  await evaluate(client, `selectView('logs', { skipUrl: true }); window.scrollTo(0, 0); true`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'desktop-dark-logs.png'));

  const desktopQueryLogMain = await evaluateValue(client, `(async () => {
    const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    selectView('logs', { skipUrl: true });
    await wait(350);
    while (state.logLoading) await wait(20);
    setLogFilterControls({ search: '', status: '', action: '', client: '', type: '', protocol: '' });
    await loadLogPage({ reset: true });
    window.scrollTo(0, 0);
    const header = document.querySelector('#view-logs .query-log-header').getBoundingClientRect();
    const title = document.querySelector('#view-logs .query-log-header h1').getBoundingClientRect();
    const actions = document.querySelector('#view-logs .query-log-header-actions').getBoundingClientRect();
    const table = document.querySelector('#view-logs .logs-table-wrap').getBoundingClientRect();
    const firstRow = document.querySelector('#recent .log-row-main');
    const firstNodeBefore = firstRow;
    document.getElementById('logStatusFilter').value = 'error';
    document.getElementById('logStatusFilter').dispatchEvent(new Event('change', { bubbles: true }));
    while (state.logLoading) await wait(20);
    const statusUrl = new URL(location.href).searchParams.get('status');
    const statusRowsValid = state.logRows.every((row) => logStatusKey(row) === 'error');
    document.getElementById('logActionFilter').value = 'refused';
    document.getElementById('logActionFilter').dispatchEvent(new Event('change', { bubbles: true }));
    while (state.logLoading) await wait(20);
    const combinedValid = state.logRows.length >= 1 && state.logRows.every((row) => row.action === 'refused');
    const reasonUrl = new URL(location.href).searchParams.get('reason');
    document.getElementById('logStatusFilter').value = 'processed';
    document.getElementById('logStatusFilter').dispatchEvent(new Event('change', { bubbles: true }));
    while (state.logLoading) await wait(20);
    const reasonClearedByStatus = document.getElementById('logActionFilter').value === '' && !new URL(location.href).searchParams.has('reason');
    document.getElementById('clearLogFilters').click();
    while (state.logLoading) await wait(20);
    const resetValid = ['logSearch', 'logStatusFilter', 'logActionFilter', 'logClientFilter', 'logTypeFilter', 'logProtocolFilter'].every((id) => document.getElementById(id).value === '');
    document.getElementById('refreshLogs').click();
    const refreshBusyVisible = document.getElementById('refreshLogs').classList.contains('is-loading') || document.getElementById('refreshLogs').disabled;
    while (state.logLoading) await wait(20);
    const rebuilt = document.querySelector('#recent .log-row-main') !== firstNodeBefore;
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      headerAligned: Math.abs((title.top + title.height / 2) - (actions.top + actions.height / 2)) <= 2,
      headerWidth: Math.round(header.width),
      actionsInside: actions.left >= header.left && actions.right <= header.right,
      controls: ['logSearch', 'logStatusFilter', 'logActionFilter', 'toggleLogAdvanced', 'refreshLogs'].every((id) => document.getElementById(id).getClientRects().length > 0),
      duplicateCardHeaderAbsent: !document.querySelector('#view-logs > .page-tools') && !document.querySelector('#view-logs > .section-card'),
      detailToggleAbsent: !document.getElementById('toggleLogDetailed'),
      headerCells: document.querySelectorAll('#logsTable .logs-table-head > span').length,
      rowCells: document.querySelector('#recent .log-row-main')?.querySelectorAll(':scope > div[role="gridcell"]').length || 0,
      rowCount: document.querySelectorAll('#recent .log-row-main').length,
      mobileCardsHidden: [...document.querySelectorAll('#recent .log-mobile-card')].every((node) => getComputedStyle(node).display === 'none'),
      tableInside: table.left >= 0 && table.right <= innerWidth,
      statusUrl,
      statusRowsValid,
      reasonUrl,
      combinedValid,
      reasonClearedByStatus,
      resetValid,
      refreshBusyVisible,
      rebuilt
    };
  })()`);
  await sleep(120);
  await screenshot(client, path.join(outputDir, 'desktop-query-log-main.png'));
  const desktopQueryLogActions = await evaluateValue(client, `(async () => {
    const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    const trigger = document.querySelector('#recent .log-row-main [data-log-actions]');
    if (!trigger) return { available: false };
    const synthetic = { qname: 'client-action.audit', qtype: 'A', client: '192.0.2.44', action: 'allow', clientId: '', clientPolicy: null };
    const anonymous = { ...synthetic, client: '192.0.2.0/24' };
    trigger.focus();
    trigger.click();
    await wait(30);
    const menu = document.getElementById('logActionsMenu');
    const actualOpened = !menu.classList.contains('hidden') && trigger.getAttribute('aria-expanded') === 'true';
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
    await wait(30);
    const escapeClosed = menu.classList.contains('hidden') && document.activeElement === trigger && trigger.getAttribute('aria-expanded') === 'false';

    openLogActionsMenu(synthetic, trigger);
    await wait(30);
    const rect = menu.getBoundingClientRect();
    const exactLabels = [...menu.querySelectorAll('button:not(.hidden)')].map((node) => node.textContent.trim());
    const exactInside = rect.left >= 0 && rect.right <= innerWidth && rect.top >= 0 && rect.bottom <= innerHeight;
    document.getElementById('logActionDisallowClient').click();
    await wait(30);
    const clientModal = document.getElementById('logClientActionModal');
    const disallowDialog = {
      visible: !clientModal.classList.contains('hidden'),
      focused: document.activeElement === document.getElementById('confirmLogClientAction'),
      clientVisible: document.getElementById('logClientActionQuestion').textContent.includes('192.0.2.44')
    };
    document.getElementById('cancelLogClientAction').click();
    await wait(30);
    const disallowCanceled = clientModal.classList.contains('hidden') && document.activeElement === trigger;

    openLogActionsMenu(anonymous, trigger);
    await wait(30);
    const anonymousHidesClientActions = ['logActionBlockClient', 'logActionDisallowClient', 'logActionAddClient'].every((id) => document.getElementById(id).classList.contains('hidden'));
    document.body.click();
    await wait(30);
    const outsideClosed = menu.classList.contains('hidden');

    openLogActionsMenu(synthetic, trigger);
    await wait(30);
    return {
      available: true,
      actualOpened,
      escapeClosed,
      exactInside,
      exactLabels,
      anonymousHidesClientActions,
      outsideClosed,
      disallowDialog,
      disallowCanceled,
      triggerInside: (() => { const box = trigger.getBoundingClientRect(); return box.left >= 0 && box.right <= innerWidth; })(),
      leftOpenForScreenshot: !menu.classList.contains('hidden')
    };
  })()`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'desktop-query-log-actions.png'));
  await evaluate(client, `closeLogActionsMenu(false); true`);
  const desktopQueryLogDetail = await evaluateValue(client, `(async () => {
    const responseFixture = ${responseFilterFixture ? 'true' : 'false'};
    if (responseFixture) {
      setLogFilterControls({ search: 'response-filter.audit', status: '', action: '', client: '', type: '', protocol: '' });
      await loadLogPage({ reset: true });
    }
    const activeRows = state.logServerMode ? state.logRows : state.recent;
    const whoisRow = activeRows.find((item) => item.qname === 'response-filter.audit') || activeRows[0];
    if (whoisRow) {
      whoisRow.clientSource = 'whois';
      whoisRow.clientWhois = { orgname: 'CleanDNS Audit Network', city: 'Shanghai', country: 'CN' };
      renderRecent(activeRows, { server: state.logServerMode });
    }
    const row = document.querySelector('#recent .log-row-main');
    if (!row) return { visible: false, responseRowFound: false };
    row.focus();
    openLogDetail(whoisRow, row);
    await new Promise((resolve) => setTimeout(resolve, 40));
    const modal = document.getElementById('logDetailModal');
    const rect = modal.querySelector('.modal').getBoundingClientRect();
    const text = document.getElementById('logDetailBody').innerText.replace(/\s+/g, ' ').trim();
    return {
      responseRowFound: !responseFixture || row.innerText.includes('response-filter.audit'),
      visible: !modal.classList.contains('hidden'),
      focused: document.activeElement === document.getElementById('closeLogDetailModal'),
      insideViewport: rect.left >= 0 && rect.right <= innerWidth && rect.top >= 0 && rect.bottom <= innerHeight,
      detailRows: document.querySelectorAll('#logDetailBody .log-detail-row').length,
      answerSections: document.querySelectorAll('#logDetailBody .log-answer-section').length,
      responseActionVisible: !responseFixture || text.includes('响应已过滤'),
      matchTypeVisible: !responseFixture || (text.includes('命中响应类型') && text.includes('A')),
      matchValueVisible: !responseFixture || (text.includes('命中响应值') && text.includes('203.0.113.54')),
      filterSourceVisible: !responseFixture || (text.includes('响应来源') && text.includes('过滤器')),
      originalResponseVisible: !responseFixture || (text.includes('原始上游响应') && text.includes('203.0.113.54')),
      whoisVisible: text.includes('CleanDNS Audit Network') && text.includes('Shanghai, CN') && [...document.querySelectorAll('#logDetailBody .log-detail-row')].some((node) => {
        const key = node.querySelector('.log-detail-key')?.textContent.trim();
        const value = node.querySelector('.log-detail-value')?.textContent.trim();
        return key === '客户端来源' && value === 'WHOIS';
      })
    };
  })()`);
  await screenshot(client, path.join(outputDir, responseFilterFixture ? 'desktop-query-log-response-detail.png' : 'desktop-query-log-detail.png'));
  Object.assign(desktopQueryLogDetail, await evaluateValue(client, `(async () => {
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 40));
    const result = {
      closed: document.getElementById('logDetailModal').classList.contains('hidden'),
      focusRestored: document.activeElement?.classList.contains('log-row-main') === true
    };
    setLogFilterControls({ search: '', status: '', action: '', client: '', type: '', protocol: '' });
    await loadLogPage({ reset: true });
    return result;
  })()`));

  await setViewport(client, 390, 844, 1, true);
  const mobileBlockedServicesAutoUpdate = await evaluateValue(client, `(async () => {
    selectView('filters', { skipUrl: true });
    selectFilterSection('services', '', { history: 'replace' });
    await loadBlockedServices();
    window.scrollTo(0, 0);
    const control = document.getElementById('blockedServicesCatalogControl').getBoundingClientRect();
    const actions = document.querySelector('#blockedServicesCatalogControl .service-catalog-auto-actions').getBoundingClientRect();
    const controls = ['blockedServicesAutoUpdateEnabled', 'blockedServicesAutoUpdateInterval', 'updateBlockedServicesCatalog'].map((id) => {
      const input = document.getElementById(id);
      const node = id === 'blockedServicesAutoUpdateEnabled' ? input.closest('.settings-toggle') : input;
      const rect = node.getBoundingClientRect();
      return { id, left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom, width: rect.width };
    });
    const meta = document.getElementById('blockedServicesAutoUpdateMeta');
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      controlInside: control.left >= 0 && control.right <= innerWidth,
      actionsInside: actions.left >= control.left && actions.right <= control.right,
      controlsInside: controls.every((item) => item.left >= 0 && item.right <= innerWidth && item.top >= actions.top - 1 && item.bottom <= actions.bottom + 1),
      controlsSeparated: controls.every((item, index) => index === 0 || item.left >= controls[index - 1].right - 1),
      actionColumns: getComputedStyle(document.querySelector('#blockedServicesCatalogControl .service-catalog-auto-actions')).gridTemplateColumns.split(' ').length,
      metaFits: meta.scrollWidth <= meta.clientWidth + 1,
      manualUpdateVisible: document.getElementById('updateBlockedServicesCatalog').getClientRects().length > 0,
      catalogRows: state.blockedServices.catalog.length
    };
  })()`);
  await sleep(120);
  await screenshot(client, path.join(outputDir, 'mobile-blocked-services-auto-update.png'));
  const mobileThemeMenu = await evaluateValue(client, `(() => {
    selectView('dashboard', { skipUrl: true });
    setMobileNav(false);
    window.scrollTo(0, 0);
    const toggle = document.getElementById('accountMenuToggle');
    if (document.getElementById('accountMenu').classList.contains('hidden')) toggle.click();
    const menu = document.getElementById('accountMenu');
    const rect = menu.getBoundingClientRect();
    return {
      opened: !menu.classList.contains('hidden'),
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      insideViewport: rect.left >= 0 && rect.right <= innerWidth && rect.top >= 0 && rect.bottom <= innerHeight,
      iconOnly: getComputedStyle(toggle.querySelector('.account-name')).display === 'none',
      options: document.querySelectorAll('[data-theme-option]').length,
      selected: document.querySelector('[data-theme-option].active')?.dataset.themeOption || ''
    };
  })()`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'mobile-account-menu-dark.png'));
  await evaluate(client, `document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true })); true`);

  const mobileQueryLogMain = await evaluateValue(client, `(async () => {
    const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    selectView('logs', { skipUrl: true });
    await wait(350);
    while (state.logLoading) await wait(20);
    setLogFilterControls({ search: '', status: '', action: '', client: '', type: '', protocol: '' });
    await loadLogPage({ reset: true });
    window.scrollTo(0, 0);
    const header = document.querySelector('#view-logs .query-log-header').getBoundingClientRect();
    const actions = document.querySelector('#view-logs .query-log-header-actions').getBoundingClientRect();
    const cards = [...document.querySelectorAll('#recent .log-mobile-card')];
    const firstCard = cards[0];
    const firstRect = firstCard?.getBoundingClientRect();
    const firstDesktopRow = document.querySelector('#recent .log-row-main');
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      headerWidth: Math.round(header.width),
      actionsInside: actions.left >= header.left && actions.right <= header.right,
      statusFullRow: Math.round(document.getElementById('logStatusFilter').getBoundingClientRect().width) === Math.round(actions.width),
      cards: cards.length,
      cardsVisible: cards.every((node) => getComputedStyle(node).display !== 'none'),
      cardsInside: cards.every((node) => {
        const rect = node.getBoundingClientRect();
        return rect.left >= 0 && rect.right <= innerWidth;
      }),
      firstCardWidth: Math.round(firstRect?.width || 0),
      desktopRowsHidden: !firstDesktopRow || getComputedStyle(firstDesktopRow).display === 'none',
      fieldLabels: [...(firstCard?.querySelectorAll('.log-mobile-field-grid > span:nth-child(odd)') || [])].map((node) => node.textContent.trim()),
      titleFits: (() => {
        const title = firstCard?.querySelector('.log-mobile-card-head strong');
        return !title || title.scrollWidth <= title.clientWidth + 1;
      })()
    };
  })()`);
  await sleep(120);
  await screenshot(client, path.join(outputDir, 'mobile-query-log-main.png'));
  const mobileQueryLogActions = await evaluateValue(client, `(async () => {
    const trigger = document.querySelector('#recent .log-mobile-card [data-log-actions]');
    if (!trigger) return { available: false };
    const closeEvents = [];
    const originalCloseLogActionsMenu = closeLogActionsMenu;
    closeLogActionsMenu = function (...args) {
      closeEvents.push({
        at: Math.round(performance.now()),
        args,
        view: state.view,
        loading: state.logLoading,
        scrollY: Math.round(window.scrollY),
        stack: String(new Error().stack || '').split(String.fromCharCode(10)).slice(1, 4).map((line) => line.trim())
      });
      return originalCloseLogActionsMenu.apply(this, args);
    };
    trigger.focus();
    trigger.click();
    await new Promise((resolve) => setTimeout(resolve, 40));
    const menu = document.getElementById('logActionsMenu');
    const initiallyVisible = !menu.classList.contains('hidden');
    await new Promise((resolve) => setTimeout(resolve, 5200));
    const rect = menu.getBoundingClientRect();
    const card = trigger.closest('.log-mobile-card').getBoundingClientRect();
    closeLogActionsMenu = originalCloseLogActionsMenu;
    return {
      available: true,
      visible: initiallyVisible,
      stableAcrossPolling: !menu.classList.contains('hidden') && trigger.isConnected,
      insideViewport: rect.left >= 0 && rect.right <= innerWidth && rect.top >= 0 && rect.bottom <= innerHeight,
      triggerInsideCard: (() => { const box = trigger.getBoundingClientRect(); return box.left >= card.left && box.right <= card.right && box.top >= card.top && box.bottom <= card.bottom; })(),
      expanded: trigger.getAttribute('aria-expanded') === 'true',
      labels: [...menu.querySelectorAll('button:not(.hidden)')].map((node) => node.textContent.trim()),
      closeEvents
    };
  })()`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'mobile-query-log-actions.png'));
  Object.assign(mobileQueryLogActions, await evaluateValue(client, `(async () => {
    const opener = logActionsOpener;
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 30));
    return {
      closed: document.getElementById('logActionsMenu').classList.contains('hidden'),
      focusRestored: document.activeElement === opener
    };
  })()`));
  const mobileQueryLogDetail = await evaluateValue(client, `(async () => {
    const activeRows = state.logServerMode ? state.logRows : state.recent;
    if (activeRows[0]) {
      activeRows[0].clientSource = 'whois';
      activeRows[0].clientWhois = { orgname: 'CleanDNS Audit Network', city: 'Shanghai', country: 'CN' };
      renderRecent(activeRows, { server: state.logServerMode });
    }
    const card = document.querySelector('#recent .log-mobile-card');
    card.focus();
    openLogDetail(activeRows[0], card);
    await new Promise((resolve) => setTimeout(resolve, 40));
    const modal = document.getElementById('logDetailModal');
    const rect = modal.querySelector('.modal').getBoundingClientRect();
    return {
      visible: !modal.classList.contains('hidden'),
      focused: document.activeElement === document.getElementById('closeLogDetailModal'),
      insideViewport: rect.left >= 0 && rect.right <= innerWidth && rect.top >= 0 && rect.bottom <= innerHeight,
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      detailRows: document.querySelectorAll('#logDetailBody .log-detail-row').length,
      whoisVisible: document.getElementById('logDetailBody').innerText.includes('CleanDNS Audit Network') && document.getElementById('logDetailBody').innerText.includes('Shanghai, CN')
    };
  })()`);
  await screenshot(client, path.join(outputDir, 'mobile-query-log-detail.png'));
  Object.assign(mobileQueryLogDetail, await evaluateValue(client, `(async () => {
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 40));
    return {
      closed: document.getElementById('logDetailModal').classList.contains('hidden'),
      focusRestored: document.activeElement?.classList.contains('log-mobile-card') === true
    };
  })()`));

  const mobileNavigation = await evaluateValue(client, `(async () => {
    const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    selectView('dashboard', { skipUrl: true });
    setMobileNav(false);
    document.getElementById('navToggle').click();
    const settingsCaret = document.querySelector('.nav-group .nav-caret[data-view="dns"]');
    settingsCaret.click();
    await wait(20);
    const group = settingsCaret.closest('.nav-group');
    const opened = document.getElementById('appHeader').classList.contains('nav-open') && group.classList.contains('menu-open');
    group.querySelector('[data-settings-jump="general"]').click();
    await wait(20);
    return {
      opened,
      closedAfterSelection: !document.getElementById('appHeader').classList.contains('nav-open') && !group.classList.contains('menu-open'),
      generalVisible: document.getElementById('settings-section-general').getClientRects().length > 0
    };
  })()`);
  const mobileRouteScrollReset = await evaluateValue(client, `(() => {
    const scrollDown = () => window.scrollTo(0, Math.min(900, Math.max(1, document.documentElement.scrollHeight - innerHeight)));
    selectView('filters', { skipUrl: true });
    selectFilterSection('services', '', { history: 'replace' });
    scrollDown();
    const viewBefore = Math.round(window.scrollY);
    selectView('dns', { skipUrl: true });
    const viewReset = window.scrollY === 0;

    selectSettingsSection('dhcp', { history: 'replace' });
    scrollDown();
    const sectionBefore = Math.round(window.scrollY);
    selectSettingsSection('clients', { history: 'replace' });
    return { viewBefore, viewReset, sectionBefore, sectionReset: window.scrollY === 0 };
  })()`);
  await showSettings(client);
  const mobileSettings = await layoutMetrics(client);
  const mobileGeneralProtection = await evaluateValue(client, `(() => {
    const moduleNode = document.getElementById('general-module-protection');
    const rows = [...document.querySelectorAll('#generalProtectionRows .settings-link-row')];
    const opener = document.getElementById('openSafeSearchConfig');
    const moduleRect = moduleNode.getBoundingClientRect();
    const openerRect = opener.getBoundingClientRect();
    const metaRect = document.getElementById('safeSearchProvidersMeta').getBoundingClientRect();
    const toggleRect = opener.querySelector('.settings-toggle').getBoundingClientRect();
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      moduleWidth: Math.round(moduleRect.width),
      rowCount: rows.length,
      rowsInside: rows.every((row) => {
        const rect = row.getBoundingClientRect();
        return rect.left >= moduleRect.left && rect.right <= moduleRect.right;
      }),
      modernToggleCount: ['protectionEnabled', 'safeBrowsingEnabled', 'parentalEnabled', 'safeSearchEnabled'].filter((id) => document.getElementById(id).closest('.settings-toggle')).length,
      switchLinkColumns: getComputedStyle(opener).gridTemplateColumns.split(/\\s+/).filter(Boolean).length,
      metaInside: metaRect.left >= openerRect.left && metaRect.right <= openerRect.right,
      toggleInside: toggleRect.left >= openerRect.left && toggleRect.right <= openerRect.right,
      oldStateAbsent: !document.getElementById('safeSearchState')
    };
  })()`);
  await screenshot(client, path.join(outputDir, 'mobile-general.png'));

  const mobileSafeSearchDialog = await evaluateValue(client, `(async () => {
    document.getElementById('openSafeSearchConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const modal = document.querySelector('#safeSearchConfigModal .modal').getBoundingClientRect();
    const list = document.getElementById('safeSearchProviders').getBoundingClientRect();
    const rows = [...document.querySelectorAll('#safeSearchProviders .safe-search-provider')].map((row) => row.getBoundingClientRect());
    return {
      visible: !document.getElementById('safeSearchConfigModal').classList.contains('hidden'),
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      modalWidth: Math.round(modal.width),
      insideViewport: modal.left >= 0 && modal.right <= innerWidth && modal.top >= 0 && modal.bottom <= innerHeight,
      listInside: list.left >= modal.left && list.right <= modal.right,
      providers: rows.length,
      singleColumn: getComputedStyle(document.getElementById('safeSearchProviders')).gridTemplateColumns.split(/\\s+/).filter(Boolean).length === 1,
      rowsInside: rows.every((rect) => rect.left >= list.left && rect.right <= list.right),
      focused: document.activeElement === document.getElementById('safeSearchBing')
    };
  })()`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'mobile-safe-search-dialog.png'));
  await evaluate(client, `cancelSafeSearchConfig(); true`);

  const mobileStatsSettings = await evaluateValue(client, `(() => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('stats', { history: 'replace' });
    const section = document.getElementById('settings-section-stats');
    const moduleNode = document.getElementById('stats-module-collection');
    const rows = [...document.querySelectorAll('#statsSettingsRows .settings-link-row')];
    window.scrollTo(0, 0);
    const sectionRect = section.getBoundingClientRect();
    const moduleRect = moduleNode.getBoundingClientRect();
    const currentPayload = settingsPayload();
    const snapshotPayload = JSON.parse(state.settingsSnapshot || '{}');
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      settingsDirty: state.settingsDirty,
      dirtyBarHidden: document.getElementById('settingsDirtyBar').classList.contains('hidden'),
      dirtyFields: Object.keys(currentPayload).filter((key) => JSON.stringify(currentPayload[key]) !== JSON.stringify(snapshotPayload[key])),
      sectionWidth: Math.round(sectionRect.width),
      moduleWidth: Math.round(moduleRect.width),
      rowCount: rows.length,
      rowsInside: rows.every((row) => {
        const rect = row.getBoundingClientRect();
        return rect.left >= moduleRect.left && rect.right <= moduleRect.right;
      }),
      modernToggleCount: ['statsEnabled', 'statsIgnoredEnabled'].filter((id) => document.getElementById(id).closest('.settings-toggle')).length,
      switchLinkColumns: getComputedStyle(document.getElementById('openStatsIgnoredDomains')).gridTemplateColumns.split(/\\s+/).filter(Boolean).length,
      oldModulesAbsent: !document.getElementById('stats-module-ignore') && !document.getElementById('stats-module-summary')
    };
  })()`);
  await screenshot(client, path.join(outputDir, 'mobile-stats-settings.png'));

  const mobileStatsRetentionDialog = await evaluateValue(client, `(async () => {
    document.getElementById('openStatsRetention').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const modal = document.querySelector('#statsRetentionModal .modal').getBoundingClientRect();
    const grid = document.getElementById('statsRetentionOptions').getBoundingClientRect();
    return {
      visible: !document.getElementById('statsRetentionModal').classList.contains('hidden'),
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      modalWidth: Math.round(modal.width),
      insideViewport: modal.left >= 0 && modal.right <= innerWidth && modal.top >= 0 && modal.bottom <= innerHeight,
      gridInside: grid.left >= modal.left && grid.right <= modal.right,
      options: document.querySelectorAll('#statsRetentionOptions .retention-option').length,
      columns: getComputedStyle(document.getElementById('statsRetentionOptions')).gridTemplateColumns.split(/\\s+/).filter(Boolean).length,
      focusedOption: document.activeElement?.dataset?.retentionKind === 'stats'
    };
  })()`);
  await screenshot(client, path.join(outputDir, 'mobile-stats-retention-dialog.png'));
  await evaluate(client, `cancelRetentionConfig('stats'); true`);

  const mobileStatsIgnoredDialog = await evaluateValue(client, `(async () => {
    document.getElementById('openStatsIgnoredDomains').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const modal = document.querySelector('#statsIgnoredModal .modal').getBoundingClientRect();
    const field = document.getElementById('statsIgnoredDomains').getBoundingClientRect();
    return {
      visible: !document.getElementById('statsIgnoredModal').classList.contains('hidden'),
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      modalWidth: Math.round(modal.width),
      insideViewport: modal.left >= 0 && modal.right <= innerWidth && modal.top >= 0 && modal.bottom <= innerHeight,
      textareaInside: field.left >= modal.left && field.right <= modal.right,
      focused: document.activeElement === document.getElementById('statsIgnoredDomains')
    };
  })()`);
  await screenshot(client, path.join(outputDir, 'mobile-stats-ignored-dialog.png'));
  await evaluate(client, `cancelIgnoredDomainsConfig('stats'); true`);

  const mobileQueryLogSettings = await evaluateValue(client, `(() => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('querylog', { history: 'replace' });
    const section = document.getElementById('settings-section-querylog');
    const moduleNode = document.getElementById('querylog-module-policy');
    const rows = [...document.querySelectorAll('#queryLogSettingsRows .settings-link-row')];
    window.scrollTo(0, 0);
    const sectionRect = section.getBoundingClientRect();
    const moduleRect = moduleNode.getBoundingClientRect();
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      sectionWidth: Math.round(sectionRect.width),
      moduleWidth: Math.round(moduleRect.width),
      rowCount: rows.length,
      rowsInside: rows.every((row) => {
        const rect = row.getBoundingClientRect();
        return rect.left >= moduleRect.left && rect.right <= moduleRect.right;
      }),
      modernToggleCount: ['queryLogEnabled', 'queryLogAnonymizeClientIp', 'queryLogIgnoredEnabled'].filter((id) => document.getElementById(id).closest('.settings-toggle')).length,
      switchLinkColumns: getComputedStyle(document.getElementById('openQueryLogIgnoredDomains')).gridTemplateColumns.split(/\\s+/).filter(Boolean).length,
      oldModulesAbsent: !document.getElementById('querylog-module-privacy') && !document.getElementById('querylog-module-ignore')
    };
  })()`);
  await screenshot(client, path.join(outputDir, 'mobile-query-log-settings.png'));

  const mobileQueryLogDialogs = await evaluateValue(client, `(async () => {
    document.getElementById('openQueryLogRetention').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const retentionModal = document.querySelector('#queryLogRetentionModal .modal').getBoundingClientRect();
    const retention = {
      visible: !document.getElementById('queryLogRetentionModal').classList.contains('hidden'),
      insideViewport: retentionModal.left >= 0 && retentionModal.right <= innerWidth && retentionModal.top >= 0 && retentionModal.bottom <= innerHeight,
      modalWidth: Math.round(retentionModal.width),
      options: document.querySelectorAll('#queryLogRetentionOptions .retention-option').length,
      columns: getComputedStyle(document.getElementById('queryLogRetentionOptions')).gridTemplateColumns.split(/\\s+/).filter(Boolean).length
    };
    cancelRetentionConfig('queryLog');
    document.getElementById('openQueryLogCapacity').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const capacityModal = document.querySelector('#queryLogCapacityModal .modal').getBoundingClientRect();
    const input = document.getElementById('queryLogMaxEntries').getBoundingClientRect();
    const capacity = {
      visible: !document.getElementById('queryLogCapacityModal').classList.contains('hidden'),
      insideViewport: capacityModal.left >= 0 && capacityModal.right <= innerWidth && capacityModal.top >= 0 && capacityModal.bottom <= innerHeight,
      modalWidth: Math.round(capacityModal.width),
      inputInside: input.left >= capacityModal.left && input.right <= capacityModal.right,
      focused: document.activeElement === document.getElementById('queryLogMaxEntries')
    };
    return { horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1, retention, capacity };
  })()`);
  await screenshot(client, path.join(outputDir, 'mobile-query-log-capacity-dialog.png'));
  await evaluate(client, `cancelQueryLogCapacity(); true`);

  await evaluate(client, `(async () => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('encryption', { history: 'replace' });
    await loadTlsStatus({ silent: true });
    document.getElementById('encryption-module-protocols').scrollIntoView({ block: 'start' });
    return true;
  })()`);
  await sleep(120);
  await screenshot(client, path.join(outputDir, 'mobile-doq-runtime.png'));

  const mobileTls = await evaluateValue(client, `(async () => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('encryption', { history: 'replace' });
    await loadTlsStatus({ silent: true });
    const moduleNode = document.getElementById('encryption-module-certificate');
    const detailsNode = document.getElementById('tlsCertificateDetails');
    const actionsNode = moduleNode.querySelector('.tls-certificate-actions');
    moduleNode.scrollIntoView({ block: 'start' });
    const moduleRect = moduleNode.getBoundingClientRect();
    const detailRect = detailsNode.getBoundingClientRect();
    const buttons = [...actionsNode.querySelectorAll('button')].map((button) => Math.round(button.getBoundingClientRect().width));
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      moduleWidth: Math.round(moduleRect.width),
      detailWidth: Math.round(detailRect.width),
      detailColumns: getComputedStyle(detailsNode).gridTemplateColumns.split(/\\s+/).filter(Boolean).length,
      rowColumns: [...detailsNode.querySelectorAll('.tls-detail-row')].map((row) => getComputedStyle(row).gridTemplateColumns.split(/\\s+/).filter(Boolean).length),
      actionDirection: getComputedStyle(actionsNode).flexDirection,
      buttonWidths: buttons,
      stateText: document.getElementById('tlsCertificateState').textContent.trim(),
      detailRows: detailsNode.querySelectorAll('.tls-detail-row').length,
      downloadEnabled: !document.getElementById('downloadDohProfile').disabled
    };
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'mobile-tls-certificate.png'));

  const mobileEncryptionDialogs = await evaluateValue(client, `(async () => {
    const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    clearToasts();
    window.scrollTo({ top: 0, left: 0, behavior: 'auto' });
    await wait(50);
    document.getElementById('encryptionActionsToggle').click();
    await wait(30);
    const menu = document.getElementById('encryptionActionsMenu');
    const menuRect = menu.getBoundingClientRect();
    const menuState = {
      visible: !menu.classList.contains('hidden'),
      insideViewport: menuRect.left >= 0 && menuRect.right <= innerWidth && menuRect.top >= 0 && menuRect.bottom <= innerHeight,
      width: Math.round(menuRect.width),
      height: Math.round(menuRect.height),
      items: menu.querySelectorAll('[role="menuitem"]').length
    };
    document.getElementById('openTlsConfigFromMenu').click();
    await wait(40);
    const tlsBackdrop = document.getElementById('tlsConfigModal');
    const tlsRect = tlsBackdrop.querySelector('.modal').getBoundingClientRect();
    const tls = {
      visible: !tlsBackdrop.classList.contains('hidden'),
      insideViewport: tlsRect.left >= 0 && tlsRect.right <= innerWidth && tlsRect.top >= 0 && tlsRect.bottom <= innerHeight,
      width: Math.round(tlsRect.width),
      fieldsInside: [...tlsBackdrop.querySelectorAll('input')].every((input) => {
        const rect = input.getBoundingClientRect();
        return rect.left >= tlsRect.left && rect.right <= tlsRect.right;
      })
    };
    closeTlsConfigModal();
    await openProtocolResetModal();
    const resetBackdrop = document.getElementById('protocolResetModal');
    const resetRect = resetBackdrop.querySelector('.modal').getBoundingClientRect();
    const reset = {
      visible: !resetBackdrop.classList.contains('hidden'),
      insideViewport: resetRect.left >= 0 && resetRect.right <= innerWidth && resetRect.top >= 0 && resetRect.bottom <= innerHeight,
      width: Math.round(resetRect.width),
      rows: resetBackdrop.querySelectorAll('.protocol-reset-row').length,
      rowColumns: [...resetBackdrop.querySelectorAll('.protocol-reset-row')].map((row) => getComputedStyle(row).gridTemplateColumns.split(/\s+/).filter(Boolean).length),
      confirmEnabled: !document.getElementById('confirmProtocolReset').disabled
    };
    closeProtocolResetModal();
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      menu: menuState,
      tls,
      reset,
      allClosed: document.getElementById('tlsConfigModal').classList.contains('hidden') && document.getElementById('protocolResetModal').classList.contains('hidden')
    };
  })()`);
  await evaluate(client, `clearToasts(); window.scrollTo({ top: 0, left: 0, behavior: 'auto' }); document.getElementById('encryptionActionsToggle').click(); true`);
  await sleep(40);
  await screenshot(client, path.join(outputDir, 'mobile-encryption-actions.png'));
  await evaluate(client, `document.getElementById('openTlsConfigFromMenu').click(); true`);
  await sleep(40);
  await screenshot(client, path.join(outputDir, 'mobile-tls-config-dialog.png'));
  await evaluate(client, `closeTlsConfigModal(); true`);
  await evaluate(client, `(async () => { await openProtocolResetModal(); return true; })()`);
  await screenshot(client, path.join(outputDir, 'mobile-protocol-reset-dialog.png'));
  await evaluate(client, `closeProtocolResetModal(); true`);

  const mobileSetupGuide = await evaluateValue(client, `(() => {
    selectView('status', { skipUrl: true });
    window.scrollTo(0, 0);
    state.setupGuideDevice = 'encrypted';
    renderSetupGuide(state.status || {});
    const card = document.getElementById('setupGuideCard');
    const body = card.querySelector('.setup-guide-body');
    const selector = document.getElementById('setupGuideDevice');
    const content = document.getElementById('setupGuideContent');
    const cardRect = card.getBoundingClientRect();
    const selectorRect = selector.getBoundingClientRect();
    const contentRect = content.getBoundingClientRect();
    const encryptedRows = [...content.querySelectorAll('.setup-guide-address')];
    const encrypted = {
      addressCount: encryptedRows.length,
      rowsInside: encryptedRows.every((row) => {
        const rect = row.getBoundingClientRect();
        return rect.left >= cardRect.left && rect.right <= cardRect.right + 1;
      }),
      rowColumns: encryptedRows.map((row) => getComputedStyle(row).gridTemplateColumns.split(/\\s+/).filter(Boolean).length)
    };

    selector.value = 'ios';
    selector.dispatchEvent(new Event('change', { bubbles: true }));
    renderStatus(state.status);
    const actions = content.querySelector('.setup-guide-actions');
    const buttons = [...actions.querySelectorAll('button')];
    const buttonRects = buttons.map((button) => button.getBoundingClientRect());
    const heading = content.querySelector('.setup-guide-heading');
    const apple = {
      preservedAfterStatusRender: selector.value === 'ios' && state.setupGuideDevice === 'ios',
      profileVisible: Boolean(content.querySelector('[data-setup-profile]')),
      buttonCount: buttons.length,
      actionColumns: getComputedStyle(actions).gridTemplateColumns.split(/\\s+/).filter(Boolean).length,
      buttonWidths: buttonRects.map((rect) => Math.round(rect.width)),
      buttonsInside: buttonRects.every((rect) => rect.left >= cardRect.left && rect.right <= cardRect.right + 1),
      headingColumns: getComputedStyle(heading).gridTemplateColumns.split(/\\s+/).filter(Boolean).length
    };
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      cardWidth: Math.round(cardRect.width),
      bodyColumns: getComputedStyle(body).gridTemplateColumns.split(/\\s+/).filter(Boolean).length,
      selectorInside: selectorRect.left >= cardRect.left && selectorRect.right <= cardRect.right + 1,
      contentInside: contentRect.left >= cardRect.left && contentRect.right <= cardRect.right + 1,
      encrypted,
      apple
    };
  })()`);
  await sleep(120);
  await evaluate(client, `document.getElementById('toastStack').replaceChildren(); true`);
  await screenshot(client, path.join(outputDir, 'mobile-setup-guide.png'));
  await evaluate(client, `(() => { state.setupGuideDevice = 'router'; renderSetupGuide(state.status || {}); return true; })()`);

  const mobileRewrite = await evaluateValue(client, `(() => {
    selectView('filters', { skipUrl: true });
    selectFilterSection('rewrites', '', { history: 'replace' });
    document.getElementById('toggleRewriteEditor').click();
    document.getElementById('rewriteDomain').value = '*.audit.example';
    const answer = document.getElementById('rewriteValue');
    answer.value = 'target.audit.example';
    answer.dispatchEvent(new Event('input', { bubbles: true }));
    const modal = document.querySelector('#rewriteQuickAdd .modal').getBoundingClientRect();
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      insideViewport: modal.left >= 0 && modal.right <= innerWidth,
      detectedType: document.getElementById('rewriteDetectedType').textContent.trim(),
      typeControlRemoved: !document.getElementById('rewriteType')
    };
  })()`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'mobile-rewrite-cname.png'));
  await evaluate(client, `document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true })); true`);

  const mobileFilteringCheck = await evaluateValue(client, `(() => {
    selectView('filters', { skipUrl: true });
    selectFilterSection('custom', '', { history: 'replace' });
    const panel = document.querySelector('#filter-section-custom .filter-check-card').getBoundingClientRect();
    const result = document.getElementById('customCheckResult').getBoundingClientRect();
    const ruleRows = [...document.querySelectorAll('#customCheckResult .custom-check-rule-row')];
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      panelInside: panel.left >= 0 && panel.right <= innerWidth + 1,
      resultInside: result.left >= panel.left && result.right <= panel.right + 1,
      state: document.getElementById('customCheckState').textContent.trim(),
      formColumns: getComputedStyle(document.querySelector('#filter-section-custom .custom-check-grid')).gridTemplateColumns.split(/\s+/).filter(Boolean).length,
      ruleRows: ruleRows.length,
      ruleRowsInside: ruleRows.every((row) => {
        const rect = row.getBoundingClientRect();
        return rect.left >= panel.left && rect.right <= panel.right + 1;
      }),
      typeOptions: document.getElementById('customCheckType').options.length
    };
  })()`);
  await screenshot(client, path.join(outputDir, 'mobile-filtering-check.png'));

  const mobileUpstreamRouting = await evaluateValue(client, `(async () => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('dns', { history: 'replace' });
    document.getElementById('upstreams').value = window.__auditUpstreamText;
    document.getElementById('upstreams').dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('privateReverseUpstreams').value = window.__auditPrivateReverseTestText;
    document.getElementById('privateReverseUpstreams').dispatchEvent(new Event('input', { bubbles: true }));
    renderUpstreamConfigSummary();
    document.getElementById('upstreamPreviewFold').open = true;
    document.getElementById('upstreamTestName').value = 'api.example.com';
    document.getElementById('upstreamTestType').value = 'A';
    await runUpstreamTest();
    document.getElementById('upstreams').value = window.__auditUpstreamText;
    renderUpstreamConfigSummary();
    await new Promise((resolve) => setTimeout(resolve, 250));
    document.getElementById('upstreamPreviewFold').open = false;
    document.getElementById('upstreamTestFold').open = false;
    document.getElementById('toastStack').replaceChildren();
    document.getElementById('dns-module-upstreams').scrollIntoView({ block: 'start' });
    const module = document.getElementById('dns-module-upstreams').getBoundingClientRect();
    const serverRow = document.getElementById('openDnsUpstreamServers');
    const serverMeta = document.getElementById('upstreamServersMeta').getBoundingClientRect();
    const serverArrow = serverRow.querySelector('.settings-link-arrow').getBoundingClientRect();
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      moduleWidth: Math.round(module.width),
      selectedRoute: state.upstreamTestResult?.selectedRoute || '',
      privateTestRows: (state.upstreamTestResult?.results || []).filter((row) => row.role === 'private-reverse').length,
      settingsDirty: state.settingsDirty,
      summaryText: document.getElementById('upstreamSettingsRows').innerText.replace(/\\s+/g, ' ').trim(),
      rowCount: document.querySelectorAll('#upstreamSettingsRows .settings-link-row').length,
      rowColumns: getComputedStyle(serverRow).gridTemplateColumns.split(/\\s+/).filter(Boolean).length,
      metaVisible: serverMeta.width > 0 && serverMeta.height > 0,
      arrowVisible: serverArrow.width > 0 && serverArrow.height > 0
    };
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'mobile-upstream-settings.png'));
  const mobileUpstreamDialog = await evaluateValue(client, `(async () => {
    document.getElementById('openDnsUpstreamServers').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const modal = document.querySelector('#dnsUpstreamConfigModal .modal').getBoundingClientRect();
    const textarea = document.getElementById('upstreams').getBoundingClientRect();
    return {
      visible: !document.getElementById('dnsUpstreamConfigModal').classList.contains('hidden'),
      focused: document.activeElement === document.getElementById('upstreams'),
      insideViewport: modal.left >= 0 && modal.right <= innerWidth && modal.top >= 0 && modal.bottom <= innerHeight,
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      textareaInside: textarea.left >= modal.left && textarea.right <= modal.right,
      textareaWidth: Math.round(textarea.width),
      modalWidth: Math.round(modal.width)
    };
  })()`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'mobile-upstream-server-dialog.png'));
  await evaluate(client, `cancelDnsUpstreamConfig(); document.getElementById('upstreamTestFold').open = true; document.getElementById('upstreamTestFold').scrollIntoView({ block: 'start' }); true`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'mobile-upstream-test.png'));
  await evaluate(client, `(() => {
    document.getElementById('upstreams').value = window.__auditOriginalUpstreamText;
    document.getElementById('privateReverseUpstreams').value = window.__auditOriginalPrivateReverseText;
    document.getElementById('upstreams').dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('privateReverseUpstreams').dispatchEvent(new Event('input', { bubbles: true }));
    handleSettingsChange();
    return true;
  })()`);

  const mobileClientsPersistent = await evaluateValue(client, `(async () => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('clients', { history: 'replace' });
    await loadClients();
    setClientView('persistent');
    window.scrollTo(0, 0);
    const section = document.getElementById('settings-section-clients').getBoundingClientRect();
    const tabList = document.querySelector('.client-view-tabs').getBoundingClientRect();
    const rows = [...document.querySelectorAll('#clientsList tr')];
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      sectionWidth: Math.round(section.width),
      tabWidth: Math.round(tabList.width),
      tabsInside: [...document.querySelectorAll('[data-client-view]')].every((tab) => {
        const rect = tab.getBoundingClientRect();
        return rect.left >= tabList.left && rect.right <= tabList.right;
      }),
      activeTab: state.clientView,
      visiblePanels: [...document.querySelectorAll('[data-client-view-panel]')].filter((node) => !node.hidden && node.getClientRects().length).length,
      clientCount: state.clients.length,
      rows: rows.length,
      rowsInside: rows.every((row) => {
        const rect = row.getBoundingClientRect();
        return rect.left >= section.left && rect.right <= section.right;
      }),
      tableHeaderHidden: getComputedStyle(document.querySelector('#clientPersistentPanel thead')).display === 'none',
      addButtonInside: (() => {
        const rect = document.getElementById('toggleClientEditor').getBoundingClientRect();
        return rect.left >= section.left && rect.right <= section.right;
      })()
    };
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'mobile-clients-persistent.png'));

  const mobileClientCache = await evaluateValue(client, `(() => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('clients', { history: 'replace' });
    openClientEditor(false);
    setClientEditorTab('upstreams');
    document.getElementById('clientUpstreams').value = 'udp://1.1.1.1';
    document.getElementById('clientUpstreamsCacheEnabled').checked = true;
    document.getElementById('clientUpstreamsCacheSize').value = '1048576';
    renderClientUpstreamControls();
    window.scrollTo(0, 0);
    const rect = document.getElementById('clientQuickAdd').getBoundingClientRect();
    const actions = document.querySelector('#clientQuickAdd .client-editor-actions').getBoundingClientRect();
    const sizeRect = document.getElementById('clientUpstreamsCacheSize').getBoundingClientRect();
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      width: Math.round(rect.width),
      stateText: document.getElementById('clientUpstreamsCacheState').textContent,
      sizeDisabled: document.getElementById('clientUpstreamsCacheSize').disabled,
      mainTabsHidden: document.querySelector('.client-view-tabs').getClientRects().length === 0,
      pageTitle: document.getElementById('settingsTitle').textContent.trim(),
      editorTitle: document.getElementById('clientEditorTitle').textContent.trim(),
      actionsPosition: getComputedStyle(document.querySelector('#clientQuickAdd .client-editor-actions')).position,
      actionsAfterInput: actions.top >= sizeRect.bottom - 1
    };
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'mobile-client-cache.png'));
  await evaluate(client, `closeClientEditor(); true`);

  const mobileRuntimeClients = await evaluateValue(client, `(async () => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('clients', { history: 'replace' });
    await loadClients();
    setClientView('runtime');
    const moduleNode = document.getElementById('runtimeClientModule');
    const row = document.querySelector('#runtimeClientsList .runtime-client-row');
    const detailButton = row?.querySelector('[data-runtime-client-detail]');
    if (detailButton && detailButton.getAttribute('aria-expanded') !== 'true') detailButton.click();
    const activeRow = document.querySelector('#runtimeClientsList .runtime-client-row');
    moduleNode.scrollIntoView({ block: 'start' });
    const moduleRect = moduleNode.getBoundingClientRect();
    const rowRect = activeRow?.getBoundingClientRect();
    const sourceRect = activeRow?.querySelector('.runtime-client-source')?.getBoundingClientRect();
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      moduleWidth: Math.round(moduleRect.width),
      rowWidth: Math.round(rowRect?.width || 0),
      rowColumns: activeRow ? getComputedStyle(activeRow).gridTemplateColumns.split(/\\s+/).filter(Boolean).length : 0,
      runtimeCount: state.runtimeClients?.length || 0,
      expanded: activeRow?.classList.contains('expanded') === true,
      sourceVisible: Boolean(sourceRect && sourceRect.width > 0 && sourceRect.height > 0),
      sourceText: activeRow?.querySelector('.runtime-client-source')?.innerText.replace(/\\s+/g, ' ').trim() || '',
      sourceTexts: [...document.querySelectorAll('#runtimeClientsList .runtime-client-source')].map((node) => node.innerText.replace(/\\s+/g, ' ').trim()),
      activityVisible: Boolean(activeRow?.querySelector('.runtime-client-tags')?.getClientRects().length),
      actionInside: Boolean(rowRect && [...activeRow.querySelectorAll('.runtime-client-actions button')].every((button) => {
        const rect = button.getBoundingClientRect();
        return rect.left >= rowRect.left && rect.right <= rowRect.right;
      })),
      activeTab: state.clientView,
      visiblePanels: [...document.querySelectorAll('[data-client-view-panel]')].filter((node) => !node.hidden && node.getClientRects().length).length
    };
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'mobile-runtime-clients.png'));

  const mobileDhcpRuntimeClient = await evaluateValue(client, `(() => {
    window.__cleandnsAuditRuntimeClients = state.runtimeClients;
    window.__cleandnsAuditRuntimeClientExpanded = state.runtimeClientExpanded;
    const address = '192.168.50.101';
    state.runtimeClients = [{
      address,
      name: 'phone.lan',
      note: '',
      clientId: '',
      tags: [],
      known: false,
      source: 'dhcp',
      dhcp: {
        kind: 'dynamic',
        hostname: 'phone.lan',
        mac: '00:11:22:33:44:55',
        expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString()
      },
      requests: 27,
      blocked: 2,
      cached: 11,
      protocols: ['udp'],
      types: ['A', 'AAAA'],
      firstSeenAt: new Date(Date.now() - 10 * 60 * 1000).toISOString(),
      lastSeenAt: new Date().toISOString(),
      queryLogAnonymized: true,
      reverseDns: { enabled: false, status: 'disabled', hostname: '', resolver: '', scope: '', error: '' },
      whois: { enabled: true, status: 'resolved', info: { orgname: 'CleanDNS Audit Network', city: 'Shanghai', country: 'CN' }, server: 'whois.arin.net:43', error: '' }
    }];
    state.runtimeClientExpanded = [address];
    state.runtimeClientPage = 1;
    renderRuntimeClients();
    const row = document.querySelector('#runtimeClientsList .runtime-client-row');
    const source = row?.querySelector('.runtime-client-source');
    const whois = row?.querySelector('.runtime-client-whois');
    const rowRect = row?.getBoundingClientRect();
    const sourceRect = source?.getBoundingClientRect();
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      rowWidth: Math.round(rowRect?.width || 0),
      sourceVisible: Boolean(sourceRect && sourceRect.width > 0 && sourceRect.height > 0),
      sourceInside: Boolean(rowRect && sourceRect && sourceRect.left >= rowRect.left && sourceRect.right <= rowRect.right),
      sourceText: source?.innerText.replace(/\\s+/g, ' ').trim() || '',
      whoisVisible: Boolean(whois?.getClientRects().length),
      whoisText: whois?.innerText.replace(/\\s+/g, ' ').trim() || '',
      whoisInside: Boolean(rowRect && whois && (() => { const rect = whois.getBoundingClientRect(); return rect.left >= rowRect.left && rect.right <= rowRect.right; })())
    };
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'mobile-runtime-client-dhcp.png'));
  await evaluate(client, `(() => {
    state.runtimeClients = window.__cleandnsAuditRuntimeClients || [];
    state.runtimeClientExpanded = window.__cleandnsAuditRuntimeClientExpanded || [];
    delete window.__cleandnsAuditRuntimeClients;
    delete window.__cleandnsAuditRuntimeClientExpanded;
    renderRuntimeClients();
    return true;
  })()`);

  await evaluate(client, `selectView('dns', { skipUrl: true }); selectSettingsSection('dns', { history: 'replace' }); document.getElementById('dns-module-cache').scrollIntoView({ block: 'start' }); true`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'mobile-dns-cache.png'));
  const mobileDnsCache = await evaluateValue(client, `(async () => {
    const cacheToggle = document.getElementById('cacheEnabled');
    const optimisticToggle = document.getElementById('cacheOptimistic');
    const cacheToggleRow = cacheToggle.closest('.settings-link-row').getBoundingClientRect();
    const cacheToggleTrack = cacheToggle.closest('.settings-toggle').querySelector('.settings-toggle-track').getBoundingClientRect();
    const capacityRow = document.getElementById('openDnsCacheCapacity');
    const capacityMeta = document.getElementById('dnsCacheCapacityMeta');
    const capacityArrow = capacityRow.querySelector('.settings-link-arrow');
    const capacityRowRect = capacityRow.getBoundingClientRect();
    const capacityMetaRect = capacityMeta.getBoundingClientRect();
    const capacityArrowRect = capacityArrow.getBoundingClientRect();
    document.getElementById('openDnsCacheAdvanced').focus();
    document.getElementById('openDnsCacheAdvanced').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const module = document.getElementById('dns-module-cache').getBoundingClientRect();
    const modal = document.querySelector('#dnsCacheConfigModal .modal').getBoundingClientRect();
    const fieldWidths = [...document.querySelectorAll('#dnsCacheAdvancedPanel input')].map((input) => Math.round(input.getBoundingClientRect().width));
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      moduleWidth: Math.round(module.width),
      modernToggle: cacheToggle.closest('.settings-toggle') !== null,
      modernOptimisticToggle: optimisticToggle.closest('.settings-toggle') !== null,
      toggleInside: cacheToggleTrack.left >= cacheToggleRow.left && cacheToggleTrack.right <= cacheToggleRow.right,
      headerStateAbsent: !document.getElementById('dnsCacheState'),
      capacityGrid: getComputedStyle(capacityRow).gridTemplateColumns,
      capacityText: capacityMeta.textContent.trim(),
      capacityMetaVisible: capacityMetaRect.width > 0 && capacityMetaRect.height > 0,
      capacityMetaInside: capacityMetaRect.left >= capacityRowRect.left && capacityMetaRect.right <= capacityRowRect.right,
      capacityArrowDisplay: getComputedStyle(capacityArrow).display,
      capacityArrowInside: capacityArrowRect.left >= capacityRowRect.left && capacityArrowRect.right <= capacityRowRect.right,
      modalWidth: Math.round(modal.width),
      insideViewport: modal.left >= 0 && modal.right <= innerWidth && modal.top >= 0 && modal.bottom <= innerHeight,
      fieldWidths,
      focused: document.activeElement === document.getElementById('cacheStaleTtl'),
      answerDisabled: document.getElementById('cacheOptimisticAnswerTtl').disabled,
      maxAgeDisabled: document.getElementById('cacheOptimisticMaxAge').disabled
    };
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'mobile-dns-cache-dialog.png'));
  await evaluate(client, `cancelDnsCacheConfig(); true`);

  const mobileDnssec = await evaluateValue(client, `(() => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('dns', { history: 'replace' });
    document.getElementById('dns-module-service').scrollIntoView({ block: 'start' });
    const module = document.getElementById('dns-module-service').getBoundingClientRect();
    const row = document.getElementById('dnsDnssecEnabled').closest('.settings-link-row').getBoundingClientRect();
    const rateRow = document.getElementById('openDnsRateLimit');
    const rateMeta = document.getElementById('dnsRateLimitMeta').getBoundingClientRect();
    const rateArrow = rateRow.querySelector('.settings-link-arrow').getBoundingClientRect();
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      moduleWidth: Math.round(module.width),
      rowWidth: Math.round(row.width),
      visible: document.getElementById('dnsDnssecEnabled').getClientRects().length > 0,
      ipv6Visible: document.getElementById('dnsIpv6ResolutionEnabled').getClientRects().length > 0,
      rowCount: document.querySelectorAll('#dnsServiceRows .settings-link-row').length,
      rateColumns: getComputedStyle(rateRow).gridTemplateColumns.split(/\\s+/).filter(Boolean).length,
      rateMetaVisible: rateMeta.width > 0 && rateMeta.height > 0,
      rateArrowVisible: rateArrow.width > 0 && rateArrow.height > 0
    };
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'mobile-dns-service.png'));

  const mobileRefuseAny = await evaluateValue(client, `(() => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('dns', { history: 'replace' });
    const module = document.getElementById('dns-module-service').getBoundingClientRect();
    const control = document.getElementById('dnsRefuseAny');
    const row = control.closest('.settings-link-row');
    row.scrollIntoView({ block: 'center' });
    const rect = row.getBoundingClientRect();
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      moduleWidth: Math.round(module.width),
      rowWidth: Math.round(rect.width),
      visible: control.getClientRects().length > 0,
      checked: control.checked
    };
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'mobile-refuse-any-setting.png'));
  const mobileDnsServiceDialog = await evaluateValue(client, `(async () => {
    document.getElementById('openDnsBlockingMode').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const modal = document.querySelector('#dnsServiceConfigModal .modal').getBoundingClientRect();
    const body = document.querySelector('#dnsServiceConfigModal .modal-body').getBoundingClientRect();
    return {
      visible: !document.getElementById('dnsServiceConfigModal').classList.contains('hidden'),
      focused: document.activeElement === document.querySelector('[data-dns-block-mode].active'),
      insideViewport: modal.left >= 0 && modal.right <= innerWidth && modal.top >= 0 && modal.bottom <= innerHeight,
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      modalWidth: Math.round(modal.width),
      bodyInside: body.left >= modal.left && body.right <= modal.right,
      optionCount: document.querySelectorAll('[data-dns-block-mode]').length,
      ttlEnabled: !document.getElementById('dnsBlockedResponseTtl').disabled
    };
  })()`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'mobile-dns-service-blocking-dialog.png'));
  await evaluate(client, `cancelDnsServiceConfig(); true`);

  const mobileEcs = await evaluateValue(client, `(() => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('dns', { history: 'replace' });
    document.getElementById('dns-module-ecs').scrollIntoView({ block: 'start' });
    const module = document.getElementById('dns-module-ecs').getBoundingClientRect();
    const row = document.getElementById('openEcsConfig');
    const rowRect = row.getBoundingClientRect();
    const metaRect = document.getElementById('ecsPolicyMeta').getBoundingClientRect();
    const toggleRect = document.querySelector('#ecsSettingsRows .settings-toggle-track').getBoundingClientRect();
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      moduleWidth: Math.round(module.width),
      rowWidth: Math.round(rowRect.width),
      rowColumns: getComputedStyle(row).gridTemplateColumns.split(/\\s+/).filter(Boolean).length,
      metaVisible: metaRect.width > 0 && metaRect.height > 0,
      metaInside: metaRect.left >= rowRect.left && metaRect.right <= rowRect.right,
      toggleVisible: toggleRect.width > 0 && toggleRect.height > 0,
      toggleInside: toggleRect.left >= rowRect.left && toggleRect.right <= rowRect.right,
      oldSummaryAbsent: !document.getElementById('ecsSummary')
    };
  })()`);
  await sleep(120);
  await screenshot(client, path.join(outputDir, 'mobile-dns-ecs.png'));

  const mobileEcsDialog = await evaluateValue(client, `(async () => {
    document.getElementById('openEcsConfig').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const modal = document.querySelector('#ecsConfigModal .modal').getBoundingClientRect();
    const body = document.querySelector('#ecsConfigModal .modal-body').getBoundingClientRect();
    const fieldWidths = [...document.querySelectorAll('#ecsConfigModal input')].map((input) => Math.round(input.getBoundingClientRect().width));
    return {
      visible: !document.getElementById('ecsConfigModal').classList.contains('hidden'),
      focused: document.activeElement === document.getElementById('ecsIpv4Prefix'),
      insideViewport: modal.left >= 0 && modal.right <= innerWidth && modal.top >= 0 && modal.bottom <= innerHeight,
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      modalWidth: Math.round(modal.width),
      bodyInside: body.left >= modal.left && body.right <= modal.right,
      fieldWidths
    };
  })()`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'mobile-dns-ecs-dialog.png'));
  await evaluate(client, `cancelEcsConfig(); true`);

  const mobileAccess = await evaluateValue(client, `(() => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('dns', { history: 'replace' });
    document.getElementById('access-module-summary').scrollIntoView({ block: 'start' });
    const module = document.getElementById('access-module-summary').getBoundingClientRect();
    const row = document.getElementById('openAccessAllowedClients');
    const rowRect = row.getBoundingClientRect();
    const metaRect = document.getElementById('accessAllowedMeta').getBoundingClientRect();
    const arrowRect = row.querySelector('.settings-link-arrow').getBoundingClientRect();
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      moduleWidth: Math.round(module.width),
      rowWidth: Math.round(rowRect.width),
      rowCount: document.querySelectorAll('#accessSettingsRows .settings-link-row').length,
      rowColumns: getComputedStyle(row).gridTemplateColumns.split(/\\s+/).filter(Boolean).length,
      metaVisible: metaRect.width > 0 && metaRect.height > 0,
      metaInside: metaRect.left >= rowRect.left && metaRect.right <= rowRect.right,
      arrowVisible: arrowRect.width > 0 && arrowRect.height > 0,
      oldEditorAbsent: !document.querySelector('.access-editor-grid')
    };
  })()`);
  await sleep(120);
  await screenshot(client, path.join(outputDir, 'mobile-dns-access.png'));

  const mobileAccessDialog = await evaluateValue(client, `(async () => {
    document.getElementById('openAccessAllowedClients').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const modal = document.querySelector('#accessConfigModal .modal').getBoundingClientRect();
    const body = document.querySelector('#accessConfigModal .modal-body').getBoundingClientRect();
    const textarea = document.getElementById('accessAllowedClients').getBoundingClientRect();
    return {
      visible: !document.getElementById('accessConfigModal').classList.contains('hidden'),
      focused: document.activeElement === document.getElementById('accessAllowedClients'),
      insideViewport: modal.left >= 0 && modal.right <= innerWidth && modal.top >= 0 && modal.bottom <= innerHeight,
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      modalWidth: Math.round(modal.width),
      bodyInside: body.left >= modal.left && body.right <= modal.right,
      textareaInside: textarea.left >= body.left && textarea.right <= body.right,
      textareaWidth: Math.round(textarea.width),
      hintItems: document.querySelectorAll('#accessAllowedHint span').length
    };
  })()`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'mobile-dns-access-dialog.png'));
  await evaluate(client, `cancelAccessConfig(); true`);

  const mobileClientReverseDns = await evaluateValue(client, `(() => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('dns', { history: 'replace' });
    document.getElementById('dns-module-private-reverse').scrollIntoView({ block: 'start' });
    const module = document.getElementById('dns-module-private-reverse').getBoundingClientRect();
    const serverRow = document.getElementById('openPrivateReverseServers');
    const row = serverRow.getBoundingClientRect();
    const meta = document.getElementById('privateReverseServersMeta').getBoundingClientRect();
    const arrow = serverRow.querySelector('.settings-link-arrow').getBoundingClientRect();
    const sourceSwitches = ['clientWhoisEnabled', 'clientHostsEnabled', 'clientArpEnabled', 'clientDhcpEnabled'].map((id) => document.getElementById(id).closest('.settings-link-row').getBoundingClientRect());
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      moduleWidth: Math.round(module.width),
      rowWidth: Math.round(row.width),
      visible: document.getElementById('clientReverseDnsEnabled').getClientRects().length > 0,
      rowCount: document.querySelectorAll('#privateReverseRows .settings-link-row').length,
      sourceSwitchesVisible: sourceSwitches.every((rect) => rect.width > 0 && rect.height > 0),
      sourceSwitchesInside: sourceSwitches.every((rect) => rect.left >= module.left && rect.right <= module.right),
      rowColumns: getComputedStyle(serverRow).gridTemplateColumns.split(/\\s+/).filter(Boolean).length,
      metaVisible: meta.width > 0 && meta.height > 0,
      arrowVisible: arrow.width > 0 && arrow.height > 0
    };
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'mobile-private-reverse-settings.png'));
  const mobilePrivateReverseDialog = await evaluateValue(client, `(async () => {
    document.getElementById('openPrivateReverseServers').click();
    await new Promise((resolve) => setTimeout(resolve, 30));
    const modal = document.querySelector('#privateReverseServersModal .modal').getBoundingClientRect();
    const textarea = document.getElementById('privateReverseUpstreams').getBoundingClientRect();
    return {
      visible: !document.getElementById('privateReverseServersModal').classList.contains('hidden'),
      focused: document.activeElement === document.getElementById('privateReverseUpstreams'),
      insideViewport: modal.left >= 0 && modal.right <= innerWidth && modal.top >= 0 && modal.bottom <= innerHeight,
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      textareaInside: textarea.left >= modal.left && textarea.right <= modal.right,
      textareaWidth: Math.round(textarea.width),
      modalWidth: Math.round(modal.width)
    };
  })()`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'mobile-private-reverse-dialog.png'));
  await evaluate(client, `cancelPrivateReverseServers(); true`);

  const mobileDhcp = await evaluateValue(client, `(async () => {
    selectView('dns', { skipUrl: true });
    selectSettingsSection('dhcp', { history: 'replace' });
    await loadDhcpStatus({ silent: true, preserveForm: true });
    document.getElementById('settings-section-dhcp').scrollIntoView({ block: 'start' });
    const section = document.getElementById('settings-section-dhcp').getBoundingClientRect();
    const table = document.getElementById('dhcpStaticLeaseRows').closest('table').getBoundingClientRect();
    const dnsField = document.getElementById('dhcpDnsServers').closest('.cache-field').getBoundingClientRect();
    const dnsInput = document.getElementById('dhcpDnsServers').getBoundingClientRect();
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      sectionWidth: Math.round(section.width),
      tableWidth: Math.round(table.width),
      runtimeText: document.getElementById('dhcpRuntimePill').textContent,
      enableDisabled: document.getElementById('dhcpEnabled').disabled,
      dnsInputWidth: Math.round(dnsInput.width),
      dnsInputHeight: Math.round(dnsInput.height),
      dnsInputInsideField: dnsInput.left >= dnsField.left && dnsInput.right <= dnsField.right
    };
  })()`);
  await sleep(150);
  await screenshot(client, path.join(outputDir, 'mobile-dhcp.png'));
  await evaluate(client, `document.getElementById('dhcpDnsServers').scrollIntoView({ block: 'center' }); true`);
  await sleep(120);
  await screenshot(client, path.join(outputDir, 'mobile-dhcp-dns.png'));

  await evaluate(client, `selectView('dashboard', { skipUrl: true }); window.scrollTo(0, 0); true`);
  await sleep(500);
  const mobileDashboard = await layoutMetrics(client);
  await screenshot(client, path.join(outputDir, 'mobile-dashboard.png'));
  const mobileDashboardFidelity = await evaluateValue(client, `(() => {
    const cards = [...document.querySelectorAll('#dashboardStats .stats-card')];
    const rects = cards.map((node) => node.getBoundingClientRect());
    const actions = document.querySelector('#view-dashboard .dashboard-actions').getBoundingClientRect();
    const protection = document.getElementById('protectionControl').getBoundingClientRect();
    const refresh = document.getElementById('refreshDashboard').getBoundingClientRect();
    const period = document.getElementById('dashboardPeriod').getBoundingClientRect();
    const outsideTitles = [...document.querySelectorAll('#dashboardStats .stats-card-title')];
    const insideTitles = [...document.querySelectorAll('#dashboardStats .stats-card-mobile-title')];
    const upstreamRows = [...document.querySelectorAll('#topUpstreams .rank-row, #topUpstreamAvg .rank-row')];
    const sortButtons = [...document.querySelectorAll('#view-dashboard [data-rank-sort]')];
    return {
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      cards: cards.length,
      oneColumn: rects.length === 4 && rects.every((rect, index) => index === 0 || (rect.top > rects[index - 1].bottom && Math.abs(rect.left - rects[0].left) <= 1)),
      equalWidths: rects.length === 4 && rects.every((rect) => Math.abs(rect.width - rects[0].width) <= 1),
      equalHeights: rects.length === 4 && rects.every((rect) => Math.abs(rect.height - rects[0].height) <= 1),
      cardsInside: rects.every((rect) => rect.left >= 0 && rect.right <= innerWidth),
      insideTitlesHidden: insideTitles.every((node) => getComputedStyle(node).display === 'none'),
      outsideTitlesVisible: outsideTitles.every((node) => getComputedStyle(node).display !== 'none'),
      titlesFit: outsideTitles.every((node) => node.scrollWidth <= node.clientWidth + 1 && node.scrollHeight <= node.clientHeight + 1),
      protectionRefreshAligned: Math.abs(protection.top - refresh.top) <= 1 && Math.abs(protection.bottom - refresh.bottom) <= 1,
      periodBelowActions: period.top >= protection.bottom + 7,
      periodFullWidth: Math.abs(period.width - actions.width) <= 1,
      refreshIconOnly: getComputedStyle(document.querySelector('#refreshDashboard > span')).display === 'none',
      selectedPeriod: document.getElementById('dashboardPeriod').value,
      statusPeriod: Number(state.status?.statistics?.periodHours || 0),
      periodOptions: [...document.getElementById('dashboardPeriod').options].map((option) => Number(option.value)),
      duplicateRefreshButtons: document.querySelectorAll('[data-dashboard-refresh]').length,
      counterIcons: document.querySelectorAll('#dashboardCounters .dashboard-stat-icon').length,
      upstreamRowsSeparated: upstreamRows.every((row) => {
        const name = row.querySelector('.rank-name')?.getBoundingClientRect();
        const metric = row.querySelector('.rank-metric')?.getBoundingClientRect();
        return !name || !metric || name.right <= metric.left + 1;
      }),
      rankSortButtons: sortButtons.length,
      rankSortButtonsInside: sortButtons.every((button) => {
        const rect = button.getBoundingClientRect();
        const head = button.closest('.rank-head')?.getBoundingClientRect();
        return head && rect.left >= head.left - 1 && rect.right <= head.right + 1 && rect.top >= head.top - 1 && rect.bottom <= head.bottom + 1;
      }),
      rankSortLabelsFit: sortButtons.every((button) => button.scrollWidth <= button.clientWidth + 1 && button.scrollHeight <= button.clientHeight + 1)
    };
  })()`);
  await evaluate(client, `document.getElementById('topClients').closest('.dashboard-panel').scrollIntoView({ block: 'start' }); true`);
  await sleep(300);
  await screenshot(client, path.join(outputDir, 'mobile-rankings.png'));

  const mobileDarkRouteAudit = await evaluateValue(client, `(() => {
    const rows = [];
    const capture = (route, node) => {
      const rect = node?.getBoundingClientRect();
      rows.push({
        route,
        visible: Boolean(node && !node.classList.contains('hidden') && node.getClientRects().length),
        horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
        width: rect ? Math.round(rect.width) : 0,
        theme: document.documentElement.dataset.theme
      });
    };
    for (const section of ['general', 'stats', 'querylog', 'dns', 'encryption', 'clients', 'dhcp']) {
      selectView('dns', { skipUrl: true });
      selectSettingsSection(section, { history: 'replace' });
      capture('settings/' + section, document.getElementById('settings-section-' + section));
    }
    for (const section of ['blocklists', 'allowlists', 'rewrites', 'services', 'custom', 'test']) {
      selectView('filters', { skipUrl: true });
      selectFilterSection(section, '', { history: 'replace' });
      capture('filters/' + section, document.getElementById('filter-section-' + section));
    }
    for (const view of ['logs', 'status', 'dashboard']) {
      selectView(view, { skipUrl: true });
      capture(view, document.getElementById('view-' + view));
    }
    window.scrollTo(0, 0);
    return rows;
  })()`);

  await setViewport(client, 1440, 1000, 1, false);
  const lightThemeAudit = await evaluateValue(client, `(() => {
    adoptProfile({ ...state.profile, theme: 'light' });
    const rows = [];
    const capture = (route, node) => rows.push({
      route,
      visible: Boolean(node && !node.classList.contains('hidden') && node.getClientRects().length),
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      theme: document.documentElement.dataset.theme
    });
    for (const section of ['general', 'stats', 'querylog', 'dns', 'encryption', 'clients', 'dhcp']) {
      selectView('dns', { skipUrl: true });
      selectSettingsSection(section, { history: 'replace' });
      capture('settings/' + section, document.getElementById('settings-section-' + section));
    }
    for (const section of ['blocklists', 'allowlists', 'rewrites', 'services', 'custom', 'test']) {
      selectView('filters', { skipUrl: true });
      selectFilterSection(section, '', { history: 'replace' });
      capture('filters/' + section, document.getElementById('filter-section-' + section));
    }
    for (const view of ['logs', 'status', 'dashboard']) {
      selectView(view, { skipUrl: true });
      capture(view, document.getElementById('view-' + view));
    }
    window.scrollTo(0, 0);
    const bodyBackground = getComputedStyle(document.body).backgroundColor;
    const cardBackground = getComputedStyle(document.querySelector('#dashboardStats .stats-card')).backgroundColor;
    const channels = (value) => (String(value).match(/\\d+/g) || []).slice(0, 3).map(Number);
    const isLight = (value) => {
      const values = channels(value);
      return values.length === 3 && values.reduce((sum, item) => sum + item, 0) / 3 > 200;
    };
    return {
      preference: document.documentElement.dataset.themePreference,
      resolved: document.documentElement.dataset.theme,
      bodyBackground,
      cardBackground,
      bodyLight: isLight(bodyBackground),
      cardLight: isLight(cardBackground),
      rows
    };
  })()`);
  await screenshot(client, path.join(outputDir, 'desktop-light-dashboard.png'));
  await evaluate(client, `document.getElementById('accountMenuToggle').click(); true`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'desktop-account-menu-light.png'));
  await evaluate(client, `document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true })); selectView('dns', { skipUrl: true }); selectSettingsSection('dns', { history: 'replace' }); window.scrollTo(0, 0); true`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'desktop-light-dns.png'));
  await evaluate(client, `selectView('dns', { skipUrl: true }); selectSettingsSection('clients', { history: 'replace' }); setClientView('persistent'); window.scrollTo(0, 0); true`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'desktop-light-clients.png'));
  await evaluate(client, `selectView('filters', { skipUrl: true }); selectFilterSection('blocklists', '', { history: 'replace' }); window.scrollTo(0, 0); true`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'desktop-light-filters.png'));
  await evaluate(client, `selectView('logs', { skipUrl: true }); window.scrollTo(0, 0); true`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'desktop-light-logs.png'));
  await setViewport(client, 390, 844, 1, true);
  await evaluate(client, `selectView('dns', { skipUrl: true }); selectSettingsSection('clients', { history: 'replace' }); setClientView('persistent'); window.scrollTo(0, 0); true`);
  await sleep(100);
  await screenshot(client, path.join(outputDir, 'mobile-light-clients.png'));
  await setViewport(client, 1440, 1000, 1, false);

  const themeRestore = await evaluateValue(client, `(async () => {
    const initial = ${JSON.stringify(desktopThemeInteraction.initial)};
    const canWrite = ${JSON.stringify(themeWrite)};
    if (canWrite) await saveThemePreference(initial);
    else adoptProfile({ ...state.profile, theme: initial });
    const persisted = canWrite ? await api('/api/profile') : { theme: state.profile?.theme };
    document.getElementById('toastStack').replaceChildren();
    return {
      preference: document.documentElement.dataset.themePreference,
      resolved: document.documentElement.dataset.theme,
      persisted: persisted.theme
    };
  })()`);

  if (desktopInteraction.browsingChanged.checked === desktopInteraction.initial.safeBrowsingEnabled || !desktopInteraction.browsingChanged.dirty || !desktopInteraction.browsingChanged.payloadMatches || !desktopInteraction.browsingChanged.saveEnabled || desktopInteraction.safeSearchChanged.checked === desktopInteraction.initial.safeSearchEnabled || !desktopInteraction.safeSearchChanged.dirty || !desktopInteraction.safeSearchChanged.payloadMatches || !desktopInteraction.providersEditableWhenDisabled || desktopInteraction.rowCount !== 4 || desktopInteraction.modernToggleCount !== 4 || desktopInteraction.switchLinkColumns !== 3 || !desktopInteraction.toggleInside || !desktopInteraction.oldStateAbsent || !desktopInteraction.providersInModal || !desktopInteraction.restored) {
    throw new Error(`general protection settings mismatch: ${JSON.stringify(desktopInteraction)}`);
  }
  if (!desktopInteraction.cancelDialog.visible || desktopInteraction.cancelDialog.title !== '安全搜索' || !desktopInteraction.cancelDialog.focused || desktopInteraction.cancelDialog.providers !== 7 || !desktopInteraction.cancelDialog.parentInModal || !desktopInteraction.cancelDialog.dirtyBeforeCancel || !desktopInteraction.cancelDialog.restored || !desktopInteraction.cancelDialog.closed || !desktopInteraction.cancelDialog.focusRestored || desktopInteraction.cancelDialog.dirtyAfterCancel || !desktopInteraction.keyboardOpened || !desktopInteraction.applied.closed || !desktopInteraction.applied.dirty || !desktopInteraction.applied.payloadMatches || !desktopInteraction.applied.metaChanged || !desktopInteraction.applied.focusRestored) {
    throw new Error(`safe search dialog interaction mismatch: ${JSON.stringify(desktopInteraction)}`);
  }
  if (!desktopSafeSearchDialog.visible || !desktopSafeSearchDialog.focused || !desktopSafeSearchDialog.insideViewport || desktopSafeSearchDialog.providers !== 7 || !desktopSafeSearchDialog.rowsInside) {
    throw new Error(`safe search desktop dialog layout mismatch: ${JSON.stringify(desktopSafeSearchDialog)}`);
  }
  if (mobileGeneralProtection.horizontalOverflow || mobileGeneralProtection.moduleWidth > 390 || mobileGeneralProtection.rowCount !== 4 || !mobileGeneralProtection.rowsInside || mobileGeneralProtection.modernToggleCount !== 4 || mobileGeneralProtection.switchLinkColumns !== 2 || !mobileGeneralProtection.metaInside || !mobileGeneralProtection.toggleInside || !mobileGeneralProtection.oldStateAbsent) {
    throw new Error(`general protection mobile layout mismatch: ${JSON.stringify(mobileGeneralProtection)}`);
  }
  if (!mobileSafeSearchDialog.visible || mobileSafeSearchDialog.horizontalOverflow || mobileSafeSearchDialog.modalWidth > 390 || !mobileSafeSearchDialog.insideViewport || !mobileSafeSearchDialog.listInside || mobileSafeSearchDialog.providers !== 7 || !mobileSafeSearchDialog.singleColumn || !mobileSafeSearchDialog.rowsInside || !mobileSafeSearchDialog.focused) {
    throw new Error(`safe search mobile dialog layout mismatch: ${JSON.stringify(mobileSafeSearchDialog)}`);
  }
  if (!desktopStatsInteraction.masterChanged.dirty || !desktopStatsInteraction.masterChanged.payloadMatches || desktopStatsInteraction.masterChanged.retentionDisabled !== !desktopStatsInteraction.masterChanged.enabled || desktopStatsInteraction.masterChanged.ignoredRowDisabled !== !desktopStatsInteraction.masterChanged.enabled || desktopStatsInteraction.masterChanged.ignoredToggleDisabled !== !desktopStatsInteraction.masterChanged.enabled || desktopStatsInteraction.rowCount !== 3 || desktopStatsInteraction.modernToggleCount !== 2 || !desktopStatsInteraction.oldModulesAbsent || !desktopStatsInteraction.restored) {
    throw new Error(`statistics settings mismatch: ${JSON.stringify(desktopStatsInteraction)}`);
  }
  if (!desktopStatsInteraction.retentionCancel.visible || !desktopStatsInteraction.retentionCancel.focusedOption || !desktopStatsInteraction.retentionCancel.dirtyBeforeCancel || !desktopStatsInteraction.retentionCancel.restored || !desktopStatsInteraction.retentionCancel.closed || !desktopStatsInteraction.retentionCancel.focusRestored || desktopStatsInteraction.retentionCancel.dirtyAfterCancel) {
    throw new Error(`statistics retention cancel mismatch: ${JSON.stringify(desktopStatsInteraction.retentionCancel)}`);
  }
  if (desktopStatsInteraction.decreaseConfirm.applicable && (!desktopStatsInteraction.decreaseConfirm.warningVisible || desktopStatsInteraction.decreaseConfirm.buttonText !== '确认缩短' || !desktopStatsInteraction.decreaseConfirm.stillOpen)) {
    throw new Error(`statistics retention confirmation mismatch: ${JSON.stringify(desktopStatsInteraction.decreaseConfirm)}`);
  }
  if (!desktopStatsInteraction.retentionApplied.closed || !desktopStatsInteraction.retentionApplied.dirty || !desktopStatsInteraction.retentionApplied.payloadMatches || !desktopStatsInteraction.retentionApplied.meta || !desktopStatsInteraction.retentionApplied.focusRestored || !desktopStatsInteraction.ignoredCancel.visible || !desktopStatsInteraction.ignoredCancel.focused || !desktopStatsInteraction.ignoredCancel.dirtyBeforeCancel || !desktopStatsInteraction.ignoredCancel.restored || !desktopStatsInteraction.ignoredCancel.closed || !desktopStatsInteraction.ignoredCancel.focusRestored || desktopStatsInteraction.ignoredCancel.dirtyAfterCancel || !desktopStatsInteraction.invalidPrevented || !desktopStatsInteraction.ignoredApplied.closed || !desktopStatsInteraction.ignoredApplied.normalized || !desktopStatsInteraction.ignoredApplied.dirty || !desktopStatsInteraction.ignoredApplied.payloadMatches || desktopStatsInteraction.ignoredApplied.meta !== '2 个域名' || !desktopStatsInteraction.ignoredApplied.focusRestored) {
    throw new Error(`statistics dialogs mismatch: ${JSON.stringify(desktopStatsInteraction)}`);
  }
  if (!desktopStatsInteraction.clearConfirm.visible || desktopStatsInteraction.clearConfirm.title !== '清空统计数据' || !desktopStatsInteraction.clearConfirm.focused || !desktopStatsInteraction.clearConfirm.closed || !desktopStatsInteraction.clearConfirm.focusRestored || !desktopStatsRetentionDialog.visible || !desktopStatsRetentionDialog.insideViewport || desktopStatsRetentionDialog.options !== 5 || desktopStatsRetentionDialog.columns !== 2 || desktopStatsRetentionDialog.active !== 1 || !desktopStatsRetentionDialog.focusedOption) {
    throw new Error(`statistics clear or dialog layout mismatch: ${JSON.stringify({ clear: desktopStatsInteraction.clearConfirm, dialog: desktopStatsRetentionDialog })}`);
  }
  if (!desktopQueryLogInteraction.masterChanged.dirty || !desktopQueryLogInteraction.masterChanged.payloadMatches || desktopQueryLogInteraction.masterChanged.anonymizeDisabled !== !desktopQueryLogInteraction.masterChanged.enabled || desktopQueryLogInteraction.masterChanged.retentionDisabled !== !desktopQueryLogInteraction.masterChanged.enabled || desktopQueryLogInteraction.masterChanged.capacityDisabled !== !desktopQueryLogInteraction.masterChanged.enabled || desktopQueryLogInteraction.masterChanged.ignoredDisabled !== !desktopQueryLogInteraction.masterChanged.enabled || !desktopQueryLogInteraction.anonymizeChanged.dirty || !desktopQueryLogInteraction.anonymizeChanged.payloadMatches || desktopQueryLogInteraction.rowCount !== 5 || desktopQueryLogInteraction.modernToggleCount !== 3 || !desktopQueryLogInteraction.oldModulesAbsent || !desktopQueryLogInteraction.restored) {
    throw new Error(`query log settings mismatch: ${JSON.stringify(desktopQueryLogInteraction)}`);
  }
  if (desktopQueryLogInteraction.decreaseConfirm.applicable && (!desktopQueryLogInteraction.decreaseConfirm.warningVisible || desktopQueryLogInteraction.decreaseConfirm.buttonText !== '确认缩短' || !desktopQueryLogInteraction.decreaseConfirm.stillOpen)) {
    throw new Error(`query log retention confirmation mismatch: ${JSON.stringify(desktopQueryLogInteraction.decreaseConfirm)}`);
  }
  if (!desktopQueryLogInteraction.retentionApplied.closed || !desktopQueryLogInteraction.retentionApplied.dirty || !desktopQueryLogInteraction.retentionApplied.payloadMatches || !desktopQueryLogInteraction.retentionApplied.focusRestored || !desktopQueryLogInteraction.capacityCancel.restored || !desktopQueryLogInteraction.capacityCancel.closed || !desktopQueryLogInteraction.capacityCancel.focusRestored || desktopQueryLogInteraction.capacityCancel.dirty || !desktopQueryLogInteraction.capacityApplied.closed || !desktopQueryLogInteraction.capacityApplied.dirty || !desktopQueryLogInteraction.capacityApplied.payloadMatches || !desktopQueryLogInteraction.capacityApplied.meta.includes('条') || !desktopQueryLogInteraction.ignoredApplied.closed || !desktopQueryLogInteraction.ignoredApplied.normalized || !desktopQueryLogInteraction.ignoredApplied.dirty || !desktopQueryLogInteraction.ignoredApplied.payloadMatches || desktopQueryLogInteraction.ignoredApplied.meta !== '2 个域名' || !desktopQueryLogInteraction.ignoredApplied.focusRestored) {
    throw new Error(`query log dialogs mismatch: ${JSON.stringify(desktopQueryLogInteraction)}`);
  }
  if (!desktopQueryLogInteraction.clearConfirm.visible || desktopQueryLogInteraction.clearConfirm.title !== '清空查询日志' || !desktopQueryLogInteraction.clearConfirm.focused || !desktopQueryLogInteraction.clearConfirm.closed || !desktopQueryLogInteraction.clearConfirm.focusRestored || !desktopQueryLogDialogs.retention.visible || !desktopQueryLogDialogs.retention.insideViewport || desktopQueryLogDialogs.retention.options !== 6 || desktopQueryLogDialogs.retention.columns !== 2 || desktopQueryLogDialogs.retention.active !== 1 || !desktopQueryLogDialogs.ignored.visible || !desktopQueryLogDialogs.ignored.focused || !desktopQueryLogDialogs.ignored.insideViewport || !desktopQueryLogDialogs.ignored.textareaInside) {
    throw new Error(`query log clear or dialog layout mismatch: ${JSON.stringify({ clear: desktopQueryLogInteraction.clearConfirm, dialogs: desktopQueryLogDialogs })}`);
  }
  if (mobileStatsSettings.settingsDirty || !mobileStatsSettings.dirtyBarHidden || mobileStatsSettings.dirtyFields.length || mobileStatsSettings.horizontalOverflow || mobileStatsSettings.sectionWidth > 390 || mobileStatsSettings.moduleWidth > mobileStatsSettings.sectionWidth || mobileStatsSettings.rowCount !== 3 || !mobileStatsSettings.rowsInside || mobileStatsSettings.modernToggleCount !== 2 || mobileStatsSettings.switchLinkColumns !== 2 || !mobileStatsSettings.oldModulesAbsent || !mobileStatsRetentionDialog.visible || mobileStatsRetentionDialog.horizontalOverflow || mobileStatsRetentionDialog.modalWidth > 390 || !mobileStatsRetentionDialog.insideViewport || !mobileStatsRetentionDialog.gridInside || mobileStatsRetentionDialog.options !== 5 || mobileStatsRetentionDialog.columns !== 1 || !mobileStatsRetentionDialog.focusedOption || !mobileStatsIgnoredDialog.visible || mobileStatsIgnoredDialog.horizontalOverflow || mobileStatsIgnoredDialog.modalWidth > 390 || !mobileStatsIgnoredDialog.insideViewport || !mobileStatsIgnoredDialog.textareaInside || !mobileStatsIgnoredDialog.focused) {
    throw new Error(`statistics mobile layout mismatch: ${JSON.stringify({ settings: mobileStatsSettings, retention: mobileStatsRetentionDialog, ignored: mobileStatsIgnoredDialog })}`);
  }
  if (mobileQueryLogSettings.horizontalOverflow || mobileQueryLogSettings.sectionWidth > 390 || mobileQueryLogSettings.moduleWidth > mobileQueryLogSettings.sectionWidth || mobileQueryLogSettings.rowCount !== 5 || !mobileQueryLogSettings.rowsInside || mobileQueryLogSettings.modernToggleCount !== 3 || mobileQueryLogSettings.switchLinkColumns !== 2 || !mobileQueryLogSettings.oldModulesAbsent || mobileQueryLogDialogs.horizontalOverflow || !mobileQueryLogDialogs.retention.visible || mobileQueryLogDialogs.retention.modalWidth > 390 || !mobileQueryLogDialogs.retention.insideViewport || mobileQueryLogDialogs.retention.options !== 6 || mobileQueryLogDialogs.retention.columns !== 1 || !mobileQueryLogDialogs.capacity.visible || mobileQueryLogDialogs.capacity.modalWidth > 390 || !mobileQueryLogDialogs.capacity.insideViewport || !mobileQueryLogDialogs.capacity.inputInside || !mobileQueryLogDialogs.capacity.focused) {
    throw new Error(`query log mobile layout mismatch: ${JSON.stringify({ settings: mobileQueryLogSettings, dialogs: mobileQueryLogDialogs })}`);
  }
  if (desktopQueryLogMain.horizontalOverflow || !desktopQueryLogMain.headerAligned || !desktopQueryLogMain.actionsInside || !desktopQueryLogMain.controls || !desktopQueryLogMain.duplicateCardHeaderAbsent || !desktopQueryLogMain.detailToggleAbsent || desktopQueryLogMain.headerCells !== 6 || desktopQueryLogMain.rowCells !== 6 || desktopQueryLogMain.rowCount < 1 || !desktopQueryLogMain.mobileCardsHidden || !desktopQueryLogMain.tableInside || desktopQueryLogMain.statusUrl !== 'error' || !desktopQueryLogMain.statusRowsValid || desktopQueryLogMain.reasonUrl !== 'refused' || !desktopQueryLogMain.combinedValid || !desktopQueryLogMain.reasonClearedByStatus || !desktopQueryLogMain.resetValid || !desktopQueryLogMain.refreshBusyVisible || !desktopQueryLogMain.rebuilt) {
    throw new Error(`query log desktop main mismatch: ${JSON.stringify(desktopQueryLogMain)}`);
  }
  const expectedLogActionLabels = ['阻止此域名', '仅对此客户端阻止', '拒绝此客户端', '添加持久客户端', '添加 DNS 重写'];
  if (!desktopQueryLogActions.available || !desktopQueryLogActions.actualOpened || !desktopQueryLogActions.escapeClosed || !desktopQueryLogActions.exactInside || JSON.stringify(desktopQueryLogActions.exactLabels) !== JSON.stringify(expectedLogActionLabels) || !desktopQueryLogActions.anonymousHidesClientActions || !desktopQueryLogActions.outsideClosed || !desktopQueryLogActions.disallowDialog.visible || !desktopQueryLogActions.disallowDialog.focused || !desktopQueryLogActions.disallowDialog.clientVisible || !desktopQueryLogActions.disallowCanceled || !desktopQueryLogActions.triggerInside || !desktopQueryLogActions.leftOpenForScreenshot) {
    throw new Error(`query log desktop actions mismatch: ${JSON.stringify(desktopQueryLogActions)}`);
  }
  const responseFilterDetailValid = !responseFilterFixture || (
    desktopQueryLogDetail.responseRowFound &&
    desktopQueryLogDetail.detailRows >= 12 &&
    desktopQueryLogDetail.answerSections >= 2 &&
    desktopQueryLogDetail.responseActionVisible &&
    desktopQueryLogDetail.matchTypeVisible &&
    desktopQueryLogDetail.matchValueVisible &&
    desktopQueryLogDetail.filterSourceVisible &&
    desktopQueryLogDetail.originalResponseVisible &&
    desktopQueryLogDetail.whoisVisible
  );
  if (!desktopQueryLogDetail.visible || !desktopQueryLogDetail.focused || !desktopQueryLogDetail.insideViewport || desktopQueryLogDetail.detailRows < 10 || desktopQueryLogDetail.answerSections < 1 || !responseFilterDetailValid || !desktopQueryLogDetail.closed || !desktopQueryLogDetail.focusRestored) {
    throw new Error(`query log desktop detail mismatch: ${JSON.stringify(desktopQueryLogDetail)}`);
  }
  if (mobileQueryLogMain.horizontalOverflow || !mobileQueryLogMain.actionsInside || !mobileQueryLogMain.statusFullRow || mobileQueryLogMain.cards < 1 || !mobileQueryLogMain.cardsVisible || !mobileQueryLogMain.cardsInside || mobileQueryLogMain.firstCardWidth <= 0 || !mobileQueryLogMain.desktopRowsHidden || JSON.stringify(mobileQueryLogMain.fieldLabels) !== JSON.stringify(['状态', '原因', '客户端', '协议']) || !mobileQueryLogMain.titleFits) {
    throw new Error(`query log mobile main mismatch: ${JSON.stringify(mobileQueryLogMain)}`);
  }
  if (!mobileQueryLogActions.available || !mobileQueryLogActions.visible || !mobileQueryLogActions.stableAcrossPolling || !mobileQueryLogActions.insideViewport || !mobileQueryLogActions.triggerInsideCard || !mobileQueryLogActions.expanded || mobileQueryLogActions.labels.length < 2 || !mobileQueryLogActions.closed || !mobileQueryLogActions.focusRestored) {
    throw new Error(`query log mobile actions mismatch: ${JSON.stringify(mobileQueryLogActions)}`);
  }
  if (!mobileQueryLogDetail.visible || !mobileQueryLogDetail.focused || !mobileQueryLogDetail.insideViewport || mobileQueryLogDetail.horizontalOverflow || mobileQueryLogDetail.detailRows < 10 || !mobileQueryLogDetail.whoisVisible || !mobileQueryLogDetail.closed || !mobileQueryLogDetail.focusRestored) {
    throw new Error(`query log mobile detail mismatch: ${JSON.stringify(mobileQueryLogDetail)}`);
  }
  const dashboardInitialPeriod = Number(desktopDashboardFidelity.initial.value);
  const dashboardOptionsValid = desktopDashboardFidelity.initial.options.length > 0
    && desktopDashboardFidelity.initial.options.includes(dashboardInitialPeriod)
    && JSON.stringify(desktopDashboardFidelity.initial.options) === JSON.stringify(desktopDashboardFidelity.initial.apiOptions)
    && desktopDashboardFidelity.initial.options.every((value, index, values) => Number.isFinite(value) && value > 0 && (index === 0 || value > values[index - 1]));
  const dashboardTargetValid = desktopDashboardFidelity.selected === desktopDashboardFidelity.targetPeriod
    && desktopDashboardFidelity.statusPeriod === Number(desktopDashboardFidelity.targetPeriod)
    && desktopDashboardFidelity.urlPeriod === desktopDashboardFidelity.targetPeriod
    && (!desktopDashboardFidelity.hasSevenDay || (desktopDashboardFidelity.targetPeriod === '168' && desktopDashboardFidelity.windowText.includes('7 天')));
  const rankSortDefaultsValid = ['topClients', 'topQueriedDomains', 'topBlockedDomains', 'topUpstreams'].every((id) => desktopDashboardFidelity.rankSort.defaults[id]?.buttons === 2 && desktopDashboardFidelity.rankSort.defaults[id]?.active === 'count' && desktopDashboardFidelity.rankSort.defaults[id]?.aria === 'descending')
    && desktopDashboardFidelity.rankSort.defaults.topUpstreamAvg?.buttons === 2
    && desktopDashboardFidelity.rankSort.defaults.topUpstreamAvg?.active === 'count'
    && desktopDashboardFidelity.rankSort.defaults.topUpstreamAvg?.aria === 'ascending';
  const rankSortInteractionValid = desktopDashboardFidelity.rankSort.headers === 5
    && desktopDashboardFidelity.rankSort.buttons === 10
    && desktopDashboardFidelity.rankSort.eachTableHasTwoButtons
    && rankSortDefaultsValid
    && desktopDashboardFidelity.rankSort.nameFocused
    && desktopDashboardFidelity.rankSort.namesAsc
    && desktopDashboardFidelity.rankSort.namesDesc
    && desktopDashboardFidelity.rankSort.nameAscAria === 'ascending'
    && desktopDashboardFidelity.rankSort.nameDescAria === 'descending'
    && desktopDashboardFidelity.rankSort.countsRestored
    && desktopDashboardFidelity.rankSort.countRestoredAria === 'descending'
    && desktopDashboardFidelity.rankSort.finalField === 'count'
    && desktopDashboardFidelity.rankSort.finalDirection === 'desc';
  if (!dashboardOptionsValid || desktopDashboardFidelity.initial.statusPeriod !== dashboardInitialPeriod || !dashboardTargetValid || desktopDashboardFidelity.horizontalOverflow || desktopDashboardFidelity.statCards !== 4 || !desktopDashboardFidelity.statCardSameRow || !desktopDashboardFidelity.statCardEqualHeight || !desktopDashboardFidelity.mobileTitlesHidden || desktopDashboardFidelity.primaryPanels !== 6 || !desktopDashboardFidelity.panelPairHeightsEqual || desktopDashboardFidelity.panelHeight !== 374 || desktopDashboardFidelity.duplicateRefreshButtons !== 0 || desktopDashboardFidelity.counterIcons !== 6 || desktopDashboardFidelity.upstreamRows < 1 || !desktopDashboardFidelity.upstreamRowsSeparated || !desktopDashboardFidelity.rankDotsSpaced || !desktopDashboardFidelity.runningDetailsVisible || !desktopDashboardFidelity.timelineVisible || !rankSortInteractionValid || desktopDashboardFidelity.restoredPeriod !== desktopDashboardFidelity.initial.value || desktopDashboardFidelity.restoredStatusPeriod !== dashboardInitialPeriod || desktopDashboardFidelity.restoredUrlPeriod !== desktopDashboardFidelity.initial.value || !desktopDashboardFidelity.refreshBusyVisible || !desktopDashboardFidelity.refreshRestored) {
    throw new Error(`dashboard desktop fidelity mismatch: ${JSON.stringify(desktopDashboardFidelity)}`);
  }
  if (!desktopAppShell.sameGrid || !desktopAppShell.compactWidth || !desktopAppShell.protectionVisible || !desktopAppShell.refreshHidden || !desktopOverlays.desktopNav?.menuOpened || !desktopOverlays.desktopNav?.closedOutside) {
    throw new Error(`application shell mismatch: ${JSON.stringify({ desktopAppShell, desktopNav: desktopOverlays.desktopNav })}`);
  }
  const mobileDashboardPeriodValid = mobileDashboardFidelity.periodOptions.includes(Number(mobileDashboardFidelity.selectedPeriod))
    && mobileDashboardFidelity.statusPeriod === Number(mobileDashboardFidelity.selectedPeriod);
  if (mobileDashboardFidelity.horizontalOverflow || mobileDashboardFidelity.cards !== 4 || !mobileDashboardFidelity.oneColumn || !mobileDashboardFidelity.equalWidths || !mobileDashboardFidelity.equalHeights || !mobileDashboardFidelity.cardsInside || !mobileDashboardFidelity.insideTitlesHidden || !mobileDashboardFidelity.outsideTitlesVisible || !mobileDashboardFidelity.titlesFit || !mobileDashboardFidelity.protectionRefreshAligned || !mobileDashboardFidelity.periodBelowActions || !mobileDashboardFidelity.periodFullWidth || !mobileDashboardFidelity.refreshIconOnly || !mobileDashboardPeriodValid || mobileDashboardFidelity.duplicateRefreshButtons !== 0 || mobileDashboardFidelity.counterIcons !== 6 || !mobileDashboardFidelity.upstreamRowsSeparated || mobileDashboardFidelity.rankSortButtons !== 10 || !mobileDashboardFidelity.rankSortButtonsInside || !mobileDashboardFidelity.rankSortLabelsFit) {
    throw new Error(`dashboard mobile fidelity mismatch: ${JSON.stringify(mobileDashboardFidelity)}`);
  }
  if (!desktopThemeInteraction.opened || !desktopThemeInteraction.closedAfterSelection || desktopThemeInteraction.preference !== 'dark' || desktopThemeInteraction.resolved !== 'dark' || desktopThemeInteraction.selected !== 'true' || desktopThemeInteraction.persisted !== 'dark' || desktopThemeInteraction.headingContrast < 4.5 || !desktopThemeInteraction.menuInsideViewport || !desktopThemeInteraction.escapeClosed || !desktopThemeInteraction.outsideClosed) {
    throw new Error(`desktop theme interaction mismatch: ${JSON.stringify(desktopThemeInteraction)}`);
  }
  const badDarkRoute = routeAudit.find((row) => !row.visible || row.horizontalOverflow || row.theme !== 'dark' || !row.darkSurface);
  if (badDarkRoute) throw new Error(`desktop dark route mismatch: ${JSON.stringify(badDarkRoute)}`);
  if (routeScrollReset.viewBefore <= 0 || !routeScrollReset.viewReset || routeScrollReset.settingsBefore <= 0 || !routeScrollReset.settingsReset || routeScrollReset.filtersBefore <= 0 || !routeScrollReset.filtersReset || !routeScrollReset.anchorVisibleBelowHeader) {
    throw new Error(`desktop route scroll reset mismatch: ${JSON.stringify(routeScrollReset)}`);
  }
  const badMobileDarkRoute = mobileDarkRouteAudit.find((row) => !row.visible || row.horizontalOverflow || row.theme !== 'dark' || row.width > 390);
  if (badMobileDarkRoute) throw new Error(`mobile dark route mismatch: ${JSON.stringify(badMobileDarkRoute)}`);
  const badLightRoute = lightThemeAudit.rows.find((row) => !row.visible || row.horizontalOverflow || row.theme !== 'light');
  if (lightThemeAudit.preference !== 'light' || lightThemeAudit.resolved !== 'light' || !lightThemeAudit.bodyLight || !lightThemeAudit.cardLight || badLightRoute) {
    throw new Error(`light theme route mismatch: ${JSON.stringify({ lightThemeAudit, badLightRoute })}`);
  }
  if (!mobileThemeMenu.opened || mobileThemeMenu.horizontalOverflow || !mobileThemeMenu.insideViewport || !mobileThemeMenu.iconOnly || mobileThemeMenu.options !== 3 || mobileThemeMenu.selected !== 'dark') {
    throw new Error(`mobile theme menu mismatch: ${JSON.stringify(mobileThemeMenu)}`);
  }
  if (!mobileNavigation.opened || !mobileNavigation.closedAfterSelection || !mobileNavigation.generalVisible) {
    throw new Error(`mobile navigation mismatch: ${JSON.stringify(mobileNavigation)}`);
  }
  if (mobileRouteScrollReset.viewBefore <= 0 || !mobileRouteScrollReset.viewReset || mobileRouteScrollReset.sectionBefore <= 0 || !mobileRouteScrollReset.sectionReset) {
    throw new Error(`mobile route scroll reset mismatch: ${JSON.stringify(mobileRouteScrollReset)}`);
  }
  if (themeRestore.preference !== desktopThemeInteraction.initial || themeRestore.persisted !== desktopThemeInteraction.initial) {
    throw new Error(`theme restore mismatch: ${JSON.stringify(themeRestore)}`);
  }
  if (!desktopOverlays.rewrite.focused || !desktopOverlays.rewrite.typeControlRemoved || desktopOverlays.rewrite.detectedType !== 'CNAME' || desktopOverlays.rewrite.wildcardNormalized !== '*.audit.example' || !desktopOverlays.rewrite.closed || !desktopOverlays.rewrite.bodyUnlocked || !desktopOverlays.rewrite.focusRestored) {
    throw new Error(`dns rewrite interaction mismatch: ${JSON.stringify(desktopOverlays.rewrite)}`);
  }
  if (!desktopOverlays.rewriteGlobal.visible || !desktopOverlays.rewriteGlobal.focused || desktopOverlays.rewriteGlobal.target !== !desktopOverlays.rewriteGlobal.original || !desktopOverlays.rewriteGlobal.switchRestoredBeforeConfirm || !desktopOverlays.rewriteGlobal.cancelRestored || !desktopOverlays.rewriteGlobal.applied || !desktopOverlays.rewriteGlobal.restored) {
    throw new Error(`dns rewrite global toggle mismatch: ${JSON.stringify(desktopOverlays.rewriteGlobal)}`);
  }
  if (!desktopOverlays.client.delayedLoad || !desktopOverlays.client.focusedBeforeLoad || !desktopOverlays.client.focusedAfterLoad || !desktopOverlays.client.openAfterLoad || !desktopOverlays.client.cacheControls.configured.effective || !desktopOverlays.client.closed || !desktopOverlays.client.routeIsolation.delayedLoad || desktopOverlays.client.routeIsolation.view !== 'dns' || desktopOverlays.client.routeIsolation.section !== 'general' || desktopOverlays.client.routeIsolation.title !== '常规设置' || !desktopOverlays.client.routeIsolation.description.includes('保护状态') || !desktopOverlays.client.routeIsolation.generalActive || !desktopOverlays.client.routeIsolation.clientsInactive) {
    throw new Error(`client route isolation mismatch: ${JSON.stringify(desktopOverlays.client)}`);
  }
  if (mobileRewrite.horizontalOverflow || !mobileRewrite.insideViewport || !mobileRewrite.typeControlRemoved || mobileRewrite.detectedType !== 'CNAME') {
    throw new Error(`dns rewrite mobile layout mismatch: ${JSON.stringify(mobileRewrite)}`);
  }
  if (desktopFilteringCheck.horizontalOverflow || !desktopFilteringCheck.insideViewport || desktopFilteringCheck.state !== desktopFilteringCheck.expectedState || !desktopFilteringCheck.hasExpectedEvidence || !desktopFilteringCheck.sourceLabelRendered || desktopFilteringCheck.ruleRows !== desktopFilteringCheck.expectedRuleRows || desktopFilteringCheck.rewriteRows !== desktopFilteringCheck.expectedRewriteRows || desktopFilteringCheck.typeOptions < 40 || !desktopFilteringCheck.busyVisible || !desktopFilteringCheck.busyRestored || !desktopFilteringCheck.recentUnchanged || !desktopFilteringCheck.statsUnchanged || !desktopFilteringCheck.editorParity.hostsHighlighted || !desktopFilteringCheck.editorParity.regexHighlighted || !desktopFilteringCheck.editorParity.hostsMetric || !desktopFilteringCheck.editorParity.regexMetric || !desktopFilteringCheck.editorParity.overviewMentionsTypes || desktopFilteringCheck.editorParity.examples < 8 || !desktopFilteringCheck.editorParity.hasExactExample || !desktopFilteringCheck.editorParity.hasMultiHostExample || !desktopFilteringCheck.editorParity.hasRegexExample) {
    throw new Error(`filtering check desktop mismatch: ${JSON.stringify(desktopFilteringCheck)}`);
  }
  if (mobileFilteringCheck.horizontalOverflow || !mobileFilteringCheck.panelInside || !mobileFilteringCheck.resultInside || mobileFilteringCheck.state !== desktopFilteringCheck.expectedState || mobileFilteringCheck.formColumns !== 1 || mobileFilteringCheck.ruleRows !== desktopFilteringCheck.expectedRuleRows || !mobileFilteringCheck.ruleRowsInside || mobileFilteringCheck.typeOptions < 40) {
    throw new Error(`filtering check mobile mismatch: ${JSON.stringify(mobileFilteringCheck)}`);
  }
  if (desktopBlockedServicesAutoUpdate.horizontalOverflow || !desktopBlockedServicesAutoUpdate.sectionInside || !desktopBlockedServicesAutoUpdate.controlInside || !desktopBlockedServicesAutoUpdate.controlsInside || !desktopBlockedServicesAutoUpdate.controlsSeparated || !desktopBlockedServicesAutoUpdate.toggleEnabled || !desktopBlockedServicesAutoUpdate.intervalDisabled || !desktopBlockedServicesAutoUpdate.manualUpdateEnabled || !desktopBlockedServicesAutoUpdate.autoDisabled || !desktopBlockedServicesAutoUpdate.metaText.includes('不会自动更新') || desktopBlockedServicesAutoUpdate.catalogRows < 1) {
    throw new Error(`blocked services auto update desktop mismatch: ${JSON.stringify(desktopBlockedServicesAutoUpdate)}`);
  }
  if (mobileBlockedServicesAutoUpdate.horizontalOverflow || !mobileBlockedServicesAutoUpdate.controlInside || !mobileBlockedServicesAutoUpdate.actionsInside || !mobileBlockedServicesAutoUpdate.controlsInside || !mobileBlockedServicesAutoUpdate.controlsSeparated || mobileBlockedServicesAutoUpdate.actionColumns !== 3 || !mobileBlockedServicesAutoUpdate.metaFits || !mobileBlockedServicesAutoUpdate.manualUpdateVisible || mobileBlockedServicesAutoUpdate.catalogRows < 1) {
    throw new Error(`blocked services auto update mobile mismatch: ${JSON.stringify(mobileBlockedServicesAutoUpdate)}`);
  }
  if (browserErrors.length) throw new Error(`browser errors: ${JSON.stringify(browserErrors)}`);
  if (desktopUpstreamRouting.horizontalOverflow || mobileUpstreamRouting.horizontalOverflow) throw new Error('upstream routing layout overflow');
  if (desktopUpstreamRouting.defaults !== 1 || desktopUpstreamRouting.routes !== 4 || desktopUpstreamRouting.comments !== 1 || desktopUpstreamRouting.targets !== 1) {
    throw new Error(`upstream routing summary mismatch: ${JSON.stringify(desktopUpstreamRouting)}`);
  }
  if (desktopUpstreamRouting.rowCount !== 5 || !desktopUpstreamRouting.modeMeta || !desktopUpstreamRouting.serversMeta.includes('1 个服务器') || !desktopUpstreamRouting.serversMeta.includes('4 条路由') || !desktopUpstreamRouting.fallbackMeta || !desktopUpstreamRouting.bootstrapMeta || !desktopUpstreamRouting.timeoutMeta.endsWith('ms')) {
    throw new Error(`upstream setting rows mismatch: ${JSON.stringify(desktopUpstreamRouting)}`);
  }
  if (!desktopUpstreamRouting.modeDialog.visible || desktopUpstreamRouting.modeDialog.title !== '上游查询模式' || !desktopUpstreamRouting.modeDialog.focused || desktopUpstreamRouting.modeDialog.options !== 3 || !desktopUpstreamRouting.modeDialog.keyboardChanged || !desktopUpstreamRouting.modeDialog.canceled || !desktopUpstreamRouting.modeDialog.focusRestored) {
    throw new Error(`upstream mode dialog mismatch: ${JSON.stringify(desktopUpstreamRouting.modeDialog)}`);
  }
  if (!desktopUpstreamRouting.serverDialog.visible || desktopUpstreamRouting.serverDialog.title !== '上游 DNS 服务器' || !desktopUpstreamRouting.serverDialog.focused || !desktopUpstreamRouting.serverDialog.dirtyBeforeCancel || !desktopUpstreamRouting.serverDialog.cancelRestored || !desktopUpstreamRouting.serverDialog.cancelClosed || !desktopUpstreamRouting.serverDialog.focusRestored || !desktopUpstreamRouting.serverDialog.applyClosed || !desktopUpstreamRouting.serverDialog.applyDirty || !desktopUpstreamRouting.serverDialog.payloadMatches) {
    throw new Error(`upstream server dialog interaction mismatch: ${JSON.stringify(desktopUpstreamRouting.serverDialog)}`);
  }
  if (!desktopUpstreamDialog.visible || desktopUpstreamDialog.title !== '上游 DNS 服务器' || !desktopUpstreamDialog.focused || !desktopUpstreamDialog.insideViewport || !desktopUpstreamDialog.textareaInside || desktopUpstreamDialog.syntaxExamples !== 5 || !desktopUpstreamDialog.doqExample) {
    throw new Error(`upstream desktop dialog layout mismatch: ${JSON.stringify(desktopUpstreamDialog)}`);
  }
  if (desktopUpstreamRouting.doqLabel !== 'DoQ' || desktopUpstreamRouting.doqAliasLabel !== 'DoQ' || !desktopUpstreamRouting.doqSummary.includes('DoQ')) {
    throw new Error(`DoQ upstream presentation mismatch: ${JSON.stringify(desktopUpstreamRouting)}`);
  }
  if (desktopUpstreamRouting.selectedRoute !== '[/*.example.com/]' || desktopUpstreamRouting.testRows !== 2 || desktopUpstreamRouting.privateTestRows !== 1 || !desktopUpstreamRouting.selectedUpstreams.length || !desktopUpstreamRouting.testFoldOpenedByRun || desktopUpstreamRouting.toastCount < 1) {
    throw new Error(`upstream routing test mismatch: ${JSON.stringify(desktopUpstreamRouting)}`);
  }
  if (desktopUpstreamRouting.previewEntries !== 80 || desktopUpstreamRouting.previewEntryCount !== 121) {
    throw new Error(`upstream preview limit mismatch: ${JSON.stringify(desktopUpstreamRouting)}`);
  }
  if (mobileUpstreamRouting.horizontalOverflow || mobileUpstreamRouting.moduleWidth > 390 || mobileUpstreamRouting.rowCount !== 5 || mobileUpstreamRouting.rowColumns !== 2 || !mobileUpstreamRouting.metaVisible || !mobileUpstreamRouting.arrowVisible || mobileUpstreamRouting.selectedRoute !== '[/*.example.com/]' || mobileUpstreamRouting.privateTestRows !== 1) {
    throw new Error(`upstream mobile setting rows mismatch: ${JSON.stringify(mobileUpstreamRouting)}`);
  }
  if (!mobileUpstreamDialog.visible || !mobileUpstreamDialog.focused || !mobileUpstreamDialog.insideViewport || mobileUpstreamDialog.horizontalOverflow || !mobileUpstreamDialog.textareaInside || mobileUpstreamDialog.textareaWidth <= 0 || mobileUpstreamDialog.textareaWidth > mobileUpstreamDialog.modalWidth) {
    throw new Error(`upstream mobile dialog layout mismatch: ${JSON.stringify(mobileUpstreamDialog)}`);
  }
  if (!desktopCacheInteraction.initial || !desktopCacheInteraction.cancelOpened.visible || !desktopCacheInteraction.cancelOpened.focused || !desktopCacheInteraction.cancelOpened.dirty || !desktopCacheInteraction.canceled.restored || !desktopCacheInteraction.canceled.closed || !desktopCacheInteraction.canceled.focusRestored || desktopCacheInteraction.canceled.dirty || !desktopCacheInteraction.applied.dirty || !desktopCacheInteraction.applied.closed || Number(desktopCacheInteraction.applied.value) !== desktopCacheInteraction.applied.payloadValue || (desktopCacheInteraction.rangeValidation.applicable && (!desktopCacheInteraction.rangeValidation.prevented || !desktopCacheInteraction.rangeValidation.restored)) || desktopCacheInteraction.changed.enabled || !desktopCacheInteraction.changed.dirty || !desktopCacheInteraction.changed.modernToggle || !desktopCacheInteraction.changed.toggleInside || !desktopCacheInteraction.changed.headerStateAbsent || !desktopCacheInteraction.changed.sizePreserved || !desktopCacheInteraction.changed.optimisticDisabled || !desktopCacheInteraction.changed.linksDisabled || desktopCacheInteraction.changed.payloadEnabled || !desktopCacheInteraction.optimisticChanged.modernToggle || desktopCacheInteraction.optimisticChanged.answerTtlDisabled === desktopCacheInteraction.optimisticChanged.enabled || desktopCacheInteraction.optimisticChanged.maxAgeDisabled === desktopCacheInteraction.optimisticChanged.enabled || !desktopCacheInteraction.optimisticChanged.valuesPreserved || desktopCacheInteraction.optimisticChanged.payloadEnabled !== desktopCacheInteraction.optimisticChanged.enabled || !desktopCacheInteraction.clearConfirm.visible || !desktopCacheInteraction.clearConfirm.focused || !desktopCacheInteraction.clearConfirm.closed || !desktopCacheInteraction.clearConfirm.focusRestored || !desktopCacheInteraction.restored) {
    throw new Error(`dns cache interaction mismatch: ${JSON.stringify(desktopCacheInteraction)}`);
  }
  if (!desktopCacheDialog.visible || desktopCacheDialog.title !== '高级缓存参数' || !desktopCacheDialog.focused || !desktopCacheDialog.insideViewport || desktopCacheDialog.fields !== 3 || !desktopCacheConfirm.visible || !desktopCacheConfirm.focused || !desktopCacheConfirm.insideViewport) {
    throw new Error(`dns cache desktop dialog mismatch: ${JSON.stringify({ desktopCacheDialog, desktopCacheConfirm })}`);
  }
  if (mobileDnsCache.horizontalOverflow || mobileDnsCache.moduleWidth > 390 || !mobileDnsCache.modernToggle || !mobileDnsCache.modernOptimisticToggle || !mobileDnsCache.toggleInside || !mobileDnsCache.headerStateAbsent || !mobileDnsCache.capacityText || !mobileDnsCache.capacityMetaVisible || !mobileDnsCache.capacityMetaInside || mobileDnsCache.capacityArrowDisplay === 'none' || !mobileDnsCache.capacityArrowInside || mobileDnsCache.modalWidth > 390 || !mobileDnsCache.insideViewport || !mobileDnsCache.focused || mobileDnsCache.fieldWidths.length !== 3 || mobileDnsCache.fieldWidths.some((width) => width <= 0 || width > mobileDnsCache.modalWidth) || mobileDnsCache.answerDisabled !== !desktopCacheInteraction.initialOptimistic || mobileDnsCache.maxAgeDisabled !== !desktopCacheInteraction.initialOptimistic) {
    throw new Error(`dns cache mobile dialog mismatch: ${JSON.stringify(mobileDnsCache)}`);
  }
  if (desktopDnssecInteraction.changed.enabled === desktopDnssecInteraction.initial || desktopDnssecInteraction.changed.payloadEnabled !== desktopDnssecInteraction.changed.enabled || !desktopDnssecInteraction.changed.dirty || !desktopDnssecInteraction.changed.upstreamSignatureChanged || !desktopDnssecInteraction.changed.rowsText.includes('DNSSEC') || !desktopDnssecInteraction.restored) {
    throw new Error(`dnssec settings interaction mismatch: ${JSON.stringify(desktopDnssecInteraction)}`);
  }
  if (desktopRefuseAnyInteraction.changed.enabled === desktopRefuseAnyInteraction.initial || desktopRefuseAnyInteraction.changed.payloadEnabled !== desktopRefuseAnyInteraction.changed.enabled || !desktopRefuseAnyInteraction.changed.dirty || !desktopRefuseAnyInteraction.changed.rowsText.includes('拒绝 ANY 查询') || !desktopRefuseAnyInteraction.restored) {
    throw new Error(`refuse ANY settings interaction mismatch: ${JSON.stringify(desktopRefuseAnyInteraction)}`);
  }
  if (desktopDnsServiceInteraction.cnameChanged.enabled === desktopDnsServiceInteraction.initial.cname || desktopDnsServiceInteraction.cnameChanged.payloadEnabled !== desktopDnsServiceInteraction.cnameChanged.enabled || !desktopDnsServiceInteraction.cnameChanged.dirty || desktopDnsServiceInteraction.ipv6Changed.enabled === desktopDnsServiceInteraction.initial.ipv6Enabled || desktopDnsServiceInteraction.ipv6Changed.payloadDisableIpv6 !== !desktopDnsServiceInteraction.ipv6Changed.enabled || !desktopDnsServiceInteraction.ipv6Changed.dirty || desktopDnsServiceInteraction.rowCount !== 9 || !desktopDnsServiceInteraction.rateMeta || !desktopDnsServiceInteraction.allowlistMeta || !desktopDnsServiceInteraction.subnetIpv4Meta.startsWith('/') || !desktopDnsServiceInteraction.subnetIpv6Meta.startsWith('/') || !desktopDnsServiceInteraction.blockingMeta.includes('TTL') || !desktopDnsServiceInteraction.restored) {
    throw new Error(`dns service setting rows mismatch: ${JSON.stringify(desktopDnsServiceInteraction)}`);
  }
  if (!desktopDnsServiceInteraction.rateDialog.visible || desktopDnsServiceInteraction.rateDialog.title !== 'DNS 请求速率限制' || !desktopDnsServiceInteraction.rateDialog.focused || !desktopDnsServiceInteraction.rateDialog.dirtyBeforeCancel || !desktopDnsServiceInteraction.rateDialog.cancelRestored || !desktopDnsServiceInteraction.rateDialog.focusRestored || !desktopDnsServiceInteraction.rateDialog.applyClosed || !desktopDnsServiceInteraction.rateDialog.applyDirty || !desktopDnsServiceInteraction.rateDialog.payloadMatches) {
    throw new Error(`dns rate limit dialog mismatch: ${JSON.stringify(desktopDnsServiceInteraction.rateDialog)}`);
  }
  if (!desktopDnsServiceInteraction.blockingDialog.visible || desktopDnsServiceInteraction.blockingDialog.title !== 'DNS 拦截响应模式' || !desktopDnsServiceInteraction.blockingDialog.focused || desktopDnsServiceInteraction.blockingDialog.options !== 6 || JSON.stringify(desktopDnsServiceInteraction.blockingDialog.modeValues) !== JSON.stringify(['default', 'refused', 'nxdomain', 'null', 'custom', 'nodata']) || desktopDnsServiceInteraction.blockingDialog.addressInitiallyVisible !== (desktopDnsServiceInteraction.initial.mode === 'custom') || !desktopDnsServiceInteraction.blockingDialog.keyboardChanged || !desktopDnsServiceInteraction.blockingDialog.addressVisibilityChanged || !desktopDnsServiceInteraction.blockingDialog.customMode?.fieldsVisible || !desktopDnsServiceInteraction.blockingDialog.customMode?.inputsEnabled || !desktopDnsServiceInteraction.blockingDialog.customMode?.invalidPrevented || !desktopDnsServiceInteraction.blockingDialog.cancelRestored || !desktopDnsServiceInteraction.blockingDialog.focusRestored || !desktopDnsServiceInteraction.blockingDialog.applyClosed || !desktopDnsServiceInteraction.blockingDialog.applyDirty || !desktopDnsServiceInteraction.blockingDialog.payloadMatches || !desktopDnsServiceInteraction.blockingDialog.appliedMeta.includes('NXDOMAIN') || !desktopDnsServiceInteraction.blockingDialog.appliedMeta.includes('TTL')) {
    throw new Error(`dns blocking mode dialog mismatch: ${JSON.stringify(desktopDnsServiceInteraction.blockingDialog)}`);
  }
  if (!desktopDnsServiceDialog.visible || !desktopDnsServiceDialog.focused || !desktopDnsServiceDialog.insideViewport || desktopDnsServiceDialog.optionCount !== 6 || !desktopDnsServiceDialog.ttlEnabled) {
    throw new Error(`dns service desktop dialog layout mismatch: ${JSON.stringify(desktopDnsServiceDialog)}`);
  }
  if (desktopEcsInteraction.toggleChanged.enabled === desktopEcsInteraction.initial.enabled || desktopEcsInteraction.toggleChanged.payloadEnabled !== desktopEcsInteraction.toggleChanged.enabled || !desktopEcsInteraction.toggleChanged.dirty || desktopEcsInteraction.rowCount !== 1 || desktopEcsInteraction.role !== 'button' || desktopEcsInteraction.rowColumns !== 3 || !desktopEcsInteraction.toggleInside || !desktopEcsInteraction.meta.includes('IPv4 /') || !desktopEcsInteraction.meta.includes('IPv6 /') || !desktopEcsInteraction.oldSummaryAbsent || !desktopEcsInteraction.restored) {
    throw new Error(`ecs switch-link row mismatch: ${JSON.stringify(desktopEcsInteraction)}`);
  }
  if (!desktopEcsInteraction.dialog.visible || desktopEcsInteraction.dialog.title !== 'EDNS Client Subnet' || !desktopEcsInteraction.dialog.focused || !desktopEcsInteraction.dialog.dirtyBeforeCancel || !desktopEcsInteraction.dialog.cancelRestored || !desktopEcsInteraction.dialog.focusRestored || !desktopEcsInteraction.dialog.invalidPrevented || !desktopEcsInteraction.dialog.applyClosed || !desktopEcsInteraction.dialog.applyDirty || !desktopEcsInteraction.dialog.payloadMatches || !desktopEcsInteraction.dialog.appliedMeta.includes('回退')) {
    throw new Error(`ecs dialog interaction mismatch: ${JSON.stringify(desktopEcsInteraction.dialog)}`);
  }
  if (!desktopEcsDialog.visible || !desktopEcsDialog.focused || !desktopEcsDialog.insideViewport || desktopEcsDialog.fields !== 3 || !desktopEcsDialog.fieldsInside) {
    throw new Error(`ecs desktop dialog layout mismatch: ${JSON.stringify(desktopEcsDialog)}`);
  }
  if (desktopAccessInteraction.rowCount !== 3 || !desktopAccessInteraction.rowsText.includes('允许客户端') || !desktopAccessInteraction.rowsText.includes('拒绝客户端') || !desktopAccessInteraction.rowsText.includes('阻止主机名') || !desktopAccessInteraction.oldSummaryAbsent || !desktopAccessInteraction.oldEditorAbsent || !desktopAccessInteraction.blockedEnabledWithoutAllow || !desktopAccessInteraction.restored) {
    throw new Error(`access setting rows mismatch: ${JSON.stringify(desktopAccessInteraction)}`);
  }
  if (!desktopAccessInteraction.allowedDialog.visible || desktopAccessInteraction.allowedDialog.title !== '允许客户端' || !desktopAccessInteraction.allowedDialog.focused || !desktopAccessInteraction.allowedDialog.dirtyBeforeCancel || !desktopAccessInteraction.allowedDialog.duplicateHint || !desktopAccessInteraction.allowedDialog.cancelRestored || !desktopAccessInteraction.allowedDialog.focusRestored || !desktopAccessInteraction.allowedDialog.invalidPrevented || !desktopAccessInteraction.allowedDialog.applyClosed || !desktopAccessInteraction.allowedDialog.applyDirty || !desktopAccessInteraction.allowedDialog.payloadMatches || !desktopAccessInteraction.allowedDialog.appliedMeta.includes('2 条规则') || !desktopAccessInteraction.allowedDialog.blockedDisabled) {
    throw new Error(`allowed clients dialog mismatch: ${JSON.stringify(desktopAccessInteraction.allowedDialog)}`);
  }
  if (!desktopAccessInteraction.blockedDialog.visible || desktopAccessInteraction.blockedDialog.title !== '拒绝客户端' || !desktopAccessInteraction.blockedDialog.focused || !desktopAccessInteraction.blockedDialog.focusRestored) {
    throw new Error(`blocked clients dialog mismatch: ${JSON.stringify(desktopAccessInteraction.blockedDialog)}`);
  }
  if (!desktopAccessInteraction.hostsDialog.invalidPrevented || !desktopAccessInteraction.hostsDialog.applyClosed || !desktopAccessInteraction.hostsDialog.applyDirty || !desktopAccessInteraction.hostsDialog.payloadMatches || !desktopAccessInteraction.hostsDialog.appliedMeta.includes('1 条规则')) {
    throw new Error(`blocked hosts dialog mismatch: ${JSON.stringify(desktopAccessInteraction.hostsDialog)}`);
  }
  if (!desktopAccessDialog.visible || !desktopAccessDialog.focused || !desktopAccessDialog.insideViewport || !desktopAccessDialog.textareaInside || desktopAccessDialog.hintItems < 3) {
    throw new Error(`access desktop dialog layout mismatch: ${JSON.stringify(desktopAccessDialog)}`);
  }
  if (desktopRefuseAnyTest.horizontalOverflow || desktopRefuseAnyTest.selectedType !== 'ANY' || desktopRefuseAnyTest.stateText !== '已拒绝' || !desktopRefuseAnyTest.decisionText.includes('REFUSED') || !desktopRefuseAnyTest.decisionText.includes('ANY') || !desktopRefuseAnyTest.decisionText.includes('拒绝 ANY') || !desktopRefuseAnyTest.summaryText.includes('0 答案数')) {
    throw new Error(`refuse ANY DNS test mismatch: ${JSON.stringify(desktopRefuseAnyTest)}`);
  }
  if (desktopClientReverseDns.clientChanged.enabled === desktopClientReverseDns.initial.clientEnabled || desktopClientReverseDns.clientChanged.payloadEnabled !== desktopClientReverseDns.clientChanged.enabled || !desktopClientReverseDns.clientChanged.dirty || !desktopClientReverseDns.clientChanged.rowsText.includes('解析客户端主机名') || !desktopClientReverseDns.clientChanged.rowsText.includes('WHOIS 客户端信息') || !desktopClientReverseDns.clientChanged.rowsText.includes('系统 Hosts') || !desktopClientReverseDns.clientChanged.rowsText.includes('ARP 邻居') || desktopClientReverseDns.whoisChanged.enabled === desktopClientReverseDns.initial.whoisEnabled || desktopClientReverseDns.whoisChanged.payloadEnabled !== desktopClientReverseDns.whoisChanged.enabled || !desktopClientReverseDns.whoisChanged.dirty || desktopClientReverseDns.hostsChanged.enabled === desktopClientReverseDns.initial.hostsEnabled || desktopClientReverseDns.hostsChanged.payloadEnabled !== desktopClientReverseDns.hostsChanged.enabled || !desktopClientReverseDns.hostsChanged.dirty || desktopClientReverseDns.privateChanged.enabled === desktopClientReverseDns.initial.privateEnabled || desktopClientReverseDns.privateChanged.payloadEnabled !== desktopClientReverseDns.privateChanged.enabled || !desktopClientReverseDns.privateChanged.dirty || desktopClientReverseDns.rowCount !== 7 || !desktopClientReverseDns.sourceControlsVisible || !desktopClientReverseDns.sourcePayloadMatches || !desktopClientReverseDns.restored) {
    throw new Error(`client reverse dns interaction mismatch: ${JSON.stringify(desktopClientReverseDns)}`);
  }
  if (!desktopClientReverseDns.dialog.visible || desktopClientReverseDns.dialog.title !== '私有反向 DNS 服务器' || !desktopClientReverseDns.dialog.focused || !desktopClientReverseDns.dialog.dirtyBeforeCancel || !desktopClientReverseDns.dialog.cancelRestored || !desktopClientReverseDns.dialog.cancelClosed || !desktopClientReverseDns.dialog.focusRestored || !desktopClientReverseDns.dialog.applyClosed || !desktopClientReverseDns.dialog.applyDirty || !desktopClientReverseDns.dialog.payloadMatches || desktopClientReverseDns.dialog.appliedMeta !== '2 个服务器 · 1 条路由') {
    throw new Error(`private reverse dialog interaction mismatch: ${JSON.stringify(desktopClientReverseDns.dialog)}`);
  }
  if (!desktopPrivateReverseDialog.visible || !desktopPrivateReverseDialog.focused || !desktopPrivateReverseDialog.insideViewport || !desktopPrivateReverseDialog.textareaInside || desktopPrivateReverseDialog.syntaxExamples !== 4) {
    throw new Error(`private reverse desktop dialog layout mismatch: ${JSON.stringify(desktopPrivateReverseDialog)}`);
  }
  if (mobileDnssec.horizontalOverflow || !mobileDnssec.visible || !mobileDnssec.ipv6Visible || mobileDnssec.rowWidth > mobileDnssec.moduleWidth + 1 || mobileDnssec.rowCount !== 9 || mobileDnssec.rateColumns !== 2 || !mobileDnssec.rateMetaVisible || !mobileDnssec.rateArrowVisible) {
    throw new Error(`dnssec mobile layout mismatch: ${JSON.stringify(mobileDnssec)}`);
  }
  if (mobileRefuseAny.horizontalOverflow || !mobileRefuseAny.visible || mobileRefuseAny.checked !== desktopRefuseAnyInteraction.initial || mobileRefuseAny.rowWidth > mobileRefuseAny.moduleWidth + 1) {
    throw new Error(`refuse ANY mobile layout mismatch: ${JSON.stringify(mobileRefuseAny)}`);
  }
  if (!mobileDnsServiceDialog.visible || !mobileDnsServiceDialog.focused || !mobileDnsServiceDialog.insideViewport || mobileDnsServiceDialog.horizontalOverflow || mobileDnsServiceDialog.modalWidth > 390 || !mobileDnsServiceDialog.bodyInside || mobileDnsServiceDialog.optionCount !== 6 || !mobileDnsServiceDialog.ttlEnabled) {
    throw new Error(`dns service mobile dialog layout mismatch: ${JSON.stringify(mobileDnsServiceDialog)}`);
  }
  if (mobileEcs.horizontalOverflow || mobileEcs.moduleWidth > 390 || mobileEcs.rowWidth > mobileEcs.moduleWidth + 1 || mobileEcs.rowColumns !== 2 || !mobileEcs.metaVisible || !mobileEcs.metaInside || !mobileEcs.toggleVisible || !mobileEcs.toggleInside || !mobileEcs.oldSummaryAbsent) {
    throw new Error(`ecs mobile switch-link layout mismatch: ${JSON.stringify(mobileEcs)}`);
  }
  if (!mobileEcsDialog.visible || !mobileEcsDialog.focused || !mobileEcsDialog.insideViewport || mobileEcsDialog.horizontalOverflow || mobileEcsDialog.modalWidth > 390 || !mobileEcsDialog.bodyInside || mobileEcsDialog.fieldWidths.length !== 3 || mobileEcsDialog.fieldWidths.some((width) => width <= 0 || width > mobileEcsDialog.modalWidth)) {
    throw new Error(`ecs mobile dialog layout mismatch: ${JSON.stringify(mobileEcsDialog)}`);
  }
  if (mobileAccess.horizontalOverflow || mobileAccess.moduleWidth > 390 || mobileAccess.rowWidth > mobileAccess.moduleWidth + 1 || mobileAccess.rowCount !== 3 || mobileAccess.rowColumns !== 2 || !mobileAccess.metaVisible || !mobileAccess.metaInside || !mobileAccess.arrowVisible || !mobileAccess.oldEditorAbsent) {
    throw new Error(`access mobile setting rows mismatch: ${JSON.stringify(mobileAccess)}`);
  }
  if (!mobileAccessDialog.visible || !mobileAccessDialog.focused || !mobileAccessDialog.insideViewport || mobileAccessDialog.horizontalOverflow || mobileAccessDialog.modalWidth > 390 || !mobileAccessDialog.bodyInside || !mobileAccessDialog.textareaInside || mobileAccessDialog.textareaWidth <= 0 || mobileAccessDialog.textareaWidth > mobileAccessDialog.modalWidth || mobileAccessDialog.hintItems < 3) {
    throw new Error(`access mobile dialog layout mismatch: ${JSON.stringify(mobileAccessDialog)}`);
  }
  if (mobileClientReverseDns.horizontalOverflow || !mobileClientReverseDns.visible || mobileClientReverseDns.rowWidth > mobileClientReverseDns.moduleWidth + 1 || mobileClientReverseDns.rowCount !== 7 || !mobileClientReverseDns.sourceSwitchesVisible || !mobileClientReverseDns.sourceSwitchesInside || mobileClientReverseDns.rowColumns !== 2 || !mobileClientReverseDns.metaVisible || !mobileClientReverseDns.arrowVisible) {
    throw new Error(`client reverse dns mobile layout mismatch: ${JSON.stringify(mobileClientReverseDns)}`);
  }
  if (!mobilePrivateReverseDialog.visible || !mobilePrivateReverseDialog.focused || !mobilePrivateReverseDialog.insideViewport || mobilePrivateReverseDialog.horizontalOverflow || !mobilePrivateReverseDialog.textareaInside || mobilePrivateReverseDialog.textareaWidth <= 0 || mobilePrivateReverseDialog.textareaWidth > mobilePrivateReverseDialog.modalWidth) {
    throw new Error(`private reverse mobile dialog layout mismatch: ${JSON.stringify(mobilePrivateReverseDialog)}`);
  }
  if (desktopDhcp.horizontalOverflow || mobileDhcp.horizontalOverflow || !desktopDhcp.enableDisabled || !mobileDhcp.enableDisabled || !desktopDhcp.dnsInputInsideField || !mobileDhcp.dnsInputInsideField || desktopDhcp.dnsInputWidth <= 0 || mobileDhcp.dnsInputWidth <= 0 || desktopDhcp.dnsInputHeight < 66 || mobileDhcp.dnsInputHeight < 66) {
    throw new Error(`dhcp layout or runtime guard mismatch: ${JSON.stringify({ desktopDhcp, mobileDhcp })}`);
  }
  if (desktopDhcp.supported || desktopDhcp.running || desktopDhcp.validationErrors < 1 || !desktopDhcp.modalFocused || !desktopDhcp.modalClosed) {
    throw new Error(`dhcp status interaction mismatch: ${JSON.stringify(desktopDhcp)}`);
  }
  if (desktopClientsPersistent.horizontalOverflow || desktopClientsPersistent.sectionWidth > 1332 || desktopClientsPersistent.tabs !== 2 || desktopClientsPersistent.activeTab !== 'persistent' || desktopClientsPersistent.visiblePanels !== 1 || !desktopClientsPersistent.keyboardSwitched || desktopClientsPersistent.headerCells !== 8 || desktopClientsPersistent.rowCount !== Math.max(1, desktopClientsPersistent.clientCount) || !desktopClientsPersistent.editorHidden || !desktopClientsPersistent.saveDisabled || !desktopClientsPersistent.actionsInside || (desktopClientsPersistent.clientCount > 0 && desktopClientsPersistent.compactSettings < desktopClientsPersistent.clientCount * 2)) {
    throw new Error(`persistent clients desktop layout mismatch: ${JSON.stringify(desktopClientsPersistent)}`);
  }
  if (directApi && desktopClientsPersistent.clientCount < 2) {
    throw new Error(`persistent client fixtures missing: ${JSON.stringify(desktopClientsPersistent)}`);
  }
  if (desktopClientDeleteDialog.available && (!desktopClientDeleteDialog.visible || !desktopClientDeleteDialog.focused || desktopClientDeleteDialog.title !== '删除客户端' || !desktopClientDeleteDialog.question.includes('确定删除') || !desktopClientDeleteDialog.insideViewport || !desktopClientDeleteDialog.closed || !desktopClientDeleteDialog.countPreserved || !desktopClientDeleteDialog.dirtyPreserved || !desktopClientDeleteDialog.focusRestored)) {
    throw new Error(`client delete confirmation mismatch: ${JSON.stringify(desktopClientDeleteDialog)}`);
  }
  if (directApi && !desktopClientDeleteDialog.available) {
    throw new Error(`client delete confirmation unavailable: ${JSON.stringify(desktopClientDeleteDialog)}`);
  }
  if (mobileClientsPersistent.horizontalOverflow || mobileClientsPersistent.sectionWidth > 390 || mobileClientsPersistent.tabWidth > mobileClientsPersistent.sectionWidth || !mobileClientsPersistent.tabsInside || mobileClientsPersistent.activeTab !== 'persistent' || mobileClientsPersistent.visiblePanels !== 1 || mobileClientsPersistent.rows !== Math.max(1, mobileClientsPersistent.clientCount) || !mobileClientsPersistent.rowsInside || !mobileClientsPersistent.tableHeaderHidden || !mobileClientsPersistent.addButtonInside) {
    throw new Error(`persistent clients mobile layout mismatch: ${JSON.stringify(mobileClientsPersistent)}`);
  }
  if (desktopClientCache.horizontalOverflow || desktopClientCache.width > 920 || desktopClientCache.stateText !== '1 MiB 上限' || desktopClientCache.sizeDisabled || !desktopClientCache.mainTabsHidden || desktopClientCache.pageTitle !== '添加客户端' || desktopClientCache.editorTitle !== '客户端配置' || desktopClientCache.actionsPosition !== 'static' || !desktopClientCache.actionsAfterInput) {
    throw new Error(`client editor desktop layout mismatch: ${JSON.stringify(desktopClientCache)}`);
  }
  if (mobileClientCache.horizontalOverflow || mobileClientCache.width > 390 || mobileClientCache.stateText !== '1 MiB 上限' || mobileClientCache.sizeDisabled || !mobileClientCache.mainTabsHidden || mobileClientCache.pageTitle !== '添加客户端' || mobileClientCache.editorTitle !== '客户端配置' || mobileClientCache.actionsPosition !== 'static' || !mobileClientCache.actionsAfterInput) {
    throw new Error(`client editor mobile layout mismatch: ${JSON.stringify(mobileClientCache)}`);
  }
  if (desktopRuntimeClients.horizontalOverflow || desktopRuntimeClients.runtimeCount < 2 || desktopRuntimeClients.rowCount < 2 || desktopRuntimeClients.headerCells !== 7 || !desktopRuntimeClients.rawHostAddresses || !desktopRuntimeClients.sourceText || !desktopRuntimeClients.sourceTexts.some((value) => value.includes('系统 Hosts')) || !desktopRuntimeClients.sourceTexts.some((value) => value.includes('ARP 邻居')) || desktopRuntimeClients.requests < 1 || !desktopRuntimeClients.clientsDirtyPreserved || desktopRuntimeClients.activeTab !== 'runtime' || desktopRuntimeClients.visiblePanels !== 1) {
    throw new Error(`runtime clients interaction mismatch: ${JSON.stringify(desktopRuntimeClients)}`);
  }
  if (directApi && (!desktopRuntimeClients.queryLogAnonymized || !desktopRuntimeClients.anonymizedRecent || !desktopRuntimeClients.addAvailable || !desktopRuntimeClients.editorOpened || !desktopRuntimeClients.prefillMatchesAddress)) {
    throw new Error(`runtime clients anonymization mismatch: ${JSON.stringify(desktopRuntimeClients)}`);
  }
  if (mobileRuntimeClients.horizontalOverflow || mobileRuntimeClients.runtimeCount < 2 || mobileRuntimeClients.moduleWidth > 390 || mobileRuntimeClients.rowWidth > mobileRuntimeClients.moduleWidth || mobileRuntimeClients.rowColumns !== 2 || !mobileRuntimeClients.expanded || !mobileRuntimeClients.sourceVisible || !mobileRuntimeClients.sourceText || !mobileRuntimeClients.sourceTexts.some((value) => value.includes('系统 Hosts')) || !mobileRuntimeClients.sourceTexts.some((value) => value.includes('ARP 邻居')) || !mobileRuntimeClients.activityVisible || !mobileRuntimeClients.actionInside || mobileRuntimeClients.activeTab !== 'runtime' || mobileRuntimeClients.visiblePanels !== 1) {
    throw new Error(`runtime clients mobile layout mismatch: ${JSON.stringify(mobileRuntimeClients)}`);
  }
  if (desktopDhcpRuntimeClient.horizontalOverflow || !desktopDhcpRuntimeClient.rowVisible || !desktopDhcpRuntimeClient.sourceInside || !desktopDhcpRuntimeClient.whoisInside || desktopDhcpRuntimeClient.name !== 'phone.lan' || !desktopDhcpRuntimeClient.sourceText.includes('DHCP 租约') || !desktopDhcpRuntimeClient.sourceText.includes('动态租约') || !desktopDhcpRuntimeClient.sourceText.includes('00:11:22:33:44:55') || !desktopDhcpRuntimeClient.whoisText.includes('CleanDNS Audit Network') || !desktopDhcpRuntimeClient.whoisText.includes('Shanghai, CN') || desktopDhcpRuntimeClient.prefill.name !== 'phone.lan' || desktopDhcpRuntimeClient.prefill.tags !== 'DHCP, 运行时客户端' || !desktopDhcpRuntimeClient.prefill.note.includes('动态租约')) {
    throw new Error(`dhcp runtime client desktop mismatch: ${JSON.stringify(desktopDhcpRuntimeClient)}`);
  }
  if (mobileDhcpRuntimeClient.horizontalOverflow || mobileDhcpRuntimeClient.rowWidth > 390 || !mobileDhcpRuntimeClient.sourceVisible || !mobileDhcpRuntimeClient.sourceInside || !mobileDhcpRuntimeClient.sourceText.includes('DHCP 租约') || !mobileDhcpRuntimeClient.sourceText.includes('动态租约') || !mobileDhcpRuntimeClient.whoisVisible || !mobileDhcpRuntimeClient.whoisInside || !mobileDhcpRuntimeClient.whoisText.includes('CleanDNS Audit Network') || !mobileDhcpRuntimeClient.whoisText.includes('Shanghai, CN')) {
    throw new Error(`dhcp runtime client mobile mismatch: ${JSON.stringify(mobileDhcpRuntimeClient)}`);
  }
  const tlsPresentationValid = desktopTls.status === 'valid'
    ? desktopTls.stateText === '有效' && desktopTls.bannerClass.includes('ok')
    : desktopTls.status === 'warning' && desktopTls.stateText === '需要关注' && desktopTls.bannerClass.includes('warn') && desktopTls.bannerText.includes('到期');
  if (desktopTls.horizontalOverflow || !tlsPresentationValid || !desktopTls.validCert || !desktopTls.validKey || !desktopTls.validChain || !desktopTls.validPair || !desktopTls.validHost || desktopTls.summaryItems !== 4 || desktopTls.detailRows !== 8 || desktopTls.detailColumns !== 2 || !desktopTls.validateRestored || !(desktopTls.validateNotice + desktopTls.validateToast).includes('重新验证') || !desktopTls.downloadEnabled || !desktopTls.noPrivateKeyMaterial || !desktopTls.doqRuntime.matches || !desktopTls.doqRuntime.pidVisible) {
    throw new Error(`tls certificate interaction mismatch: ${JSON.stringify(desktopTls)}`);
  }
  if (desktopTls.profile.status !== 200 || !desktopTls.profile.contentType.includes('application/x-apple-aspen-config') || !desktopTls.profile.disposition.includes('CleanDNS-DoH.mobileconfig') || !desktopTls.profile.hasDohUrl || !desktopTls.profile.hasDnsPayload || desktopTls.profile.bytes < 500) {
    throw new Error(`doh mobile profile mismatch: ${JSON.stringify(desktopTls.profile)}`);
  }
  if (!desktopEncryptionDialogs.menu.visible || !desktopEncryptionDialogs.menu.expanded || desktopEncryptionDialogs.menu.items !== 3 || desktopEncryptionDialogs.menu.width < 180 || desktopEncryptionDialogs.menu.height < 100 || !desktopEncryptionDialogs.menu.insideViewport || !desktopEncryptionDialogs.outsideClose || !desktopEncryptionDialogs.tls.visible || !desktopEncryptionDialogs.tls.insideViewport || !desktopEncryptionDialogs.tls.focused || !desktopEncryptionDialogs.tls.certificateMatches || !desktopEncryptionDialogs.tls.privateKeyMatches || !desktopEncryptionDialogs.tls.source.includes('服务器文件路径') || !desktopEncryptionDialogs.tlsEscape.closed || !desktopEncryptionDialogs.tlsEscape.focusRestored || !desktopEncryptionDialogs.reset.visible || !desktopEncryptionDialogs.reset.insideViewport || desktopEncryptionDialogs.reset.rows !== 4 || !desktopEncryptionDialogs.reset.confirmEnabled || !desktopEncryptionDialogs.reset.preserveText.includes('隐藏 DoH 路径') || !desktopEncryptionDialogs.reset.unchangedBeforeConfirm || !desktopEncryptionDialogs.resetClosed) {
    throw new Error(`desktop encryption dialogs mismatch: ${JSON.stringify(desktopEncryptionDialogs)}`);
  }
  if (mobileTls.horizontalOverflow || mobileTls.moduleWidth > 390 || mobileTls.detailWidth > mobileTls.moduleWidth || mobileTls.detailColumns !== 1 || mobileTls.rowColumns.some((columns) => columns !== 1) || mobileTls.actionDirection !== 'column' || mobileTls.buttonWidths.length !== 3 || Math.max(...mobileTls.buttonWidths) - Math.min(...mobileTls.buttonWidths) > 1 || mobileTls.detailRows !== 8 || mobileTls.stateText !== desktopTls.stateText || !mobileTls.downloadEnabled) {
    throw new Error(`tls certificate mobile layout mismatch: ${JSON.stringify(mobileTls)}`);
  }
  if (mobileEncryptionDialogs.horizontalOverflow || !mobileEncryptionDialogs.menu.visible || !mobileEncryptionDialogs.menu.insideViewport || mobileEncryptionDialogs.menu.width < 300 || mobileEncryptionDialogs.menu.width > 390 || mobileEncryptionDialogs.menu.height < 100 || mobileEncryptionDialogs.menu.items !== 3 || !mobileEncryptionDialogs.tls.visible || !mobileEncryptionDialogs.tls.insideViewport || mobileEncryptionDialogs.tls.width > 390 || !mobileEncryptionDialogs.tls.fieldsInside || !mobileEncryptionDialogs.reset.visible || !mobileEncryptionDialogs.reset.insideViewport || mobileEncryptionDialogs.reset.width > 390 || mobileEncryptionDialogs.reset.rows !== 4 || mobileEncryptionDialogs.reset.rowColumns.some((columns) => columns !== 1) || !mobileEncryptionDialogs.reset.confirmEnabled || !mobileEncryptionDialogs.allClosed) {
    throw new Error(`mobile encryption dialogs mismatch: ${JSON.stringify(mobileEncryptionDialogs)}`);
  }
  const expectedSetupGuideOptions = ['router', 'windows', 'macos', 'android', 'ios', 'encrypted'];
  if (desktopSetupGuide.horizontalOverflow || desktopSetupGuide.initial !== 'router' || JSON.stringify(desktopSetupGuide.options) !== JSON.stringify(expectedSetupGuideOptions) || !desktopSetupGuide.selectedRestored || desktopSetupGuide.bodyColumns !== 2 || !desktopSetupGuide.cardInside || !desktopSetupGuide.selectorInside || !desktopSetupGuide.contentInside || desktopSetupGuide.macos.title !== 'macOS' || !desktopSetupGuide.macos.profileVisible || desktopSetupGuide.macos.profileEnabled !== desktopSetupGuide.macos.profileExpectedEnabled || desktopSetupGuide.macos.actionCount !== 2 || desktopSetupGuide.macos.addressCount !== 1 || !desktopSetupGuide.macos.addressMatches || !desktopSetupGuide.macos.preservedAfterStatusRender || desktopSetupGuide.ios.title !== 'iOS' || !desktopSetupGuide.ios.profileVisible || desktopSetupGuide.ios.profileEnabled !== desktopSetupGuide.ios.profileExpectedEnabled || desktopSetupGuide.ios.actionCount !== 2 || desktopSetupGuide.ios.addressCount !== 1 || !desktopSetupGuide.ios.preservedAfterStatusRender || desktopSetupGuide.encrypted.title !== '加密 DNS 客户端' || desktopSetupGuide.encrypted.addressCount !== 2 || desktopSetupGuide.encrypted.actionCount !== 1 || desktopSetupGuide.encrypted.rowStates.some((row) => !row.matches) || desktopSetupGuide.shortcut.view !== 'dns' || desktopSetupGuide.shortcut.section !== 'encryption' || !desktopSetupGuide.shortcut.settingsVisible || !desktopSetupGuide.shortcut.protocolModuleVisible) {
    throw new Error(`desktop setup guide mismatch: ${JSON.stringify(desktopSetupGuide)}`);
  }
  if (mobileSetupGuide.horizontalOverflow || mobileSetupGuide.cardWidth > 390 || mobileSetupGuide.bodyColumns !== 1 || !mobileSetupGuide.selectorInside || !mobileSetupGuide.contentInside || mobileSetupGuide.encrypted.addressCount !== 2 || !mobileSetupGuide.encrypted.rowsInside || mobileSetupGuide.encrypted.rowColumns.some((columns) => columns !== 2) || !mobileSetupGuide.apple.preservedAfterStatusRender || !mobileSetupGuide.apple.profileVisible || mobileSetupGuide.apple.buttonCount !== 2 || mobileSetupGuide.apple.actionColumns !== 1 || mobileSetupGuide.apple.buttonWidths.length !== 2 || Math.abs(mobileSetupGuide.apple.buttonWidths[0] - mobileSetupGuide.apple.buttonWidths[1]) > 1 || !mobileSetupGuide.apple.buttonsInside || mobileSetupGuide.apple.headingColumns !== 2) {
    throw new Error(`mobile setup guide mismatch: ${JSON.stringify(mobileSetupGuide)}`);
  }
  console.log(JSON.stringify({ desktopSettings, desktopAppShell, desktopInteraction, desktopSafeSearchDialog, desktopStatsInteraction, desktopStatsRetentionDialog, desktopQueryLogInteraction, desktopQueryLogDialogs, desktopQueryLogMain, desktopQueryLogActions, desktopQueryLogDetail, desktopCacheInteraction, desktopCacheDialog, desktopCacheConfirm, desktopDnssecInteraction, desktopRefuseAnyInteraction, desktopDnsServiceInteraction, desktopDnsServiceDialog, desktopEcsInteraction, desktopEcsDialog, desktopAccessInteraction, desktopAccessDialog, desktopRefuseAnyTest, desktopFilteringCheck, desktopBlockedServicesAutoUpdate, desktopClientReverseDns, desktopPrivateReverseDialog, desktopUpstreamRouting, desktopUpstreamDialog, desktopDhcp, desktopEncryptionDialogs, desktopTls, desktopSetupGuide, desktopClientsPersistent, desktopClientDeleteDialog, desktopRuntimeClients, desktopDhcpRuntimeClient, desktopDashboard, desktopDashboardFidelity, desktopOverlays, desktopClientCache, desktopThemeInteraction, routeAudit, routeScrollReset, mobileThemeMenu, mobileQueryLogMain, mobileQueryLogActions, mobileQueryLogDetail, mobileNavigation, mobileRouteScrollReset, mobileSettings, mobileGeneralProtection, mobileSafeSearchDialog, mobileStatsSettings, mobileStatsRetentionDialog, mobileStatsIgnoredDialog, mobileQueryLogSettings, mobileQueryLogDialogs, mobileEncryptionDialogs, mobileTls, mobileSetupGuide, mobileClientsPersistent, mobileRuntimeClients, mobileDhcpRuntimeClient, mobileRewrite, mobileFilteringCheck, mobileBlockedServicesAutoUpdate, mobileUpstreamRouting, mobileUpstreamDialog, mobileDnssec, mobileDnsServiceDialog, mobileEcs, mobileEcsDialog, mobileAccess, mobileAccessDialog, mobileClientReverseDns, mobilePrivateReverseDialog, mobileDhcp, mobileClientCache, mobileDnsCache, mobileDashboard, mobileDashboardFidelity, mobileDarkRouteAudit, lightThemeAudit, themeRestore, browserErrors }, null, 2));
} finally {
  await client?.shutdown();
  await stopChromeProcess(chrome);
  await removeAuditProfile(profileDir);
}
}

async function stopChromeProcess(child) {
  if (!child || child.exitCode !== null) return;
  if (process.platform === 'win32' && child.pid) {
    const killer = spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
    await Promise.race([
      new Promise((resolve) => killer.once('exit', resolve)),
      sleep(3000)
    ]);
  } else {
    child.kill('SIGTERM');
  }
  await Promise.race([
    new Promise((resolve) => child.once('exit', resolve)),
    sleep(3000)
  ]);
}

async function removeAuditProfile(directory) {
  const resolved = path.resolve(directory);
  const tempRoot = path.resolve(os.tmpdir());
  if (!resolved.startsWith(tempRoot + path.sep) || !path.basename(resolved).startsWith('cleandns-audit-chrome-')) {
    throw new Error(`refusing to remove unexpected audit profile: ${resolved}`);
  }
  let lastError = null;
  for (let attempt = 0; attempt < 8; attempt += 1) {
    try {
      fs.rmSync(resolved, { recursive: true, force: true, maxRetries: 2, retryDelay: 100 });
      return;
    } catch (error) {
      lastError = error;
      if (!['EBUSY', 'EPERM', 'ENOTEMPTY'].includes(error.code)) throw error;
      await sleep(150 * (attempt + 1));
    }
  }
  console.warn(`audit profile cleanup skipped: ${lastError?.message || resolved}`);
}

async function showSettings(cdp) {
  await evaluate(cdp, `selectView('dns', { skipUrl: true }); selectSettingsSection('general', { history: 'replace' }); document.getElementById('settings-section-general').scrollIntoView({ block: 'start' }); true`);
  await sleep(500);
}

async function layoutMetrics(cdp) {
  return evaluateValue(cdp, `(() => {
    const rect = (node) => {
      if (!node) return null;
      const value = node.getBoundingClientRect();
      return { left: Math.round(value.left), top: Math.round(value.top), right: Math.round(value.right), bottom: Math.round(value.bottom), width: Math.round(value.width), height: Math.round(value.height) };
    };
    const ids = ['safeBrowsingEnabled', 'parentalEnabled', 'safeSearchEnabled', 'mTotal', 'mBlocked', 'mSafeBrowsing', 'mParental'];
    const idCounts = Object.fromEntries(ids.map((id) => [id, document.querySelectorAll('#' + id).length]));
    const cards = [...document.querySelectorAll('#dashboardStats .stats-card')].map(rect);
    const visibleControls = ids.filter((id) => {
      const node = document.getElementById(id);
      return node && node.offsetParent !== null;
    });
    const rankRows = (id) => [...document.querySelectorAll('#' + id + ' .rank-row')].map((row) => ({
      name: row.querySelector('.rank-name-text')?.textContent?.trim() || '',
      count: Number((row.querySelector('.rank-value')?.textContent || '').replace(/[^0-9.]/g, '')) || 0,
      share: Number((row.querySelector('.rank-share')?.textContent || '').replace(/[^0-9.]/g, '')) || 0
    }));
    return {
      viewport: { width: innerWidth, height: innerHeight },
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      scrollWidth: document.documentElement.scrollWidth,
      idCounts,
      visibleControls,
      protectionModule: rect(document.getElementById('general-module-protection')),
      settingsSection: rect(document.getElementById('settings-section-general')),
      statCards: cards,
      statCardHeightsEqual: cards.length === 4 && new Set(cards.map((item) => item.height)).size === 1,
      dashboardCounters: [...document.querySelectorAll('#dashboardCounters .counter-row')].map((row) => row.querySelector('.counter-label-text')?.textContent?.trim() || ''),
      timelineSvg: Boolean(document.querySelector('#dashboardTimeline svg')),
      timelineLabel: document.querySelector('#dashboardTimeline svg')?.getAttribute('aria-label') || '',
      statisticsSeries: typeof state !== 'undefined' && state.status?.statistics?.series ? {
        timeUnits: state.status.statistics.series.timeUnits,
        points: state.status.statistics.series.starts?.length || 0,
        queries: (state.status.statistics.series.dnsQueries || []).reduce((sum, value) => sum + Number(value || 0), 0),
        processingCount: (state.status.statistics.series.processingCount || []).reduce((sum, value) => sum + Number(value || 0), 0),
        averageProcessingMs: state.status.stats?.avgProcessingMs
      } : null,
      rankings: typeof state !== 'undefined' && state.status ? {
        source: state.status.dashboard?.rankingSource || '',
        coverage: state.status.dashboard?.coverage || '',
        counted: state.status.dashboard?.window || 0,
        total: state.status.stats?.total || 0,
        clients: rankRows('topClients'),
        queried: rankRows('topQueriedDomains'),
        blocked: rankRows('topBlockedDomains')
      } : null
    };
  })()`);
}

async function setViewport(cdp, width, height, scale, mobile) {
  await cdp.send('Emulation.setDeviceMetricsOverride', {
    width,
    height,
    deviceScaleFactor: scale,
    mobile,
    screenWidth: width,
    screenHeight: height
  });
}

async function navigate(cdp, targetUrl) {
  await cdp.send('Page.navigate', { url: targetUrl });
  await waitFor(() => evaluateValue(cdp, `document.readyState === 'complete'`), 15_000);
}

async function screenshot(cdp, file) {
  const result = await cdp.send('Page.captureScreenshot', { format: 'png', fromSurface: true, captureBeyondViewport: false });
  fs.writeFileSync(file, Buffer.from(result.data, 'base64'));
}

async function evaluate(cdp, expression) {
  const result = await cdp.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
  if (result.exceptionDetails) {
    throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text || 'runtime evaluation failed');
  }
  return result.result;
}

async function evaluateValue(cdp, expression) {
  return (await evaluate(cdp, expression)).value;
}

async function fetchJson(targetUrl, options) {
  try {
    const response = await fetch(targetUrl, options);
    if (!response.ok) return null;
    return response.json();
  } catch {
    return null;
  }
}

function parseStringArrayEnv(name) {
  const source = process.env[name];
  if (!source) return [];
  let value;
  try {
    value = JSON.parse(source);
  } catch (err) {
    throw new Error(`${name} must be a JSON string array: ${err.message}`);
  }
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || !item.trim())) {
    throw new Error(`${name} must be a JSON string array`);
  }
  return value;
}

async function waitFor(check, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await check()) return;
    await sleep(100);
  }
  throw new Error('audit wait timeout');
}

function unusedPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const value = server.address().port;
      server.close((error) => error ? reject(error) : resolve(value));
    });
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

class CdpClient {
  static connect(url) {
    return new Promise((resolve, reject) => {
      const socket = new WebSocket(url);
      socket.addEventListener('open', () => resolve(new CdpClient(socket)), { once: true });
      socket.addEventListener('error', reject, { once: true });
    });
  }

  constructor(socket) {
    this.socket = socket;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Map();
    this.closing = false;
    socket.addEventListener('message', (event) => this.handle(JSON.parse(event.data)));
    socket.addEventListener('close', () => {
      if (!this.closing) {
        for (const { reject } of this.pending.values()) reject(new Error('CDP connection closed'));
      }
      this.pending.clear();
    });
  }

  send(method, params = {}) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }

  on(method, listener) {
    const values = this.listeners.get(method) || [];
    values.push(listener);
    this.listeners.set(method, values);
  }

  handle(message) {
    if (message.id) {
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      if (message.error) pending.reject(new Error(message.error.message || 'CDP error'));
      else pending.resolve(message.result || {});
      return;
    }
    for (const listener of this.listeners.get(message.method) || []) listener(message.params || {});
  }

  close() {
    this.closing = true;
    this.socket.close();
  }

  async shutdown() {
    this.closing = true;
    if (this.socket.readyState === WebSocket.OPEN) {
      await Promise.race([
        this.send('Browser.close').catch(() => {}),
        sleep(1500)
      ]);
    }
    if (this.socket.readyState === WebSocket.OPEN || this.socket.readyState === WebSocket.CONNECTING) {
      this.socket.close();
    }
  }
}

await runAudit();
