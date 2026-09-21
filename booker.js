/**
 * 上海交大体育场馆 —— 定时预约脚本
 *
 * 设计原则（防封号优先）：
 *  1. 所有请求都在「真实 Edge 浏览器的页面上下文」里，通过站点自己的 axios 实例发出，
 *     TLS 指纹、请求头顺序、Cookie 全部与手动操作完全一致。
 *  2. 加密（RSA sid/tim + AES body）直接调用站点自带的 Rsa / Aes，不做任何手写复现。
 *  3. 以服务器时间为准对齐开抢时刻，且默认延后触发，绝不提前打空枪。
 *  4. 请求次数硬上限 + 随机抖动；成功或遇到终止性错误立即停止。
 *  5. 不自动破解滑块验证码：触发验证码即停手，交由人工在已打开的窗口完成。
 */
const { chromium } = require('playwright-core');
const path = require('path');
const fs = require('fs');

const CFG = JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8'));
const ORIGIN = 'https://sports.sjtu.edu.cn';
const SSO = 'https://jaccount.sjtu.edu.cn/oauth2/authorize?response_type=code&client_id=mB5nKHqC00MusWAgnqSF&redirect_uri=' + ORIGIN + '/oauth2Login';

const p2 = (n) => String(n).padStart(2, '0');
const stamp = () => {
  const d = new Date();
  return `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}.${String(d.getMilliseconds()).padStart(3, '0')}`;
};
// 日志必须落盘：最有价值的诊断数据（每请求 ms、是否对冲、失败原因）
// 只存在于终端回滚缓冲里，窗口一关就没了 —— 踩过一次，抢到的那次日志就此丢失。
const LOG_DIR = path.join(__dirname, 'logs');
let logStream = null;
let logFile = null;

function initLog(keep) {
  try {
    fs.mkdirSync(LOG_DIR, { recursive: true });
    const d = new Date();
    logFile = `run-${d.getFullYear()}${p2(d.getMonth() + 1)}${p2(d.getDate())}-${p2(d.getHours())}${p2(d.getMinutes())}${p2(d.getSeconds())}.log`;
    logStream = fs.createWriteStream(path.join(LOG_DIR, logFile), { flags: 'a' });
    const olds = fs.readdirSync(LOG_DIR).filter((f) => /^run-.*\.log$/.test(f)).sort();
    for (const f of olds.slice(0, Math.max(0, olds.length - (keep ?? 30)))) {
      fs.unlinkSync(path.join(LOG_DIR, f));
    }
  } catch { /* 落盘失败不影响抢票本身 */ }
}

const log = (...a) => {
  const line = `[${stamp()}] ${a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(' ')}`;
  console.log(line);
  if (logStream) logStream.write(line + '\n');
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * 限流不一定走 HTTP 429。实测本站是 HTTP 200 + code≠0 + msg「请求过于频繁，请稍后再试」，
 * 触发阈值约 8 个请求 / 1.6 秒。认不出来就会继续按常规间隔硬敲，把限流越捅越深。
 */
const isRateLimited = (msg) => /频繁|过于频繁|限流|稍后再试/.test(String(msg || ''));

/**
 * 全局请求配额闸。
 * 实测限流不是按速率而是按计数：约「8 个请求 / 2 秒滑动窗口」就会返回
 * HTTP 200 + code 500 + 「请求过于频繁」。两次实测分别在第 8、第 9 个请求被拒。
 * 这里按 6 个/2 秒放行，把剩余额度留给最关键的 ConfirmOrder（下单不走这个闸）。
 */
const REQ_LOG = [];
async function budgetGate(max, windowMs) {
  const cap = max ?? 6;
  const win = windowMs ?? 2000;
  for (;;) {
    const now = Date.now();
    while (REQ_LOG.length && now - REQ_LOG[0] > win) REQ_LOG.shift();
    if (REQ_LOG.length < cap) { REQ_LOG.push(now); return; }
    await sleep(win - (now - REQ_LOG[0]) + 20);
  }
}

/** 把失败归类，好分别处理 —— 绝不能把 429/5xx 当成「日期还没放出来」继续快探 */
function classify(res) {
  if (!res.ok) {
    if (res.timedOut || res.status === 0) return 'timeout';
    if (res.status === 401 || res.status === 403) return 'auth';
    if (res.status === 429) return 'ratelimit';
    if (res.status >= 500) return 'server';
    return 'http';
  }
  // 关键：本站鉴权失败不体现在 HTTP 状态码上。实测未登录时返回的是
  //   HTTP 200 + {"code":401,"msg":"您还未登录或登录超时，请再次登录"}
  // 只看 status 会判成 ok，随后 data 为空又被当成「日期还没放出来」继续快探 —— 正是最该避免的。
  const b = res.body;
  if (!b || typeof b !== 'object' || !('code' in b)) return 'session'; // HTML 等非预期响应
  if (b.code === 401 || b.code === 403) return 'auth';
  return 'ok';
}

// —— 会话持久化 ——
// Chromium 的持久化目录不会保留 session cookie（JSESSIONID / jaccount 都是），
// 所以这里显式把 storageState 落盘，下次启动再注入，免去重复登录。
const PROFILE_DIR = process.env.SJTU_PROFILE || path.join(__dirname, '.profile');
const STATE_FILE = process.env.SJTU_STATE || path.join(__dirname, '.state.json');

/**
 * .state.json 里是明文的 JAccount / JSESSIONID 会话，泄漏基本等同账号泄漏。
 * Windows 上 chmod 不起作用，改用 icacls 去掉继承、只留当前用户。
 */
function restrictAcl(file) {
  if (process.platform !== 'win32') return;
  try {
    require('child_process').execFileSync(
      'icacls', [file, '/inheritance:r', '/grant:r', `${process.env.USERNAME}:F`],
      { stdio: 'ignore', timeout: 5000 },
    );
  } catch { /* 收窄失败不影响功能，README 已提示风险 */ }
}

async function restoreState(ctx) {
  if (!fs.existsSync(STATE_FILE)) return false;
  try {
    const s = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    if (s.cookies?.length) {
      await ctx.addCookies(s.cookies);
      return true;
    }
  } catch (e) {
    log('历史会话不可用，将重新登录:', e.message);
  }
  return false;
}

async function saveState(ctx) {
  try {
    // 用 ctx.cookies() 而不是 storageState()：后者会新开一个标签页去读 localStorage，
    // 而 Ctrl+C 时浏览器已在关闭，会报 "Failed to open a new tab" 导致会话存不下来（实测踩过）。
    // 反正 restoreState 也只用 cookies。
    const all = await ctx.cookies();
    const cookies = all.filter((c) => String(c.domain).replace(/^\./, '').endsWith('sjtu.edu.cn'));
    fs.writeFileSync(STATE_FILE, JSON.stringify({ cookies }), { mode: 0o600 });
    restrictAcl(STATE_FILE);
  } catch (e) {
    log('会话保存失败（不影响本次运行）:', e.message);
  }
}

/** 回到一个稳定页面：站点在 SSO 回跳后会自行 location.href 跳转，必须等它跑完 */
async function gotoStable(page) {
  await page.goto(`${ORIGIN}/pc/`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => !!document.querySelector('#app')?.__vue__, null, { timeout: 60000 });
  await sleep(500);
}

/** 只读请求可安全重试：页面导航会摧毁执行上下文 */
async function evalWithRetry(page, fn, arg) {
  for (let i = 0; ; i++) {
    try {
      return await page.evaluate(fn, arg);
    } catch (e) {
      if (i >= 2 || !/Execution context was destroyed|Target closed|navigation/i.test(e.message)) throw e;
      await gotoStable(page).catch(() => {});
    }
  }
}

// —— 与前端 period() 完全一致：行号 -> 时段 ——
const PERIODS = ['07:00-08:00','08:00-09:00','09:00-10:00','10:00-11:00','11:00-12:00','12:00-13:00','13:00-14:00','14:00-15:00','15:00-16:00','16:00-17:00','17:00-18:00','18:00-19:00','19:00-20:00','20:00-21:00','21:00-22:00'];
// —— 与前端 nervousness() 完全一致 ——
const TENSION = { 0: '正常', 1: '紧张', 2: '很紧张', 3: '非常紧张', 4: '很紧张(签退)' };

/** 在页面上下文里用站点自带的 axios 发请求 */
function api(page, opts) {
  return evalWithRetry(page, async (o) => {
    const vm = document.querySelector('#app').__vue__;
    const build = () => {
      // 站点 axios 实例默认 timeout=50000，任何一个请求被挂住就会堵死整轮。
      // 只读探测必须自带短超时覆盖它。
      const cfg = { method: o.method || 'post', url: o.url };
      if (o.timeout) cfg.timeout = o.timeout;
      if (o.form) {
        cfg.headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
        cfg.data = Object.entries(o.data).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
      } else if (o.data !== undefined) {
        cfg.data = o.data;
      }
      return cfg;
    };
    const once = async () => {
      const t0 = performance.now();
      try {
        const r = await vm.$ajax(build());
        return { ok: true, status: r.status, body: r.data, serverDate: r.headers?.date || null, ms: Math.round(performance.now() - t0) };
      } catch (e) {
        const msg = String(e.message || e);
        return {
          ok: false, status: e.response?.status ?? 0, body: e.response?.data ?? null,
          timedOut: /timeout/i.test(msg), error: msg, ms: Math.round(performance.now() - t0),
        };
      }
    };

    if (!o.hedgeAfterMs) return once();

    // 受控对冲：首发超过阈值未回就再发一个，谁先成功用谁。最多 2 个在途，仅限只读。
    //
    // 为什么要对冲：高峰期不只是「慢」，还会丢包。被丢的请求永远不会回来，
    // 干等到超时是纯浪费；补发一个才是唯一的补救。反过来说，如果只是排队慢，
    // 对冲会加重服务端负担 —— 所以阈值要设得比正常拥塞延迟高，只在疑似丢包时才触发。
    const a = once();
    const early = await Promise.race([a, new Promise((r) => setTimeout(() => r(null), o.hedgeAfterMs))]);
    if (early) return early;
    const b = once();
    const first = await Promise.race([a, b]);
    if (first.ok) return { ...first, hedged: true };
    const both = await Promise.all([a, b]);
    return { ...(both.find((x) => x.ok) || first), hedged: true };
  }, opts);
}

/** 下单：sid/tim 用站点 RSA，body 用站点 AES —— 与 agreeTerms() 逐字段一致 */
function confirmOrder(page, payload, timeout) {
  // 绝不对冲、绝不重试：这是非幂等写请求，并发或重放都可能变成重复订单
  return page.evaluate(async ({ p, to }) => {
    const vm = document.querySelector('#app').__vue__;
    const t = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');
    let key = '';
    for (let i = 0; i < 16; i++) key += t[Math.ceil(35 * Math.random())];
    const ts = Date.now();
    const t0 = performance.now();
    try {
      const r = await vm.$ajax({
        method: 'post',
        url: '/venue/personal/ConfirmOrder',
        timeout: to,
        headers: { 'Content-Type': 'application/json;charset=utf-8', sid: vm.Rsa.encrypt(key), tim: vm.Rsa.encrypt(String(ts)) },
        data: vm.Aes.encrypt(JSON.stringify(p), key),
      });
      return { ok: true, status: r.status, body: r.data, ms: Math.round(performance.now() - t0) };
    } catch (e) {
      const msg = String(e.message || e);
      return {
        ok: false, status: e.response?.status ?? 0, body: e.response?.data ?? null,
        timedOut: /timeout/i.test(msg), error: msg, ms: Math.round(performance.now() - t0),
      };
    }
  }, { p: payload, to: timeout });
}


/**
 * 把浏览器带到站内某个页面，交还给人操作。
 * 注意：SPA 的路由守卫查的是 sessionStorage.token（按标签页存），
 * 只有 Cookie 的话会被弹回登录框 —— 所以必须先把 token 补上。
 */
async function openInApp(page, hash, orderId) {
  try {
    // 必须先落到站内页面：api() 依赖页面里的 Vue 实例，sessionStorage 也要同源才能写
    await gotoStable(page);
    // 实测：jaccount SSO 流程下 currentUser 的 data.params 是空的（只有手机号登录才回 JSESSIONID）。
    // 而路由守卫只判 sessionStorage.token 非空 —— 它只是前端登录标记，真鉴权靠 Cookie。
    // 所以取不到就直接用 Cookie 里的 JSESSIONID，语义一致。
    const me = await api(page, { method: 'get', url: '/system/user/currentUser', timeout: 5000 });
    const tok = me.body?.data?.params?.JSESSIONID
      || (await page.context().cookies(ORIGIN)).find((c) => c.name === 'JSESSIONID')?.value;
    await page.evaluate(({ t, id }) => {
      if (t) sessionStorage.setItem('token', t);
      if (id) sessionStorage.setItem('newOrderDetailsId', id); // 订单详情页就靠它取单
    }, { t: tok, id: orderId });
    await page.goto(`${ORIGIN}/pc/#${hash}`);
    await page.bringToFront();
    return true;
  } catch (e) {
    log(`打开页面失败（不影响已完成的操作）: ${e.message}`);
    return false;
  }
}

async function whoami(page) {
  const me = await api(page, { method: 'get', url: '/system/user/currentUser' });
  return me.ok && me.body?.data?.loginName ? me.body.data : null;
}

async function ensureLogin(ctx, page) {
  await gotoStable(page);

  let me = await whoami(page);
  if (me) {
    await saveState(ctx);
    return me;
  }

  log('会话已失效，正在走 jaccount…（若弹出登录页请在浏览器窗口里完成，含双因子）');
  await page.goto(SSO, { waitUntil: 'domcontentloaded' });

  // 三振出局：只统计「已跳回本站却仍拿不到会话」的次数。
  // 还停在 jaccount 页面时不计数也不发请求，所以慢慢做双因子不受影响。
  const MAX_MISS = 3;
  let miss = 0;
  for (let i = 0; i < 200; i++) {
    await sleep(3000);
    if (!page.url().startsWith(ORIGIN)) continue; // 还在 jaccount 上，等你操作

    // 站点在 SSO 回跳后会自行 location.href 跳一次，先落到稳定页再验证
    await gotoStable(page).catch(() => {});
    me = await whoami(page);
    if (me) {
      await saveState(ctx);
      return me;
    }
    if (++miss >= MAX_MISS) {
      throw new Error(
        `已跳回本站但连续 ${MAX_MISS} 次拿不到会话，停止重试以免触发风控。\n` +
        `        浏览器窗口已为你保留，请在里面手动登录一次，成功后重新运行 node booker.js。`
      );
    }
    log(`已跳回本站但未拿到会话（${miss}/${MAX_MISS}）…`);
  }
  throw new Error('登录超时');
}

/**
 * 对时：Date 响应头只有「秒」级精度，直接读会带最多 1 秒误差，
 * 所以连续探测、捕捉秒数跳变的那一刻 —— 此时服务器时间正好是 X.000，
 * 误差随之压到约 ±轮询间隔。探测打的是静态图标(HEAD)，完全不碰业务接口。
 */
async function syncClock(page) {
  // 16 次 ×130ms 是全脚本最密的一段突发。实测限流阈值不明但确实存在，
  // 这里收到 10 次 ×200ms（约 5 次/秒 -> 2.5 次/秒），精度损失有限而足迹减半。
  const N = CFG.clockSamples ?? 10;
  const STEP = CFG.clockStepMs ?? 200;
  const probe = () =>
    page.evaluate(async (u) => {
      const t0 = Date.now();
      const r = await fetch(u, { method: 'HEAD', cache: 'no-store' });
      const t1 = Date.now();
      return { date: r.headers.get('date'), t0, t1 };
    }, `${ORIGIN}/pc/static/bitbug_favicon.ico`);

  // 必须有墙钟上限：拥塞时单个请求要 4-5 秒，10 个样本能耗掉 40 秒，
  // 把开枪前的准备时间全吃光（实测踩过）。宁可样本少一点也不能误了点。
  const deadline = Date.now() + (CFG.clockBudgetMs ?? 8000);
  const s = [];
  for (let i = 0; i < N && Date.now() < deadline; i++) {
    try {
      const x = await probe();
      const sec = Date.parse(x.date);
      if (!Number.isNaN(sec)) s.push({ sec, t0: x.t0, t1: x.t1, rtt: x.t1 - x.t0 });
    } catch { /* 单次探测失败忽略 */ }
    await sleep(STEP);
  }
  if (s.length < N) log(`对时样本 ${s.length}/${N}（受 ${CFG.clockBudgetMs ?? 8000}ms 预算限制，服务端偏慢）`);
  if (!s.length) {
    log('⚠ 对时失败，退回本机时钟（可能不准）');
    return () => new Date();
  }

  // 只保留 RTT 较小的一半：RTT 越小，约束越紧、排队噪声越少
  const rttMid = [...s].sort((a, b) => a.rtt - b.rtt)[Math.floor(s.length / 2)].rtt;
  const low = s.filter((x) => x.rtt <= rttMid);
  const use = low.length >= 4 ? low : s;

  let lo = -Infinity;
  let hi = Infinity;
  for (const x of use) {
    lo = Math.max(lo, x.sec - x.t1);
    hi = Math.min(hi, x.sec + 1000 - x.t0);
  }

  let offset;
  let err;
  if (lo <= hi) {
    offset = (lo + hi) / 2;
    err = Math.round((hi - lo) / 2);
  } else {
    // 区间冲突 = 后端各机时钟不完全一致。秒级量化误差在整个周期上对称，取中位数最稳。
    const pts = s.map((x) => x.sec + 500 - (x.t0 + x.t1) / 2).sort((a, b) => a - b);
    offset = pts[Math.floor(pts.length / 2)];
    err = 500;
    log('⚠ 多次对时结果不一致（服务端多机时钟有差异），改用中位数估计');
  }

  log(`对时完成：偏移 ${Math.round(offset)}ms（约 ±${err}ms，样本 ${s.length} 个）`);
  if (Math.abs(offset) > 5000) log(`  注意：本机时钟与服务器差了 ${(offset / 1000).toFixed(1)}s，建议顺手校准一下 Windows 时间`);
  if (err > (CFG.preOpenLeadMs ?? 1500)) log('  提示：对时误差大于 preOpenLeadMs，可能错过开放瞬间，建议把 preOpenLeadMs 调大');
  return () => new Date(Date.now() + offset);
}

const fmtDate = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;

/** targetDate 依赖「当下是哪天」，跨午夜后必须重算 —— 见 main() 里等待结束后的复核 */
function resolveTargetDate(serverNow) {
  const t = String(CFG.targetDate || '').trim();
  if (/^\+\d+$/.test(t)) return fmtDate(new Date(serverNow().getTime() + parseInt(t.slice(1), 10) * 86400000));
  return t;
}

/**
 * 实测：服务端是多机集群，各机时钟相差可达 ~0.5s，绝对时间不可能对准到百毫秒级。
 * 所以不用「掐点开火」，改成「提前一点开始轻探、一发现日期放出来就立刻下单」——
 * 边沿触发，命中精度只取决于 earlyRetryMs，与时钟误差无关。
 */
function computeStart(serverNow) {
  const [hh, mm, ss] = CFG.fireAt.split(':').map(Number);
  const now = serverNow();
  const open = new Date(now);
  open.setHours(hh, mm, ss || 0, 0);
  const passed = open <= now;
  if (passed) open.setDate(open.getDate() + 1);
  return { open, start: new Date(open.getTime() - (CFG.preOpenLeadMs ?? 1500)), passed };
}

async function waitUntilFire(serverNow) {
  if (!CFG.fireAt || CFG.fireAt === 'now') return;
  const { open, start, passed } = computeStart(serverNow);
  if (passed) log(`今天的 ${CFG.fireAt} 已过，将等到明天。想立刻试一次就把 fireAt 改成 "now"。`);
  log(`开放时刻(服务器时间) ${open.toLocaleString('zh-CN', { hour12: false })}`);
  log(`提前 ${CFG.preOpenLeadMs ?? 1500}ms 开始轻探，等待 ${((start - serverNow()) / 1000).toFixed(1)}s`);
  while (start - serverNow() > 0) await sleep(Math.min(1000, Math.max(20, start - serverNow())));
}

/**
 * 一次最多能订几个时段 —— 逆自前端 handleChooseSeat 的互斥逻辑：
 *   紧张/很紧张/很紧张(签退)：已选超过 1 个时会踢掉最早选的  -> 上限 2
 *   非常紧张：已选 1 个时再点会把已选全部清空              -> 上限 1
 *   正常：无互斥代码                                        -> 不限
 */
function slotCapFor(tension) {
  const t = Number(tension); // 实测接口返回的是字符串 "4"，用 === 比数字会全部落空
  if (t === 3) return 1;
  if (t === 1 || t === 2 || t === 4) return 2;
  return Infinity;
}

/** 校验时段写法。写错就直接报错，绝不静默跳过 —— 否则会被误报成「无余位」 */
function parseSlots(list, label) {
  const rows = [];
  const bad = [];
  for (const s of list || []) {
    const r = PERIODS.indexOf(String(s).trim());
    if (r < 0) bad.push(s);
    else if (!rows.includes(r)) rows.push(r);
  }
  if (bad.length) {
    throw new Error(
      `${label} 里有无法识别的时段：${bad.map((x) => JSON.stringify(x)).join('、')}\n` +
      `        只接受整点段，合法取值：\n        ${PERIODS.join('  ')}`
    );
  }
  return rows;
}

/** 摊平成所有「可约」的格子 */
function availableCells(fields) {
  const wantFields = CFG.fields || [];
  const out = [];
  for (let col = 0; col < fields.length; col++) {
    const f = fields[col];
    if (wantFields.length && !wantFields.includes(f.fieldName)) continue;
    const pl = f.priceList || [];
    for (let row = 0; row < pl.length; row++) {
      // 实测接口返回的是字符串 "0"/"-1"/"-3"，用 === 0 比数字会永远为假 —— 一个空位都找不到。
      // 注意 Number(null) === 0，所以必须先挡掉空值。
      const st = pl[row]?.status;
      if (st != null && Number(st) === 0) out.push({ row, col, cell: pl[row], field: f, slotName: PERIODS[row] ?? `第${row + 1}段` });
    }
  }
  return out;
}

/** 心仪时段：严格按 config.slots 的书写顺序取 */
function pickPreferred(cells, prefRows, cap) {
  const out = [];
  for (const row of prefRows) {
    if (out.length >= cap) break;
    const hit = cells.find((c) => c.row === row);
    if (hit) out.push(hit);
  }
  return dedupeByRow(out, cap); // prefRows 已去重，这里是防御性的
}

/**
 * 兜底：从全场剩余席位里挑。
 *   nearest —— 离心仪时段最近的优先，同样近则晚的优先
 *   later   —— 一律越晚越优先
 */
function pickFallback(cells, prefRows, cap, mode, excludeRows) {
  const skip = excludeRows ?? prefRows; // 补位时要排除「已选中的行」，而不是全部心仪行
  const rest = cells.filter((c) => !skip.includes(c.row));
  const scored = rest.map((c) => ({
    c,
    dist: prefRows.length ? Math.min(...prefRows.map((p) => Math.abs(c.row - p))) : 0,
  }));
  scored.sort((a, b) => (mode === 'later' ? b.c.row - a.c.row : a.dist - b.dist || b.c.row - a.c.row));
  // 时段必须互不相同：服务端会以「同一时段不允许预约多个场地」拒单。
  // 官方说的「2 个场地各 1 个小时」指的是两个不同时段，不是同一时段占两间。
  return dedupeByRow(scored.map((x) => x.c), cap);
}

/** 同一时段只保留一个场地，并截到 cap */
function dedupeByRow(list, cap) {
  const out = [];
  const seenRows = new Set();
  for (const c of list) {
    if (out.length >= cap) break;
    if (seenRows.has(c.row)) continue;
    seenRows.add(c.row);
    out.push(c);
  }
  return out;
}

/** dryRun 用：把真实的「场地 × 时段」结构原样打出来，便于核对 */
function renderMatrix(fields) {
  // 中日韩字符是双宽，不能用 padEnd 按字符数对齐
  const dw = (s) => [...String(s)].reduce((n, ch) => n + (/[\u1100-\u115f\u2e80-\ua4cf\uac00-\ud7a3\uf900-\ufaff\ufe30-\ufe6f\uff00-\uff60\uffe0-\uffe6]/.test(ch) ? 2 : 1), 0);
  const pad = (s, w) => String(s) + ' '.repeat(Math.max(0, w - dw(s)));

  const rows = Math.max(0, ...fields.map((f) => (f.priceList || []).length));
  const names = fields.map((f) => f.fieldName || '?');
  const w = names.map((n) => Math.max(6, dw(n)));
  const lines = ['', `${pad('时段', 13)} ${names.map((n, i) => pad(n, w[i])).join(' ')}`];
  const seen = new Map();
  for (let row = 0; row < rows; row++) {
    const cells = fields.map((f, i) => {
      const st = f.priceList?.[row]?.status;
      seen.set(String(st), (seen.get(String(st)) ?? 0) + 1);
      // 不可约时把原始 status 一并显示，才能区分「真的订满」和「status 语义跟预期不符」
      return pad(st == null ? '--' : Number(st) === 0 ? '可约' : `×(${st})`, w[i]);
    });
    lines.push(`${pad(PERIODS[row] ?? `第${row + 1}段`, 13)} ${cells.join(' ')}`);
  }
  lines.push(`status 分布：${[...seen].map(([k, v]) => `${k}×${v}`).join('  ')}   (0=可约)`);
  if (rows !== PERIODS.length) lines.push(`(注意：实际 ${rows} 行，与前端 period() 的 ${PERIODS.length} 行不一致，时段标签可能对不上)`);
  return lines.join('\n');
}

/** 复刻前端 handleChooseSeat：注入字段后对整段 JSON 做 price -> venuePrice */
function buildSpaces(picks) {
  const arr = picks.map((p) => {
    const c = { ...p.cell };
    c.scheduleTime = PERIODS[p.row];
    c.subSitename = p.field.fieldName;
    c.subSiteId = p.field.fieldId;
    c.tensity = p.field.fieldDetailStatus;
    c.venueNum = 1;
    c.status = 1;
    return c;
  });
  return JSON.parse(JSON.stringify(arr).replace(/price/g, 'venuePrice'));
}

async function main() {
  initLog(CFG.keepLogs);
  log(`日志同时写入 logs/${logFile}`);

  const ctx = await chromium.launchPersistentContext(PROFILE_DIR, {
    channel: 'msedge',
    headless: false,
    viewport: { width: 1440, height: 900 },
    // 实测不加这条时 navigator.webdriver === true，是最廉价的自动化指纹
    args: ['--disable-blink-features=AutomationControlled'],
  });
  const page = ctx.pages()[0] || (await ctx.newPage());
  let done = false;

  // Ctrl+C 也要把会话存下来，否则 keepOpen 模式下永远存不到刷新后的 cookie
  process.on('SIGINT', async () => {
    log('收到中断，正在保存会话…');
    await saveState(ctx).catch(() => {});
    await ctx.close().catch(() => {});
    process.exit(0);
  });

  try {
    if (await restoreState(ctx)) log('已载入上次的登录会话');
    const user = await ensureLogin(ctx, page);
    log(`已登录：${user.loginName}${user.userName ? ' / ' + user.userName : ''}`);

    const serverNow = await syncClock(page);

    // 1) 场馆信息 + 运动类型
    const venueRes = await api(page, { url: '/manage/venue/queryVenueById', form: true, data: { id: CFG.venueId } });
    if (!venueRes.ok || !venueRes.body?.data) throw new Error('获取场馆信息失败: ' + JSON.stringify(venueRes.body));
    const venue = venueRes.body.data;
    const types = venue.motionTypes || [];
    log(`可选运动类型：${types.map((x) => x.name).join('、') || '（无）'}`);
    const want = String(CFG.motionType || '').trim();
    const mt = want
      ? types.find((x) => String(x.name || '').trim() === want) || types.find((x) => String(x.name || '').includes(want))
      : types[0];
    if (!mt) throw new Error(`未找到运动类型「${want}」，请从上面这行列表里挑一个填进 config.json`);
    const tenSity = TENSION[mt.tension];
    log(`场馆：${venue.venueName || venue.name || CFG.venueId} ｜ 类型：${mt.name} ｜ 紧张度：${tenSity}`);

    const prefRows = parseSlots(CFG.slots, 'config.slots');
    // 紧张度「正常」时前端没有数量互斥逻辑，slotCapFor 返回 Infinity。
    // 但兜底会 slice(0, cap) —— 不设限就会把全场空位一次性塞进一单，
    // 订下整天再不去就是违约记录。所以自动模式下强制收敛到一个安全值。
    const tensionCap = slotCapFor(mt.tension);
    const capCfg = Number(CFG.maxSlotsPerOrder) > 0 ? Number(CFG.maxSlotsPerOrder) : null;
    let cap;
    if (capCfg) {
      cap = Math.min(tensionCap, capCfg);
    } else if (tensionCap === Infinity) {
      cap = CFG.defaultCapWhenUnlimited ?? 2;
      log(`⚠ 紧张度「${tenSity}」前端不限单次数量；为避免一次订走整天，自动收敛为 ${cap} 个。要更多请显式设 maxSlotsPerOrder。`);
    } else {
      cap = tensionCap;
    }
    const fbMode = CFG.fallback ?? 'nearest';

    let targetDate = resolveTargetDate(serverNow);
    log(`目标日期：${targetDate}${CFG.dryRun ? '' : '（等待结束后会按当时日期复核）'}`);
    log(`心仪时段：${prefRows.map((r) => PERIODS[r]).join(' > ') || '（未设，直接走兜底）'}`);
    log(`单次上限：${cap === Infinity ? '不限' : cap + ' 个时段'}（据紧张度「${tenSity}」推定）｜ 兜底：${fbMode}`);

    // 开放时段之外的格子服务端一律回 -1，再怎么抢也抢不到，提前告警
    const ot = /(\d{1,2}):\d{2}\s*-\s*(\d{1,2}):\d{2}/.exec(venue.openTime || '');
    if (ot) {
      const outside = prefRows.filter((r) => Number(PERIODS[r].slice(0, 2)) < +ot[1] || Number(PERIODS[r].slice(6, 8)) > +ot[2]);
      if (outside.length) {
        log(`⚠ 心仪时段 ${outside.map((r) => PERIODS[r]).join('、')} 不在场馆开放时间 ${venue.openTime} 内，服务端只会返回不可约`);
      }
    }
    // 注：isAvailable=0 不代表停用。实测该场馆放号后数分钟内即被约满，
    // 开放时段内的格子随即全变 -3，此时 isAvailable 也是 0 —— 故不作为告警依据。

    // 演练模式不等开放时刻：dryRun 的目的是核对配置和时段结构，等到明天中午毫无意义
    if (CFG.dryRun) {
      log('dryRun=true，跳过等待，立即演练一次。');
    } else {
      await waitUntilFire(serverNow);
      // 关键：targetDate 是等待前算的。若等待跨过了午夜（比如头天晚上就挂上脚本），
      // 「今天+7」的基准日已经变了，不复核就会去抢一个昨天就放完的日期。
      const fresh = resolveTargetDate(serverNow);
      if (fresh !== targetDate) {
        log(`⚠ 等待期间跨日，目标日期由 ${targetDate} 修正为 ${fresh}`);
        targetDate = fresh;
      }
    }

    const probeTimeout = CFG.probeTimeoutMs ?? 800;
    const hedgeAfter = CFG.hedgeAfterMs ?? 0; // 0 = 不对冲
    const maxStreak = CFG.maxErrorStreak ?? 5;

    // 12:00 拥塞时超时是常态，不是风控信号 —— 它和限流必须分开计数。
    // 混在一起会让脚本在窗口刚开 5 秒就整个放弃（实测踩过）。
    let curTimeout = probeTimeout;
    let toStreak = 0;

    /** 错误统一处置：鉴权立即停；限流重退避；超时只放宽超时、不终止 */
    const handleErr = async (tag, r, n) => {
      const kind = classify(r);
      log(`${tag} ${kind} status=${r.status} ${r.ms}ms${r.hedged ? ' [对冲]' : ''} ${r.error || ''}`);
      if (kind === 'session') throw new Error('响应不是预期的 JSON（多半是 302 跳到了登录页）。已停止，请重新运行以重新登录。');
      if (kind === 'auth') throw new Error('会话失效(401/403)。已停止，请重新运行以重新登录。');

      if (kind === 'timeout') {
        // 服务端根本没回应，说明它在挨打，不是我们被限流。
        // 正确反应是「给它更多时间」而不是「更快地再问一遍」，更不是放弃。
        toStreak++;
        const cap = CFG.probeTimeoutMaxMs ?? 6000;
        if (curTimeout < cap) {
          curTimeout = Math.min(cap, Math.round(curTimeout * 1.6));
          log(`   ↳ 连续超时 ${toStreak} 次，阈值放宽到 ${curTimeout}ms（拥塞时服务端需要更久）`);
        }
        await sleep(200 + Math.random() * 200);
        return kind;
      }

      if (n >= maxStreak) throw new Error(`连续 ${n} 次 ${kind}，停止 —— 继续快探只会把限流升级成风控。`);
      const back = kind === 'ratelimit' ? 2000 * n : kind === 'server' ? 800 * n : (CFG.earlyRetryMs ?? 150);
      await sleep(back + Math.random() * 120);
      return kind;
    };

    // ===== 阶段 1：等目标日期放出来（独立预算 + 墙钟截止，不与抢位共用）=====
    let day = null;
    let probeDate = targetDate;
    let openDays = [];
    let matrixShown = false;
    const probeEnd = Date.now() + (CFG.probeWindowMs ?? 20000);
    let probeN = 0;
    let streak = 0;
    let rlHits = 0; // 被限流次数，跨两个阶段累计

    // 按「每秒次数」配速，而不是固定 sleep：减去请求自身耗时后再补足周期，
    // 这样 RTT 从 20ms 抖到 300ms 时速率依然稳定。
    //
    // 分档降频：实测放号通常只晚 1~2 秒，几秒内必定命中；越往后越不可能，
    // 但一直按 3 次/秒打，遇到罕见的大幅延迟会在一分钟内堆出上百个请求而触发限流。
    // 检测精度本身不值钱 —— 下单要 16 秒，探测早 300ms 只占 2%。
    const probePeriodAt = (elapsed) => {
      const r = elapsed < (CFG.probeFastMs ?? 6000) ? (CFG.probeRatePerSec ?? 3)
        : elapsed < (CFG.probeSlowMs ?? 20000) ? (CFG.probeSlowRatePerSec ?? 1)
          : (CFG.probeTailRatePerSec ?? 0.33);
      return 1000 / Math.max(0.1, r);
    };
    const probeStart = Date.now();

    while (!day && Date.now() < probeEnd) {
      const cycleStart = Date.now();
      probeN++;
      // 注意：该接口的 date 传「今天」，返回的是当前可预约的日期列表（与前端 querySiteAll 一致）
      await budgetGate(CFG.reqBudgetPerWindow, CFG.reqBudgetWindowMs);
      const r = await api(page, {
        url: '/manage/fieldDetail/queryFieldReserveSituationIsFull',
        data: { id: CFG.venueId, feildType: mt.id, date: fmtDate(serverNow()) },
        timeout: curTimeout,
        hedgeAfterMs: hedgeAfter,
      });
      const kind0 = classify(r);
      if (kind0 !== 'ok') {
        if (kind0 !== 'timeout') streak++; // 超时不计入终止计数
        await handleErr(`探测#${probeN}`, r, streak);
        continue;
      }
      streak = 0;
      toStreak = 0;
      // 业务码非 0 时 data 也是空的，绝不能顺着走成「未放号」而继续快探
      if (r.body.code !== 0) {
        const rl = isRateLimited(r.body.msg);
        log(`探测#${probeN} ${rl ? '被限流' : '业务失败'} code=${r.body.code} ${r.body.msg || ''}（${r.ms}ms）`);
        if (rl && ++rlHits >= 3) { log('⛔ 连续被限流，停止以免继续恶化。'); break; }
        await sleep((rl ? 1500 * rlHits : (CFG.attemptIntervalMs ?? 500)) + Math.random() * 300);
        continue;
      }

      openDays = r.body?.data || [];
      day = openDays.find((d) => d.date === targetDate) || null;
      probeDate = targetDate;

      // 演练时若目标日期还没放出来，改用一个已开放的日期来展示结构，
      // 否则永远看不到矩阵 —— 而看结构正是 dryRun 的意义所在。
      if (!day && CFG.dryRun && openDays.length) {
        day = openDays[openDays.length - 1];
        probeDate = day.date;
        log(`目标日期 ${targetDate} 尚未开放，改用已开放的 ${probeDate} 演练结构`);
      }
      if (!day) {
        log(`探测#${probeN} ${r.ms}ms 未放号（现有 ${openDays.map((d) => d.date).join(',') || '无'}）`);
        const wait = Math.max(0, probePeriodAt(Date.now() - probeStart) - (Date.now() - cycleStart));
        // 抖动做成乘性(±15%)而非加性：加性会把均值抬高、速率掉到目标值以下
        await sleep(wait * (0.85 + Math.random() * 0.3));
      }
    }

    if (!day) throw new Error(`探测窗口 ${CFG.probeWindowMs ?? 20000}ms 内目标日期始终未放出（共探测 ${probeN} 次）`);
    log(`✔ ${probeDate} 已放号（第 ${probeN} 次探测命中），dateId 已缓存`);

    // ===== 阶段 2：抢位（独立次数 + 墙钟截止）=====
    const maxAttempts = Math.max(1, CFG.maxAttempts ?? 10);
    const bookStart = Date.now();
    const bookEnd = bookStart + (CFG.bookWindowMs ?? 20000);
    const burstEnd = bookStart + (CFG.burstWindowMs ?? 3000);
    streak = 0;
    let lastFailMsg = null;
    let sameFail = 0;
    let fullHits = 0; // code 888「已满」次数，与 sameFail 分开计

    // 放号瞬间用短间隔贴住（日期列表和时段矩阵未必同时就绪），之后退回常规间隔。
    // 抖动按间隔比例缩放，否则 250ms 的抖动会把 200ms 的突发间隔冲垮。
    const attemptSleep = async () => {
      const iv = Date.now() < burstEnd ? (CFG.burstIntervalMs ?? 200) : (CFG.attemptIntervalMs ?? 500);
      await sleep(iv + Math.random() * Math.min(CFG.jitterMs ?? 250, iv * 0.5));
    };

    for (let attempt = 1; attempt <= maxAttempts && Date.now() < bookEnd; attempt++) {
      log(`— 抢位 ${attempt}/${maxAttempts} —`);

      await budgetGate(CFG.reqBudgetPerWindow, CFG.reqBudgetWindowMs);
      const fieldRes = await api(page, {
        url: '/manage/fieldDetail/queryFieldSituation',
        data: { fieldType: mt.id, date: probeDate, venueId: venue.venueId, dateId: day.dateId },
        timeout: curTimeout,
        hedgeAfterMs: hedgeAfter,
      });
      const kindF = classify(fieldRes);
      if (kindF !== 'ok') {
        if (kindF !== 'timeout') streak++;
        await handleErr(`时段查询#${attempt}`, fieldRes, streak);
        continue;
      }
      streak = 0;
      toStreak = 0;
      if (fieldRes.body?.code !== 0 || !fieldRes.body?.data) {
        const msg = fieldRes.body?.msg || '无数据';
        if (isRateLimited(msg)) {
          rlHits++;
          const back = 1500 * rlHits;
          log(`⚠ 被限流（${msg}），退避 ${back}ms 后再试（第 ${rlHits} 次）`);
          if (rlHits >= 3) { log('⛔ 连续被限流，停止以免继续恶化。'); done = true; break; }
          await sleep(back + Math.random() * 300);
        } else {
          log(`时段查询业务失败: ${msg}（${fieldRes.ms}ms）`);
          await attemptSleep();
        }
        continue;
      }

      const cells = availableCells(fieldRes.body.data);
      // 用标志位而不是 attempt===1：首轮若卡在「日期未开放」就 continue 了，矩阵会永远打不出来
      if (CFG.dryRun && !matrixShown) {
        log(`${probeDate} 的可约矩阵：` + renderMatrix(fieldRes.body.data));
        matrixShown = true;
      }

      const show = (list) => (list.length ? list.map((p) => `${p.field.fieldName} ${p.slotName}`).join('  +  ') : '无');

      // 第 1 轮只认心仪时段；第 2 轮起若心仪仍无位，才启用兜底
      let picks = pickPreferred(cells, prefRows, cap);
      let via = '心仪';

      // 演练：把心仪和兜底的结果一次报全然后收工，没必要空转重试
      if (CFG.dryRun) {
        log(`全场剩余 ${cells.length} 个可约时段`);
        log(`心仪命中：${show(picks)}`);
        log(`兜底(${fbMode}) 候选：${show(pickFallback(cells, prefRows, cap, fbMode === 'off' ? 'nearest' : fbMode))}` +
          (fbMode === 'off' ? '   ← fallback=off，实际不会启用' : ''));

        // 一格都没有时，横向扫一遍所有已开放日期作对照，
        // 才能分清是「这天订满了」还是「整个场馆压根还没放位」。仅演练模式执行。
        if (!cells.length && openDays.length > 1) {
          log('全场无位，扫描其它已开放日期对照：');
          for (const d of openDays) {
            const r = await api(page, {
              url: '/manage/fieldDetail/queryFieldSituation',
              data: { fieldType: mt.id, date: d.date, venueId: venue.venueId, dateId: d.dateId },
            });
            if (r.body?.code !== 0 || !r.body?.data) {
              log(`   ${d.date}  查询失败: ${r.body?.msg || r.error}`);
              continue;
            }
            const stat = new Map();
            for (const f of r.body.data) for (const c of f.priceList || []) stat.set(String(c?.status), (stat.get(String(c?.status)) ?? 0) + 1);
            log(`   ${d.date}  可约 ${availableCells(r.body.data).length} 个   status: ${[...stat].map(([k, v]) => `${k}×${v}`).join(' ')}`);
            await sleep(400); // 实测 ~4.9 次/秒会触发限流，这里是诊断用途，不必抢速度
          }
        }
        log('演练结束，未下单。确认无误后把 config.json 的 dryRun 改为 false。');
        done = true;
        break;
      }

      // 同一份矩阵里心仪为空就立刻兜底 —— 等下一轮才兜底平白丢掉一个 attemptInterval。
      // 仅当 fallbackImmediate=false 时才退回「第 2 轮起才兜底」的旧行为。
      const fbNow = CFG.fallbackImmediate !== false || attempt >= 2;
      const fbOn = fbNow && fbMode !== 'off';

      if (!picks.length && fbOn) {
        picks = pickFallback(cells, prefRows, cap, fbMode);
        via = `兜底/${fbMode}`;
      } else if (fbOn && picks.length && picks.length < cap && CFG.topUpWithFallback !== false) {
        // 心仪没凑满名额时用兜底补齐。名额空着也是浪费，且可提前退订。
        // 排除的是「已选中的行」而非全部心仪行 —— 否则补位会漏掉可用的心仪时段。
        const extra = pickFallback(cells, prefRows, cap - picks.length, fbMode, picks.map((p) => p.row));
        if (extra.length) {
          picks = picks.concat(extra);
          via = `心仪+补位/${fbMode}`;
        }
      }
      if (!picks.length) {
        const phase = Date.now() < burstEnd ? '突发' : '常规';
        log(`${cells.length === 0 ? '全场无余位' : `无可用时段（全场尚余 ${cells.length} 个但均被过滤）`}（查询 ${fieldRes.ms}ms，${phase}）`);
        await attemptSleep();
        continue;
      }
      log(`命中[${via}]：${show(picks)}   (时段查询 ${fieldRes.ms}ms)`);

      // 3) 下单（字段顺序与站点 agreeTerms() 一致）
      const res = await confirmOrder(page, {
        venTypeId: mt.id,
        venueId: venue.venueId,
        fieldType: mt.name,
        returnUrl: `${ORIGIN}/#/paymentResult/1`,
        scheduleDate: targetDate,
        week: '0123456'.charAt(new Date(targetDate).getDay()), // 与前端一致
        spaces: buildSpaces(picks),
        tenSity,
      }, CFG.orderTimeoutMs ?? 12000);
      const body = res.body || {};
      log(`ConfirmOrder ${res.ms}ms status=${res.status ?? '-'} code=${body.code ?? '-'}`);

      // 结果不确定（超时/连接断/5xx）：订单可能已经建了。非幂等写请求绝不自动重试。
      if (!res.ok && (res.timedOut || res.status === 0 || res.status >= 500)) {
        done = true;
        process.stdout.write('\x07');
        log('⛔ 下单结果不确定（可能已成单，也可能没有）。');

        // 反查一次刚才那些格子还在不在，用来推断订单到底有没有落地。
        // 不能据此自动重试（别人也可能同时抢走），但足以告诉你该往哪个方向核对。
        const chk = await api(page, {
          url: '/manage/fieldDetail/queryFieldSituation',
          data: { fieldType: mt.id, date: probeDate, venueId: venue.venueId, dateId: day.dateId },
          timeout: CFG.probeTimeoutMs ?? 4000,
        });
        if (classify(chk) === 'ok' && chk.body?.code === 0) {
          const still = availableCells(chk.body.data);
          const taken = picks.filter((p) => !still.some((c) => c.row === p.row && c.field.fieldId === p.field.fieldId));
          log(taken.length === picks.length
            ? '   反查：目标时段已不可约 —— 很可能已经成单了，别重复下单。'
            : taken.length
              ? '   反查：部分时段已不可约，情况不明。'
              : '   反查：目标时段仍可约 —— 订单多半没落地。');
        } else {
          log('   反查也失败了，无法判断。');
        }
        log('   已为你打开「我的订单」，请人工确认后再决定是否重跑。');
        await openInApp(page, '/Order');
        break;
      }

      if (body.code === 0) {
        done = true; // 抢到即停，绝不再发一单
        process.stdout.write('\x07'); // 响一声，12:00 你未必盯着屏幕
        log(`✅ 预约成功！订单号 ${body.data}`);
        log(`   ${targetDate}  ${picks.map((p) => `${p.field.fieldName} ${p.slotName}`).join('  +  ')}`);
        // 复刻前端成功后的跳转：写入 newOrderDetailsId 再进订单详情（含付款入口）
        await openInApp(page, '/orderDetails/0', body.data);
        log('已为你打开订单详情页。若需付款请在浏览器里完成，并务必按时到场签到。');
        break;
      }
      if (body.code === 1002) {
        done = true;
        process.stdout.write('\x07');
        log('⚠️ 服务端要求滑块验证码，脚本不做自动破解。');
        log(`   已打开预约页，但滑块不会自己弹出 —— 它由前端组件在你点「预订」后触发。`);
        log(`   请在页面上手动选 ${targetDate} 的时段并提交，届时滑块才会出现。`);
        await openInApp(page, `/apointmentDetails/1/${CFG.venueId}/${encodeURIComponent(mt.name)}/0`);
        break;
      }
      if (body.code === 10001) {
        log('⛔ 账号资料不完整，需先在「我的信息」补全后才能预约：', body.msg);
        done = true;
        break;
      }
      const failMsg = body.msg || res.error || JSON.stringify(body);
      log('下单失败:', failMsg);

      // 限流也会出现在下单响应里（同样是 HTTP 200 + code 500），必须退避而不是接着敲
      if (isRateLimited(failMsg)) {
        rlHits++;
        if (rlHits >= 3) { log('⛔ 连续被限流，停止以免继续恶化。'); done = true; break; }
        const back = 1500 * rlHits;
        log(`⚠ 下单被限流，退避 ${back}ms（第 ${rlHits} 次）`);
        await sleep(back + Math.random() * 300);
        continue;
      }

      // 「同一时段不允许预约多个场地」：这是规则冲突，原样重试只会一直失败。
      // 降到单时段重选，而不是把同一个无效组合反复提交。
      if (/同一时段|多个场地/.test(failMsg)) {
        if (cap > 1) {
          cap = 1;
          log('↳ 按服务端规则把单次上限降为 1 个时段，下一轮重新选位。');
        } else {
          log('⛔ 已是单时段仍被拒，停止。');
          done = true;
          break;
        }
        await attemptSleep();
        continue;
      }

      if (/违约|黑名单|限制|冻结|超出|已达/.test(failMsg)) {
        log('⛔ 属于账号规则限制，立即停止，避免触发风控。');
        done = true;
        break;
      }

      // code 888「场地预定人数已满」= 抢位竞争失败。
      // 关键区别：服务端明确回了业务码，说明请求完整往返、订单确定没建 ——
      // 这和超时/5xx 的「结果不确定」完全不同，重试安全且必要。
      // 实测 9/21：第一次 888，2.6s 后重查两个时段仍可约，第二次即成功。
      // 单列的原因：它天然会连续出现，走 sameFail 会在第 3 次把最该重试的情形停掉。
      if (Number(body.code) === 888 || /人数已满|预定人数/.test(failMsg)) {
        if (++fullHits >= (CFG.maxFullRetries ?? 6)) {
          log(`⛔ 连续 ${fullHits} 次「已满」，判定为真售罄而非瞬时冲突，停止。`);
          done = true;
          break;
        }
        // 退避要短：名额回补/冲突缓解的窗口很窄，等一个 attemptInterval 就错过了。
        // 下一轮会重新查询矩阵，若该时段真没了，兜底会自动换位。
        log(`↳ 竞争失败（第 ${fullHits} 次「已满」），立即重查换位重试。`);
        await sleep(200 + Math.random() * 150);
        continue;
      }

      // 同一条错误重复出现说明重试无意义，别把额度耗在必然失败的请求上
      if (failMsg === lastFailMsg) {
        if (++sameFail >= 2) { log('⛔ 同一错误连续 3 次，重试无意义，停止。'); done = true; break; }
      } else {
        lastFailMsg = failMsg;
        sameFail = 0;
      }
      await attemptSleep();
    }

    if (!done) log('已用完预算次数，停止。');
  } catch (e) {
    log('异常终止:', e.message);
  } finally {
    await saveState(ctx).catch(() => {}); // 落盘刷新后的会话，供下次免登录
    if (CFG.keepOpen) {
      log('浏览器保持打开（config.keepOpen=false 可自动关闭）。按 Ctrl+C 结束。');
      await new Promise(() => {});
    } else {
      await ctx.close();
    }
  }
}

if (require.main === module) main();

// 供测试用：这些都是纯函数，不碰网络
module.exports = { CFG, PERIODS, slotCapFor, parseSlots, availableCells, pickPreferred, pickFallback, renderMatrix, buildSpaces, api, classify, syncClock, resolveTargetDate, openInApp };
