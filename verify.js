// 验证本轮改动：webdriver 指纹、每请求超时是否真的覆盖 50s、错误分类
const { chromium } = require('playwright-core');
const os = require('os');
const path = require('path');
const { api, classify, syncClock } = require('./booker.js');

const ORIGIN = 'https://sports.sjtu.edu.cn';
let fail = 0;
const chk = (name, ok, extra = '') => { if (!ok) fail++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? '   ' + extra : ''}`); };

(async () => {
  const ctx = await chromium.launchPersistentContext(path.join(os.tmpdir(), 'sjtu-verify'), {
    channel: 'msedge', headless: true,
    args: ['--disable-blink-features=AutomationControlled'],
  });
  const page = ctx.pages()[0] || (await ctx.newPage());
  await page.goto(`${ORIGIN}/pc/`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => !!document.querySelector('#app')?.__vue__, null, { timeout: 30000 });

  // 1) 自动化指纹
  const wd = await page.evaluate(() => navigator.webdriver);
  chk('navigator.webdriver 为 false', wd === false, `实际=${wd}`);

  // 2) 站点 axios 默认仍是 50s（证明我们必须逐请求覆盖）
  const dflt = await page.evaluate(() => document.querySelector('#app').__vue__.$ajax.defaults.timeout);
  chk('站点默认 timeout 确为 50000', dflt === 50000, `实际=${dflt}`);

  // 3) 极短超时必须真的触发，而不是等满 50 秒
  const t0 = Date.now();
  const r1 = await api(page, { method: 'get', url: '/system/user/currentUser', timeout: 1 });
  const el = Date.now() - t0;
  chk('timeout=1ms 立即返回（未继承 50s）', el < 3000, `耗时 ${el}ms`);
  chk('超时被识别为 timeout', classify(r1) === 'timeout', `classify=${classify(r1)} timedOut=${r1.timedOut} status=${r1.status}`);

  // 4) 正常请求带回 ms
  const r2 = await api(page, { method: 'get', url: '/system/user/currentUser', timeout: 5000 });
  chk('正常请求返回 ms 计时', typeof r2.ms === 'number' && r2.ms >= 0, `ms=${r2.ms} ok=${r2.ok} status=${r2.status}`);

  // 5) 未登录时 302->/login 不能被当成 ok（本 profile 未登录）
  console.log(`      未登录探测: ok=${r2.ok} status=${r2.status} kind=${classify(r2)} body=${JSON.stringify(r2.body)?.slice(0, 80)}`);

  // 6) 对冲：阈值极小必然触发第二发，结果仍应正常
  const r3 = await api(page, { method: 'get', url: '/system/user/currentUser', timeout: 5000, hedgeAfterMs: 1 });
  chk('对冲后仍能拿到结果', r3 && typeof r3.ms === 'number', `hedged=${r3.hedged} ms=${r3.ms}`);

  // 7) 会话失效：后端 302 到 /login，axios 跟随后是 HTML + HTTP 200。
  //    这是最隐蔽的误判源 —— 必须归为 session 而不是 ok。
  const r4 = await api(page, {
    url: '/manage/fieldDetail/queryFieldReserveSituationIsFull',
    data: { id: 'x', feildType: 'x', date: '2026-01-01' }, timeout: 5000,
  });
  chk('未登录业务接口判为 auth（HTTP200 + code401）', classify(r4) === 'auth',
    `status=${r4.status} code=${r4.body?.code} kind=${classify(r4)}`);

  // 8) 非 JSON 响应（拿 HTML 页面模拟）必须判为 session，不能当 ok
  const r5 = await api(page, { method: 'get', url: '/pc/', timeout: 5000 });
  chk('HTML 响应判为 session', classify(r5) === 'session', `kind=${classify(r5)} bodyType=${typeof r5.body}`);

  // 9) 对时诊断：本机校准后，剩下的就是服务器相对真实时间的偏差
  console.log('\n--- 对时诊断 ---');
  const now1 = await syncClock(page);
  const off1 = now1().getTime() - Date.now();
  const now2 = await syncClock(page);
  const off2 = now2().getTime() - Date.now();
  console.log(`两轮偏移 ${Math.round(off1)}ms / ${Math.round(off2)}ms，极差 ${Math.abs(Math.round(off1 - off2))}ms`);
  chk('时钟偏移在 ±5s 内（本机已校准）', Math.abs(off1) < 5000 && Math.abs(off2) < 5000,
    `若超出说明本机或服务器时钟有问题`);

  console.log(fail === 0 ? '\n全部通过' : `\n${fail} 项失败`);
  await ctx.close();
  process.exit(fail === 0 ? 0 : 1);
})();
