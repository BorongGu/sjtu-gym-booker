// 跡测选位逻辑（纯函数，不联网）。造一个假矩阵覆盖各种情况。
const B = require('./booker.js');
const { CFG, PERIODS, slotCapFor, parseSlots, availableCells, pickPreferred, pickFallback, renderMatrix, buildSpaces } = B;

let fail = 0;
const eq = (name, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `\n      got  ${JSON.stringify(got)}\n      want ${JSON.stringify(want)}`}`);
};

// —— 单次上限：逆自 handleChooseSeat ——
eq('cap 正常(0) = 不限', slotCapFor(0), null === null ? Infinity : 0);
eq('cap 紧张(1) = 2', slotCapFor(1), 2);
eq('cap 很紧张(2) = 2', slotCapFor(2), 2);
eq('cap 非常紧张(3) = 1', slotCapFor(3), 1);
eq('cap 很紧张签退(4) = 2', slotCapFor(4), 2);
// 实测接口返回的 tension 是字符串，必须同样生效
eq('cap 字符串 "4" = 2', slotCapFor('4'), 2);
eq('cap 字符串 "3" = 1', slotCapFor('3'), 1);
eq('cap 字符串 "0" = 不限', slotCapFor('0'), Infinity);

// —— 时段校验：写错必须抛错，不能静默 ——
eq('合法时段 -> 行号', parseSlots(['14:00-15:00', '15:00-16:00'], 't'), [7, 8]);
let threw = null;
try { parseSlots(['19:00', '14:00-15:00'], 'config.slots'); } catch (e) { threw = e.message; }
eq('非法时段必须抛错', threw !== null, true);
console.log(`      报错信息: ${String(threw).split('\n')[0]}`);

// —— 假矩阵：2 个场地 × 15 行 ——
// A 场地：只剩 09:00-10:00(2) 和 16:00-17:00(9)
// B 场地：只剩 15:00-16:00(8) 和 21:00-22:00(14)
// 注意 status 用字符串：实测接口返回的就是 "0"/"-1"，数字比较会全部落空
const mk = (name, id, openRows) => ({
  fieldName: name,
  fieldId: id,
  fieldDetailStatus: 1,
  priceList: PERIODS.map((_, r) => ({ price: 10, status: openRows.includes(r) ? '0' : '-1' })),
});
const fields = [mk('A区', 'fa', [2, 9]), mk('B区', 'fb', [8, 14])];

CFG.fields = [];
const cells = availableCells(fields);
eq('字符串 "0" 必须识别为可约', cells.length, 4);
// 空值不能被 Number(null)===0 误判成可约
eq('status 为 null 不算可约',
  availableCells([{ fieldName: 'X', fieldId: 'x', priceList: [{ status: null }, { status: undefined }, { status: '0' }] }]).length, 1);
eq('可约格子数', cells.length, 4);
eq('可约行号', cells.map((c) => c.row).sort((a, b) => a - b), [2, 8, 9, 14]);

// 心仪 14:00-15:00(7) + 15:00-16:00(8)：只有 8 有位
const pref = [7, 8];
eq('心仪命中 15:00-16:00', pickPreferred(cells, pref, 2).map((c) => c.slotName), ['15:00-16:00']);
eq('心仪全满时为空', pickPreferred(cells, [0, 1], 2).length, 0);
eq('cap=1 时只取 1 个', pickPreferred(availableCells([mk('A区', 'fa', [7, 8])]), pref, 1).map((c) => c.slotName), ['14:00-15:00']);

// 兜底 nearest：排除心仪行(7,8)后剩 2,9,14；距 {7,8} 距离 = 9->1, 2->5, 14->6
eq('兜底 nearest 顺序', pickFallback(cells, pref, 3, 'nearest').map((c) => c.slotName),
  ['16:00-17:00', '09:00-10:00', '21:00-22:00']);
eq('兜底 nearest 取 2 个', pickFallback(cells, pref, 2, 'nearest').map((c) => c.slotName),
  ['16:00-17:00', '09:00-10:00']);

// 兜底 later：一律越晚越优先 -> 14, 9, 2
eq('兜底 later 顺序', pickFallback(cells, pref, 3, 'later').map((c) => c.slotName),
  ['21:00-22:00', '16:00-17:00', '09:00-10:00']);

// 同距离时晚的优先：心仪 8，剩 7 和 9 距离都是 1
const tie = availableCells([mk('A区', 'fa', [7, 9])]);
eq('同距离时晚的优先', pickFallback(tie, [8], 2, 'nearest').map((c) => c.slotName),
  ['16:00-17:00', '14:00-15:00']);

// —— spaces 构造：字段注入 + price -> venuePrice ——
const spaces = buildSpaces(pickFallback(cells, pref, 2, 'nearest'));
eq('spaces 条数', spaces.length, 2);
eq('price 已改名 venuePrice', Object.keys(spaces[0]).sort(),
  ['scheduleTime', 'status', 'subSiteId', 'subSitename', 'tensity', 'venueNum', 'venuePrice'].sort());
eq('注入 venueNum/status', [spaces[0].venueNum, spaces[0].status], [1, 1]);
eq('scheduleTime 正确', spaces[0].scheduleTime, '16:00-17:00');
eq('subSiteId 正确', spaces[0].subSiteId, 'fa');

// —— fields 过滤 ——
CFG.fields = ['B区'];
eq('fields 过滤只留 B区', availableCells(fields).map((c) => c.slotName), ['15:00-16:00', '21:00-22:00']);
CFG.fields = [];

// —— 心仪不足 cap 时用兜底补位 ——
{
  // 心仪 [13,14]，只有 13 有位；另有 9、11 可用
  const c2 = availableCells([mk('A区', 'fa', [9, 11, 13])]);
  const pref2 = [13, 14];
  const got = pickPreferred(c2, pref2, 2);
  eq('心仪只命中 1 个', got.map((c) => c.slotName), ['20:00-21:00']);

  // later 模式补位：剩余里最晚的是 11(18:00-19:00)
  const upLater = pickFallback(c2, pref2, 2 - got.length, 'later', got.map((c) => c.row));
  eq('later 补位取最晚的', upLater.map((c) => c.slotName), ['18:00-19:00']);

  // nearest 模式补位：距 {13,14} 最近的是 11
  const upNear = pickFallback(c2, pref2, 2 - got.length, 'nearest', got.map((c) => c.row));
  eq('nearest 补位取最近的', upNear.map((c) => c.slotName), ['18:00-19:00']);

  // 补位绝不能重复已选中的行
  eq('补位不与已选重复', upLater.some((c) => c.row === 13), false);

  // 已经凑满 cap 时不补位
  const full = pickPreferred(availableCells([mk('A区', 'fa', [13, 14])]), pref2, 2);
  eq('心仪已满不需要补位', full.length, 2);
}

// —— 服务端规则：同一时段不允许预约多个场地，选位必须按时段去重 ——
{
  // 两个房间都只在 row 5 有空位 —— 绝不能同时选中
  const sameRow = availableCells([mk('B301', 'b1', [5]), mk('D401', 'd1', [5])]);
  eq('同一时段两个场地只取一个', pickFallback(sameRow, [7, 8], 2, 'nearest').length, 1);

  // row 5 有两间、row 9 有一间 -> 应取两个不同时段
  const mixed = availableCells([mk('B301', 'b1', [5, 9]), mk('D401', 'd1', [5])]);
  const got = pickFallback(mixed, [7, 8], 2, 'nearest');
  eq('跨时段可取两个', got.length, 2);
  eq('两个时段必须不同', new Set(got.map((c) => c.row)).size, 2);

  // 心仪路径同样要去重
  const pref = availableCells([mk('B301', 'b1', [7]), mk('D401', 'd1', [7])]);
  eq('心仪同一时段也只取一个', pickPreferred(pref, [7], 2).length, 1);
}

// —— 安全上限：tension=0 时 cap 为 Infinity，兜底会 slice(0,Infinity) 抓走全场 ——
{
  const many = availableCells([mk('A区', 'fa', [2, 3, 4, 9, 10, 11, 12, 13, 14])]);
  eq('tension=0 的 cap 确实是 Infinity', slotCapFor('0'), Infinity);
  eq('不设限时兜底会抓走全部空位', pickFallback(many, [7, 8], Infinity, 'nearest').length, 9);
  eq('收敛到 2 之后只取 2 个', pickFallback(many, [7, 8], 2, 'nearest').length, 2);
  eq('收敛到 1 之后只取 1 个', pickFallback(many, [7, 8], 1, 'nearest').length, 1);
}

// —— targetDate 跨午夜必须重算：头天晚上挂脚本、等到次日 12:00 才触发的场景 ——
{
  const { resolveTargetDate } = B;
  const old = CFG.targetDate;
  CFG.targetDate = '+7';
  const night = new Date('2026-09-16T23:00:00');
  const noon = new Date('2026-09-17T12:00:00');
  const before = resolveTargetDate(() => night);
  const after = resolveTargetDate(() => noon);
  eq('晚上算出的目标日期', before, '2026-09-23');
  eq('次日中午应重算为后一天', after, '2026-09-24');
  eq('两者必须不同（故必须复核）', before !== after, true);
  CFG.targetDate = '2026-10-01';
  eq('写死日期不受影响', resolveTargetDate(() => noon), '2026-10-01');
  CFG.targetDate = old;
}

console.log('\n--- 矩阵渲染 ---');
console.log(renderMatrix(fields));

console.log(fail === 0 ? '\n全部通过' : `\n${fail} 项失败`);
process.exit(fail === 0 ? 0 : 1);
