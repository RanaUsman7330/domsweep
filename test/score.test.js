import test from 'node:test';
import assert from 'node:assert/strict';
import { scoreIssues, grade, worstLevel } from '../src/score.js';

test('a clean domain scores 100', () => {
  assert.equal(scoreIssues([]).score, 100);
});

test('severity is weighted', () => {
  assert.equal(scoreIssues([{ level: 'critical' }]).score, 75);
  assert.equal(scoreIssues([{ level: 'warning' }]).score, 92);
  assert.equal(scoreIssues([{ level: 'info' }]).score, 100);
});

test('the score floors at zero rather than going negative', () => {
  const many = Array.from({ length: 12 }, () => ({ level: 'critical' }));
  assert.equal(scoreIssues(many).score, 0);
});

test('counts are returned per level', () => {
  const { counts } = scoreIssues([{ level: 'critical' }, { level: 'warning' }, { level: 'warning' }]);
  assert.deepEqual(counts, { critical: 1, warning: 2, info: 0 });
});

test('grades map to the expected bands', () => {
  assert.equal(grade(100), 'A');
  assert.equal(grade(90), 'A');
  assert.equal(grade(89), 'B');
  assert.equal(grade(60), 'C');
  assert.equal(grade(0), 'F');
});

test('worst level wins', () => {
  assert.equal(worstLevel([{ level: 'warning' }, { level: 'critical' }]), 'critical');
  assert.equal(worstLevel([{ level: 'info' }, { level: 'warning' }]), 'warning');
  assert.equal(worstLevel([{ level: 'info' }]), 'ok');
  assert.equal(worstLevel([]), 'ok');
});
