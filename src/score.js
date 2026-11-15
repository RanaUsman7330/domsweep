/**
 * One number per domain so a sweep of hundreds can be sorted by urgency.
 * Deductions are weighted by severity and the score floors at zero: a domain
 * with five critical problems is not meaningfully worse than one with four.
 */
export const WEIGHTS = { critical: 25, warning: 8, info: 0 };

export function scoreIssues(issues = []) {
  const counts = { critical: 0, warning: 0, info: 0 };
  let deduction = 0;

  for (const issue of issues) {
    const level = issue.level in counts ? issue.level : 'info';
    counts[level] += 1;
    deduction += WEIGHTS[level];
  }

  return { score: Math.max(0, 100 - deduction), counts };
}

export function grade(score) {
  // A domain whose checks did not complete has no grade. Scoring it anyway
  // would hand out an A for a domain nothing is known about.
  if (score === null || score === undefined) return '?';
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

/** Worst severity present, used for CI exit codes. */
export function worstLevel(issues = []) {
  if (issues.some((i) => i.level === 'critical')) return 'critical';
  if (issues.some((i) => i.level === 'warning')) return 'warning';
  return 'ok';
}
