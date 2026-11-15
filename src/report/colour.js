const CODES = {
  reset: '\u001b[0m', bold: '\u001b[1m', dim: '\u001b[2m',
  red: '\u001b[31m', green: '\u001b[32m', yellow: '\u001b[33m',
  blue: '\u001b[34m', grey: '\u001b[90m',
};

export function createColour(enabled) {
  const wrap = (code) => (s) => (enabled ? `${CODES[code]}${s}${CODES.reset}` : String(s));
  return {
    enabled,
    bold: wrap('bold'), dim: wrap('dim'), red: wrap('red'),
    green: wrap('green'), yellow: wrap('yellow'), blue: wrap('blue'), grey: wrap('grey'),
  };
}

/** Visible width, ignoring any escape sequences already embedded. */
export function width(s) {
  return String(s).replace(/\u001b\[[0-9;]*m/g, '').length;
}

export function pad(s, n) {
  return String(s) + ' '.repeat(Math.max(0, n - width(s)));
}
