/**
 * Several RDAP endpoints reject requests that arrive without a User-Agent,
 * which is easy to miss because the failure is a 403 rather than an error.
 */
export const USER_AGENT = 'domsweep/0.1.1 (+https://github.com/RanaUsman7330/domsweep)';
