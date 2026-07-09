/**
 * middleware/csrf.js
 *
 * CSRF protection for AD Web Console.
 *
 * Uses the "double-submit cookie" pattern via the `csrf-csrf` package,
 * which is the modern replacement for the deprecated `csurf` package.
 *
 * SETUP
 * -----
 * 1. Install the package:
 *      npm install csrf-csrf
 *
 * 2. Mount this middleware in server.js AFTER session and cookie-parser:
 *
 *      const { csrfMiddleware, generateToken } = require('./middleware/csrf');
 *
 *      // Protect all state-changing routes
 *      app.use(csrfMiddleware);
 *
 *      // Make the token available in all EJS templates
 *      app.use((req, res, next) => {
 *        res.locals.csrfToken = generateToken(req, res);
 *        next();
 *      });
 *
 * 3. Add the token to every HTML form in your EJS templates:
 *
 *      <input type="hidden" name="_csrf" value="<%= csrfToken %>">
 *
 * 4. For AJAX/fetch calls, send the token in the header:
 *
 *      fetch('/api/users', {
 *        method: 'POST',
 *        headers: { 'x-csrf-token': document.querySelector('meta[name="csrf-token"]').content },
 *        body: JSON.stringify(data)
 *      });
 *
 *    And in your layout EJS template add:
 *      <meta name="csrf-token" content="<%= csrfToken %>">
 */

const { doubleCsrf } = require('csrf-csrf');

const {
  generateToken,      // Call this to get a token for a response
  doubleCsrfProtection, // Express middleware — validates the token on POST/PUT/DELETE/PATCH
} = doubleCsrf({
  /**
   * The secret used to sign the CSRF token.
   * Must be the same SESSION_SECRET used for express-session —
   * so both are invalidated together if the secret rotates.
   */
  getSecret: () => process.env.SESSION_SECRET,

  /**
   * Cookie name for the CSRF double-submit cookie.
   * Prefixed with __Host- so the browser enforces:
   *   - Secure flag required
   *   - Path must be /
   *   - No Domain attribute (can't be sent cross-origin)
   * This prefix provides strong CSRF resistance by itself.
   * NOTE: __Host- prefix only works over HTTPS.
   * For HTTP-only dev environments, change to '_csrf' and set secure: false.
   */
  cookieName: process.env.NODE_ENV === 'production'
    ? '__Host-adwc.csrf'
    : '_adwc.csrf',

  cookieOptions: {
    httpOnly: true,
    sameSite: 'strict',   // Blocks cross-site requests entirely
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: 60 * 60 * 8,  // 8 hours — matches default session lifetime
  },

  /**
   * Which HTTP methods to protect.
   * GET/HEAD/OPTIONS are safe methods (no side effects) — skip them.
   */
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],

  /**
   * Where to look for the submitted token.
   * Checks (in order): request body field, then custom header.
   */
  getTokenFromRequest: (req) =>
    req.body?._csrf || req.headers['x-csrf-token'],

  /**
   * Token size in bytes. 32 = 256 bits, well above OWASP minimum.
   */
  size: 32,
});

/**
 * Error handler — intercepts CSRF validation failures and returns
 * a clean 403 instead of crashing the process.
 */
const csrfErrorHandler = (err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN' || err.message?.includes('csrf')) {
    const ip = req.ip || req.connection?.remoteAddress;
    // Log the violation — your Winston logger should be available here
    console.warn(`[CSRF] Rejected ${req.method} ${req.path} from ${ip} | user: ${req.session?.user?.username || 'unauthenticated'}`);
    return res.status(403).render('error', {
      title: 'Forbidden',
      message: 'Invalid or missing CSRF token. Please reload the page and try again.',
    });
  }
  next(err);
};

/**
 * Combined middleware array — mount both in server.js:
 *
 *   app.use(csrfMiddleware);
 *   app.use(csrfErrorHandler);
 */
const csrfMiddleware = doubleCsrfProtection;

module.exports = {
  csrfMiddleware,
  csrfErrorHandler,
  generateToken,
};
