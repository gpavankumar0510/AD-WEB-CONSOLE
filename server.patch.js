/**
 * server.patch.js
 * ───────────────
 * This is NOT a standalone file — it shows exactly how to update your
 * existing server.js to add CSRF protection, force LDAPS warning,
 * and auto-generate a session secret check.
 *
 * Search for each SECTION comment below and apply the changes to server.js.
 */

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 1 — Add to the top of server.js, after your existing requires
// ─────────────────────────────────────────────────────────────────────────────

const { csrfMiddleware, csrfErrorHandler, generateToken } = require('./middleware/csrf');

// Startup security checks — warn loudly before anything else initialises
(function runSecurityChecks() {
  const errors = [];
  const warnings = [];

  // 1. SESSION_SECRET must be set and strong
  if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
    errors.push('SESSION_SECRET is missing or too short (minimum 32 chars). Generate one with: node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'hex\'))"');
  }
  if (process.env.SESSION_SECRET === 'change-this-to-64-random-chars') {
    errors.push('SESSION_SECRET is still the example placeholder. Change it before starting.');
  }

  // 2. Local admin password must be changed
  if (process.env.LOCAL_ADMIN_PASSWORD === 'Admin@Console2025!') {
    errors.push('LOCAL_ADMIN_PASSWORD is still the example value. Change it immediately.');
  }

  // 3. Warn about plain LDAP in production
  if (process.env.NODE_ENV === 'production' && process.env.AD_HOST?.startsWith('ldap://')) {
    warnings.push('AD_HOST uses plain ldap:// (unencrypted). Change to ldaps:// for production.');
  }

  if (warnings.length) {
    warnings.forEach(w => console.warn(`\x1b[33m[SECURITY WARNING]\x1b[0m ${w}`));
  }
  if (errors.length) {
    errors.forEach(e => console.error(`\x1b[31m[SECURITY ERROR]\x1b[0m ${e}`));
    console.error('\x1b[31mServer startup aborted due to security configuration errors.\x1b[0m');
    process.exit(1);
  }
})();


// ─────────────────────────────────────────────────────────────────────────────
// SECTION 2 — Add CSRF middleware AFTER session + cookieParser, BEFORE routes
// Your existing code probably looks like:
//
//   app.use(session({...}));
//   app.use(express.urlencoded({ extended: true }));
//   // ... routes here
//
// Add the lines marked with ← NEW between session and routes:
// ─────────────────────────────────────────────────────────────────────────────

// ← NEW: CSRF protection on all state-changing routes
app.use(csrfMiddleware);

// ← NEW: Expose CSRF token to all EJS templates via res.locals
app.use((req, res, next) => {
  res.locals.csrfToken = generateToken(req, res);
  next();
});


// ─────────────────────────────────────────────────────────────────────────────
// SECTION 3 — Add CSRF error handler AFTER all routes, before your generic
// error handler. Your existing error section probably looks like:
//
//   app.use((err, req, res, next) => { ... });
//
// Add csrfErrorHandler BEFORE it:
// ─────────────────────────────────────────────────────────────────────────────

// ← NEW: Must come before your generic error handler
app.use(csrfErrorHandler);

// Your existing generic error handler stays here
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).render('error', { title: 'Error', message: 'Something went wrong.' });
});


// ─────────────────────────────────────────────────────────────────────────────
// SECTION 4 — Update your EJS layout template (views/layout.ejs or similar)
//
// Add inside <head>:
//   <meta name="csrf-token" content="<%= csrfToken %>">
//
// Add inside EVERY <form> that uses POST/PUT/DELETE:
//   <input type="hidden" name="_csrf" value="<%= csrfToken %>">
//
// Example form before:
//   <form method="POST" action="/users/create">
//     <input name="username"> <button type="submit">Create</button>
//   </form>
//
// Example form after:
//   <form method="POST" action="/users/create">
//     <input type="hidden" name="_csrf" value="<%= csrfToken %>">
//     <input name="username"> <button type="submit">Create</button>
//   </form>
//
// For fetch/XHR calls in your client JS, add a header:
//   fetch('/api/users', {
//     method: 'POST',
//     headers: {
//       'Content-Type': 'application/json',
//       'x-csrf-token': document.querySelector('meta[name="csrf-token"]').content
//     },
//     body: JSON.stringify(payload)
//   });
// ─────────────────────────────────────────────────────────────────────────────
