'use strict';

// AD-style password complexity check (matches default Windows policy)
function checkComplexity(password, username, displayName) {
  var errors = [];
  if (!password || password.length < 8) errors.push('Must be at least 8 characters long');
  if (password && password.length > 256) errors.push('Must be less than 256 characters');

  var categories = 0;
  if (/[a-z]/.test(password)) categories++;
  if (/[A-Z]/.test(password)) categories++;
  if (/[0-9]/.test(password)) categories++;
  if (/[^a-zA-Z0-9]/.test(password)) categories++;
  if (categories < 3) errors.push('Must contain at least 3 of: lowercase, uppercase, numbers, symbols');

  // Cannot contain username
  if (username && password.toLowerCase().indexOf(username.toLowerCase()) >= 0) {
    errors.push('Cannot contain the username');
  }
  // Cannot contain parts of display name (3+ char chunks)
  if (displayName) {
    var parts = displayName.split(/[\s,]+/).filter(function(p) { return p.length >= 3; });
    for (var i = 0; i < parts.length; i++) {
      if (password.toLowerCase().indexOf(parts[i].toLowerCase()) >= 0) {
        errors.push('Cannot contain parts of your name');
        break;
      }
    }
  }

  return { valid: errors.length === 0, errors: errors };
}

// Score a password 0-100 for UI strength meter
function scorePassword(password) {
  if (!password) return 0;
  var score = 0;
  score += Math.min(password.length * 4, 40);
  if (/[a-z]/.test(password)) score += 10;
  if (/[A-Z]/.test(password)) score += 10;
  if (/[0-9]/.test(password)) score += 10;
  if (/[^a-zA-Z0-9]/.test(password)) score += 15;
  if (password.length >= 12) score += 10;
  if (password.length >= 16) score += 5;
  return Math.min(score, 100);
}

module.exports = { checkComplexity, scorePassword };
