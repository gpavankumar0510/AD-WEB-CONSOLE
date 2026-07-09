'use strict';
function getAdminGroups() {
  var s = require('./autoDetect').getSettings();
  var groups = s.adminGroups || ['Domain Admins','Administrators','Enterprise Admins'];
  return groups.map(function(g) { return g.toLowerCase(); });
}
function determineRole(user) {
  if (!user) return 'user';
  if (user.isLocal) return 'admin';
  if (user.role === 'admin') return 'admin';
  var memberOf = Array.isArray(user.memberOf) ? user.memberOf : (user.memberOf ? [user.memberOf] : []);
  var adminGroups = getAdminGroups();
  var isAdmin = memberOf.some(function(g) { return adminGroups.some(function(a) { return g.toLowerCase().indexOf('cn='+a+',') >= 0; }); });
  return isAdmin ? 'admin' : 'user';
}
var PERMISSIONS = {
  admin: ['dashboard.view','users.view','users.create','users.edit','users.delete','users.resetPassword','users.unlock','users.disable','users.viewGroups','users.manageGroups','computers.view','computers.disable','computers.delete','gpo.view','gpo.create','gpo.edit','gpo.delete','gpo.link','gpo.import','backup.view','backup.run'],
  user:  ['dashboard.view','self.viewProfile','self.editProfile','self.changePassword','self.viewGroups','self.viewGPOs','self.viewBackup'],
};
function hasPermission(session, permission) {
  if (!session || !session.admin) return false;
  return (PERMISSIONS[session.admin.role || 'user'] || []).indexOf(permission) >= 0;
}
function requirePermission(permission) {
  return function(req, res, next) {
    if (!req.session.admin) return res.redirect('/login');
    if (!hasPermission(req.session, permission)) return res.status(403).render('error', { code: 403, message: 'Access Denied', admin: req.session.admin });
    next();
  };
}
function requireAuth(req, res, next) { if (!req.session.admin) return res.redirect('/login'); next(); }
module.exports = { determineRole, hasPermission, requirePermission, requireAuth, PERMISSIONS };
