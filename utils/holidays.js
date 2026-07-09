'use strict';
// Common public holidays - can be extended via settings
function getHolidays(year) {
  year = year || new Date().getFullYear();
  // US Federal Holidays as a sensible default set; orgs can customize via settings.orgHolidays
  return [
    { date: year+'-01-01', name: "New Year's Day" },
    { date: year+'-07-04', name: 'Independence Day' },
    { date: year+'-11-11', name: 'Veterans Day' },
    { date: year+'-12-25', name: 'Christmas Day' },
    { date: year+'-12-31', name: "New Year's Eve" },
  ];
}

function getUpcomingHolidays(customHolidays, limit) {
  var now = new Date();
  var year = now.getFullYear();
  var all = getHolidays(year).concat(getHolidays(year+1));
  if (Array.isArray(customHolidays)) {
    customHolidays.forEach(function(h) {
      if (h.date && h.name) all.push(h);
    });
  }
  var upcoming = all.filter(function(h) {
    return new Date(h.date + 'T23:59:59') >= now;
  }).sort(function(a,b) { return new Date(a.date) - new Date(b.date); });
  return upcoming.slice(0, limit || 5);
}

module.exports = { getHolidays, getUpcomingHolidays };
