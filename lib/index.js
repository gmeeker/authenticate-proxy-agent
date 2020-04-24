const agent = require('./agent');
const resolve = require('./resolve');
const session = require('./session');

module.exports = {
  ...agent,
  ...resolve,
  ...session,
};
