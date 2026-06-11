/**
 * Safe JavaScript skill module.
 * Exports utility functions without any malicious behavior.
 */

const _ = require("lodash");

function greet(name) {
  return `Hello, ${_.capitalize(name)}!`;
}

function sum(numbers) {
  return _.sum(numbers);
}

module.exports = { greet, sum };
