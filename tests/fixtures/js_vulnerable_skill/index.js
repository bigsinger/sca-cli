/**
 * Vulnerable JavaScript skill module.
 * Uses known vulnerable dependency versions.
 */

const _ = require("lodash");

function mergeObjects(target, source) {
  return _.merge(target, source);
}

function get(object, path, defaultValue) {
  return _.get(object, path, defaultValue);
}

module.exports = { mergeObjects, get };
