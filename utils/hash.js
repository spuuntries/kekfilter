const crypto = require("crypto");

/**
 * Hash a string using sha256
 * @param {string} str - The string to hash
 * @returns {string} The hashed string
 * @example
 * hash('hello world')
 * // => '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
 */
function hash(str) {
  return crypto.createHash("sha256").update(str).digest("hex");
}

module.exports = { hash };
