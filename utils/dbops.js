/**
 * Redundant DB operations
 * @param {String} dbpath DB path, defaults to `./data/data.sqlite`.
 */
module.exports = function (dbpath = "./data/data.sqlite") {
  var module = {};
  const path = require("path"),
    axios = require("axios").default,
    logger = require("./logger.js"),
    safe = require("./safe.js"),
    quickdb = require("quick.db"),
    db = quickdb(dbpath);

  /**
   * Cacheing the list every 1 hour
   */
  function cacheList() {
    try {
      axios
        .get(
          "https://raw.githubusercontent.com/relative/discord-bad-domains/master/plain.TXT"
        )
        .then((res) => {
          if (!res.status == 200 || !typeof res.data == "string") return;
          let filteredList = res.data.split("\n").filter((e) => e.length > 80);
          db.set("domainList", filteredList);
        });

      axios
        .get("https://cdn.discordapp.com/bad-domains/hashes.json")
        .then((res) => {
          if (!res.status == 200 || !typeof res.data == "object") return;
          db.set("hashList", res.data);
        });

      setTimeout(cacheList, 3600000);
    } catch (e) {
      console.log(e);
    }
  }

  cacheList();

  // Check if safeurls are defined, if not set it to the safeurls array
  if (!db.get("safeurls")) db.set("safeurls", safe);

  module.safeurls = db.get("safeurls");

  /**
   * Get current cache of phishing domains list
   * @returns {Array<String>} Array of phishing domains
   * @example
   * getDomainList()
   * // => ['example.com', 'example.net', 'example.org']
   */
  module.getDomainList = function () {
    return db.get("domainList");
  };

  /**
   * Get current cache of phishing hashes list
   * @returns {Array<String>} Array of phishing hashes
   * @example
   * getHashList()
   * // => ['fe3fe392794a3fc140b06c339878d96ed57380932bda764aea7c677a821c1776', 'fe3fe392794a3fc140b06c339878d96ed57380932bda764aea7c677a821c1776']
   */
  module.getHashList = function () {
    return db.get("hashList");
  };

  /** Internal DB client */
  module.db = db;

  return module;
};
