require("dotenv").config();

const Discord = require("discord.js"),
  client = new Discord.Client({
    intents: ["GUILDS", "GUILD_MEMBERS", "GUILD_MESSAGES"],
  }),
  pkg = require("./package.json"),
  logger = require("./utils/logger.js"),
  phishing = require("stop-discord-phishing"),
  dbops = require("./utils/dbops.js")("./data/data.sqlite"),
  db = dbops.db,
  safe = require("./utils/safe.js"),
  { URL } = require("url"),
  hashUtil = require("./utils/hash.js"),
  levenshtein = require("fast-levenshtein");

function login() {
  client.login(process.env.TOKEN).catch(() => {
    logger(`[${new Date()}] Failed to login! Retrying in 5 seconds...`);
    setTimeout(() => {
      login();
    }, 5000);
  });
}
login();

client.on("ready", () => {
  logger(
    `[${new Date()}] ${client.user.tag} using ${pkg.name} v${
      pkg.version
    } ready!`
  );
});

var reportedList = [];

client.on("messageCreate", async (message) => {
  if (message.author.bot) return;
  let splitMessage = message.content
      .split(" ")
      .join("\r")
      .split("\r")
      .join("\n")
      .split("\n"),
    stopPhishingList = await phishing.listDomains(),
    /** @type {Discord.TextChannel} */
    logChannel = await client.channels.fetch(process.env.REPORTCHANNEL),
    detected = [];

  splitMessage
    .map((m) => {
      let clean = m;
      if (safe.includes(clean)) return clean;
      try {
        clean = new URL(m).host;
      } finally {
        clean = clean.toLowerCase();
        return clean;
      }
    })
    .forEach((word) => {
      if (dbops.getDomainList().includes(word)) detected.push(word);
      // Use levenshtein distance to detect similar domains
      if (
        dbops
          .getDomainList()
          .filter((domain) => levenshtein.get(word, domain) < 2, {
            useCollator: true,
          }).length > 0
      )
        detected.push(word);
      if (dbops.getHashList().includes(hashUtil.hash(word)))
        detected.push(word);
      if (stopPhishingList.includes(word)) detected.push(word);
      if (
        stopPhishingList.filter((domain) => levenshtein.get(word, domain) < 2, {
          useCollator: true,
        }).length > 0
      )
        detected.push(word);
    });

  if (!detected.length > 0) return;

  logger(
    `[${new Date()}] Detected phishing attempt from ${message.author.tag} in #${
      message.channel.name
    }`
  );

  await message.delete();
  logger(`[${new Date()}] Deleted the message from ${message.author.tag}`);

  if (reportedList.filter((r) => r == message.author.id).length > 2) {
    logger(
      `[${new Date()}] ${
        message.author.tag
      } has been reported too many times, sending a critical alert...`
    );

    if (reportedList.filter((r) => r == message.author.id).length > 4) return;

    await logChannel.send(
      `🔥 **<@${message.author.id}> has been sending suspicious links too many times, please investigate!** 🔥`
    );

    reportedList.push(message.author.id);
    return;
  }

  if (reportedList.includes(message.author.id)) {
    reportedList.push(message.author.id);
    return;
  }

  if (!logChannel) return;

  // Create embed
  let joined = detected
      .map((e) => hashUtil.hash(e))
      .slice(0, 5)
      .join(",\n"),
    embed = new Discord.MessageEmbed()
      .setColor("#ff0000")
      .setTitle("⚠️ Phishing attempt detected!")
      .setDescription(
        `**${message.author.tag}** has attempted to send a phishing message in **<#${message.channel.id}>**`
      )
      .addField("Detected Phishing Domain Hashes:", joined)
      .setTimestamp();

  // Send embed
  try {
    await logChannel.send({ embeds: [embed] });
  } catch (err) {
    logger(`[${new Date()}] Failed to send embed to #${logChannel.name}`);
    logger(err);
  }

  logger(`[${new Date()}] Sent embed for ${message.author.tag}`);

  // Add to reported list
  reportedList.push(message.author.id);
});
