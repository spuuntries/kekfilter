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
  { URL } = require("url"),
  dns = require("dns"),
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
  logger(
    `Current safe URLs list: `,
    dbops.safeurls.map((e) => "- " + e).join("/n")
  );
});

var reportedList = [];

/**
 * Command handler
 *
 * @param {Discord.Message} message The message object
 * @returns {void}
 * @example
 * cmdHandler(message);
 */
function cmdHandler(message) {
  if (
    message.author.bot ||
    message.channel.type === "dm" ||
    !message.content.toLowerCase().startsWith("kek!filter")
  )
    return;

  // Check if author has staff role
  if (
    !message.author.member.roles.filter((r) => r.name.toLowerCase() == "staff")
      .length > 0
  ) {
    message.reply(
      "You do not have the required permissions to use this command."
    );
    return;
  }

  // Get args
  let args = message.content.slice("kek!filter".length).trim().split(/ +/g),
    commandAndPrefix = args.shift().toLowerCase();

  // Check if number of args is correct
  if (args.length < 1) {
    message.reply("You need to specify a subcommand!");
    return;
  } else if (args.length > 2) {
    message.reply("Too many arguments!");
    return;
  }

  // Check if subcommand is valid
  switch (args[0]) {
    case "allow":
      if (args.length < 2) {
        message.reply(
          "You need to specify a URL to add to the exception list!"
        );
        return;
      }
      let url = args[1];
      try {
        url = new URL(args[1]).host;
      } catch (e) {
        message.reply("You need to specify a valid URL!");
        return;
      }
      db.push("safeurls", url);
      break;
    case "remove":
      if (args.length < 2) {
        message.reply(
          "You need to specify a URL to remove from the exception list!"
        );
        return;
      }
      let remUrl = args[1];
      try {
        remUrl = new URL(args[1]).host;
      } catch (e) {
        message.reply("You need to specify a valid URL!");
        return;
      }
      if (!dbops.safeurls.includes(remUrl)) {
        message.reply("That URL is not in the exception list!");
        return;
      }
      db.set(
        "safeurls",
        dbops.safeurls.filter((u) => u != remUrl)
      );
      break;
    default:
      message.reply("Invalid subcommand!");
      return;
  }
}

client.on("messageCreate", async (message) => {
  if (message.author.bot) return;
  if (message.content.toLowerCase().startsWith("kek!filter"))
    cmdHandler(message);

  let splitMessage = message.content
      .split(/ +/g)
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
      try {
        let url = new URL(m).host;
        clean =
          url.split(".").length > 2 ? url.split(".").slice(1).join(".") : url;
      } catch (e) {
        dns.lookup(
          m.split("/")[0],
          (e, a, f) =>
            (clean =
              e || a == process.env.ISPBULLSHIT ? "fake://" + clean : clean)
        );
      } finally {
        clean = clean.toLowerCase();
        if (dbops.safeurls.includes(clean)) return "";

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
