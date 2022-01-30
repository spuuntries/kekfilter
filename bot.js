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
  let safeurls = dbops.safeurls();
  logger(
    `[${new Date()}] ${client.user.tag} using ${pkg.name} v${
      pkg.version
    } ready!`
  );
  logger(
    `Current safe URLs list: \n${safeurls.map((e) => "- " + e).join("\n")}`
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
    !message.member.roles.cache.find((r) => r.name.toLowerCase() == "staff")
  ) {
    message.reply(
      "You do not have the required permissions to use this command."
    );
    return;
  }

  // Get args
  let args = message.content.trim().split(/ +/g),
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
      message.reply(`Added ${url} to the exception list!`);
      logger(
        `[${new Date()}] ${
          message.author.tag
        } added ${url} to the safe URL list!`
      );
      logger(
        `[${new Date()}] Current safe URLs list: \n${db
          .get("safeurls")
          .map((e) => "- " + e)
          .join("\n")}`
      );
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
      if (!dbops.safeurls().includes(remUrl)) {
        message.reply("That URL is not in the exception list!");
        return;
      }
      db.set(
        "safeurls",
        dbops.safeurls().filter((u) => u != remUrl)
      );
      message.reply(`Removed ${remUrl} from the exception list!`);
      logger(
        `[${new Date()}] ${
          message.author.tag
        } removed ${remUrl} from the exception list!`
      );
      logger(
        `[${new Date()}] Current safe URLs list: \n${db
          .get("safeurls")
          .map((e) => "- " + e)
          .join("\n")}`
      );
      break;
    case "list":
      let embed = new Discord.MessageEmbed()
        .setTitle("Safe URLs")
        .setDescription(
          `${dbops
            .safeurls()
            .map((e) => "- " + e)
            .join("\n")}`
        )
        .setColor("#c0ffee")
        .setFooter({
          text: `kekfilter`,
          iconURL: logChannel.guild.iconURL(),
        })
      message.reply({
        embeds: [embed],
        allowedMentions: { repliedUser: false },
      });
      break;
    case "help":
      let embed2 = new Discord.MessageEmbed()
        .setTitle("🤔 Filter Help 💡")
        .setDescription(
          `\n**kek!filter allow** \`<url>\` - Adds a URL to the exception list.\n**kek!filter remove** \`<url>\` - Removes a URL from the exception list.\n**kek!filter list** - Lists all URLs in the exception list.\n**kek!filter help** - Displays this help message.`
        )
        .setColor("#208075")
       .setFooter({
          text: `kekfilter`,
          iconURL: logChannel.guild.iconURL(),
        })
      message.reply({
        embeds: [embed2],
        allowedMentions: { repliedUser: false },
      });
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
  if (message.member.roles.cache.find((r) => r.name.toLowerCase() == "staff"))
    return;

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
        if (dbops.safeurls().includes(clean)) return "";

        return clean;
      }
    })
    .forEach((word) => {
      if (dbops.getDomainList().includes(word)) detected.push(word);
      // Use levenshtein distance to detect similar domains
      else if (
        dbops
          .getDomainList()
          .filter((domain) => levenshtein.get(word, domain) < 4, {
            useCollator: true,
          }).length > 0
      )
        detected.push(word);
      else if (dbops.getHashList().includes(hashUtil.hash(word)))
        detected.push(word);
      else if (stopPhishingList.includes(word)) detected.push(word);
      else if (
        stopPhishingList.filter((domain) => levenshtein.get(word, domain) < 4, {
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

  reportedList.push(message.author.id);

  if (reportedList.filter((r) => r == message.author.id).length > 2) {
    if (reportedList.filter((r) => r == message.author.id).length >= 5) {
      // Check if user is bannable
      if (!message.member.bannable) {
        logger(
          `[${new Date()}] ${
            message.author.tag
          } is not bannable, therefore not timeout-able, skipping...`
        );
        return;
      }

      // Timeout the user for the number of times they've triggered the system
      // minus 4 to account for headstart then multiplied
      // by 10 minutes in ms.
      let time =
        10 *
        60 *
        1000 *
        (reportedList.filter((r) => r == message.author.id).length - 4);
      logger(`[${new Date()}] Timing out ${message.author.tag} for ${time}ms`);
      await message.member.timeout(time);
      let embed = new Discord.MessageEmbed()
        .setTitle("⚠️ You have been timed out!")
        .setDescription(
          `You have been timed out for ${
            10 * (reportedList.filter((r) => r == message.author.id).length - 4)
          } minutes for triggering our phishing detection system too many times.`
        )
        .setColor("#c0ffee")
        .setAuthor({
          name: `Suspect: ${message.author.tag}`,
          iconURL: message.author.avatarURL(),
        })
        .setFooter({
          text: `If you believe this is a mistake,\nplease contact a staff member at ${logChannel.guild.name}!`,
          iconURL: logChannel.guild.iconURL(),
        })
        .setTimestamp();

      await message.author.send({ embeds: [embed] });

      // Report to the log channel
      let embed2 = new Discord.MessageEmbed()
        .setTitle("🛡️ User timed out!")
        .setDescription(
          `<@${message.author.id}> has been timed out for ${
            10 * (reportedList.filter((r) => r == message.author.id).length - 4)
          } minutes for triggering our phishing detection system too many times.`
        )
        .setColor("#c0ffee")
        .setAuthor({
          name: `Suspect: ${message.author.tag}`,
          iconURL: message.author.avatarURL(),
        })
        .setFooter({ text: `kekfilter`, iconURL: logChannel.guild.iconURL() })
        .setTimestamp();

      await logChannel.send({ embeds: [embed2] });
    }

    if (reportedList.filter((r) => r == message.author.id).length > 3) return;

    logger(
      `[${new Date()}] ${
        message.author.tag
      } has been reported too many times, sending a critical alert...`
    );

    await logChannel.send(
      `🔥 **<@${
        message.author.id
      }> has been sending suspicious links too many times (${
        reportedList.filter((r) => r == message.author.id).length
      } to be exact), please investigate! 🔥**`
    );
    return;
  }

  if (!logChannel || reportedList.filter((r) => r == message.author.id).length > 1) return;

  // Create embed
  let joined = detected
      .map((e) => hashUtil.hash(e))
      .slice(0, 5)
      .join(",\n"),
    embed = new Discord.MessageEmbed()
      .setColor("#ff0000")
      .setTitle("⚠️ Phishing attempt detected!")
      .setDescription(
        `\n<@${message.author.id}> has attempted to send a phishing message in **<#${message.channel.id}>**`
      )
      .addField("Detected Phishing Domain Hashes:", joined)
      .setFooter({
        text: `kekfilter`,
        iconURL: logChannel.guild.iconURL(),
      })
      .setAuthor({
        name: `Suspect: ${message.author.tag}`,
        iconURL: message.author.avatarURL(),
      })

      .setTimestamp();

  // Send embed
  try {
    await logChannel.send({ embeds: [embed] });
  } catch (err) {
    logger(`[${new Date()}] Failed to send embed to #${logChannel.name}`);
    logger(err);
  }

  logger(`[${new Date()}] Sent embed for ${message.author.tag}`);
});
