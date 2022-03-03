require("dotenv").config();

const Discord = require("discord.js"),
  client = new Discord.Client({
    intents: ["GUILDS", "GUILD_MEMBERS", "GUILD_MESSAGES"],
  }),
  pkg = require("./package.json"),
  logger = require("./utils/logger.js"),
  phishing = require("stop-discord-phishing"),
  { Pagination } = require("discordjs-button-embed-pagination"),
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

/**
 * @param {Discord.GuildMember} user - The user to check.
 * @returns {boolean} - Whether the user is a staff member or not.
 */
function isStaff(user) {
  return (
    user.roles.cache.filter((r) =>
      r.name.toLowerCase().includes(process.env.STAFFROLE)
    ).size > 0 ||
    user.roles.cache.filter((r) => r.id == process.env.STAFFROLE).size > 0
  );
}

// https://stackoverflow.com/a/15604206
function replaceAll(str, mapObj) {
  var re = new RegExp(Object.keys(mapObj).join("|"), "gi");

  return str.replace(re, function (matched) {
    return mapObj[matched.toLowerCase()];
  });
}

client.on("ready", () => {
  let safeurls = dbops.safeurls();
  logger(
    `[${new Date()}] ${client.user.tag} using ${pkg.name} v${
      pkg.version
    } ready!`
  );
  logger(
    `Current safe URLs list: \n[${
      safeurls.length > 5
        ? safeurls.slice(0, 4).join(", ") + ", ..."
        : safeurls.join(", ")
    }]`
  );
});

var reportedList = () => {
  let list = db.get("reportedList");
  if (!list) {
    list = [];
    db.set("reportedList", list);
  }
  return list;
};

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
    !message.content
      .toLowerCase()
      .startsWith(process.env.PREFIX.toLowerCase() + "filter")
  )
    return;

  // Check if author has staff role
  if (!isStaff(message.member)) {
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
  } else if ((args[0] != "clean" && args.length > 2) || args.length > 3) {
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
    case "clean":
      if (message.mentions.users.size < 1) {
        message.reply("You need to mention a user to clean records from!");
        return;
      }

      let user = message.mentions.users.first(),
        amount = args[2] || 1;

      if (user.bot) {
        message.reply("You can't clean records from bots!");
        return;
      }

      if (!parseInt(amount)) {
        message.reply("You need to specify a valid number!");
        return;
      }

      // Check if user is in the reported list
      if (!reportedList().includes(user.id)) {
        message.reply("That user is not in the reported list!");
        return;
      }

      // Clean records from user up to the specified amount
      db.set(
        "reportedList",
        reportedList().filter((u, i) => {
          if (u == user.id) {
            if (i < amount) {
              return false;
            } else {
              return true;
            }
          } else {
            return true;
          }
        })
      );

      message.reply(
        `Cleaned ${amount} records from ${user.tag}'s report list!`
      );
      logger(
        `[${new Date()}] ${message.author.tag} cleaned ${amount} records from ${
          user.tag
        }'s report list!`
      );
      break;
    case "info":
      if (message.mentions.users.size < 1) {
        message.reply("You need to mention a user to get info from!");
        return;
      }

      let user2 = message.mentions.users.first();

      if (user2.bot) {
        message.reply("You can't get info from bots!");
        return;
      }

      // Check if user is in the reported list
      if (!reportedList().includes(user2.id)) {
        message.reply("That user is not in the reported list!");
        return;
      }

      // Get user's records
      let records = reportedList().filter((u) => u == user2.id);

      message.reply(
        `${user2.tag} has ${records.length} warns in the reports list!`
      );
      logger(
        `[${new Date()}] ${message.author.tag} got info on ${
          user2.tag
        }'s warns list!`
      );
      break;
    case "list":
      // Split the safe urls list into chunks of 5
      let splitList = [];
      for (let i = 0; i < dbops.safeurls().length; i += 5) {
        splitList.push(dbops.safeurls().slice(i, i + 5));
      }
      let embeds = [];
      for (let i = 0; i < splitList.length; i++) {
        embeds.push(
          new Discord.MessageEmbed()
            .setTitle("Safe URLs")
            .setDescription(splitList[i].map((e) => "- " + e).join("\n"))
            .setColor("#c0ffee")
            .setFooter({
              text: `kekfilter | Page ${i + 1}/${splitList.length}`,
              iconURL: message.guild.iconURL(),
            })
        );
      }
      new Pagination(message.channel, embeds, "page").paginate();
      break;
    case "help":
      let embed2 = new Discord.MessageEmbed()
        .setTitle("⚔️ Kekfilter ⚔️")
        .setDescription(
          `
[Kekfilter](https://github.com/spuuntries/kekfilter) is a bot that filters out messages containing unsafe links,
it only has a few commands, all of which are staff only:

**${process.env.PREFIX}filter allow** \`<url>\` - Adds a URL to the exception list.
**${process.env.PREFIX}filter remove** \`<url>\` - Removes a URL from the exception list.
**${process.env.PREFIX}filter list** - Lists all URLs in the exception list.
**${process.env.PREFIX}filter clean** \`<user>\` \`<amount>\` - Cleans records from a user's warns list.
**${process.env.PREFIX}filter info** \`<user>\` - Displays the warns list of a user.
**${process.env.PREFIX}filter help** - Displays this help message.`
        )
        .addField(
          "\u200b",
          `
📝 Notes:
- Make sure that the URL you're adding to the exception list is a **valid URL**! (i.e. \`https://google.com\`, with the \`https://\` part included)
- **All the user mentions must be valid** user mentions! (e.g. \`<@userID>\`)
- **The clean amount is optional**, but if you want to clean more than 1 record, you need to specify the amount!`
        )
        .setAuthor({
          name: "kekfilter - Help",
          iconURL: message.guild.iconURL(),
        })
        .setColor("#208075")
        .setFooter({
          text: `Catching scammers, one kek at a time!`,
          iconURL: message.guild.iconURL(),
        });
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
  if (
    message.content
      .toLowerCase()
      .startsWith(process.env.PREFIX.toLowerCase() + "filter")
  )
    cmdHandler(message);
  if (isStaff(message.member)) return;

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

  db.set("reportedList", [...reportedList(), message.author.id]);

  if (reportedList().filter((r) => r == message.author.id).length > 2) {
    if (reportedList().filter((r) => r == message.author.id).length >= 5) {
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
        (reportedList().filter((r) => r == message.author.id).length - 4);
      logger(`[${new Date()}] Timing out ${message.author.tag} for ${time}ms`);
      await message.member.timeout(time);
      let embed = new Discord.MessageEmbed()
        .setTitle("⚠️ You have been timed out!")
        .setDescription(
          `You have been timed out for ${
            10 *
            (reportedList().filter((r) => r == message.author.id).length - 4)
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

      try {
        await message.author.send({ embeds: [embed] });
      } catch (error) {
        logger(
          `[${new Date()}] Error sending message to ${
            message.author.tag
          }\nErr: ${error}`
        );
      }

      // Report to the log channel
      let embed2 = new Discord.MessageEmbed()
        .setTitle("🛡️ User timed out!")
        .setDescription(
          `<@${message.author.id}> has been timed out for ${
            10 *
            (reportedList().filter((r) => r == message.author.id).length - 4)
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

    if (reportedList().filter((r) => r == message.author.id).length > 3) return;

    logger(
      `[${new Date()}] ${
        message.author.tag
      } has been reported too many times, sending a critical alert...`
    );

    await logChannel.send(
      `🔥 **<@${
        message.author.id
      }> has been sending suspicious links too many times (${
        reportedList().filter((r) => r == message.author.id).length
      } to be exact), please investigate! 🔥**`
    );
    return;
  }

  if (
    !logChannel ||
    reportedList().filter((r) => r == message.author.id).length > 1
  )
    return;

  // Create embed
  let joined = detected
      .map((e) => hashUtil.hash(e))
      .slice(0, 5)
      .join(",\n"),
    embed = new Discord.MessageEmbed()
      .setColor("#ff0000")
      .setTitle("⚠️ Phishing attempt detected!")
      .setDescription(
        `\n<@${
          message.author.id
        }> has attempted to send a phishing message in **<#${
          message.channel.id
        }>**
**Message content (with URLs hashed):** 
\`\`\`${replaceAll(
          message.content,
          Object.assign(...detected.map((k) => ({ [k]: hashUtil.hash(k) })))
        )}
\`\`\``
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
