# ⚠️ kekfilter ⚔️

Clear dem scam URLs off da chat,  
'cuz scammers can go and eat shit.

## 🤔 What

This project is an open source automated scam URL
filtering bot designed for [**Art Union**](https://discord.thisisartunion.com)
by Kek.

## 🛠️ How

The thing works by fetching from multiple **Discord**
scam URL public lists and comparing URLs within a
message to them.

> Note that it might only target URLs used for Discord scams due to this,  
> see `utils/dbops.js (Ln 17, Col 3)` and `bot.js (Ln 9, Col 3)` for the current lists we're fetching from, add to the function in `dbops.js` if you'd like to add more lists.

To deal with the whole "Kill one, 20 bajillion more pop up" problem,
it checks the levenshtein distance between suspect and target domains
and will trigger when the distance is `< 4`.

This system will allow for anticipation for variations
of the domains that may pop up in the future.

When triggered:

- Once, it will delete the message and send a log message to the configured `LOGCHANNEL`.
- 3 times, it will delete the message and send a critical log message to the configured `LOGCHANNEL`.
- \>= 5 times, it will delete the message, do an incremental timeout, and send a timeout log message to the configured `LOGCHANNEL`.

Incremental timeout follows the following formula:  
`10 minutes * (number of times triggered - 4)`

## 🌐 Running

To run the project for your server,
you need to first copy the `.env copy` file into a `.env`.

Then, you need to fill in the `.env` with your bot's
token and an id of the channel for the bot to log to.

The `ISPBULLSHIT` can be removed if your ISP doesn't have a
fallback page for "DNS record not found" type of errors.

Afterwards, you can run it like any other node.js project.  
e.g. `node .`

## 📜 How to use

For staff exists 3 commands to modify the behaviour of the bot,
all of which start with the prefix `kek!filter`.

Note that urls must have their protocol also prepended,
e.g. `https://` or `http://`

1. `allow`
   > e.g. `kek!filter allow https://example.com`

This command adds a url to the Safe URLs list.

2. `remove`
   > e.g. `kek!filter remove https://example.com`

This removes the url from the Safe URLs list.

3. `list`
   > e.g. `kek!filter list`

List the current list of Safe URLs.

4. `clean`
   > e.g. `kek!filter clean <user> <amount>`

This will clean one or `amount` of the user's records in the database. Has to be a valid user mention.

5. `info`

   > e.g. `kek!filter info <user>`

This will show the user's current record count. Has to be a valid user mention.

6. `help`
   > e.g. `kek!filter help`

Send the help message.

## 🐛 Caveats

At the moment, I have found two major
caveats to this system.

First, as you know, we use levenshtein distance
to determine similarities between domains to anticipate changes in URLs.

Unfortunately, this does come at a cost, that being normal URLs 
(or normal words, if sufficiently similar to the domains) _could_
(keyword "could", afaict is unlikely) get caught up in the crossfire,
to anticipate for this, one may modify a list of "Safe" URLs,
that the bot will ignore.

Lastly, ~~I'm dumb lmao. 💩~~  
Jk, I'm dumb, but not _that_ dumb, anw,
shortened URLs have a chance to slip through the scanning system
as I haven't yet implemented an unshortener function,
I'll try to get on it asap. (Contribs are welcome _wink wink_)

## 📫 Contribute

If you'd like to contribute, thanku so much!
Just open up a PR with a descriptive title, and I'll gladly check it out!
