# ⚠️ kekfilter ⚔️

Clear dem scam URLs off da chat,  
'cuz scammers can go and eat shit.

## 🤔 What
This project is an open source automated scam URL 
filtering bot designed for [**Art Union**](https://discord.thisisartunion.com)
by Kek.

## 🛠️ How
The thing works by fetching from multiple **Discord**   
> (note that it might only target URLs used for 
Discord scams due to this)  

scam URL public lists and comparing URLs within a 
message to them.  

To deal with the whole 
"Kill one, 20 bajillion more pop up" problem,
it checks the levenshtein distance between 
suspect and target domains and 
will trigger when the distance is `< 4`.  

This system will allow for anticipation 
for variations of the domains that 
may pop up in the future.  

## 🌐 Running
To run the project for your server, 
you need to first copy the `.env copy` file 
into a `.env`.

Then, you need to fill in the `.env` with your bot's
token and an id of the channel for the bot to log to.

## 📜 How to use
For staff exists 3 commands to modify the behaviour
of the bot, all of which start with the prefix 
`kek!filter`.  

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

## 🐛 Caveats
At the moment, I have found two major 
caveats to this system.  

First, we use levenshtein distance to 
determine similarities between domains to anticipate 
changes in URLs.  

Unfortunately, this does come 
at a cost, that being normal URLs *could* 
(keyword "could", afaict is unlikely) get caught up
in the crossfire, to anticipate for this, 
one may modify a list of "Safe" URLs, that the bot
will ignore.  

Lastly, ~~I'm dumb lmao. 💩~~  
Jk, I'm dumb, 
but not *that* dumb, shortened URLs have a chance to
slip through the scanning system as I haven't yet
implemented an unshortener function, I'll try
to get on it asap. (Contribs are welcome *wink wink*)

## 📫 Contribute
If you'd like to contribute, thanku so much! 
Just open up a PR with a descriptive title,
and I'll gladly check it out!

