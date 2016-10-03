# dotOscar (defunct)
.NET Library for the AOL Instant Messenger OSCAR Protocol

## What is dotOscar?

dotOscar is a .NET client library for AOL's Instant Messenger service. 

## Current Features

dotOscar currently only has a basic set of functionality compared to the entire OSCAR implementation. These include:

- Login and Logout
- Auto-relogin 
- Add one or more buddies to the user's server-side Buddy List
- Send and receive Instant Messages

## History

The code was originally written around 2005-2006 for a project I worked on named RemindMe. RemindME was an IM based reminder system that allowed user to send it messages such as "remind me tomorrow at 3pm to take out the trash" and then would send those reminders back at the appropriate time. 

More recently I started updating [vBulletinBot](https://github.com/zethon/vbulletinbot) in an effort to get it work with Mono so that I could run it on my Linux box. vBulletinBot also makes heavy use of Instant Messages, including AOL Instance Messenger, but did not use the dotOscar project. My efforts to find a recently written .NET library for use with dotOscar proved to fruitless and on a whim I decided to try dotOscar. I wasn't expecting much since the library was 10+ years old and I figured surely the OSCAR protocol had changed some in that time.

Luckily I was wrong! dotOscar worked perfectly for what I needed it do! 

## License

MIT
