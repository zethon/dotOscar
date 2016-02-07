# dotOscar
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

Copyright (c) 2016, Adalid Claure
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
