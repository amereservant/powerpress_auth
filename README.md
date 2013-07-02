PowerPress Token Authentication
=======

A WordPress plugin that works with the Blubrry [Powerpress][1] plugin to create a token authentication system for use with mobile devices/etc. on private feeds.

On devices such as iOS devices, password-protected RSS feeds are unsupported, so the problem is resolved by using a hash token to validate the user instead.

Requirements
------------
Besides the obvious, it requires [Blubrry PowerPress][2] >= 4.0.9.

Changelog
------------
**1.3**

 - Changed the login system from HTTP Authentication to the WordPress login system.
 
 PROBLEM - The pretty URLs aren't working for some reason.  They keep generating 404 error pages instead of rendering the content accordingly.

  [1]: http://create.blubrry.com/resources/powerpress/
  [2]: http://wordpress.org/plugins/powerpress/
