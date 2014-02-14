# This is a HubiC to OpenStack Swift Gateway (hubic2swiftgate)

It supports OAuth2 with api.hubic.com and has to be installed on an apache2 webserver using a ssl-certificate.

## Warning!

This tool is not supported by OVH.

## What can it do?

While using a real (non self-signed) certificate I got 100% compabillity with:

* Duplicity swift:// backend
* swift command line client
* CyberDuck
* ExpanDrive2 (this really needs a non self-signed certificate!)
* Dulwich (GIT Server!) with Swift-Repo Backend by https://github.com/enovance/

I publish this code in an alpha "proof of concept" state. Please don't expect it to be easy to install (but it actually is easy to use after you got it working).

I made it because the HubicSwiftGateway (https://github.com/Toorop/HubicSwiftGateway) "suddenly" stopped working because it's (reverse engineered) authentication scheme is now deprecated.

## How to make it work?

I suppose you have the code run in an apache2 server with php, curl, mod_rewrite, mod_ssl.

The docroot of a virtual server is pointing at the root of this project and asume the server is available under https://yourserver.com/ for this description.

In the current state the gateway only works for one HubiC Client which needs to be registered in the HubiC account panel (developer section).

### Setting things up in you HubiC account:

* Log into your HubiC account
* Click onto account details
* Add a new personal client app in the developer section
* You can choose any name you like (e.g. SwiftGate)
* Redirect URL needs to point to https://yourserver.com/callback/ (currently https://yourserver.com/ works too)

### Configuring the gateway:

* rename config.php.sample to config.php and put your Password, Client ID and Client Secret in there.
* change permission on "cache" folder to allow apache to store data there
* make sure the .htaccess is used or configure your virtual server similar

**To register the gateway with hubic visit:**

https://yourserver.com/register/?user=hubic&password=mypassword

If everything is working you are redirected to the Hubic Client Authentication Site. There you need to login with the data of the HubiC account which should be connected to this user (currently only one user 'hubic' is supported).

After that you get redirected back to your server which should take the code and redirect again to a simple "success" page.

To verify that it worked you can access: https://yourserver.com/usage/ which should show you a brief space usage report (this is not protected with a password so 'everybody' can see the usage of the client right now).

I am using the the user "hubic" and the password from the config.php for "pseudo" authentication with the swift clients. This allows to hide everything hubic related from the user of the swift-client.

The real authentication is done with the OAuth2 tokens from the Hubic API "in the background" which then gets the OpenStack Tokens for the API to the filestorage.

###  Configuring the Swift Clients

To use it with "any" client supporting openstack swift protocol you need to set those up similiar to this:

<pre>
# HubiC for swift and duplicity
export ST_AUTH='https://yourserver.com/auth/v1.0/'
export ST_USER='hubic' // fixed atm
export ST_KEY='mypassword' // from config.php

export SWIFT_AUTHURL=$ST_AUTH
export SWIFT_USERNAME=$ST_USER
export SWIFT_PASSWORD=$ST_KEY
</pre>

P.S.: This work is dedicated to my friends from METATEXX GmbH!
