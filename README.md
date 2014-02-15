# This is a HubiC to OpenStack Swift Gateway (hubic2swiftgate)

It supports OAuth2 with api.hubic.com and has to be installed on an apache2 webserver using a ssl-certificate.

## Warning!

This tool is not supported by OVH! 

But they encourage user to use the API and allow access to non default containers explicitly on their forums! You find me on the Forum as "OderWat" too.

## What can it do?

**While using a real (non self-signed) certificate I got 100% compabillity with:**

* [Duplicity][] THE backup solution with encryption and diff (using: swift:// backend, this was added in 0.6.22 afaik)
* [Python-SwiftClient][] command line client - very useful (up to version 1.9 currently)
* CyberDuck - FTP like access to all containers (using 'Swift')
* ExpanDrive2 - Mounts your HubiC Storage as external Drive (Select 'Open Stack Swift Storage. This really needs a __non self-signed__ certificate!)

**I got limited success with:**

* Dulwich (the GIT Server component) with Swift-Repo Backend by Enovance (using my patch until they fix return code acceptance). This may be unusable slow depending on network/workflow.
* CloudFuse (It works with v1.0 auth but crashes fairly often on my Mac)

**Notice:** The actuall datastore access is not running over the gateway! So you get full possible speed! The gateway just handles the authentication (v1.0 not v2.0) of swift clients

## State of the project!

It works "perfectly well" for me and some friends but still is kinda "alpha code" because it has limited error control and needs some knowledge to setup it up correctly.

It is not meant as "finished product" and maybe never will. Actually it is kind of a hack like most "gateways" are :)

Please don't expect it to be easy to install (but it actually is easy to use after you got it working).

This was made because the HubicSwiftGateway (https://github.com/Toorop/HubicSwiftGateway) "suddenly" stopped working after the (reverse engineered) authentication scheme which was used is now deprecated.

P.S.: I was thinking about creating a stand alone binary version written in GoLang which would work for "everybody" and on Mac/Linux/PC. But I still hope that the HubiC Guys may implement this kind of gateway natively into their service. So don't expect this to happen soon, if at all.

## How to make it work?

I suppose you have the code run in an apache2 server with php, curl, mod_rewrite, mod_ssl.

The docroot of a virtual server is pointing at the root of this project and asume the server is available under https://yourserver.com/ for this description.

In the current state the gateway only works for one HubiC Client which needs to be registered in the HubiC account panel (developer section).

### Setting things up in you HubiC account:

* Log into your HubiC account
* Click onto account details
* Add a new personal client app in the developer section
* You can choose any name you like (e.g. SwiftGate)
* Redirect URL needs to point to https://yourserver.com(:port)/callback/ (Important: Only add non standard ports, for 443 do not add a port in the url!)

### Configuring the gateway:

* rename config.php.sample to config.php and put your Password, Client ID and Client Secret in there.
* change permission on "cache" folder to allow apache to store data there
* make sure the .htaccess is used or configure your virtual server similar

### Registering the client with your HubiC account

Visit: `https://yourserver.com/register/?client=hubic&password=mypassword`

If everything is working you are redirected to the Hubic Client Authentication Site. There you need to login with the data of the HubiC account which should be connected to this user (currently only one user 'hubic' is supported).

After that you get redirected back to your server which should take the code and redirect again to a simple "success" page.

To verify that it worked you can access: `https://yourserver.com/usage/` which should show you a brief space usage report (this is not protected with a password so 'everybody' can see the usage of the client right now).

I am using the the user "hubic" and the password (aka authkey) from the `config.php` for "pseudo" authentication with the swift clients. This allows to hide everything hubic related from the user of the swift-client.

The real authentication is done with the OAuth2 tokens from the Hubic API "in the background" which then gets the OpenStack Tokens for the API to the filestorage.

###  Configuring the Swift Clients

To use it with "any" client supporting openstack swift protocol you need to set those up similiar to these examples:

#### Duplicity

    # Setting up the environment. Put it into .bashrc    
    
    export SWIFT_AUTHURL='https://yourserver.com/auth/v1.0/'
    export SWIFT_USERNAME='hubic' // fixed atm
    export SWIFT_PASSWORD='mypassword' // from config.php
    export PASSPHRASE='somethingreallylongandsecret'
    
    duplicity /mydatetobackup swift://containername

    # I personally use it for something like:

    mysqlhotcopy .... (making a snapshot of the mysql databases to backup)
    duplicity /backups/mysqlhotcopies swift://duplicity:server1:mysqldbs
    duplicity /home swift://duplicity:server1:homes

#### Python-SwiftClient

Grab it here: https://github.com/openstack/python-swiftclient

Attention: I believe starting with 2.0 they broke support for "gzip" compressed swift backends! So make sure you use 1.8 or 1.9 until that got fixed. I use the Version you get with "git checkout 1.9.0"

    # Setting up the environment. Put it into .bashrc    
    
    export ST_AUTH='https://yourserver.com/auth/v1.0/'
    export ST_USER='hubic' // fixed atm
    export ST_KEY='mypassword' // from config.php

    # Examples
    swift list --lh
    swift delete duplicity:server1:homes
    swift stat

P.S.: This work is dedicated to my friends from <a href="http://www.metatexx.de/#hsgate">METATEXX GmbH</a>!
