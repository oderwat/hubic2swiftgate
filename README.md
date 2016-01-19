# HubiC to OpenStack Swift Gateway

[![Join the chat at https://gitter.im/oderwat/hubic2swiftgate](https://badges.gitter.im/oderwat/hubic2swiftgate.svg)](https://gitter.im/oderwat/hubic2swiftgate?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

With HubiC now offering 10 TB (yes 10.000 GB) for 5,- Euro a month (or 50,- Euro a year) it becomes extremly interesting as datastorage for multiple and automated tasks!

As HubiC exposes an OpenStack Swift API to the developer the idea to use it with existing swift client implementations is a natural thing.

Sadly the HubiC authorisation is currently limited to OAuth2. This is those thing wich redirects you to a Website where you have to agree to connect your Account to a client. You know these ones!

To close this gap I made: hubic2swiftgate. A gateway which supports OAuth2 with api.hubic.com and has to be installed on an apache2 or nginx webserver using a ssl-certificate.

## Warning!

This tool is not supported by OVH!

But they encourage user to use the API and allow access to non default containers explicitly on their forums! You find me on the Forum as "OderWat" too.

## What can it do?

**While using a real (non self-signed) certificate I got 100% compabillity with:**

* [Duplicity](#duplicity) - THE backup solution with encryption and diff (using: swift:// backend, this was added in 0.6.22 afaik)
* [Python-SwiftClient](#pythonswiftclient) - Command line client. Very useful.
* CyberDuck - FTP like access to all containers (using 'Swift'). As we only support v1.0 authentication you need to use the v1.0 devauth authentication supplied on the CyberDuck Homepage [Auth 1.0 Profile Info](https://trac.cyberduck.io/wiki/help/en/howto/openstack)
* ExpanDrive2 - Mounts your HubiC Storage as external Drive (Select 'Open Stack Swift Storage. This really needs a __non self-signed__ certificate!)
* [ftp-cloudfs](https://github.com/cloudfs/ftp-cloudfs) - Users reported that this works very good to abstract Hubic as FTP Server.

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

Here some more help for that: [Setting up Apache2 for Hubic2SwiftGate](#apachesetup) or [Setting up nginx for Hubic2SwiftGate](#nginxsetup)

There is also a docker image available from [here](https://github.com/jkaberg/docker-hubic2swiftgate).

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

### Overriding the automatic redirect uri (callback)

There are use cases where the redirect uri calculated by the server is different to the real uri. This can happen if your server is behind some proxy or uses port mapping and you are using autoregister from internal or a browser from external. In that case the automatically generated redirect_uri does not match what is needed to really access the server and the callback after (auto)register fails to reach the server.

In those cases you remove the comment and set your value for `redirect_uri` in `config.php` to force the callback to a certain URI. For example, if you want to access to use `https://yourserver.com:8080/autoregister/?client=hubic&password=mypassword&hubic_user=myhubiclogin&hubic_password=myhubicpassword`, that internally is a redirection to port 80 inside a VM or a container, then you could use:

```php
     'redirect_uri'=>'https://localhost/callback/', // only needed for special use cases
```

### Registering the client with your HubiC account without user intervention

Visit: `https://yourserver.com/autoregister/?client=hubic&password=mypassword&hubic_user=myhubiclogin&hubic_password=myhubicpassword`

It will get fill the form and send it back without user intervention.

###  Configuring the Swift Clients

To use it with "any" client supporting openstack swift protocol you need to set those up similiar to these examples:

#### <a name="duplicity"></a>Duplicity

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

#### <a name="pythonswiftclient"></a>Python-SwiftClient

Grab it here: https://github.com/openstack/python-swiftclient , or install with pip: pip install python-swiftclient

Attention: I believe starting with 2.0 they broke support for "gzip" compressed swift backends! The problem is now fixed in version 2.6, so make sure you use 1.9 or 2.6 or more recent, but not an older 2.x.

    # Setting up the environment. Put it into .bashrc    

    export ST_AUTH='https://yourserver.com/auth/v1.0/'
    export ST_USER='hubic' // fixed atm
    export ST_KEY='mypassword' // from config.php
    export SWIFTCLIENT_INSECURE=true // if you use a self-signed certificate

    # Examples
    swift list --lh
    swift delete duplicity:server1:homes
    swift stat

#### <a name="apache setup"></a>Setting up Apache2 for HubiC2SwiftGate

I am not explaining how to get apache2 running in detail. Make sure you have php with curl extension, mod_ssl, mod_rewrite installed for your system. There is plenty of information about this on the net!

After you got those installed you need to configure apache2 to run the gateway.

First you need either a "real" (preferred) or self signed SSL certificate. On Linux and Mac you can create one like this:

    openssl genrsa -des3 -passout pass:x -out server.pass.key 2048
    openssl rsa -passin pass:x -in server.pass.key -out server.key
    rm server.pass.key
    openssl req -new -key server.key -out server.csr
    openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

You will be asked different stuff. The most important ist the "common name". There you need to enter the domain you want to use! It generates the private key **server.key** and the certificate **server.crt**. The file **server.csr** is the (reusable) certificate sign request.

You can order a "real" certificate for free from different sources. I checked out COMODO in the past which give you a certificate which is valid for 90 day for free.

Cautious: If you use a self signed certificate there may be problems with some of the clients. Sometimes you can deactivate certificate checking. It may even be possible to not use SSL at all. But I can't recommend this for software with these security relevance!

After you got the certificates you can set up an apache virtual server *like* this:

    <VirtualHost *:443>
      ServerName hsgate.domain.name
      DocumentRoot /var/www/hsgate/www/

      SSLEngine on
      SSLCipherSuite ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP
      SSLCertificateFile /etc/apache2/ssl/server.crt
      SSLCertificateKeyFile /etc/apache2/ssl/server.key

      CustomLog /var/log/apache2/hsgate_ssl_access.log combined
      ErrorLog /var/log/apache2/hsgate_ssl_error.log

      <Directory "/var/www/hsgate/www/">
        Options Indexes FollowSymLinks
        AllowOverride All
        Order allow,deny
        Allow from all
      </Directory>

      php_admin_flag engine on

    </VirtualHost>

*Notice: This is just an example. You need to adjust the paths for your system and maybe more. Here `hsgate` is the repository root folder which contains the `www` folder which the virtual host needs to point at.*

Depending on where you setup the server you may need to create a port mapping from outside in you router if you want to use the gateway from another than your own network.

It is fine to install this all "inside" your own network as long as your local browser has access to it! You even can use localhost! My scope is different in that I am using the gateway from many different servers in different locations.

#### <a name="nginxsetup"></a> Setting up nginx for HubiC2SwiftGate

The creation of the self-signed certificate is the same as for apache2. A possible nginx-configuration would be:

```
server  {
          listen 443 ssl;

          #access_log  /var/log/nginx/hsgate.access.log;
          error_log   /var/log/nginx/hsgate.error.log error;

          server_name hsgate;

          ssl                  on;
          ssl_certificate      /etc/nginx/ssl/hsgate.crt;
          ssl_certificate_key  /etc/nginx/ssl/hsgate.key;

          root /var/www/hsgate/;
          index index.php;

          location / {
                root /var/www/hsgate/html;
                try_files $uri $uri/ /simple.php?$args;

              }


          location ~ \.php$ {
                fastcgi_index  index.php;
                fastcgi_param  SCRIPT_FILENAME $document_root$fastcgi_script_name;
                include fastcgi_params;
                fastcgi_pass  unix:/var/run/php5-fpm.sock;
              }


        # redirect server error pages to the static page /50x.html
        #
        error_page 500 502 503 504 /50x.html;
        location = /50x.html {
                root /usr/share/nginx/html;
        }

      }
```
In this config php5-fpm is used to serve .php-files with nginx. But there are also some other ways to use nginx with PHP. The ssl config is also quite minimal and if you want to use this in production, it would be a good suggestion to extend it.

P.S.: This work is dedicated to my friends from <a href="http://www.metatexx.de/#hsgate">METATEXX GmbH</a>!
