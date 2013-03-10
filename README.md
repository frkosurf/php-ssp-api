# Introduction
This project aims at providing a REST API management interface for 
simpleSAMLphp. The goal is to make it possible to configure remote SP and 
IdP entries. Without this module these entries need to be configured through
the metadata registry files. This project replaces this with a `PDO` database.

The REST interface can be used to create, update, delete and retrieve 
SP and IdP registrations using the JSON format. The format is nothing more than
a JSON encode of the PHP arrays that are used with the existing metadata files.

The use would be to configure simpleSAMLphp like normal, but for the SP and IdP
"remotes" use the PDO database.

This interface needs a patch to simpleSAMLphp for a PDO driver, which can
currently be found here: https://code.google.com/p/simplesamlphp/issues/detail?id=529

In the future also a HTML5 "webapp" will be made available to manage the 
entries. For now there is just a JSON based REST API.

# Using the API
To obtain an entry and store it in `sp.json`:

    curl -H "Authorization: Bearer abcdef" http://localhost/frkonext/php-ssp-api/api.php/saml20-sp-remote/entity?id=http://localhost/frkonext/sspsp/module.php/saml/sp/metadata.php/default-sp > sp.json

To update an entry from the file `sp.json`:
    curl -d @sp.json -X PUT -H "Authorization: Bearer abcdef" http://localhost/frkonext/php-ssp-api/api.php/saml20-sp-remote/entity?id=http://localhost/frkonext/sspsp/module.php/saml/sp/metadata.php/default-sp

