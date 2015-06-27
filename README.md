# NAME

Krypté - A database encryption service w/ multiple user support.

# SYNOPSIS

    use App::Krypte;

    my $app = App::Krypte->new(
        dsn => 'dbi:mysql:dbname',
        db_username => 'alice',
        db_password => 'secretz',
    );

# WARNING

**I am not a security expert. So use with caution.**

If you see a flaw, **PLEASE** [submit an issue](https://github.com/lejeunerenard/krypte/issues) or better yet [submit a PR](https://github.com/lejeunerenard/krypte/pulls) with the reason why your change is better and more secure.

# DESCRIPTION

Krypté is a service that provides a simple API to developers so they don't have to worry about how they encrypt their data. Instead they send it off to Krypté and it's taken care of.

# METHODOLOGIES

Krypté's method of encrypting data and managing multiple users looks like this:

## Initial Setup

1. One random master key ( or `share_key` ) is created.
2. A random user key is created and used to encrypt the master key.
3. The user key is encrypted with a password for that user.
4. The encrypted user key and master key are stored for that user in the database.

## Storing ( Putting ) Data

1. Krypté receives credentials  and a chunk of data.
2. The credentials are validated.
3. The shared key is retrieved.
    1. If the credentials are a username and password, the encrypted user key stored for the username is unencrypted using the password.
    2. The user key is then used to unencrypt the shared key.
4. The shared key is used to encrypt the data using [Crypt::CBC](https://metacpan.org/pod/Crypt::CBC) with the Blowfish cipher.
5. The encrypted result is stored with a sha1 key of the data.
6. The key is returned to the initial requester as a key for the data.

# METHODS

## create\_user\_hash

Creates or overrides the user hash with the given info

## delete\_user

Using a valid admin user, remove the given user

## $self->new\_user

`$self-`new\_user> is a function to create a new user and all the related keys.

## find\_user

`find_user` will search for the given user name and resolved the returned promise with a hash of the users information.

## get\_shared\_key

Given a user and password or given a token, get\_shared\_key will return the unencrypted shared key for the system.

Be careful to handle the shared key with care. It should never be left anywhere (memory or disk) unencrypted.

## create\_session

`create_session` will create a temporary session for the given user
and password. It returns the session token which can be used by the
application to unencrypt all future traffic. It will also setup an
automatic timer to kill the session based on a hard coded value.

## end\_session

`end_session` will completely remove a given session token from memory. If this isn't called by the client, it will be automatically called after a hardcoded timeout period. `end_session` takes the unpacked for of the token as the `session_token` parameter.

## validate\_credentials

`validate_credentials` will return a promise which will return a boolean
based on whether the provided credentials are valid or not. User and
password is only validated by checking to see if the user exists in the
current hash.

## put\_data

`put_data` will take data and credentials to store the data encrypted into the database

## get\_data

`get_data` will return the data from the db given valid credentials.

## dbh

`dbh` return database handler based on the app's config. If the
connection has already been created, return that instead.

# AUTHOR

Sean Zellmer <sean@lejeunerenard.com>

# COPYRIGHT

Copyright 2015 - Sean Zellmer

# LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.
