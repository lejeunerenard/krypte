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

# NAME

App::Jiffy - A minimalist time tracking app focused on precision and effortlessness.

# SYNOPSIS

    use App::Jiffy;
    # cmd line tool
    jiffy Solving world hunger
    jiffy Cleaning the plasma manifolds
    jiffy current # Returns the elapsed time for the current task
    # Run server
    jiffyd
    curl -d "title=Meeting with Client X" http://localhost:3000/timeentry

# DESCRIPTION

App::Jiffy's philosophy is that you should have to do as little as possible to track your time. Instead you should focus on working. App::Jiffy also focuses on precision. Many times time tracking results in globbing activities together masking the fact that your 5 hours of work on project "X" was actually 3 hours of work with interruptions from your coworker asking about project "Y".
In order to be precise with as little effort as possible, App::Jiffy will be available via a myriad of mediums and devices but will have a central server to combine all the information. Plans currently include the following applications:

- Command line tool
- Web app [App::Jiffyd](https://metacpan.org/pod/App::Jiffyd)
- iPhone app ( potentially )

# INSTALLATION

    curl -L https://cpanmin.us | perl - git://github.com/lejeunerenard/jiffy

# METHODS

The following are methods available on the `App::Jiffy` object.

## add\_entry

`add_entry` will create a new TimeEntry with the current time as the entry's start\_time.

## current\_time

`current_time` will print out the elapsed time for the current task (AKA the time since the last entry was created).

## run

`run` will start an instance of the Jiffy app.

# AUTHOR

Sean Zellmer <sean@lejeunerenard.com>

# COPYRIGHT

Copyright 2015- Sean Zellmer

# LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.
