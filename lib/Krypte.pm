package Krypte;

use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../local/lib/perl5";

use AnyEvent::Socket;
use AnyEvent::Handle;
use AnyEvent::DBI::Abstract;

use JSON;
use Promises qw(deferred);

# Cryptography Modules
use Crypt::CBC;
use Crypt::Random::Seed;
use Digest::SHA1;

use Data::Dumper;

use constant DEBUG => $ENV{SERVER_DEBUG};

=head2 create_user_hash

Creates or overrides the user hash with the given info

=cut

sub create_user_hash {
   my $self = shift;
   my %options = @_;
   my $user = $options{user};
   my $user_key = $options{user_key};
   my $shared_key = $options{shared_key};
   my $user_password = $options{user_password};
   my $is_admin = ( $options{is_admin} ) ? 1 : 0;

   # Die if inputs are not set
   foreach ('user', 'user_key', 'shared_key', 'user_password') {
      die $_.' must be defined' unless defined $options{$_};
   }
   undef %options;

   # ----- Encrypt SharedKey with UserKey -----
   # Create cipher for the SharedKey
   my $cipher = Crypt::CBC->new(
      -key => $user_key,
      -cipher => 'Blowfish',
   );
   my $enc_shared_key = $cipher->encrypt($shared_key);
   # Garbage collect, just in case
   undef $cipher;
   undef $shared_key;

   # ----- Encrypt Userkey with password -----
   # Create cipher for the UserKey
   my $user_cipher = Crypt::CBC->new(
      -key => $user_password,
      -cipher => 'Blowfish',
   );

   my $deferred = deferred;

   # Store user info into the keys hash
   my $enc_user_key = $user_cipher->encrypt($user_key);
   $self->dbh->insert('users', {
      username => $user,
      password => Digest::SHA1::sha1_hex($user_password),
      user_key => $enc_user_key,
      shared_key => $enc_shared_key,
      is_admin => $is_admin,
   }, sub {
      my($dbh, $rows, $rv) = @_;

      if ( $@ ) {
         $deferred->reject($@);
      } elsif ( $rv ) {
         $deferred->resolve()
      } else {
         $deferred->reject('Something went wrong creating the user');
      }
   });

   undef $user_key;

   return $deferred->promise;
}

=head2 delete_user

Using a valid admin user, remove the given user

=cut

sub delete_user {
   my $self = shift;
   my %options = @_;
   my $user = $options{user};
   my $admin_user = $options{admin_user};
   my $admin_password = $options{admin_password};

   # Die if inputs are not set
   foreach ('user', 'admin_user', 'admin_password') {
      die $_.' must be defined' unless defined $options{$_};
   }
   undef %options;

   my $deferred = deferred;

   $self->find_user( $admin_user )->then(sub {
      my $user_hash = shift;

      # Die if $admin_user is not an admin
      $deferred->reject('$admin_user is not an admin')
         # Check is_admin column
         unless $user_hash->{is_admin};

      $self->find_user( $user )->then(sub {
         $self->dbh->delete( 'users', { username => $user }, sub {
            my($dbh, $rows, $rv) = @_;
            if ( $rv ) {
               $deferred->resolve();
            } else {
               $deferred->reject();
            }
         });
      }, sub {
         # Die if $user is doesnt exist
         $deferred->reject("$user doesn't exist");
      });
   }, sub {
      # Die if $admin_user is doesnt exist
      $deferred->reject("$admin_user doesn't exist");
   });

   return $deferred->promise;
}

=head2 $self->new_user

C<$self->new_user> is a function to create a new user and all the related keys.

=cut

sub new_user {
   my $self = shift;
   my %options = @_;
   my $admin_user = $options{admin_user};
   my $admin_password = $options{admin_password};
   my $new_user = $options{new_user};
   my $new_password = $options{new_password};
   my $new_is_admin = ( $options{new_is_admin} ) ? 1 : 0;

   my $deferred = deferred;

   # Die if inputs are not set
   foreach ('admin_user', 'admin_password', 'new_user', 'new_password') {
      die $_.' must be defined' unless defined $options{$_};
   }
   undef %options;

   $self->find_user( $admin_user )->then(sub {
      my $user_hash = shift;
       # Die if $admin_user is not an admin
       return $deferred->reject('$admin_user is not an admin')
         # Check is_admin column
         unless $user_hash->{is_admin};

       # ----- Get SharedKey with admin creds -----
       $self->get_shared_key( $admin_user, $admin_password )->then(sub {
         my $shared_key = shift;
         # ----- Generate UserKey -----
         my $user_key = $self->{crypt_source}->random_bytes(512);

         undef $admin_user;
         undef $admin_password;

         $self->create_user_hash(
             user          => $new_user,
             user_key      => $user_key,
             user_password => $new_password,
             shared_key    => $shared_key,
             is_admin      => $new_is_admin,
         );
         undef $shared_key;
         undef $user_key;
         undef $new_password;

         $deferred->resolve();
       });
   }, sub {
       # Die if $admin_user is doesnt exist
       $deferred->reject('$admin_user doesn\'t exist');
   });

   return $deferred->promise;
}

=head2 find_user

C<find_user> will search for the given user name and resolved the returned promise with a hash of the users information.

=cut

sub find_user {
   my $self = shift;
   my $user = shift;

   my $deferred = deferred;

   my $fields = ['username', 'password', 'is_admin', 'user_key', 'shared_key'];

   $self->dbh->select( 'users', $fields, { username => $user }, sub {
       my($dbh, $rows, $rv) = @_;

       if ( $rv and $#$rows >= 0 ) {
         my $user_hash;

         for my $i ( 0 .. $#$fields ) {
            $user_hash->{$fields->[$i]} = $rows->[0][$i];
         }

         $deferred->resolve($user_hash);
       } else {
         $deferred->reject("User $user not found");
       }
   });

   return $deferred->promise;
}

=head2 get_shared_key

Given a user and password or given a token, get_shared_key will return the unencrypted shared key for the system.

Be careful to handle the shared key with care. It should never be left anywhere (memory or disk) unencrypted.

=cut

sub get_shared_key {
   my $self = shift;
   my $user_or_token = shift;
   my $password = shift;
   my ( $user, $token );

   # If password is undef, then check if $user_or_token is in the token hash
   # else set the user
   if ( not( defined $password ) and exists $self->{sessions}{$user_or_token} ) {
      $token = $user_or_token;
   } else {
      $user = $user_or_token;
   }

   # Get key and encrypted key from a session or a individual user
   my ( $key, $encrypted_shared_key );

   my $deferred = deferred;

   if ( $token ) {
      # In the case of a session, the token is the key and the SharedKey is
      # encrypted by the token.
      $key                  = $token;
      $encrypted_shared_key = $self->{sessions}{$token}{shared_key};

      # Refresh the timer too
      $self->{sessions}{$token}{timer} = AE::timer $self->{session_time_out}, 0,
         sub {
            $self->end_session( session_token => $token );
         };

      # ----- Get SharedKey with key -----
      # Create cipher for getting the SharedKey
      my $shared_cipher = Crypt::CBC->new(
         -key => $key,
         -cipher => 'Blowfish',
      );
      $deferred->resolve($shared_cipher->decrypt($encrypted_shared_key));
   } else {
      # Die if inputs are not set
      die 'User and Password must be defined'
        unless defined($user)
        and defined($password);

      $self->find_user( $user )->then(sub {
         my $user_hash = shift;

         # Die if password doesnt match
         if ( $user_hash->{password} ne Digest::SHA1::sha1_hex($password) ) {
            die 'Password doesn\'t match';
         }

         # ----- Get UserKey with password -----
         # Create cipher for getting the UserKey
         my $user_cipher = Crypt::CBC->new(
             -key    => $password,
             -cipher => 'Blowfish',
         );
         $key = $user_cipher->decrypt( $user_hash->{user_key} );
         $encrypted_shared_key =  $user_hash->{shared_key};

         # ----- Get SharedKey with key -----
         # Create cipher for getting the SharedKey
         my $shared_cipher = Crypt::CBC->new(
            -key => $key,
            -cipher => 'Blowfish',
         );
         my $shared_key = $shared_cipher->decrypt($encrypted_shared_key);
         # Garbage collect, just in case
         undef $shared_cipher;
         undef $encrypted_shared_key;

         # Garbage collect, just in case
         undef $user_cipher;
         undef $password;
         undef $user;

         $deferred->resolve($shared_key);
      }, sub {
         # Die if user doesnt exist
         $deferred->reject('User must exist');
      });
   }

   return $deferred->promise;
}

=head2 create_session

C<create_session> will create a temporary session for the given user
and password. It returns the session token which can be used by the
application to unencrypt all future traffic. It will also setup an
automatic timer to kill the session based on a hard coded value.

=cut

sub create_session {
   my $self = shift;
   my %options = @_;
   my $user = $options{user};
   my $password = $options{password};

   # Die if inputs are not set
   foreach ('user', 'password') {
      die $_.' must be defined' unless defined $options{$_};
   }
   undef %options;

   # Die if user doesnt exist
   die "$user must exist" unless defined $self->{users}{$user};

   # Generate new session token
   my $session_token = $self->{crypt_source}->random_bytes(512);

   # Get shared key and encrypt it with the session token
   my $cipher = Crypt::CBC->new(
      -key => $session_token,
      -cipher => 'Blowfish',
   );

   $self->get_shared_key($user, $password)->then(sub {
      my $shared_key = shift;
      $self->{sessions}{$session_token}{shared_key} = $cipher->encrypt(
         $shared_key,
      );
   }, sub {
      die "Creating Token ( $session_token ) failed\n";
   });
   $self->{sessions}{$session_token}{shared_key} = $cipher->encrypt(
     $self->get_shared_key($user, $password)
   );

   # Create timer for the session
   $self->{sessions}{$session_token}{timer} = AE::timer $self->{session_time_out}, 0, sub {
      $self->end_session( session_token => $session_token );
   };

   # Return the session token so the application can use it
   return $session_token;
}

=head2 end_session

C<end_session> will completely remove a given session token from memory. If this isn't called by the client, it will be automatically called after a hardcoded timeout period. C<end_session> takes the unpacked for of the token as the C<session_token> parameter.

=cut

sub end_session {
   my $self = shift;
   my %options = @_;
   my $session_token = $options{session_token};

   # Die if inputs are not set
   foreach ('session_token') {
      die $_.' must be defined' unless defined $options{$_};
   }
   undef %options;

   delete $self->{sessions}{$session_token};
}

=head2 validate_credentials

C<validate_credentials> will return a boolean based on whether the
provided credentials are valid or not. User and password is only validated
by checking to see if the user exists in the current hash.

=cut

sub validate_credentials {
   my $self = shift;
   my %options = @_;
   my $session_token = $options{session_token};
   my $user = $options{user};
   my $password = $options{password};

   if ( defined $user ) {
      # Return 0 if user doesnt exist
      return 0 unless defined $self->{users}{$user};

      # A user must have a password to valid
      return 0 unless defined $password;

      # Else return
      return 1;
   } else {
      # Return 0 if token doesnt exist
      return 0 unless defined $self->{sessions}{$session_token};

      # Else return
      return 1;
   }
}

=head2 put_data

C<put_data> will take data and credentials to store the data encrypted into the database

=cut

sub put_data {
   my $self = shift;
   my %options = @_;

   # Die if credentials are invalid
   die "Credentials are invalid" unless $self->validate_credentials(@_);

   # Get the SharedKey
   my $session_token = $options{session_token};
   my $user = $options{user};
   my $password = $options{password};

   my $data = $options{data};

   my $shared_key;

   if ( $user ) {
      $shared_key = $self->get_shared_key( $user, $password );

      # Clean up
      undef $user;
      undef $password;
   } else {
      $shared_key = $self->get_shared_key( $session_token );

      # Clean up
      undef $session_token;
   }

   # ----- Encrypt data -----
   my $cipher = Crypt::CBC->new(
      -key => $shared_key,
      -cipher => 'Blowfish',
   );
   my $encrypted_data = $cipher->encrypt( $data );

   my $deferred = deferred;

   # Get the key for the data
   my $sha1_key = Digest::SHA1::sha1_hex($data);

   # Check to see if this data has already been stored
   $self->dbh->select( 'data', ['sha1_key'], { sha1_key => $sha1_key, },sub {
      my($dbh, $rows, $rv) = @_;

      # If its already found then just return the hash
      if ( $#$rows == 0 ) {
         $deferred->resolve($sha1_key);
      } else {
         $dbh->insert('data', { value => $encrypted_data,
           sha1_key => $sha1_key }, sub {
            my($dbh, undef, $rv) = @_;

            if ( $@ ) {
               $deferred->reject($@);
            } else {
               $deferred->resolve($sha1_key);
            }
         });
      }
   });


   return $deferred->promise;
}

=head2 get_data

Summary of get_data

=cut

sub get_data {
   my $self = shift;
   my %options = @_;

   # Die if credentials are invalid
   die "Credentials are invalid" unless $self->validate_credentials(@_);

   # Get the SharedKey
   my $session_token = $options{session_token};
   my $user = $options{user};
   my $password = $options{password};

   my $key = $options{key};

   my $shared_key;

   if ( $user ) {
      $shared_key = $self->get_shared_key( $user, $password );

      # Clean up
      undef $user;
      undef $password;
   } else {
      $shared_key = $self->get_shared_key( $session_token );

      # Clean up
      undef $session_token;
   }

   # ----- Encrypt data -----
   my $cipher = Crypt::CBC->new(
      -key => $shared_key,
      -cipher => 'Blowfish',
   );

   my $deferred = deferred;

   # GET THE DATA
   $self->dbh->select( 'data', ['value'], { sha1_key => $key, },sub {
      my($dbh, $rows, $rv) = @_;

      # First check that there is no error
      if ( $@ ) {
         $deferred->reject($@);
      } else {
         # Check that something was actually found
         if ( $#$rows == 0 ) {
            # Get data from rows
            my $encrypted_data = $rows->[0][0];
            my $data = $cipher->decrypt( $encrypted_data );
            # Get the key for the data
            my $sha1_key = Digest::SHA1::sha1_hex($data);

            # Now check if the key matchs the data
            if ( $sha1_key ne $key ) {
               $deferred->reject('Data not decrypted successfully');
            }

            $deferred->resolve($data);
         } else {
            $deferred->reject('data not found');
         }
      }
   });

   return $deferred->promise;
}

sub new {
   my $class = shift;
   my %options = @_;

   my $self = {
      crypt_source => Crypt::Random::Seed->new( NonBlocking => 1 ),
      users => {},
      dsn => $options{dsn},
      db_username => $options{db_username},
      db_password => $options{db_password},
      session_time_out => $options{session_time_out} || 120,
   };

   bless $self, $class;
   return $self;
}

=head2 dbh

C<dbh> return database handler based on the app's config. If the
connection has already been created, return that instead.

=cut

sub dbh {
   my $self = shift;

   return $self->{dbh} if defined $self->{dbh};

   $self->{dbh} = AnyEvent::DBI::Abstract->new($self->{dsn}, $self->{db_username}, $self->{db_password}, AutoCommit => 1);
   return $self->{dbh};
}

sub prepare_handler {
   my ($self, $sock, $host, $port) = @_;
   my $user = 'admin';
   my $password = 'underground';

   # ===== Setup admin user =====
   $self->create_user_hash(
      user => $user,
      user_password => $password,
      user_key => $self->{crypt_source}->random_bytes(512),
      # @TODO get this shared key some other way at startup
      shared_key => $self->{crypt_source}->random_bytes(512),
      is_admin => 1,
   );
   print STDOUT "First Admin Credentials:\n";
   print STDOUT "u: $user\n";
   print STDOUT "p: $password\n";
   undef $user;
   undef $password;

   DEBUG && warn "Listening on $host:$port\n";
}

sub tcp_handler {
   my $self = shift;

   return sub {
      my ($sock,$peer_host, $peer_port) = @_;

      my $handle = AnyEvent::Handle->new( fh => $sock );

      # ------ Receive Message ------
      $handle->on_read(sub {
         my ($hdl) = @_;
         print STDERR "hdl->rbuf: ".Dumper($hdl->rbuf)."\n";
         my $message;
         eval {
            $message = from_json( $hdl->rbuf );
         };
         undef $hdl->rbuf; # Clear buffer so it doesnt stack

         # Check that the buffer was valid JSON
         if ( ! $@ ) {
            print "Received: " .Dumper($message)."\n";

            eval {
               if ( $message->{method} eq 'newUser' ) {
                   $self->new_user(
                       new_user       => $message->{new_user},
                       new_password   => $message->{new_password},
                       admin_user     => $message->{admin_user},
                       admin_password => $message->{admin_password},
                   );
               }
               elsif ( $message->{method} eq 'deleteUser' ) {
                   $self->delete_user(
                       user           => $message->{user},
                       admin_user     => $message->{admin_user},
                       admin_password => $message->{admin_password},
                   );
               }
               elsif ( $message->{method} eq 'createSession' ) {
                   my $token = $self->create_session(
                      user     => $message->{user},
                      password => $message->{password},
                   );
                   if ($token) {
                       $handle->push_write(
                           json => {
                               sessionToken => unpack( 'H*', $token ),
                           }
                       );
                       # Extra newline
                       $handle->push_write ("\012");
                   }
               }
               elsif ( $message->{method} eq 'endSession' ) {
                   $self->end_session(
                      session_token => pack( 'H*', $message->{sessionToken} ),
                   );
               }
               elsif ( $message->{method} eq 'putData' ) {
                  my $packed_token = ( defined $message->{sessionToken} ) ? pack( 'H*', $message->{sessionToken} ) : undef;
                   $self->put_data(
                      session_token => $packed_token,
                      user => $message->{user},
                      password => $message->{password},
                      data => $message->{data},
                   )->then(sub {
                      $handle->push_write(
                         json => {
                            status => 'success',
                            key => $_[0],
                         }
                      );
                      # Extra newline
                      $handle->push_write ("\012");
                   }, sub {
                      $handle->push_write(
                         json => {
                            status => 'error',
                            reason => $_[0],
                         }
                      );
                      # Extra newline
                      $handle->push_write ("\012");
                   });
               }
               elsif ( $message->{method} eq 'getData' ) {
                  my $packed_token = ( defined $message->{sessionToken} ) ? pack( 'H*', $message->{sessionToken} ) : undef;
                   $self->get_data(
                      session_token => $packed_token,
                      user => $message->{user},
                      password => $message->{password},
                      key => $message->{key},
                   )->then(sub {
                      $handle->push_write(
                         json => {
                            status => 'success',
                            data => $_[0],
                         }
                      );
                      # Extra newline
                      $handle->push_write ("\012");
                   }, sub {
                      $handle->push_write(
                         json => {
                            status => 'error',
                            reason => $_[0],
                         }
                      );
                      # Extra newline
                      $handle->push_write ("\012");
                   });
               }
               elsif ( $message->{method} eq 'dump' ) {
                   print "===== Users =====\n";
                   foreach my $user ( keys %{ $self->{users} } ) {
                       print "$user:\n";
                       print "key: "
                         . unpack( 'H*', $self->{users}{$user}{key} ) . "\n";
                       print "shared key: "
                         . unpack( 'H*', $self->{users}{$user}{shared_key} )
                         . "\n";
                       print "\n";
                   }
                   print "===== Sessions =====\n";
                   foreach my $session ( keys %{ $self->{sessions} } ) {
                       print unpack( 'H*',$session) . "\n";
                       print "shared key: "
                         . unpack( 'H*', $self->{sessions}{$session}{shared_key} )
                         . "\n";
                       print "\n";
                   }
               }
           };
        }
        if ( $@ ) {
           $handle->push_write(
               json => {
                   error => $@,
               }
           );
           # Extra newline
           $handle->push_write ("\012");
        }
      });

      # ------ Socket closed ------
      $handle->on_eof(sub {
         my ($hdl) = @_;
         $hdl->destroy();
      });

      $self->{connections}{$handle} = $handle; # keep it alive.
      return;
   };
}

sub start_listening {
   my $self = shift;
   my %options = @_;
   my $host = $options{host} || undef;
   my $port = $options{port} || '5734';

   $self->{server} = tcp_server $host, $port, $self->tcp_handler, sub{ prepare_handler($self, @_) };
}

sub run {
   my $self = shift || Krypte->new();
   my %options = @_;
   my $host = $options{host};
   my $port = $options{port};
   my $session_time_out = $options{session_time_out};

   $self->start_listening(
      host => $host,
      port => $port,
   );
   AE::cv->recv;
}

1;

__END__
