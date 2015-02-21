#!/usr/bin/env perl

use strict;
use warnings;

use FindBin qw($RealBin);
use lib "$RealBin/../local/lib/perl5";

use Test::More;
use Test::Deep; # (); # uncomment to stop prototype errors
use Test::Exception;

use Promises qw(collect);

use Data::Dumper;

plan skip_all => 'DB credentials not given' unless defined $ENV{DB_USER} and defined $ENV{DB_PASSWORD};

use Krypte;

my $test_db_name = 'krypte_test';

my $user = $ENV{DB_USER};
my $password = $ENV{DB_PASSWORD};

my $app = new Krypte(
   dsn => "dbi:mysql:",
   db_username => $user || '',
   db_password => $password || '',
);

sub load_fixture {
   is system( "mysql -u$user --password=$password $test_db_name -se '\\. $RealBin/../sql/fixtures/db-structure.sql'" ), 0, 'Fixture loaded';
}

subtest 'setup' => sub {
   my $cv = AE::cv;
   $app->dbh->exec("DROP DATABASE IF EXISTS $test_db_name", sub {
      my($dbh, $rows, $rv) = @_;

      if ( $rv ) {
         pass 'drop test db';
         $app->dbh->exec("CREATE DATABASE $test_db_name", sub {
            my($dbh, $rows, $rv) = @_;

            if ( $rv ) {
               pass 'create test db';
               $app->dbh->exec("use $test_db_name", sub {
                  my($dbh, $rows, $rv) = @_;

                  if ( $rv ) {
                     pass 'use test db';
                     load_fixture;
                     $cv->broadcast;
                  }
               });
            }
         });
      } else {
         fail 'drop test db: '. $@;
      }
   });
   $cv->wait;
};

my $admin_user_password = 'underground';
my $admin_user_key = 'im a user key';
my $tmp_shared_key = 'ooo lala shared key';
subtest 'create_user_hash' => sub {

  throws_ok { $app->create_user_hash(
        user => undef,
        user_password => $admin_user_password,
        user_key => $admin_user_key,
        shared_key => $tmp_shared_key,
     ) } qr/user must be defined/, 'dies when user is undefined';
  throws_ok { $app->create_user_hash(
        user => 'admin',
        user_password => undef,
        user_key => $admin_user_key,
        shared_key => $tmp_shared_key,
     ) } qr/user_password must be defined/, 'dies when user_password is undefined';
  throws_ok { $app->create_user_hash(
        user => 'admin',
        user_password => $admin_user_password,
        user_key => undef,
        shared_key => $tmp_shared_key,
     ) } qr/user_key must be defined/, 'dies when user_key is undefined';
  throws_ok { $app->create_user_hash(
        user => 'admin',
        user_password => $admin_user_password,
        user_key => $admin_user_key,
        shared_key => undef,
     ) } qr/shared_key must be defined/, 'dies when shared_key is undefined';
  lives_ok { $app->create_user_hash(
        user => 'admin',
        user_password => $admin_user_password,
        user_key => $admin_user_key,
        shared_key => $tmp_shared_key,
        is_admin => 1,
     ) } 'lives when used properly';
  my $cv = AE::cv;
  my $admin_hash = $app->dbh->select('users', [ 'username', 'password', 'user_key', 'shared_key' ], sub {
        my ($dbh, $rows, $rv) = @_;

        if ($rv) {
           if ($#$rows == 0) {
              my $found_undef = 0;
              foreach my $value ( @{ $rows->[0] } ) {
                 if ( not defined $value ) {
                    $found_undef = 1;
                    last;
                 }
              }
              is $found_undef, 0, 'All columns were set';
              is $rows->[0][0], 'admin', 'username was correctly set';
              is $rows->[0][1], Digest::SHA1::sha1_hex($admin_user_password), 'password was correctly hashed';
              $cv->broadcast;
           }
        }
     });
  $cv->wait;
};

# Setup temp admin
subtest 'get_shared_key' => sub {
  # Validation
  throws_ok { $app->get_shared_key(undef, 'underground'); } qr/User and Password must be defined/, 'dies when user undefined';
  throws_ok { $app->get_shared_key('admin', undef); } qr/User and Password must be defined/, 'dies when password undefined';
  throws_ok {
     my $cv = AE::cv;
     $app->get_shared_key('bob', 'thebuilder')->then(sub {
         $cv->send;
        }, sub { $cv->croak( $_[0] ); });
     $cv->wait;
  } qr/User must exist/, 'dies when given a nonexistent user';

  # Gives expected shared key
  my $cv = AE::cv;
  $app->get_shared_key('admin', $admin_user_password)->then( sub {
     my $key = shift;
     is $key, $tmp_shared_key, 'get_shared_key unencrypts user key and shared key correctly';
      $cv->send;
  }, sub {
      fail 'get_shared_key unencrypts user key and shared key correctly';
      $cv->send;
  } );
  $cv->wait;

};

subtest 'new_user' => sub {

   load_fixture;
   # Create default admin
   $app->prepare_handler(undef,undef,undef);

  throws_ok { $app->new_user(
        admin_user => undef,
        admin_password => 'pw',
        new_user => 'bob',
        new_password => 'thebuilder',
     ); } qr/admin_user must be defined/, 'dies when admin_user is undefined';
  throws_ok { $app->new_user(
        admin_user => 'admin',
        admin_password => undef,
        new_user => 'bob',
        new_password => 'thebuilder',
     ); } qr/admin_password must be defined/, 'dies when admin_password is undefined';
  throws_ok { $app->new_user(
        admin_user => 'admin',
        admin_password => 'pw',
        new_user => undef,
        new_password => 'thebuilder',
     ); } qr/new_user must be defined/, 'dies when new_user is undefined';
  throws_ok { $app->new_user(
        admin_user => 'admin',
        admin_password => 'pw',
        new_user => 'bob',
        new_password => undef,
     ); } qr/new_password must be defined/, 'dies when new_password is undefined';
  throws_ok {
     my $cv = AE::cv;
     $app->new_user(
        new_user => 'bob',
        new_password => 'thebuilder',
        admin_user => 'bob',
        admin_password => 'pw',
     )->then( undef, sub {
        $cv->croak(shift);
     });
     $cv->wait;
  } qr/doesn't exist/, 'dies when given non-existent admin';
  lives_ok {
     my $cv = AE::cv;
     $app->new_user(
        new_user => 'bob',
        new_password => 'thebuilder',
        admin_user => 'admin',
        admin_password => 'underground',
     )->then(sub {
        $cv->send(shift);
     }, sub {
        $cv->croak(shift);
     });
     $cv->wait;
  } 'lives when used properly';
  throws_ok {
     my $cv = AE::cv;
     $app->new_user(
        new_user => 'alice',
        new_password => 'inwonderland',
        admin_user => 'bob',
        admin_password => 'thebuilder',
     )->then(undef, sub {
        $cv->croak(shift);
     });
     $cv->wait;
  } qr/is not an admin/, 'dies when given a non-admin user as admin';

  my $cv = AE::cv;
  $app->dbh->select('users', [ 'username', 'password', 'user_key', 'shared_key', 'is_admin' ], {
        username => 'bob',
     }, sub {
        my ($dbh, $rows, $rv) = @_;

        if ($rv) {
           if ($#$rows == 0) {
              is $rows->[0][1], Digest::SHA1::sha1_hex('thebuilder'), 'password was correctly hashed';
              ok $rows->[0][2], 'user_key is truthy';
              ok $rows->[0][3], 'shared_key is truthy';
              isnt $rows->[0][4], 1, 'Bob isn\'t an admin';
              $cv->broadcast;
           }
        } else {
           fail 'Retrieving created user';
        }
     });
  $cv->wait;

  $cv = AE::cv;
  $cv->begin;
  collect(
     $app->get_shared_key('admin','underground'),
     $app->get_shared_key('bob','thebuilder')
  )->then(sub {
     is $_[0][0], $_[1][0], 'Admin user and Bob have the same decrypted shared_key';
     $cv->end;
  }, sub {
     fail 'Admin user and Bob have the same decrypted shared_key';
     $cv->end;
  });

  $cv->begin;
  $app->new_user(
     new_user => 'alice',
     new_password => 'inwonderland',
     new_is_admin => 1,
     admin_user => 'admin',
     admin_password => 'underground',
  )->then(sub {
     $app->dbh->select('users', [ 'username', 'password', 'user_key', 'shared_key', 'is_admin' ], {
           username => 'alice',
        }, sub {
           my ($dbh, $rows, $rv) = @_;

           if ($rv) {
              if ($#$rows == 0) {
                 is $rows->[0][4], 1, 'Alice is an admin';
                 $cv->end;
              }
           } else {
              fail 'Alice is an admin';
              $cv->end;
           }
        });
  }, sub {
     fail 'Alice is an admin';
     $cv->end;
  });

  $cv->begin;
  $app->new_user(
     new_user => 'carl',
     new_password => 'sagan',
     new_is_admin => 'isamazing',
     admin_user => 'admin',
     admin_password => 'underground',
   )->then(sub {
     $app->dbh->select('users', [ 'username', 'password', 'user_key', 'shared_key', 'is_admin' ], {
           username => 'carl',
        }, sub {
           my ($dbh, $rows, $rv) = @_;

           if ($rv) {
              if ($#$rows == 0) {
                 is $rows->[0][4], 1, 'new_is_admin takes a truthy value';
                 $cv->end;
              }
           } else {
              fail 'new_is_admin takes a truthy value';
              $cv->end;
           }
        });
  }, sub {
     fail 'new_is_admin takes a truthy valueAlice is an admin';
     $cv->end;
  });

  $cv->recv;
};

subtest 'delete_user' => sub {
  throws_ok { $app->delete_user(
     user => undef,
     admin_user => 'admin',
     admin_password => 'underground',
  ); } qr/user must be defined/, 'dies when user is undefined';
  throws_ok { $app->delete_user(
     user => 'bob',
     admin_user => undef,
     admin_password => 'underground',
  ); } qr/admin_user must be defined/, 'dies when admin_user is undefined';
  throws_ok { $app->delete_user(
     user => 'bob',
     admin_user => 'admin',
     admin_password => undef,
  ); } qr/admin_password must be defined/, 'dies when admin_password is undefined';
  throws_ok {
     my $cv = AE::cv;
     $app->delete_user(
        user => 'methuselah',
        admin_user => 'admin',
        admin_password => 'underground',
     )->then(undef, sub {
         $cv->croak(shift);
     });
     $cv->wait;
   } qr/methuselah doesn't exist/, 'dies when given non-existent user';
  throws_ok {
     my $cv = AE::cv;
     $app->delete_user(
        user => 'bob',
        admin_user => 'derek',
        admin_password => 'jeter',
     )->then(undef, sub {
         $cv->croak(shift);
     });
     $cv->wait;
   } qr/derek doesn't exist/, 'dies when given non-existent admin';
  throws_ok {
     my $cv = AE::cv;
     $app->delete_user(
        user => 'bob',
        admin_user => 'bob',
        admin_password => 'thebuilder',
     )->then(undef, sub {
        $cv->croak(shift);
     });
     $cv->wait;
   } qr/is not an admin/, 'dies when given a non-admin user as admin';
  lives_ok { $app->delete_user(
     user => 'bob',
     admin_user => 'admin',
     admin_password => 'underground',
  ); } 'lives when all args are given';
  ok not( defined $app->{users}{'bob'} ), 'Bob is no more';
};
my $session_token;
subtest 'create_session' => sub {
  # Test error throwing for input
  my @required_fields = ( 'user', 'password');
  my %user_creds = (
    user => 'carl',
    password => 'password',
  );
  foreach my $field ( @required_fields ) {
    my %input_user = %user_creds;
    $input_user{$field} = undef;
    throws_ok { $app->create_session(
        %input_user
    ); } qr/$field must be defined/, "dies when $field is undefined";
  }

  throws_ok { $app->create_session(
    user => 'diana',
    password => 'princess',
  ); } qr/diana must exist/, "dies when user doesn't exist";

  lives_ok {
    $session_token = $app->create_session(
      %user_creds,
    );
  } 'lives when used with a valid user';
  ok $session_token, 'returns a session token';
  my @session_keys = ( 'shared_key', 'timer' );
  is_deeply [ sort keys $app->{sessions}{$session_token} ], \@session_keys, 'created session has proper hash structure';
  foreach ( @session_keys ) {
    ok defined $app->{sessions}{$session_token}{$_}, "$_ is defined in session hash";
  }
};
subtest 'end_session' => sub {
   my %token = (
      sessionToken => $session_token,
   );
   subtest 'errors' => sub {
      throws_ok { $app->end_session(
         session_token => undef,
      ); } qr/session_token must be defined/, "dies when sessionToken is undefined";
   };
   subtest 'functionality' => sub {
      ok exists $app->{sessions}{$session_token}, 'session token exists prior to being removed';
      lives_ok { $app->end_session(
         session_token => $session_token,
      ); } 'lives when used with a valid session token';
      ok not( exists $app->{sessions}{$session_token} ), 'session token was successfully removed';
   };
};
done_testing;
