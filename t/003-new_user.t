#!/usr/bin/env perl

use strict;
use warnings;

use FindBin;

use Test::More tests => 22;
use Test::Deep; # (); # uncomment to stop prototype errors
use Test::Exception;

use Krypte;

my $app = new Krypte;
note("create_user_hash");
# Setup temp admin
my $admin_user_password = 'underground';
my $admin_user_key = 'im a user key';
my $tmp_shared_key = 'ooo lala shared key';
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
   ) } 'lives when used properly';
is_deeply [ sort keys $app->{users}{'admin'} ], [ 'is_admin', 'key', 'shared_key' ], 'Created user has proper hash structure'; 

note("get_shared_key");
# Validation
throws_ok { $app->get_shared_key(undef, 'underground'); } qr/User and Password must be defined/, 'dies when user undefined';
throws_ok { $app->get_shared_key('admin', undef); } qr/User and Password must be defined/, 'dies when password undefined';
throws_ok { $app->get_shared_key('bob', 'thebuilder'); } qr/User must exist/, 'dies when given a nonexistent user';

# Gives expected shared key
is $app->get_shared_key('admin', $admin_user_password), $tmp_shared_key, 'get_shared_key unencrypts user key and shared key correctly';

# Create default admin
$app->prepare_handler(undef,undef,undef);

note("new_user");
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
throws_ok { $app->new_user(
      new_user => 'bob',
      new_password => 'thebuilder',
      admin_user => 'bob',
      admin_password => 'pw',
   ); } qr/doesn't exist/, 'dies when given non-existent admin';
lives_ok { $app->new_user(
      new_user => 'bob',
      new_password => 'thebuilder',
      admin_user => 'admin',
      admin_password => 'underground',
   ) } 'lives when used properly';
throws_ok { $app->new_user(
      new_user => 'alice',
      new_password => 'inwonderland',
      admin_user => 'bob',
      admin_password => 'thebuilder',
   ); } qr/is not an admin/, 'dies when given a non-admin user as admin';
is_deeply [ sort keys $app->{users}{'bob'} ], [ 'is_admin', 'key', 'shared_key' ], 'Created user has proper hash structure'; 
is $app->get_shared_key('admin','underground'), $app->get_shared_key('bob','thebuilder'), 'Admin user and Bob have the same uncrypted shared_key';
isnt $app->{users}{'bob'}{is_admin}, 1, 'Bob isn\'t an admin';

$app->new_user(
   new_user => 'alice',
   new_password => 'inwonderland',
   new_is_admin => 1,
   admin_user => 'admin',
   admin_password => 'underground',
);
is $app->{users}{'alice'}{is_admin}, 1, 'Alice is an admin';
$app->new_user(
   new_user => 'carl',
   new_password => 'sagan',
   new_is_admin => 'isamazing',
   admin_user => 'admin',
   admin_password => 'underground',
);
is $app->{users}{'alice'}{is_admin}, 1, 'new_is_admin takes a truthy value';
