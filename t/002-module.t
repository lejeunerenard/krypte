#!/usr/bin/env perl

use strict;
use warnings;

use FindBin;

use Test::More tests => 5;
use Test::Deep; # (); # uncomment to stop prototype errors
use Test::Exception;

use App::Krypte;

my $app = App::Krypte->new;
isa_ok $app, 'App::Krypte';
can_ok $app, qw(new_user get_shared_key prepare_handler tcp_handler start_listening run);
isa_ok $app->{crypt_source}, 'Crypt::Random::Seed';
ok not($app->{crypt_source}->is_blocking), 'Crypt::Random::Seed is non-blocking';
ok( ( defined($app->{users}) and ref $app->{users} eq 'HASH' ), '"users" hash is declared on creation');
