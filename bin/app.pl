#!/usr/bin/env perl

use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../lib";

use App::Krypte;

my $app = App::Krypte->new(
   dsn => 'dbi:mysql:krypte:localhost',
   db_username => $ENV{DB_USER},
   db_password => $ENV{DB_PASSWORD},
);
$app->run();
