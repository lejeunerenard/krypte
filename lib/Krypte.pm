package Krypte;

use strict;
use warnings;

use lib "$FindBin::Bin/../local/lib/perl5";

use AnyEvent::Socket;
use AnyEvent::Handle;

use JSON;

# Cryptography Modules
use Crypt::CBC;
use Crypt::Random::Seed;

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
   # Store user info into the keys hash
   $self->{users}{$user} = {
      key => $user_cipher->encrypt($user_key),
      is_admin => $is_admin,
      shared_key => $enc_shared_key,
   };
   undef $user_key;
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

   # Die if inputs are not set
   foreach ('admin_user', 'admin_password', 'new_user', 'new_password') {
      die $_.' must be defined' unless defined $options{$_};
   }

   # Die if $admin_user is doesnt exist
   die '$admin_user doesn\'t exist' unless $self->{users}{$admin_user};

   # Die if $admin_user is not an admin
   die '$admin_user is not an admin' unless $self->{users}{$admin_user}{is_admin};

   # ----- Get SharedKey with admin creds -----
   my $shared_key = $self->get_shared_key($admin_user, $admin_password);
   undef $admin_user;
   undef $admin_password;

   # ----- Generate UserKey -----
   my $user_key = $self->{crypt_source}->random_bytes(512);

   $self->create_user_hash(
      user => $new_user,
      user_key => $user_key,
      user_password => $new_password,
      shared_key => $shared_key,
      is_admin => $new_is_admin,
   );
   undef $shared_key;
   undef $user_key;
   undef $new_password;
}

=head2 get_shared_key

Given a user and password, get_shared_key will return the unencrypted shared key for the system.

Be careful to handle the shared key with care. It should never be left anywhere (memory or disk) unencrypted.

=cut

sub get_shared_key {
   my $self = shift;
   my $user = shift;
   my $password = shift;

   # Die if inputs are not set
   die 'User and Password must be defined' unless defined( $user ) and defined( $password );

   # Die if user doesnt exist
   die 'User must exist' unless defined $self->{users}{$user};

   # ----- Get UserKey with password -----
   # Create cipher for getting the UserKey
   my $user_cipher = Crypt::CBC->new(
      -key => $password,
      -cipher => 'Blowfish',
   );
   my $user_key = $user_cipher->decrypt($self->{users}{$user}{key});
   # Garbage collect, just in case
   undef $user_cipher;
   undef $password;

   # ----- Get SharedKey with user key -----
   # Create cipher for getting the SharedKey
   my $shared_cipher = Crypt::CBC->new(
      -key => $user_key,
      -cipher => 'Blowfish',
   );
   my $shared_key = $shared_cipher->decrypt($self->{users}{$user}{shared_key});
   # Garbage collect, just in case
   undef $shared_cipher;
   undef $user_key;
   undef $user;

   return $shared_key;
}

sub new {
   my $class = shift;
   my $self = {
      crypt_source => Crypt::Random::Seed->new( NonBlocking => 1 ),
      users => {},
   };

   bless $self, $class;
   return $self;
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
         my $message = from_json($hdl->rbuf);
         undef $hdl->rbuf; # Clear buffer so it doesnt stack

         print "Received: " .Dumper($message)."\n";

         if ($message->{method} eq 'newUser') {
            $self->new_user(
               new_user => $message->{new_user},
               new_password => $message->{new_password},
               admin_user => $message->{admin_user},
               admin_password => $message->{admin_password},
            );
         } elsif ($message->{method} eq 'dump') {
            foreach my $user ( keys %{$self->{users}} ) {
               print STDERR "$user:\n";
               print STDERR "key: ".unpack('H*',$self->{users}{$user}{key})."\n";
               print STDERR "shared key: ".unpack('H*',$self->{users}{$user}{shared_key})."\n";
               print STDERR "\n";
            }
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


   $self->start_listening(
      host => $host,
      port => $port,
   );
   AE::cv->recv;
}

1;

__END__
