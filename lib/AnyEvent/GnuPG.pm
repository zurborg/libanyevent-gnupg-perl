use strict;
use warnings;

package AnyEvent::GnuPG;

# ABSTRACT: AnyEvent-based interface to the GNU Privacy Guard

=head1 SYNOPSIS

    use AnyEvent::GnuPG qw( :algo );

    my $gpg = AnyEvent::GnuPG->new();

    $gpg->encrypt(
        plaintext   => "file.txt",
        output      => "file.gpg",
        armor       => 1,
        sign        => 1,
        passphrase  => $secret
    );
    
    $gpg->decrypt(
        ciphertext    => "file.gpg",
        output        => "file.txt"
    );
    
    $gpg->clearsign(
        plaintext => "file.txt",
        output => "file.txt.asc",
        passphrase => $secret,
        armor => 1,
    );
    
    $gpg->verify(
        signature => "file.txt.asc",
        file => "file.txt"
    );
    
    $gpg->gen_key(
        name => "Joe Blow",
        comment => "My GnuPG key",
        passphrase => $secret,
    );

=head1 DESCRIPTION

AnyEvent::GnuPG is a perl interface to the GNU Privacy Guard. It uses the shared memory coprocess interface that gpg provides for its wrappers. It tries its best to map the interactive interface of the gpg to a more programmatic model.

=head1 API OVERVIEW

The API is accessed through methods on a AnyEvent::GnuPG object which is a wrapper around the B<gpg> program. All methods takes their argument using named parameters, and errors are returned by throwing an exception (using croak). If you wan't to catch errors you will have to use eval or L<Try::Tiny>.

This modules uses L<AnyEvent::Proc>. For input data, all of L<AnyEvent::Proc/pull> and for output data, all of L<AnyEvent::Proc/pipe> allowed handle types are allowed.

The code is based on L<GnuPG> with API compatibility except that L<GnuPG::Tie> is B<not> ported.

=cut

use Exporter 'import';
use AnyEvent;
use AnyEvent::Proc 0.104;
use Email::Address;
use Async::Chain;
use Try::Tiny;
use Carp qw(confess);

use constant RSA_RSA     => 1;
use constant DSA_ELGAMAL => 2;
use constant DSA         => 3;
use constant RSA         => 4;

use constant TRUST_UNDEFINED => -1;
use constant TRUST_NEVER     => 0;
use constant TRUST_MARGINAL  => 1;
use constant TRUST_FULLY     => 2;
use constant TRUST_ULTIMATE  => 3;

# VERSION

=head1 EXPORTS

Nothing by default. Available tags:

=over 4

=item * :algo

RSA_RSA DSA_ELGAMAL DSA RSA

=item * :trust

TRUST_UNDEFINED TRUST_NEVER TRUST_MARGINAL TRUST_FULLY TRUST_ULTIMATE

=back

=cut

our @EXPORT = qw();

our %EXPORT_TAGS = (
    algo  => [qw[ RSA_RSA DSA_ELGAMAL DSA RSA ]],
    trust => [
        qw[ TRUST_UNDEFINED TRUST_NEVER TRUST_MARGINAL TRUST_FULLY TRUST_ULTIMATE ]
    ],
);

Exporter::export_ok_tags(qw( algo trust ));

sub _parse_trust {
    for (shift) {
        if (defined) {
            /ULTIMATE/ && do { return TRUST_ULTIMATE; };
            /FULLY/    && do { return TRUST_FULLY; };
            /MARGINAL/ && do { return TRUST_MARGINAL; };
            /NEVER/    && do { return TRUST_NEVER; };
        }
        return TRUST_UNDEFINED;    # Default
    }
}

sub _options {
    my $self = shift;
    $self->{cmd_options} = shift if ( $_[0] );
    $self->{cmd_options};
}

sub _command {
    my $self = shift;
    $self->{command} = shift if ( $_[0] );
    $self->{command};
}

sub _args {
    my $self = shift;
    $self->{args} = shift if ( $_[0] );
    $self->{args};
}

sub _cmdline {
    my $self = shift;
    my $args = [ $self->{gnupg_path} ];

    # Default options
    push @$args, "--no-tty", "--no-greeting", "--yes";

    # Check for homedir and options file
    push @$args, "--homedir", $self->{homedir} if $self->{homedir};
    push @$args, "--options", $self->{options} if $self->{options};

    # Command options
    push @$args, @{ $self->_options };

    # Command and arguments
    push @$args, "--" . $self->_command;
    push @$args, @{ $self->_args };

    return $args;
}

sub _condvar {
    my $cb = shift;
    return $cb if ref $cb eq 'AnyEvent::CondVar';
    my $cv = AE::cv;
    $cv->cb($cb) if ref $cb eq 'CODE';
    $cb ||= '';
    $cv;
}

sub _croak {
    my ( $cv, $msg ) = @_;
    AE::log error => $msg;
    $cv->croak($msg);
    $cv;
}

sub _catch {
    my ( $cv1, $cb ) = @_;
    AE::cv {
        my $cv2 = shift;
        try {
            $cb->( $cv2->recv );
        }
        catch {
            s{ at \S+ line \d+\.\s+$}{};
            $cv1->croak($_)
        };
    }
}

sub _read_from_status {
    my ( $self, $cb ) = @_;
    my $cv = _condvar($cb);

    # Check if a status was pushed back
    if ( $self->{next_status} ) {
        my $status = $self->{next_status};
        $self->{next_status} = undef;
        return $cv->send(@$status);
    }

    unless ( $self->{status_fd} ) {
        return $self->_abort_gnupg( "status fd not there", $cv );
    }

    chain sub {
        my $next = shift;
        $self->{status_fd}->readline_cb( _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        my $line = shift;
        unless ( defined $line ) {
            return $self->_abort_gnupg( "got nothing from status fd", $cv );
        }

        my ( $cmd, $arg ) = $line =~ /\[GNUPG:\] (\w+) ?(.+)?$/;
        return $self->_abort_gnupg(
            "error communicating with gnupg: bad status line: $line", $cv )
          unless $cmd;
        $arg ||= '';
        AE::log debug => "got status command: $cmd (arguments: $arg)";

        $cv->send( $cmd, $arg );
      };

    $cv;
}

sub _next_status {
    my ( $self, $cmd, $arg ) = @_;

    $self->{next_status} = [ $cmd, $arg ];
}

sub _abort_gnupg {
    my ( $self, $msg, $cb ) = @_;
    my $cv = _condvar($cb);
    AE::log error => $msg if $msg;
    if ( $self->{gnupg_proc} ) {
        $self->{gnupg_proc}->fire_and_kill(
            10,
            sub {
                AE::log debug => "fired and killed";
                $self->_end_gnupg(
                    sub {
                        AE::log debug => "gnupg aborted";
                        $cv->croak($msg);
                    }
                );
            }
        );
    }
    $cv;
}

sub _end_gnupg {
    my ( $self, $cb ) = @_;
    my $cv = _condvar($cb);

    if ( ref $self->{input} eq 'GLOB' ) {
        close $self->{input};
    }

    if ( $self->{command_fd} ) {
        $self->{command_fd}->finish;
    }

    if ( 0 && $self->{status_fd} ) {
        $self->{status_fd}->A->destroy;
    }

    if ( $self->{gnupg_proc} ) {

        $self->{gnupg_proc}->wait(
            sub {
                if ( ref $self->{output} eq 'GLOB' ) {
                    close $self->{output};
                }

                for (
                    qw(protocol proc command options args status_fd command_fd input output next_status )
                  )
                {
                    delete $self->{$_};
                }

                AE::log debug => "gnupg exited";
                $cv->send;
            }
        );

        #});
    }
    else {
        $cv->send;
    }
    $cv;
}

sub _run_gnupg {
    my $self = shift;

    if ( defined $self->{input} and not ref $self->{input} ) {
        my $file = $self->{input};
        open( my $fh, "<$file" ) or die "cannot open file $file: $!";
        AE::log info => "input file $file opened at $fh";
        $self->{input} = $fh;
    }

    if ( defined $self->{output} and not ref $self->{output} ) {
        my $file = $self->{output};
        open( my $fh, ">$file" ) or die "cannot open file $file: $!";
        AE::log info => "output file $file opened at $fh";
        $self->{output} = $fh;
    }

    my $cmdline = $self->_cmdline;

    my $gpg = shift @$cmdline;

    my $status  = AnyEvent::Proc::reader();
    my $command = AnyEvent::Proc::writer();

    unshift @$cmdline, '--status-fd'  => $status;
    unshift @$cmdline, '--command-fd' => $command;

    my $err;

    AE::log debug => "running $gpg " . join( ' ' => @$cmdline );
    my $proc = AnyEvent::Proc->new(
        bin    => $gpg,
        args   => $cmdline,
        extras => [ $status, $command ],
        ttl    => 300,
        errstr => \$err,
    );

    if ( defined $self->{input} ) {
        $proc->pull( $self->{input} );
    }

    if ( defined $self->{output} ) {
        $proc->pipe( out => $self->{output} );
    }

    $self->{command_fd} = $command;
    $self->{status_fd}  = $status;
    $self->{gnupg_proc} = $proc;

    AE::log debug => "gnupg ready";

    $proc;
}

sub _cpr_maybe_send {
    my ( $self, $key, $value, $cb ) = @_;
    $self->_cpr_send( $key, $value, 1, $cb );
}

sub _cpr_send {
    my ( $self, $key, $value, $optional, $cb ) = @_;
    my $cv = _condvar($cb);

    AE::log debug => "sending key '$key' with value '$value'";

    my $fd = $self->{command_fd};

    chain sub {
        my $next = shift;
        $self->_read_from_status( _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        my ( $cmd, $arg ) = @_;
        unless ( $cmd =~ /^GET_/ ) {
            return $self->_abort_gnupg( "protocol error: expected GET_*", $cv )
              unless $optional;
            $self->_next_status( $cmd, $arg );
            return $cv->send;
        }

        unless ( $arg eq $key ) {
            return $self->_abort_gnupg( "protocol error: expected key '$key' got '$arg'",
                $cv )
              unless $optional;
            return $cv->send;
        }

        $fd->writeln($value);

        $self->_read_from_status( _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        my ( $cmd, $arg ) = @_;
        unless ( $cmd =~ /^GOT_IT/ ) {
            $self->_next_status( $cmd, $arg );
        }
        $cv->send;
      };
    $cv;
}

sub _send_passphrase {
    my ( $self, $passwd, $cb ) = @_;
    my $cv = _condvar($cb);

    chain sub {
        my $next = shift;

        # GnuPG should now tell us that it needs a passphrase
        $self->_read_from_status( _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        my ($cmd) = @_;

        # Skip UserID hint
        if ( $cmd =~ /USERID_HINT/ ) {
            $self->_read_from_status( _catch( $cv, $next ) );
        }
        else {
            $next->($cmd);
        }
      }, sub {
        my $next = shift;
        my ($cmd) = @_;
        if ( $cmd =~ /GOOD_PASSPHRASE/ )
        {    # This means we didnt need a passphrase
            $self->_next_status($cmd)
              ;    # We push this back on for read_from_status
            return $cv->send;
        }

        return $self->_abort_gnupg(
            "Protocol error: expected NEED_PASSPHRASE got $cmd", $cv )
          unless $cmd =~ /NEED_PASSPHRASE/;
        $self->_cpr_send( "passphrase.enter", $passwd, 0,
            _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        unless ($passwd) {
            $self->_read_from_status( _catch($next) );
        }
        else {
            $next->skip->();
        }
      }, sub {
        my $next = shift;
        my ($cmd) = @_;
        return $self->_abort_gnupg(
            "Protocol error: expected MISSING_PASSPHRASE got $cmd", $cv )
          unless $cmd eq "MISSING_PASSPHRASE";
        $next->();
      }, sub {
        $cv->send;
      };
    $cv;
}

sub _check_sig {
    my ( $self, $cmd, $arg, $cb ) = @_;
    my $cv = _condvar($cb);

    my ( $sigid, $date, $time, $keyid, $name, $policy_url, $fingerprint,
        $trust );

    chain sub {
        my $next = shift;

        # Our caller may already have grabbed the first line of
        # signature reporting.
        if ($cmd) {
            $next->( $cmd, $arg );
        }
        else {
            $self->_read_from_status( _catch( $cv, $next ) );
        }
      }, sub {
        my $next = shift;
        ( $cmd, $arg ) = @_;

        # Ignore patent warnings.
        if ( $cmd =~ /RSA_OR_IDEA/ ) {
            $self->_read_from_status( _catch( $cv, $next ) );
        }
        else {
            $next->(@_);
        }
      }, sub {
        my $next = shift;
        ( $cmd, $arg ) = @_;

        # Ignore automatic key imports
        if ( $cmd =~ /IMPORTED/ ) {
            $self->_read_from_status( _catch( $cv, $next ) );
        }
        else {
            $next->(@_);
        }
      }, sub {
        my $next = shift;
        ( $cmd, $arg ) = @_;
        if ( $cmd =~ /IMPORT_OK/ ) {
            $self->_read_from_status( _catch( $cv, $next ) );
        }
        else {
            $next->(@_);
        }
      }, sub {
        my $next = shift;
        ( $cmd, $arg ) = @_;
        if ( $cmd =~ /IMPORT_RES/ ) {
            $self->_read_from_status( _catch( $cv, $next ) );
        }
        else {
            $next->(@_);
        }
      }, sub {
        my $next = shift;
        ( $cmd, $arg ) = @_;
        if ( $cmd =~ /BADSIG/ ) {
            return $self->_abort_gnupg( "invalid signature from $arg", $cv );
        }
        if ( $cmd =~ /ERRSIG/ ) {
            my ( $keyid, $key_algo, $digest_algo, $sig_class, $timestamp, $rc )
              = split ' ', $arg;
            if ( $rc == 9 ) {
                return $self->_abort_gnupg( "no public key $keyid", $cv );
            }
            else {
                return $self->_abort_gnupg(
                    "error verifying signature from $keyid", $cv );
            }
        }
        return $self->_abort_gnupg( "protocol error: expected SIG_ID", $cv )
          unless $cmd =~ /SIG_ID/;
        ( $sigid, $date, $time ) = split /\s+/, $arg;
        $self->_read_from_status( _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        ( $cmd, $arg ) = @_;
        return $self->_abort_gnupg( "protocol error: expected GOODSIG", $cv )
          unless $cmd =~ /GOODSIG/;
        ( $keyid, $name ) = split /\s+/, $arg, 2;

        $self->_read_from_status( _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        ( $cmd, $arg ) = @_;
        if ( $cmd =~ /POLICY_URL/ ) {
            $policy_url = $arg;
            $self->_read_from_status( _catch( $cv, $next ) );
        }
        else {
            $next->(@_);
        }
      }, sub {
        my $next = shift;
        ( $cmd, $arg ) = @_;

        return $self->_abort_gnupg( "protocol error: expected VALIDSIG", $cv )
          unless $cmd =~ /VALIDSIG/;
        ($fingerprint) = split /\s+/, $arg, 2;

        $self->_read_from_status( _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        ( $cmd, $arg ) = @_;
        return $self->_abort_gnupg( "protocol error: expected TRUST*", $cv )
          unless $cmd =~ /TRUST/;
        ($trust) = _parse_trust($cmd);

        $cv->send(
            {
                sigid       => $sigid,
                date        => $date,
                timestamp   => $time,
                keyid       => $keyid,
                user        => $name,
                fingerprint => $fingerprint,
                trust       => $trust,
                policy_url  => $policy_url,
            }
        );
      };
    $cv;
}

sub DESTROY {
    my $self = shift;

    $self->{gnupg_proc}->kill if $self->{gnupg_proc};
}

=method new(%params)

You create a new AnyEvent::GnuPG wrapper object by invoking its new method. (How original!). The module will try to finds the B<gpg> program in your path and will croak if it can't find it. Here are the parameters that it accepts:

=over 4

=item * gnupg_path

Path to the B<gpg> program.

=item * options

Path to the options file for B<gpg>. If not specified, it will use the default one (usually F<~/.gnupg/options>).

=item * homedir

Path to the B<gpg> home directory. This is the directory that contains the default F<options> file, the public and private key rings as well as the trust database.

=back

Example:

    my $gpg = AnyEvent::GnuPG->new();

=cut

sub new {
    my $proto = shift;
    my $class = ref $proto || $proto;

    my %args = @_;

    my $self = {};
    if ( $args{homedir} ) {
        confess("Invalid home directory: $args{homedir}")
          unless -d $args{homedir} && -x _;
        $self->{homedir} = $args{homedir};
    }
    if ( $args{options} ) {
        confess("Invalid options file: $args{options}")
          unless -r $args{options};
        $self->{options} = $args{options};
    }
    if ( $args{gnupg_path} ) {
        confess("Invalid gpg path: $args{gnupg_path}")
          unless -x $args{gnupg_path};
        $self->{gnupg_path} = $args{gnupg_path};
    }
    else {
        my ($path) = grep { -x "$_/gpg" } split /:/, $ENV{PATH};
        confess("Couldn't find gpg in PATH ($ENV{PATH})") unless $path;
        $self->{gnupg_path} = "$path/gpg";
    }

    bless $self, $class;
}

=method gen_key(%params)

This methods is used to create a new gpg key pair. The methods croaks if there is an error. It is a good idea to press random keys on the keyboard while running this methods because it consumes a lot of entropy from the computer. Here are the parameters it accepts:

=over 4

=item * algo

This is the algorithm use to create the key. Can be I<DSA_ELGAMAL>, I<DSA>, I<RSA_RSA> or I<RSA>. It defaults to I<DSA_ELGAMAL>. To import those constant in your name space, use the I<:algo> tag.

=item * size

The size of the public key. Defaults to 1024. Cannot be less than 768 bits, and keys longer than 2048 are also discouraged. (You *DO* know that your monitor may be leaking sensitive information ;-).

=item * valid

How long the key is valid. Defaults to 0 or never expire.

=item * name

This is the only mandatory argument. This is the name that will used to construct the user id.

=item * email

Optional email portion of the user id.

=item * comment

Optional comment portion of the user id.

=item * passphrase

The passphrase that will be used to encrypt the private key. Optional but strongly recommended.

=back

Example:

    $gpg->gen_key(
        algo => DSA_ELGAMAL,
        size => 1024,
        name => "My name"
    );

=cut

sub gen_key {
    shift->gen_key_cb(@_)->recv;
}

=method gen_key_cb(%params[, cb => $callback|$condvar])

Asynchronous variant of L</gen_key>.

=cut

sub gen_key_cb {
    my ( $self, %args ) = @_;
    my $cv = _condvar( delete $args{cb} );
    my $cmd;
    my $arg;

    my $algo = $args{algo};
    $algo ||= RSA_RSA;

    my $size = $args{size};
    $size ||= 1024;
    return _croak( $cv, "Keysize is too small: $size" ) if $size < 768;
    return _croak( $cv, "Keysize is too big: $size" )   if $size > 2048;

    my $expire = $args{valid};
    $expire ||= 0;

    my $passphrase = $args{passphrase} || "";
    my $name = $args{name};

    return _croak( $cv, "Missing key name" ) unless $name;
    return _croak( $cv, "Invalid name: $name" )
      unless $name =~ /^\s*[^0-9\<\(\[\]\)\>][^\<\(\[\]\)\>]+$/;

    my $email = $args{email};
    if ($email) {
        ($email) = Email::Address->parse($email)
          or _croak( $cv, "Invalid email address: $email" );
    }
    else {
        $email = "";
    }

    my $comment = $args{comment};
    if ($comment) {
        _croak( $cv, "Invalid characters in comment" ) if $comment =~ /[\(\)]/;
    }
    else {
        $comment = "";
    }

    $self->_command("gen-key");
    $self->_options( [] );
    $self->_args(    [] );

    my $proc = $self->_run_gnupg;
    $proc->finish unless $self->{input};

    chain sub {
        my $next = shift;
        $self->_cpr_send( "keygen.algo", $algo, 0, _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        $self->_cpr_send( "keygen.size", $size, 0, _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        $self->_cpr_send( "keygen.valid", $expire, 0, _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        $self->_cpr_send( "keygen.name", $name, 0, _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        $self->_cpr_send( "keygen.email", $email, 0, _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        $self->_cpr_send( "keygen.comment", $comment, 0, _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        $self->_send_passphrase( $passphrase, _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        $self->_end_gnupg( _catch( $cv, $next ) );
      }, sub {
        $cv->send(@_);
      };
    $cv;
}

=method import_keys(%params)

Import keys into the GnuPG private or public keyring. The method croaks if it encounters an error. It returns the number of keys imported. Parameters:

=over 4

=item * keys

Only parameter and mandatory. It can either be a filename or a reference to an array containing a list of files that will be imported.

=back

Example:

    $gpg->import_keys(
        keys => [qw[ key.pub key.sec ]]
    );

=cut

sub import_keys {
    shift->import_keys_cb(@_)->recv;
}

=method import_keys_cb(%args[, cb => $callback|$condvar])

Asynchronous variant of L</import_keys>.

=cut

sub import_keys_cb {
    my ( $self, %args ) = @_;
    my $cv = _condvar( delete $args{cb} );

    $self->_command("import");
    $self->_options( [] );

    my $count;
    if ( ref $args{keys} ) {
        $self->_args( $args{keys} );
    }
    else {
        # Only one file to import
        $self->{input} = $args{keys};
        $self->_args( [] );
    }

    my $proc = $self->_run_gnupg;
    $proc->finish unless $self->{input};

    my $num_files = ref $args{keys} ? @{ $args{keys} } : 1;

    my ( $sub1, $sub2, $sub3 );

    $sub1 = sub {
        my ( $cmd, $arg ) = @_;
        if ( $cmd =~ /IMPORTED/ ) {
            $count++;
            $sub2->();
        }
        else {
            $sub3->( $cmd, $arg );
        }
    };

    $sub3 = sub {
        my ( $cmd, $arg ) = @_;
        return $self->_abort_gnupg(
            "protocol error expected IMPORT_OK got $cmd", $cv )
          unless $cmd =~ /IMPORT_OK/;
        $self->_end_gnupg(
            _catch(
                $cv,
                sub {
                    $cv->send($count);
                }
            )
        );
    };

    $sub2 = sub {
        $self->_read_from_status( _catch( $cv, $sub1 ) );
    };

    $sub2->();

    $cv;
}

=method import_key($string)

Import one single key into the GnuPG private or public keyring. The method croaks if it encounters an error.

Example:

    $gpg->import_keys($string);

=cut

sub import_key {
    shift->import_key_cb(@_)->recv;
}

=method import_key_cb($string[, $callback|$condvar])

Asynchronous variant of L</import_key>.

=cut

sub import_key_cb {
    my ( $self, $keystr, $cb ) = @_;
    my $cv = _condvar($cb);

    $self->_command("import");
    $self->_options( [] );

    $self->{input} = \"$keystr";
    $self->_args( [] );

    my $proc = $self->_run_gnupg;
    $proc->finish unless $self->{input};

    chain sub {
        my $next = shift;
        $self->_read_from_status( _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        my ( $cmd, $arg ) = @_;
        return $self->_abort_gnupg( "protocol error expected IMPORTED got $cmd",
            $cv )
          unless $cmd =~ /IMPORTED|IMPORT_OK/;
        $self->_read_from_status( _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        my ( $cmd, $arg ) = @_;
        return $self->_abort_gnupg(
            "protocol error expected IMPORT_OK got $cmd", $cv )
          unless $cmd =~ /IMPORT_OK|IMPORT_RES/;
        $self->_end_gnupg( _catch( $cv, $next ) );
      }, sub {
        shift;
        $cv->send(@_);
      };

    $cv;
}

=method export_keys(%params)

Exports keys from the GnuPG keyrings. The method croaks if it encounters an error. Parameters:

=over 4

=item * keys

Optional argument that restricts the keys that will be exported. Can either be a user id or a reference to an array of userid that specifies the keys to be exported. If left unspecified, all keys will be exported.

=item * secret

If this argument is to true, the secret keys rather than the public ones will be exported.

=item * all

If this argument is set to true, all keys (even those that aren't OpenPGP compliant) will be exported.

=item * output

This argument specifies where the keys will be exported. Can be either a file name or a reference to a file handle.

=item * armor

Set this parameter to true, if you want the exported keys to be ASCII armored.

=back

Example:

    $gpg->export_keys(
        armor => 1,
        output => "keyring.pub"
    );

=cut

sub export_keys {
    shift->export_keys_cb(@_)->recv;
}

=method export_keys_cb(%params[, cb => $callback|$condvar])

Asynchronous variant of L</export_keys>.

=cut

sub export_keys_cb {
    my ( $self, %args ) = @_;
    my $cv = _condvar( delete $args{cb} );

    my $options = [];
    push @$options, "--armor" if $args{armor};

    $self->{output} = $args{output};

    my $keys = [];
    if ( $args{keys} ) {
        push @$keys, ref $args{keys} ? @{ $args{keys} } : $args{keys};
    }

    if ( $args{secret} ) {
        $self->_command("export-secret-keys");
    }
    elsif ( $args{all} ) {
        $self->_command("export-all");
    }
    else {
        $self->_command("export");
    }

    $self->_options($options);
    $self->_args($keys);

    my $proc = $self->_run_gnupg;

    $proc->finish unless $self->{input};

    $self->_end_gnupg( _catch( $cv, sub { $cv->send(@_) } ) );

    $cv;
}

=method encrypt(%params)

This method is used to encrypt a message, either using assymetric or symmetric cryptography. The methods croaks if an error is encountered. Parameters:

=over

=item * plaintext

This argument specifies what to encrypt. It can be either a filename or a reference to a file handle.

=item * output

This optional argument specifies where the ciphertext will be output. It can be either a file name or a reference to a file handle.

=item * armor

If this parameter is set to true, the ciphertext will be ASCII armored.

=item * symmetric

If this parameter is set to true, symmetric cryptography will be used to encrypt the message. You will need to provide a I<passphrase> parameter.

=item * recipient

If not using symmetric cryptography, you will have to provide this parameter. It should contains the userid of the intended recipient of the message. It will be used to look up the key to use to encrypt the message. The parameter can also take an array ref, if you want to encrypt the message for a group of recipients.

=item * sign

If this parameter is set to true, the message will also be signed. You will probably have to use the I<passphrase> parameter to unlock the private key used to sign message. This option is incompatible with the I<symmetric> one.

=item * local-user

This parameter is used to specified the private key that will be used to sign the message. If left unspecified, the default user will be used. This option only makes sense when using the I<sign> option.

=item * passphrase

This parameter contains either the secret passphrase for the symmetric algorithm or the passphrase that should be used to decrypt the private key.

=back

Example:

    $gpg->encrypt(
        plaintext => file.txt,
        output => "file.gpg",
        sign => 1,
        passphrase => $secret
    );

=cut

sub encrypt {
    shift->encrypt_cb(@_)->recv;
}

=method encrypt_cb(%params[, cb => $callback|$condvar])

Asynchronous variant of L</encrypt>.

=cut

sub encrypt_cb {
    my ( $self, %args ) = @_;
    my $cv = _condvar( delete $args{cb} );

    my $options = [];
    croak("no recipient specified")
      unless $args{recipient} or $args{symmetric};

    for my $recipient (
        grep defined,
        (
            ref $args{recipient} eq 'ARRAY'
            ? @{ $args{recipient} }
            : $args{recipient}
        )
      )
    {
        # Escape spaces in the recipient. This fills some strange edge case
        $recipient =~ s/ /\ /g;
        push @$options, "--recipient" => $recipient;
    }

    push @$options, "--sign" if $args{sign};
    croak("can't sign an symmetric encrypted message")
      if $args{sign} and $args{symmetric};

    my $passphrase = $args{passphrase} || "";

    push @$options, "--armor" if $args{armor};
    push @$options, "--local-user", $args{"local-user"}
      if defined $args{"local-user"};

    push @$options, "--auto-key-locate", $args{"auto-key-locate"}
      if defined $args{"auto-key-locate"};

    push @$options, "--keyserver", $args{"keyserver"}
      if defined $args{"keyserver"};

    $self->{input} = $args{plaintext} || $args{input};
    $self->{output} = $args{output};
    if ( $args{symmetric} ) {
        $self->_command("symmetric");
    }
    else {
        $self->_command("encrypt");
    }
    $self->_options($options);
    $self->_args( [] );

    my $proc = $self->_run_gnupg;
    $proc->finish unless $self->{input};

    chain sub {
        my $next = shift;
        # Unless we decided to sign or are using symmetric cipher, we are done
        if ( $args{sign} or $args{symmetric} ) {
            $self->_send_passphrase( $passphrase, _catch( $cv, $next ) );
        }
        else {
            $next->skip(2)->();
        }
      }, sub {
        my $next = shift;
        if ( $args{sign} ) {
            $self->_read_from_status( _catch( $cv, $next ) );
        }
        else {
            $next->skip->();
        }
      }, sub {
        my $next = shift;
        my ( $cmd, $arg ) = @_;
        return $self->_abort_gnupg( "invalid passphrase - $cmd", $cv )
          unless $cmd =~ /GOOD_PASSPHRASE/;
        $next->();
      }, sub {
        my $next = shift;

        # It is possible that this key has no assigned trust value.
        # Assume the caller knows what he is doing.
        $self->_cpr_maybe_send( "untrusted_key.override", 'y',
            _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        $self->_read_from_status( _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        my ( $cmd, $arg ) = @_;
        unless ( $args{sign} ) {
            return $next->skip->(@_);
        }
        return $self->_abort_gnupg(
            "protocol error expected BEGIN_SIGN got $cmd", $cv )
          unless $cmd =~ /BEGIN_SIGN/;
        $self->_read_from_status( _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        my ( $cmd, $arg ) = @_;
        return $self->_abort_gnupg(
            "protocol error expected SIG_CREATED got $cmd", $cv )
          unless $cmd =~ /SIG_CREATED/;
        $self->_read_from_status( _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        my ( $cmd, $arg ) = @_;
        return $self->_abort_gnupg(
            "protocol error expected BEGIN_ENCRYPTION got $cmd", $cv )
          unless $cmd =~ /BEGIN_ENCRYPTION/;
        $self->_read_from_status( _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        my ( $cmd, $arg ) = @_;
        return $self->_abort_gnupg(
            "protocol error expected END_ENCRYPTION got $cmd", $cv )
          unless $cmd =~ /END_ENCRYPTION/;
        $self->_end_gnupg( _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        $cv->send(@_);
      };

    $cv;
}

=method sign(%params)

This method is used create a signature for a file or stream of data.
This method croaks on errors. Parameters:

=over 4

=item * plaintext

This argument specifies what  to sign. It can be either a filename or a reference to a file handle.

=item * output

This optional argument specifies where the signature will be output. It can be either a file name or a reference to a file handle.

=item * armor

If this parameter is set to true, the signature will be ASCII armored.

=item * passphrase

This parameter contains the secret that should be used to decrypt the private key.

=item * local-user

This parameter is used to specified the private key that will be used to make the signature. If left unspecified, the default user will be used.

=item * detach-sign

If set to true, a digest of the data will be signed rather than the whole file.

=back

Example:

    $gpg->sign(
        plaintext => "file.txt",
        output => "file.txt.asc",
        armor => 1
    );

=cut

sub sign {
    shift->sign_cb(@_)->recv;
}

=method sign_cb(%params[, cb => $callback|$condvar])

Asynchronous variant of L</sign>.

=cut

sub sign_cb {
    my ( $self, %args ) = @_;
    my $cv = _condvar( delete $args{cb} );

    my $options = [];
    my $passphrase = $args{passphrase} || "";

    push @$options, "--armor" if $args{armor};
    push @$options, "--local-user", $args{"local-user"}
      if defined $args{"local-user"};

    $self->{input} = $args{plaintext} || $args{input};
    $self->{output} = $args{output};
    if ( $args{clearsign} ) {
        $self->_command("clearsign");
    }
    elsif ( $args{"detach-sign"} ) {
        $self->_command("detach-sign");
    }
    else {
        $self->_command("sign");
    }
    $self->_options($options);
    $self->_args( [] );

    my $proc = $self->_run_gnupg;
    $proc->finish unless $self->{input};

    chain sub {
        my $next = shift;
        # We need to unlock the private key
        $self->_send_passphrase( $passphrase, _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        $self->_read_from_status( _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        my ( $cmd, $line ) = @_;
        return $self->_abort_gnupg( "invalid passphrase", $cv )
          unless $cmd =~ /GOOD_PASSPHRASE/;
        $self->_end_gnupg( _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        $cv->send(@_);
      };

    $cv;
}

=head2 clearsign(%params)

This methods clearsign a message. The output will contains the original message with a signature appended. It takes the same parameters as the L</sign> method.

=cut

sub clearsign {
    my $self = shift;
    $self->sign( @_, clearsign => 1 );
}

=method clearsign_cb(%params[, cb => $callback|$condvar])

Asynchronous variant of L</clearsign>.

=cut

sub clearsign_cb {
    my $self = shift;
    $self->sign_cb( @_, clearsign => 1 );
}

=method verify(%params)

This method verifies a signature against the signed message. The methods croaks if the signature is invalid or an error is encountered. If the signature is valid, it returns an hash with the signature parameters. Here are the method's parameters:

=over 4

=item * signature

If the message and the signature are in the same file (i.e. a clearsigned message), this parameter can be either a file name or a reference to a file handle. If the signature doesn't follows the message, than it must be the name of the file that contains the signature.

=item * file

This is a file name or a reference to an array of file names that contains the signed data.

=back

When the signature is valid, here are the elements of the hash that is returned by the method:

=over 4

=item * sigid

The signature id. This can be used to protect against replay attack.

=item * date

The data at which the signature has been made.

=item * timestamp

The epoch timestamp of the signature.

=item * keyid

The key id used to make the signature.

=item * user

The userid of the signer.

=item * fingerprint

The fingerprint of the signature.

=item * trust

The trust value of the public key of the signer. Those are values that can be imported in your namespace with the :trust tag. They are (TRUST_UNDEFINED, TRUST_NEVER, TRUST_MARGINAL, TRUST_FULLY, TRUST_ULTIMATE).

=back

Example:

    my $sig = $gpg->verify(
        signature => "file.txt.asc",
        file => "file.txt"
    );

=cut

sub verify {
    shift->verify_cb(@_)->recv;
}

=method verify_cb(%params[, cb => $callback|$condvar])

Asynchronous variant of L</verify>.

=cut

sub verify_cb {
    my ( $self, %args ) = @_;
    my $cv = _condvar( delete $args{cb} );

    return _croak( $cv, "missing signature argument" ) unless $args{signature};
    my $files = [];
    if ( $args{file} ) {
        return _croak( $cv, "detached signature must be in a file" )
          unless -f $args{signature};
        push @$files, $args{signature},
          ref $args{file} ? @{ $args{file} } : $args{file};
    }
    else {
        $self->{input} = $args{signature};
    }

    my $options = [];

    push @$options, "--auto-key-locate", $args{"auto-key-locate"}
      if defined $args{"auto-key-locate"};

    push @$options, "--keyserver", $args{"keyserver"}
      if defined $args{"keyserver"};

    my @verify_options = ();

    push @verify_options => 'pka-lookups'        if $args{'pka-loopups'};
    push @verify_options => 'pka-trust-increase' if $args{'pka-trust-increase'};

    push @$options => ( '--verify-options' => join( ',' => @verify_options ) )
      if @verify_options;

    $self->_command("verify");
    $self->_options($options);
    $self->_args($files);

    my $proc = $self->_run_gnupg;
    $proc->finish unless $self->{input};

    my $sig;

    chain sub {
        my $next = shift;
        $self->_check_sig( undef, undef, _catch( $cv, $next ) );
      }, sub {
        my $next = shift;
        ($sig) = @_;
        $self->_end_gnupg( _catch( $cv, $next ) );
      }, sub {
        $cv->send($sig);
      };

    $cv;
}

=method decrypt(%params)

This method decrypts an encrypted message. It croaks, if there is an error while decrypting the message. If the message was signed, this method also verifies the signature. If decryption is sucessful, the method either returns the valid signature parameters if present, or true. Method parameters:

=over 4

=item * ciphertext

This optional parameter contains either the name of the file containing the ciphertext or a reference to a file handle containing the ciphertext.

=item * output

This optional parameter determines where the plaintext will be stored. It can be either a file name or a reference to a file handle.

=item * symmetric

This should be set to true, if the message is encrypted using symmetric cryptography.

=item * passphrase

The passphrase that should be used to decrypt the message (in the case of a message encrypted using a symmetric cipher) or the secret that will unlock the private key that should be used to decrypt the message.

=back

Example:

    $gpg->decrypt(
        ciphertext => "file.gpg",
        output => "file.txt",
        passphrase => $secret
    );

=cut

sub decrypt {
    shift->decrypt_cb(@_)->recv;
}

=method decrypt_cb(%params[, cb => $callback|$condvar])

Asynchronous variant of L</decrypt>.

=cut

sub decrypt_cb {
    my ( $self, %args ) = @_;
    my $cv = _condvar( delete $args{cb} );

    $self->{input} = $args{ciphertext} || $args{input};
    $self->{output} = $args{output};
    $self->_command("decrypt");
    $self->_options( [] );
    $self->_args(    [] );

    my $proc = $self->_run_gnupg;
    $proc->finish unless $self->{input};

    my $passphrase = $args{passphrase} || "";

    my $sig;

    if ( $args{symmetric} ) {

        chain sub {
            my $next = shift;
            $self->_send_passphrase( $passphrase, _catch( $cv, $next ) );
          }, sub {
            my $next = shift;
            $self->_read_from_status( _catch( $cv, $next ) );
          }, sub {
            my $next = shift;
            my ( $cmd, $arg ) = @_;
            return $self->_abort_gnupg( "invalid passphrase", $cv )
              if $cmd =~ /BAD_PASSPHRASE/;
            $self->_read_from_status( _catch( $cv, $next ) );
          }, sub {
            my $next = shift;
            my ( $cmd, $arg ) = @_;
            if ( $cmd =~ /BEGIN_DECRYPTION/ ) {
                $self->_read_from_status( _catch( $cv, $next ) );
            }
            else {
                $next->(@_);
            }
          }, sub {
            my $next = shift;
            my ( $cmd, $arg ) = @_;
            if ( $cmd =~ /DECRYPTION_INFO/ ) {
                $self->_read_from_status( _catch( $cv, $next ) );
            }
            else {
                $next->(@_);
            }
          }, sub {
            my $next = shift;
            my ( $cmd, $arg ) = @_;
            return $self->_abort_gnupg(
                "protocol error expected PLAINTEXT got $cmd", $cv )
              unless $cmd =~ /PLAINTEXT/;
            $self->_end_gnupg( _catch( $cv, $next ) );
          }, sub {
            $cv->send($sig);
          };

    }
    else {

        chain sub {
            my $next = shift;
            $self->_read_from_status( _catch( $cv, $next ) );
          }, sub {
            my $next = shift;
            $self->_send_passphrase( $passphrase, _catch( $cv, $next ) );
          }, sub {
            my $next = shift;
            $self->_read_from_status( _catch( $cv, $next ) );
          }, sub {
            my $next = shift;
            my ( $cmd, $arg ) = @_;
            return $self->_abort_gnupg( "invalid passphrase", $cv )
              unless $cmd =~ /GOOD_PASSPHRASE/;
            $self->_read_from_status( _catch( $cv, $next ) );
          }, sub {
            my $next = shift;
            my ( $cmd, $arg ) = @_;
            if ( $cmd =~ /BEGIN_DECRYPTION/ ) {
                $self->_read_from_status( _catch( $cv, $next ) );
            }
            else {
                $next->(@_);
            }
          }, sub {
            my $next = shift;
            my ( $cmd, $arg ) = @_;
            if ( $cmd =~ /SIG_ID/ ) {
                $self->_check_sig( $cmd, $arg, $next );
            }
            else {
                $next->skip->(@_);
            }
          }, sub {
            my $next = shift;
            ($sig) = @_;
            $self->_read_from_status( _catch( $cv, $next ) );
          }, sub {
            my $next = shift;
            my ( $cmd, $arg ) = @_;
            return $self->_abort_gnupg(
                "protocol error expected DECRYPTION_INFO got $cmd", $cv )
              unless $cmd =~ /DECRYPTION_INFO/;
            $self->_end_gnupg( _catch( $cv, $next ) );
          }, sub {
            $cv->send($sig);
          };

    }

    $cv;
}

=head1 BUGS AND LIMITATIONS

This module doesn't work (yet) with the v2 branch of GnuPG.

=head1 SEE ALSO

=over 4

=item * L<GnuPG>

=item * L<gpg(1)>

=back

=cut

1;
