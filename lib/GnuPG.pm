use strict;
use warnings;

package GnuPG;

# ABSTRACT: Interface to the GNU Privacy Guard

=head1 SYNOPSIS

    use GnuPG qw( :algo );

    my $gpg = new GnuPG();

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

GnuPG is a perl interface to the GNU Privacy Guard. It uses the shared memory coprocess interface that gpg provides for its wrappers. It tries its best to map the interactive interface of the gpg to a more programmatic model.

=head1 API OVERVIEW

The API is accessed through methods on a GnuPG object which is a wrapper around the B<gpg> program. All methods takes their argument using named parameters, and errors are returned by throwing an exception (using croak). If you wan't to catch errors you will have to use eval or L<Try::Tiny>.

This modules uses L<AnyEvent::Proc>. For input data, all of L<AnyEvent::Proc/pull> and for output data, all of L<AnyEvent::Proc/pipe> allowed handle types are allowed.

Since the flexible handling with AnyEvent::Proc is available, GnuPG::Tie is now longer supported.

=cut

use Exporter 'import';
use AnyEvent;
use AnyEvent::Proc 0.102;
use Email::Address;
use Carp;

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

sub _read_from_status {
    my $self = shift;

    # Check if a status was pushed back
    if ( $self->{next_status} ) {
        my $status = $self->{next_status};
        $self->{next_status} = undef;
        return @$status;
    }

    unless ( $self->{status_fd} ) {
        $self->_abort_gnupg("status fd not there");
    }

    AE::log debug => "reading from status fd";
    my $line = $self->{status_fd}->readline;
    unless ( defined $line ) {
        $self->_abort_gnupg("got nothing from status fd");
    }

    AE::log debug => "got from status fd: $line";

    my ( $cmd, $arg ) = $line =~ /\[GNUPG:\] (\w+) ?(.+)?$/;
    $self->_abort_gnupg(
        "error communicating with gnupg: bad status line: $line")
      unless $cmd;
    $arg ||= '';
    AE::log debug => "parsed as: $cmd - $arg";

    return wantarray ? ( $cmd, $arg ) : $cmd;
}

sub _next_status {
    my ( $self, $cmd, $arg ) = @_;

    $self->{next_status} = [ $cmd, $arg ];
}

sub _abort_gnupg {
    my ( $self, $msg ) = @_;
    AE::log error => $msg if $msg;
    $self->{gnupg_proc}->fire_and_kill(10) if $self->{gnupg_proc};
    AE::log debug => "fired and killed";
    $self->_end_gnupg;
    AE::log debug => "gnupg aborted";
    confess($msg);
}

sub _end_gnupg {
    my $self = shift;

    if ( ref $self->{input} eq 'GLOB' ) {
        AE::log debug => "close input file";
        close $self->{input};
    }

    if ( $self->{command_fd} ) {
        AE::log debug => "finish command fd";
        $self->{command_fd}->finish;
    }

    if ( $self->{status_fd} ) {
        AE::log debug => "destroy status fd";
        $self->{status_fd}->A->destroy;
    }

    if ( $self->{gnupg_proc} ) {
        AE::log debug => "finish proc";
        $self->{gnupg_proc}->finish;
        AE::log debug => "waiting...";
        my $exitcode = $self->{gnupg_proc}->wait;
        AE::log debug => "exited with $exitcode";
    }

    if ( ref $self->{output} eq 'GLOB' ) {
        AE::log debug => "close output file";
        close $self->{output};
    }

    for (
        qw(protocol proc command options args status_fd command_fd input output next_status )
      )
    {
        AE::log debug => "delete $_";
        delete $self->{$_};
    }
}

sub _run_gnupg {
    my $self = shift;

    if ( defined $self->{input} and not ref $self->{input} ) {
        my $file = $self->{input};
        open( my $fh, '<', $file ) or die "cannot open file $file: $!";
        AE::log info => "input file $file opened at $fh";
        $self->{input} = $fh;
    }

    if ( defined $self->{output} and not ref $self->{output} ) {
        my $file = $self->{output};
        open( my $fh, '>', $file ) or die "cannot open file $file: $!";
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
        bin     => $gpg,
        args    => $cmdline,
        extras  => [ $status, $command ],
        ttl     => 300,
        errstr  => \$err,
        on_exit => sub {
            AE::log note => $err if $err;
        },
    );

    if ( defined $self->{input} ) {
        AE::log debug => "pull from input";
        $proc->pull( $self->{input} );
    }

    if ( defined $self->{output} ) {
        AE::log debug => "pipe to output";
        $proc->pipe( $self->{output} );
    }

    $self->{command_fd} = $command;
    $self->{status_fd}  = $status;
    $self->{gnupg_proc} = $proc;

    AE::log debug => "gnupg ready";
}

sub _cpr_maybe_send {
    ( $_[0] )->_cpr_send( @_[ 1, $#_ ], 1 );
}

sub _cpr_send {
    my ( $self, $key, $value, $optional ) = @_;
    my $fd = $self->{command_fd};

    my ( $cmd, $arg ) = $self->_read_from_status;
    unless ( $cmd =~ /^GET_/ ) {
        $self->_abort_gnupg("protocol error: expected GET_XXX")
          unless $optional;
        $self->_next_status( $cmd, $arg );
        return;
    }

    unless ( $arg eq $key ) {
        $self->_abort_gnupg("protocol error: expected key $key")
          unless $optional;
        return;
    }

    $fd->writeln($value);

    ( $cmd, $arg ) = $self->_read_from_status;
    unless ( $cmd =~ /^GOT_IT/ ) {
        $self->_next_status( $cmd, $arg );
    }
}

sub _send_passphrase {
    my ( $self, $passwd ) = @_;

    # GnuPG should now tell us that it needs a passphrase
    my $cmd = $self->_read_from_status;

    # Skip UserID hint
    $cmd = $self->_read_from_status if ( $cmd =~ /USERID_HINT/ );
    if ( $cmd =~ /GOOD_PASSPHRASE/ ) {   # This means we didnt need a passphrase
        $self->_next_status($cmd);   # We push this back on for read_from_status
        return;
    }
    $self->_abort_gnupg("Protocol error: expected NEED_PASSPHRASE.*")
      unless $cmd =~ /NEED_PASSPHRASE/;
    $self->_cpr_send( "passphrase.enter", $passwd );
    unless ($passwd) {
        my $cmd = $self->_read_from_status;
        $self->_abort_gnupg("Protocol error: expected MISSING_PASSPHRASE")
          unless $cmd eq "MISSING_PASSPHRASE";
    }
}

sub _check_sig {
    my ( $self, $cmd, $arg ) = @_;

    # Our caller may already have grabbed the first line of
    # signature reporting.
    ( $cmd, $arg ) = $self->_read_from_status unless ($cmd);

    # Ignore patent warnings.
    ( $cmd, $arg ) = $self->_read_from_status()
      if ( $cmd =~ /RSA_OR_IDEA/ );

    # Ignore automatic key imports
    ( $cmd, $arg ) = $self->_read_from_status()
      if ( $cmd =~ /IMPORTED/ );

    ( $cmd, $arg ) = $self->_read_from_status()
      if ( $cmd =~ /IMPORT_OK/ );

    ( $cmd, $arg ) = $self->_read_from_status()
      if ( $cmd =~ /IMPORT_RES/ );

    $self->_abort_gnupg("invalid signature from $arg") if ( $cmd =~ /BADSIG/ );

    if ( $cmd =~ /ERRSIG/ ) {
        my ( $keyid, $key_algo, $digest_algo, $sig_class, $timestamp, $rc ) =
          split ' ', $arg;
        if ( $rc == 9 ) {
            ( $cmd, $arg ) = $self->_read_from_status();
            $self->_abort_gnupg("no public key $keyid");
        }
        $self->_abort_gnupg("error verifying signature from $keyid");
    }

    $self->_abort_gnupg("protocol error: expected SIG_ID")
      unless $cmd =~ /SIG_ID/;
    my ( $sigid, $date, $time ) = split /\s+/, $arg;

    ( $cmd, $arg ) = $self->_read_from_status;
    $self->_abort_gnupg("protocol error: expected GOODSIG")
      unless $cmd =~ /GOODSIG/;
    my ( $keyid, $name ) = split /\s+/, $arg, 2;

    ( $cmd, $arg ) = $self->_read_from_status;
    my $policy_url = undef;
    if ( $cmd =~ /POLICY_URL/ ) {
        $policy_url = $arg;
        ( $cmd, $arg ) = $self->_read_from_status;
    }

    $self->_abort_gnupg("protocol error: expected VALIDSIG")
      unless $cmd =~ /VALIDSIG/;
    my ($fingerprint) = split /\s+/, $arg, 2;

    ( $cmd, $arg ) = $self->_read_from_status;
    $self->_abort_gnupg("protocol error: expected TRUST*")
      unless $cmd =~ /TRUST/;
    my ($trust) = _parse_trust($cmd);

    return {
        sigid       => $sigid,
        date        => $date,
        timestamp   => $time,
        keyid       => $keyid,
        user        => $name,
        fingerprint => $fingerprint,
        trust       => $trust,
        policy_url  => $policy_url,
    };
}

sub DESTROY {
    my $self = shift;

    $self->{gnupg_proc}->kill if $self->{gnupg_proc};
}

=method new(%params)

You create a new GnuPG wrapper object by invoking its new method. (How original!). The module will try to finds the B<gpg> program in your path and will croak if it can't find it. Here are the parameters that it accepts:

=over 4

=item * gnupg_path

Path to the B<gpg> program.

=item * options

Path to the options file for B<gpg>. If not specified, it will use the default one (usually F<~/.gnupg/options>).

=item * homedir

Path to the B<gpg> home directory. This is the directory that contains the default F<options> file, the public and private key rings as well as the trust database.

=back

Example:

    my $gpg = new GnuPG();

=cut

sub new {
    my $proto = shift;
    my $class = ref $proto || $proto;

    my %args = @_;

    my $self = {};
    if ( $args{homedir} ) {
        croak("Invalid home directory: $args{homedir}")
          unless -d $args{homedir} && -x _;
        $self->{homedir} = $args{homedir};
    }
    if ( $args{options} ) {
        croak("Invalid options file: $args{options}") unless -r $args{options};
        $self->{options} = $args{options};
    }
    if ( $args{gnupg_path} ) {
        croak("Invalid gpg path: $args{gnupg_path}")
          unless -x $args{gnupg_path};
        $self->{gnupg_path} = $args{gnupg_path};
    }
    else {
        my ($path) = grep { -x "$_/gpg" } split /:/, $ENV{PATH};
        croak("Couldn't find gpg in PATH ($ENV{PATH})") unless $path;
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
    my ( $self, %args ) = @_;
    my $cmd;
    my $arg;

    my $algo = $args{algo};
    $algo ||= RSA_RSA;

    my $size = $args{size};
    $size ||= 1024;
    croak("Keysize is too small: $size") if $size < 768;
    croak("Keysize is too big: $size")   if $size > 2048;

    my $expire = $args{valid};
    $expire ||= 0;

    my $passphrase = $args{passphrase} || "";
    my $name = $args{name};

    croak "Missing key name" unless $name;
    croak "Invalid name: $name"
      unless $name =~ /^\s*[^0-9\<\(\[\]\)\>][^\<\(\[\]\)\>]+$/;

    my $email = $args{email};
    if ($email) {
        ($email) = Email::Address->parse($email)
          or croak "Invalid email address: $email";
    }
    else {
        $email = "";
    }

    my $comment = $args{comment};
    if ($comment) {
        croak "Invalid characters in comment" if $comment =~ /[\(\)]/;
    }
    else {
        $comment = "";
    }

    $self->_command("gen-key");
    $self->_options( [] );
    $self->_args(    [] );

    $self->_run_gnupg;

    $self->_cpr_send( "keygen.algo", $algo );

    #    if ( $algo == ELGAMAL ) {
    #        # Shitty interactive program, yes I'm sure.
    #        # I'm a program, I can't change my mind now.
    #        $self->_cpr_send( "keygen.algo.elg_se", 1 )
    #    }

    $self->_cpr_send( "keygen.size",    $size );
    $self->_cpr_send( "keygen.valid",   $expire );
    $self->_cpr_send( "keygen.name",    $name );
    $self->_cpr_send( "keygen.email",   $email );
    $self->_cpr_send( "keygen.comment", $comment );

    $self->_send_passphrase($passphrase);

    $self->_end_gnupg;

    # Woof. We should now have a generated key !
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
    my ( $self, %args ) = @_;

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

    $self->_run_gnupg;

    my $num_files = ref $args{keys} ? @{ $args{keys} } : 1;
    my ( $cmd, $arg );

    # We will see one IMPORTED for each key that is imported
    while ( ( $cmd, $arg ) = $self->_read_from_status ) {
        last unless $cmd =~ /IMPORTED/;
        $count++;
    }

    # We will see one IMPORT_RES for all files processed
    $self->_abort_gnupg("protocol error expected IMPORT_OK got $cmd")
      unless $cmd =~ /IMPORT_OK/;
    $self->_end_gnupg;

    # We return the number of imported keys
    return $count;
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
    my ( $self, %args ) = @_;

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

    $self->_run_gnupg;
    $self->_end_gnupg;
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
    my ( $self, %args ) = @_;

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

    $self->_run_gnupg;

    # Unless we decided to sign or are using symmetric cipher, we are done
    if ( $args{sign} or $args{symmetric} ) {
        $self->_send_passphrase($passphrase);
        if ( $args{sign} ) {
            my ( $cmd, $line ) = $self->_read_from_status;
            $self->_abort_gnupg("invalid passphrase - $cmd")
              unless $cmd =~ /GOOD_PASSPHRASE/;
        }
    }

    # It is possible that this key has no assigned trust value.
    # Assume the caller knows what he is doing.
    $self->_cpr_maybe_send( "untrusted_key.override", 'y' );

    $self->_end_gnupg;
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
    my ( $self, %args ) = @_;

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

    $self->_run_gnupg;

    # We need to unlock the private key
    $self->_send_passphrase($passphrase);
    my ( $cmd, $line ) = $self->_read_from_status;
    $self->_abort_gnupg("invalid passphrase") unless $cmd =~ /GOOD_PASSPHRASE/;

    $self->_end_gnupg;
}

=head2 clearsign(%params)

This methods clearsign a message. The output will contains the original message with a signature appended. It takes the same parameters as the L</sign> method.

=cut

sub clearsign {
    my $self = shift;
    $self->sign( @_, clearsign => 1 );
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
    my ( $self, %args ) = @_;

    croak("missing signature argument") unless $args{signature};
    my $files = [];
    if ( $args{file} ) {
        croak("detached signature must be in a file")
          unless -f $args{signature};
        push @$files, $args{signature},
          ref $args{file} ? @{ $args{file} } : $args{file};
    }
    else {
        $self->{input} = $args{signature};
    }
    $self->_command("verify");
    $self->_options( [] );
    $self->_args($files);

    $self->_run_gnupg;
    my $sig = $self->_check_sig;

    $self->_end_gnupg;

    return $sig;
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
    my $self = shift;
    my %args = @_;

    $self->{input} = $args{ciphertext} || $args{input};
    $self->{output} = $args{output};
    $self->_command("decrypt");
    $self->_options( [] );
    $self->_args(    [] );

    $self->_run_gnupg;

    my $passphrase = $args{passphrase} || "";

    my ( $cmd, $arg );
    unless ( $args{symmetric} ) {
        ( $cmd, $arg ) = $self->_read_from_status;
        $self->_abort_gnupg("protocol error: expected ENC_TO got $cmd")
          unless $cmd =~ /ENC_TO/;
    }

    $self->_send_passphrase($passphrase);
    ( $cmd, $arg ) = $self->_read_from_status;

    $self->_abort_gnupg("invalid passphrase") if $cmd =~ /BAD_PASSPHRASE/;

    my $sig = undef;

    if ( !$args{symmetric} ) {
        $self->_abort_gnupg("protocol error: expected GOOD_PASSPHRASE")
          unless $cmd =~ /GOOD_PASSPHRASE/;

        $sig = $self->_decrypt_postread();
    }
    else {
        # gnupg 1.0.2 adds this status message
        ( $cmd, $arg ) = $self->_read_from_status()
          if $cmd =~ /BEGIN_DECRYPTION/;

        # gnupg 1.4.12 adds this status message
        ( $cmd, $arg ) = $self->_read_from_status()
          if $cmd =~ /DECRYPTION_INFO/;

        $self->_abort_gnupg("invalid passphrasd") unless $cmd =~ /PLAINTEXT/;
    }

    $self->_end_gnupg();

    return $sig ? $sig : 1;
}

sub _decrypt_postread {
    my $self = shift;

    my @cmds;

    # gnupg 1.0.2 adds this status message
    my ( $cmd, $arg ) = $self->_read_from_status;
    push @cmds, $cmd if $cmd;

    if ( $cmd =~ /BEGIN_DECRYPTION/ ) {
        ( $cmd, $arg ) = $self->_read_from_status();
        push @cmds, $cmd if $cmd;
    }

    my $sig = undef;
    while ( defined $cmd && !( $cmd =~ /DECRYPTION_OKAY/ ) ) {
        if ( $cmd =~ /SIG_ID/ ) {
            $sig = $self->_check_sig( $cmd, $arg );
        }
        ( $cmd, $arg ) = $self->_read_from_status();
        push @cmds, $cmd if $cmd;
    }

    my $cmds = join ', ', @cmds;
    $self->_abort_gnupg(
        "protocol error: expected DECRYPTION_OKAY but never got it")
      unless $cmd =~ /DECRYPTION_OKAY/;

    return $sig ? $sig : 1;
}

=head1 BUGS AND LIMITATIONS

This module doesn't work (yet) with the v2 branch of GnuPG.

=head1 SEE ALSO

=over 4

=item * L<gpg(1)>

=back

=cut

1;
