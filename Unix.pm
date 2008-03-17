package Passwd::Unix;

use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

use warnings;
use strict;
use Passwd::Linux qw(modpwinfo setpwinfo rmpwnam mgetpwnam);
use Crypt::PasswdMD5 qw(unix_md5_crypt);
require Exporter;
#======================================================================
$VERSION = '0.3';
@ISA = qw(Exporter);
@EXPORT_OK = qw(del encpass gecos gid uid home maxuid passwd shell rename user users);
#======================================================================
use constant PASSWD => '/etc/passwd';
#======================================================================
sub new { return bless { }, __PACKAGE__; }
#======================================================================
sub del {
	shift if $_[0] =~ __PACKAGE__;
	return rmpwnam(@_);
}
#======================================================================
sub encpass {
	shift if $_[0] =~ __PACKAGE__;
	return unix_md5_crypt($_[0]);
}
#======================================================================
sub gecos {
	shift if $_[0] =~ __PACKAGE__;
	return (getpwnam($_[0]))[6] unless defined $_[1];
	my ($name,$passwd,$uid,$gid, $quota,$comment,$gcos,$dir,$shell,$expire) = getpwnam($_[0]);
	return setpwinfo($name, $passwd, $uid, $gid, $_[1], $dir, $shell);
}
#======================================================================
sub gid {
	shift if $_[0] =~ __PACKAGE__;
	return (getpwnam($_[0]))[3] unless defined $_[1];
	my ($name,$passwd,$uid,$gid, $quota,$comment,$gcos,$dir,$shell,$expire) = getpwnam($_[0]);
	return setpwinfo($name, $passwd, $uid, $_[1], $gcos, $dir, $shell);
}
#======================================================================
sub uid {
	shift if $_[0] =~ __PACKAGE__;
	return (getpwnam($_[0]))[2] unless defined $_[1];
	my ($name,$passwd,$uid,$gid, $quota,$comment,$gcos,$dir,$shell,$expire) = getpwnam($_[0]);
	return setpwinfo($name, $passwd, $_[1], $gid, $gcos, $dir, $shell);
}
#======================================================================
sub home {
	shift if $_[0] =~ __PACKAGE__;
	return (getpwnam($_[0]))[7] unless defined $_[1];
	my ($name,$passwd,$uid,$gid, $quota,$comment,$gcos,$dir,$shell,$expire) = getpwnam($_[0]);
	return setpwinfo($name, $passwd, $uid, $gid, $gcos, $_[1], $shell);
}
#======================================================================
sub maxuid {
	my $max = 0;
	open(my $fh, '<', PASSWD);
	while(<$fh>){
		my $tmp = (split(/:/,$_))[2];
		$max = $tmp > $max ? $tmp : $max;
	}
	close($fh);
	return $max;
}
#======================================================================
sub passwd {
	shift if $_[0] =~ __PACKAGE__;
	return (getpwnam($_[0]))[1] unless defined $_[1];
	my ($name,$passwd,$uid,$gid, $quota,$comment,$gcos,$dir,$shell,$expire) = getpwnam($_[0]);
	return setpwinfo($name, $_[1], $uid, $gid, $gcos, $dir, $shell);
}
#======================================================================
sub shell {
	shift if $_[0] =~ __PACKAGE__;
	return (getpwnam($_[0]))[8] unless defined $_[1];
	my ($name,$passwd,$uid,$gid, $quota,$comment,$gcos,$dir,$shell,$expire) = getpwnam($_[0]);
	return setpwinfo($name, $passwd, $uid, $gid, $gcos, $dir, $_[1]);
}
#======================================================================
sub rename {
	shift if $_[0] =~ __PACKAGE__;
	my ($name,$passwd,$uid,$gid, $quota,$comment,$gcos,$dir,$shell,$expire) = getpwnam($_[0]);
	__PACKAGE__::delete($name);
	return setpwinfo($_[1], $passwd, $uid, $gid, $gcos, $dir, $shell);
}
#======================================================================
# name, passwd, uid, gid, gecos, home, shell
sub user {
	shift if $_[0] =~ __PACKAGE__;

	return getpwnam($_[0]) unless defined $_[1];
	__PACKAGE__::delete($_[0]);
	return setpwinfo(@_);

}
#======================================================================
sub users {
	my @a;
	open(my $fh, '<', PASSWD);
	push @a, (split(/:/,$_))[0] while <$fh>;
	close($fh);
	return @a;
}
#======================================================================
1;


=head1 NAME

Passwd::Unix


=head1 SYNOPSIS

	use Passwd::Unix;
	
	my $pu = Passwd::Unix->new();
	my $err = $pu->user("example", $pu->encpass("my_secret"), $pu->maxuid + 1, 10,
						"My User", "/home/example", "/bin/bash" );
	$pu->passwd("example", $pu->encpass("newsecret"));
	foreach my $user ($pu->users) {
		print "Username: $user\nFull Name: ", $pu->gecos($user), "\n\n";
	}
	my $uid = $pu->uid('example');
	$pu->del("example");

	# or 

	use Passwd::Unix qw(del encpass gecos gid uid home maxuid passwd shell rename user users);
	
	my $err = user( "example", encpass("my_secret"), $pu->maxuid + 1, 10,
					"My User", "/home/example", "/bin/bash" );
	passwd("example",encpass("newsecret"));
	foreach my $user (users()) {
		print "Username: $user\nFull Name: ", gecos($user), "\n\n";
	}
	my $uid = uid('example');
	del("example");

=head1 DESCRIPTION

The Passwd::Unix module provides an abstract interface to /etc/passwd and /etc/shadow format files. It is inspired by Unix::PasswdFile module (this one does not handle /etc/shadow file, what is necessary in modern systems like Sun Solaris 10 or Linux).

=head1 SUBROUTINES/METHODS

=over 4

=item B<new( )>

Constructor.

=item B<delete( USERNAME0, USERNAME1... )>

This method will delete the list of users. It has no effect if the supplied user does not exist.

=item B<encpass( PASSWORD )>

This method will encrypt plain text into unix style MD5 password.

=item B<gecos( USERNAME [,GECOS] )>

Read or modify a user's GECOS string (typically their full name). Returns the result of operation (TRUE or FALSE) if GECOS was specified otherwhise returns the GECOS.

=item B<gid( USERNAME [,GID] )>

Read or modify a user's GID. Returns the result of operation (TRUE or FALSE) if GID was specified otherwhise returns the GID.

=item B<home( USERNAME [,HOMEDIR] )>

Read or modify a user's home directory. Returns the result of operation (TRUE or FALSE) if HOMEDIR was specified otherwhise returns the HOMEDIR.

=item B<maxuid( [IGNORE] )>

This method returns the maximum UID in use by all users. 

=item B<passwd( USERNAME [,PASSWD] )>

Read or modify a user's password. Returns the encrypted password in either case. If you have a plaintext password, use the encpass method to encrypt it before passing it to this method. Returns the result of operation (TRUE or FALSE) if PASSWD was specified otherwhise returns the PASSWD.

=item B<rename( OLDNAME, NEWNAME )>

This method changes the username for a user. If NEWNAME corresponds to an existing user, that user will be overwritten. It returns FALSE on failure and TRUE on success.

=item B<shell( USERNAME [,SHELL] )>

Read or modify a user's shell. Returns the result of operation (TRUE or FALSE) if SHELL was specified otherwhise returns the SHELL.

=item B<uid( USERNAME [,UID] )>

Read or modify a user's UID. Returns the result of operation (TRUE or FALSE) if UID was specified otherwhise returns the UID.

=item B<user( USERNAME [,PASSWD, UID, GID, GECOS, HOMEDIR, SHELL] )>

This method can add, modify, or return information about a user. Supplied with a single username parameter, it will return a six element list consisting of (PASSWORD, UID, GID, GECOS, HOMEDIR, SHELL), or undef if no such user exists. If you supply all seven parameters, the named user will be created or modified if it already exists.

=item B<users()>

This method returns a list of all existing usernames. 

=back

=head1 DEPENDENCIES

=over 4

=item Gtk2::GladeXML

=item Exporter

=back


=head1 INCOMPATIBILITIES

None known.

=head1 BUGS AND LIMITATIONS

None known.

=head1 AUTHOR

Strzelecki Łukasz <strzelec@rswsystems.com>

=head1 LICENCE AND COPYRIGHT

This program is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

See http://www.perl.com/perl/misc/Artistic.html

