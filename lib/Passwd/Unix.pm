package Passwd::Unix;

use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

use warnings;
use strict;
use Carp;
use File::Spec;
use File::Path;
use IO::Compress::Bzip2;
use Struct::Compare;
use File::Basename qw(dirname basename);
use Crypt::PasswdMD5 qw(unix_md5_crypt);
require Exporter;
#======================================================================
$VERSION = '0.45';
@ISA = qw(Exporter);
@EXPORT_OK = qw(check_sanity reset encpass passwd_file shadow_file 
				group_file backup debug warnings del del_user uid gid 
				gecos home shell passwd rename maxgid maxuid exists_user 
				exists_group user users users_from_shadow del_group 
				group groups);
#======================================================================
use constant TRUE 	=> not undef;
use constant FALSE 	=> undef;
#======================================================================
use constant DAY		=> 86400;
use constant PASSWD 	=> '/etc/passwd';
use constant SHADOW 	=> '/etc/shadow';
use constant GROUP  	=> '/etc/group';
use constant BACKUP 	=> TRUE;
use constant DEBUG  	=> FALSE;
use constant WARNINGS 	=> FALSE;
use constant PATH		=>  qr/^[\w\+_\040\#\(\)\{\}\[\]\/\-\^,\.:;&%@\\~]+\$?$/;
#======================================================================
my $_CHECK = {
	rename 	=> sub { return if not defined $_[0] or $_[0] !~ /^[A-Z0-9_-]+$/io; TRUE },
	gid		=> sub { return if not defined $_[0] or $_[0] !~ /^[0-9]+$/o; TRUE },
	uid		=> sub { return if not defined $_[0] or $_[0] !~ /^[0-9]+$/o; TRUE },
	home	=> sub { return if not defined $_[0] or $_[0] !~ PATH; TRUE },
	shell	=> sub { return if not defined $_[0] or $_[0] !~ PATH; TRUE },
	gecos	=> sub { return if not defined $_[0] or $_[0] !~ /^[^:]+$/o; TRUE },
	passwd 	=> sub { return if not defined $_[0]; TRUE},
};
#======================================================================
my $Self = __PACKAGE__->new();
#======================================================================
sub new {
	my ($class, %params) = @_;
	
	my $self = bless {
				passwd 		=> (defined $params{passwd} 	? $params{passwd} 	: PASSWD	),
				shadow 		=> (defined $params{shadow} 	? $params{shadow} 	: SHADOW	),
				group 		=> (defined $params{group} 		? $params{group} 	: GROUP		),
				backup 		=> (defined $params{backup} 	? $params{backup} 	: BACKUP	),
				debug 		=> (defined $params{debug} 		? $params{debug} 	: DEBUG		),
				warnings	=> (defined $params{warnings} 	? $params{warnings} : WARNINGS	),
			}, $class;
			
	$self->check_sanity(TRUE) if (caller())[0] ne __PACKAGE__;
			
	return $self;
}
#======================================================================
sub check_sanity {
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	my $quiet = shift;

	for($self->shadow_file, $self->passwd_file, $self->group_file){
		next if -f $_;
		croak('File not found: ' . $_);
	}

	if($( !~ /^0/o){
		carp(q/Running as "/ . getlogin() . qq/", which has currently no permissions to write to system files. READ ONLY mode ENABLED!\n/) unless $quiet;
		return;
	}

	unless(compare([$self->users()], [$self->users_from_shadow()])){
		carp(qq/\nYour ENVIRONMENT IS INSANE! Users in files "/.$self->passwd_file().q/" and "/.$self->shadow_file().qq/ are diffrent!!!\nI'll continue, but it is YOUR RISK! You'll probably go into BIG troubles!\n\n/);
		warn "\a\n";
		sleep 5;
	}

	return;
}
#======================================================================
sub reset {
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	$self->{passwd} = PASSWD;
	$self->{shadow} = SHADOW;
	$self->{group}  = GROUP;
	return TRUE;
}
#======================================================================
sub encpass {
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	my ($val) = @_;
	return unless defined $val;
	return unix_md5_crypt($val);
}
#======================================================================
sub _do_backup {
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	my ($sec,$min,$hour,$mday,$mon,$year) = localtime(time);

	my $dir = File::Spec->catfile($self->passwd_file.'.bak', ($year+1900).'.'.($mon+1).'.'.$mday.'-'.$hour.'.'.$min.'.'.$sec);
	mkpath $dir; chmod 0700, $dir;

	my $cpasswd	= File::Spec->catfile($dir, basename($self->passwd_file()) . q/.bz2/);
	my $cshadow	= File::Spec->catfile($dir, basename($self->shadow_file()) . q/.bz2/);
	my $cgroup	= File::Spec->catfile($dir, basename($self->group_file())  . q/.bz2/);

	# passwd
	my $compress = IO::Compress::Bzip2->new($cpasswd, AutoClose => 1, Append => 1, BlockSize100K => 9);
	open(my $fh, '<', $self->passwd_file) or return;
	$compress->print($_) while <$fh>;
	$compress->close;
	chmod 0644, $cpasswd;

	# shadow
	$compress = IO::Compress::Bzip2->new($cshadow, AutoClose => 1, Append => 1, BlockSize100K => 9);
	open($fh, '<', $self->shadow_file) or return;
	$compress->print($_) while <$fh>;
	$compress->close;
	chmod 0400, $cshadow;
	
	# group
	$compress = IO::Compress::Bzip2->new($cgroup, AutoClose => 1, Append => 1, BlockSize100K => 9);
	open($fh, '<', $self->group_file) or return;
	$compress->print($_) while <$fh>;
	$compress->close;
	chmod 0644, $cgroup;

	return;
}
#======================================================================
sub passwd_file { 
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	my ($val) = @_;
	return $self->{passwd} unless defined $val;
	$self->{passwd} = File::Spec->canonpath($val);
	return $self->{passwd};
}
#======================================================================
sub shadow_file { 
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	my ($val) = @_;
	return $self->{shadow} unless defined $val;
	$self->{shadow} = File::Spec->canonpath($val);
	return $self->{shadow};
}
#======================================================================
sub group_file { 
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	my ($val) = @_;
	return $self->{group} unless defined $val;
	$self->{group} = File::Spec->canonpath($val);
	return $self->{group};
}
#======================================================================
sub backup {
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	my ($val) = @_;
	return $self->{backup} unless defined $val;
	$self->{backup} = $val ? TRUE : FALSE;
	return $self->{backup};
}
#======================================================================
sub debug {
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	my ($val) = @_;
	return $self->{debug} unless defined $val;
	$self->{debug} = $val ? TRUE : FALSE;
	return $self->{debug};
}
#======================================================================
sub warnings {
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	my ($val) = @_;
	return $self->{warnings} unless defined $val;
	$self->{warnings} = $val ? TRUE : FALSE;
	return $self->{warnings};
}
#======================================================================
*del_user = { };
*del_user = \&del;
sub del { 
	return if $( !~ /^0/o;

	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	unless(scalar @_){
		carp(q|Method/function "del" cannot run without params!|) if $self->warnings();
		return;
	}
	
	$self->_do_backup() if $self->backup();
	
	my $regexp = '^'.join('$|^',@_).'$';
	$regexp = qr/$regexp/;
	
	# here unused gids will be saved
	my (@gids, @deleted);
	
	# remove from passwd
	my $tmp = $self->passwd_file.'.tmp';
	open(my $fh, '<', $self->passwd_file());
	open(my $ch, '>', $tmp);
	while(my $line = <$fh>){
		my ($user, undef, undef, $gid) = split(/:/,$line, 5);
		if($user =~ $regexp){ 
			push @gids, $gid; 
			push @deleted, $user;
		}else{ print $ch $line; }
	}
	close($fh);close($ch);
	move($tmp, $self->passwd_file());
	
	# remove from shadow
	$tmp = $self->shadow_file.'.tmp';
	open($fh, '<', $self->shadow_file());
	open($ch, '>', $tmp);
	while(my $line = <$fh>){
		next if (split(/:/,$line,2))[0] =~ $regexp;
		print $ch $line;
	}
	close($fh);close($ch);
	move($tmp, $self->shadow_file());
	
	# remove from group
	my $gids = '^'.join('$|^',@gids).'$';
	$gids = qr/$gids/;
	$tmp = $self->group_file.'.tmp';
	open($fh, '<', $self->group_file());
	open($ch, '>', $tmp);
	while(my $line = <$fh>){
		chomp $line;
		my ($name, $passwd, $gid, $users) = split(/:/,$line,4);
		$users = join(q/,/, grep { !/$regexp/ } split(/\s*,\s*/, $users));
		next if $gid =~ $gids and not length $users;
		print $ch join(q/:/, $name, $passwd, $gid, $users),"\n";
	}
	close($fh);close($ch);
	move($tmp, $self->group_file());
	
	return @deleted if wantarray;
	return scalar @deleted;
}
#======================================================================
sub _set {
	return if $( !~ /^0/o;
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	return if scalar @_ < 4;
	my ($file, $user, $pos, $val, $count) = @_;
	
	my @t = split(/::/,(caller(1))[3]);
	croak(qq/\n"_set" cannot be called from outside of Passwd::Unix!/) if $t[-2] ne 'Unix';	
	unless($_CHECK->{$t[-1]}($val)){ 
		carp(qq/Incorrect parameters for "$t[-1]! Leaving unchanged..."/) if $self->warnings(); 
		return; 
	}

	$self->_do_backup() if $self->backup();

	$count ||= 6;
	my $tmp = $file.'.tmp';
	open(my $fh, '<', $file);
	open(my $ch, '>', $tmp);
	my $ret;
	while(<$fh>){
		chomp;
		my @a = split /:/;
		if($a[0] eq $user){
			$a[$pos] = $val;
			$ret = TRUE;
			for(scalar @a .. $count){ push @a, ''; }
			print $ch join(q/:/, @a),"\n";
		}else{
			print $ch $_,"\n";	
		}
	}
	close($fh);close($ch);
	move($tmp, $file);
	return $ret;
}
#======================================================================
sub _get {
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	return if scalar @_ != 3;
	my ($file, $user, $pos) = @_;
	
	unless($_CHECK->{rename}($user)){ 
		carp(qq/Incorrect user "$user"!/) if $self->warnings(); 
		return; 
	}
	
	open(my $fh, '<', $file);
	while(<$fh>){
		my @a = split /:/;
		next if $a[0] ne $user;
		chomp $a[$pos];
		return $a[$pos];
	}
	return;
}
#======================================================================
sub uid { 
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	if(scalar @_ == 1){
		return $self->_get($self->passwd_file(), $_[0], 2);
	}elsif(scalar @_ != 2){
		carp(q/Incorrect parameters for "uid"!/) if $self->warnings();
		return;
	}
	return $self->_set($self->passwd_file(), $_[0], 2, $_[1]);
}
#======================================================================
sub gid {
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	if(scalar @_ == 1){
		return $self->_get($self->passwd_file(), $_[0], 3);
	}elsif(scalar @_ != 2){
		carp(q/Incorrect parameters for "gid"!/) if $self->warnings();
		return;
	}
	return $self->_set($self->passwd_file(), $_[0], 3, $_[1]);
}
#======================================================================
sub gecos {
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	if(scalar @_ == 1){
		return $self->_get($self->passwd_file(), $_[0], 4);
	}elsif(scalar @_ != 2){
		carp(q/Incorrect parameters for "gecos"!/) if $self->warnings();
		return;
	}
	return $self->_set($self->passwd_file(), $_[0], 4, $_[1]);
}
#======================================================================
sub home { 
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	if(scalar @_ == 1){
		return $self->_get($self->passwd_file(), $_[0], 5);
	}elsif(scalar @_ != 2){
		carp(q/Incorrect parameters for "home"!/) if $self->warnings();
		return;
	}
	return $self->_set($self->passwd_file(), $_[0], 5, $_[1]);
}
#======================================================================
sub shell { 
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	if(scalar @_ == 1){
		return $self->_get($self->passwd_file(), $_[0], 6);
	}elsif(scalar @_ != 2){
		carp(q/Incorrect parameters for "shell"!/) if $self->warnings();
		return;
	}
	return $self->_set($self->passwd_file(), $_[0], 6, $_[1]);	
}
#======================================================================
sub passwd { 
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	if(scalar @_ == 1){
		return $self->_get($self->shadow_file(), $_[0], 1);
	}elsif(scalar @_ != 2){
		carp(q/Incorrect parameters for "passwd"!/) if $self->warnings();
		return;
	}
	return $self->_set($self->shadow_file(), $_[0], 1, $_[1], 8);	
}
#======================================================================
sub rename { 
	return if $( !~ /^0/o;

	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	
	if(scalar @_ != 2){ 
		carp(q/Incorrect parameters for "rename"!/) if $self->warnings(); 
		return; 
	}
	
	my ($user, $val) = @_;
	unless($self->exists_user($user)){ 
		carp(qq/User "$user" does not exists!/) if $self->warnings(); 
		return; 
	}
	
	my $gid = $self->gid($user);
	unless(defined $gid){ 
		carp(qq/Cannot retrieve GID of user "$user"! Leaving unchanged.../) if $self->warnings(); 
		return; 
	}
	
	$self->_do_backup() if $self->backup();
	
	my $tmp = $self->group_file.'.tmp';
	open(my $fh, '<', $self->group_file());
	open(my $ch, '>', $tmp);
	while(my $line = <$fh>){
		chomp $line;
		my ($name, $passwd, $gid, $users) = split(/:/,$line,4);
		$users = join(q/,/, map { $_ eq $user ? $val : $_ } split(/\s*,\s*/, $users));
		print $ch join(q/:/, $name, $passwd, $gid, $users),"\n";
	}
	close($fh);close($ch);
	move($tmp, $self->group_file());
		
	$self->_set($self->passwd_file(), $user, 0, $val);	
	return $self->_set($self->shadow_file(), $user, 0, $val);
}
#======================================================================
sub maxgid {
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	my $max = 0;
	open(my $fh, '<', $self->passwd_file());
	while(<$fh>){
		my $tmp = (split(/:/,$_))[3];
		$max = $tmp > $max ? $tmp : $max;
	}
	close($fh);
	return $max;
}
#======================================================================
sub maxuid {
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	my $max = 0;
	open(my $fh, '<', $self->passwd_file());
	while(<$fh>){
		my $tmp = (split(/:/,$_))[2];
		$max = $tmp > $max ? $tmp : $max;
	}
	close($fh);
	return $max;
}
#======================================================================
sub _exists {
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	return if scalar @_ != 3;
	my ($file, $pos, $val) = @_;
	
	open(my $fh, '<', $file);
	while(<$fh>){
		my @a = split /:/;
		return TRUE if $a[$pos] eq $val;
	}
	return;
}
#======================================================================
sub exists_user {
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	my ($user) = @_;
	unless($_CHECK->{rename}($user)){ 
		carp(qq/Incorrect user "$user"!/) if $self->warnings(); 
		return; 
	}
	return $self->_exists($self->passwd_file(), 0, $user);
}
#======================================================================
sub exists_group {
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	my ($group) = @_;
	unless($_CHECK->{rename}($group)){ 
		carp(qq/Incorrect group "$group"!/) if $self->warnings(); 
		return; 
	}
	return $self->_exists($self->group_file(), 0, $group);
}
#======================================================================
sub user { 
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	my (@user) = @_;
	
	unless($_CHECK->{rename}($user[0])){ 
		carp(qq/Incorrect user "$user[0]"!/) if $self->warnings(); 
		return; 
	}

	if(scalar @_ != 7){
		open(my $fh, '<', $self->passwd_file());
		while(<$fh>){
			my @a = split /:/;
			next if $a[0] ne $user[0];
			chomp $a[-1];
			splice @a, 0, 2;
			return $self->passwd($user[0]), @a;
		}
		carp(qq/User "$user[0]" does not exists!/) if $self->warnings();
		return;
	}
	
	return if $( !~ /^0/o;

	my @tests = qw(rename passwd uid gid gecos home shell);
	for(1..6){
		unless($_CHECK->{$tests[$_]}($user[$_])){ 
			carp(qq/Incorrect parameters for "$tests[$_]"!/) if $self->warnings(); 
			return; 
		}
	}
	
	$self->_do_backup() if $self->backup();
	
	my $passwd = splice @user,1, 1, 'x';
	
	my $mod;
	my $tmp = $self->passwd_file.'.tmp';
	open(my $fh, '<', $self->passwd_file());
	open(my $ch, '>', $tmp);
	while(<$fh>){
		my @a = split /:/;
		if($user[0] eq $a[0]){
			$mod = TRUE;
			print $ch join(q/:/, @user),"\n";
		}else{ print $ch $_; }
	}
	close($fh);
	print $ch join(q/:/, @user),"\n" unless $mod;
	close($ch);
	move($tmp, $self->passwd_file());
	
	# user already exists	
	if($mod){ $self->passwd($user[0], $passwd); }
	else{ 
		open(my $fh, '>>', $self->shadow_file());
		print $fh join(q/:/, $user[0], $passwd, int(time()/DAY), ('') x 5, "\n");
		close($fh);
	}
	
	return TRUE;
}
#======================================================================
sub users { 
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	my @a;
	open(my $fh, '<', $self->passwd_file());
	push @a, (split(/:/,$_))[0] while <$fh>;
	close($fh);
	return @a;
}
#======================================================================
sub users_from_shadow { 
	return if $( !~ /^0/o;
	
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	my @a;
	open(my $fh, '<', $self->shadow_file());
	push @a, (split(/:/,$_))[0] while <$fh>;
	close($fh);
	return @a;
}
#======================================================================
sub del_group {
	return if $( !~ /^0/o;
	
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	my ($group) = @_;
	unless($_CHECK->{rename}($group)){ 
		carp(qq/Incorrect group "$group"!/) if $self->warnings(); 
		return; 
	}
	
	$self->_do_backup() if $self->backup();
	
	my @dels;
	my $tmp = $self->group_file.'.tmp';
	open(my $fh, '<', $self->group_file());
	open(my $ch, '>', $tmp);
	while(my $line = <$fh>){
		my ($name) = split(/:/,$line,2);
		if($group eq $name){ push @dels, $name; }
		else{ print $ch $line; }
	}
	close($fh);close($ch);
	move($tmp, $self->group_file());
	
	return @dels if wantarray;
	return scalar @dels;
}
#======================================================================
sub group { 
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	my ($group, $gid, $users) = @_;
	unless($_CHECK->{rename}($group)){ 
		carp(qq/Incorrect group "$group"!/) if $self->warnings(); 
		return; 
	}
	
	if(scalar @_ == 3){
		return if $( !~ /^0/o;
		
		$self->_do_backup() if $self->backup();
		
		unless($_CHECK->{gid}($gid)){ 
			carp(qq/Incorrect GID "$gid"!/) if $self->warnings(); 
			return; 
		}
		unless(ref $users and ref $users eq 'ARRAY'){ 
			carp(qq/Incorrect parameter "users"! It should be arrayref.../) if $self->warnings(); 
			return; 
		}
		$users ||= [ ];
		foreach(@$users){
			unless($_CHECK->{rename}($_)){ 
				carp(qq/Incorrect user "$_"!/) if $self->warnings(); 
				return; 
			}
		}
		
		my $mod;
		my $tmp = $self->group_file.'.tmp';
		open(my $fh, '<', $self->group_file());
		open(my $ch, '>', $tmp);
		while(my $line = <$fh>){
			chomp $line;
			my ($name, $passwd) = split(/:/,$line,3);
			if($group eq $name){ 
				print $ch join(q/:/, $group, 'x', $gid, join(q/,/, @$users)),"\n"; 
				$mod = TRUE;
			} else{ print $ch $line,"\n"; }
		}
		print $ch join(q/:/, $group, 'x', $gid, join(q/,/, @$users)),"\n" unless $mod;
		close($fh);close($ch);
		move($tmp, $self->group_file());
	}else{
		my ($gid, @users);
		open(my $fh, '<', $self->group_file());
		while(my $line = <$fh>){
			chomp $line;
			my ($name, undef, $id, $usrs) = split(/:/,$line,4);
			next if $group ne $name;
			$gid = $id;
			$usrs =~ s/\s+$//o;
			push @users, split(/\s*,\s*/o, $usrs) if $usrs;
			last;
		}
		
		# if searched ground does not exist
		return undef, [ ] unless defined $gid;
	
		open($fh, '<', $self->passwd_file());
		while(my $line = <$fh>){
			my ($login, undef, undef, $id) = split(/:/,$line,5);
			next if $id != $gid;
			push @users, $login;
		}

		@users = sort @users;
		for(reverse 0..$#users){
			last if $_ == 0;
			splice @users, $_, 1 if $users[$_] eq $users[ $_ - 1 ];
		}
		return $gid, \@users;
	}
	
	return;
}
#======================================================================
sub groups { 
	my $self = scalar @_ && ref $_[0] eq __PACKAGE__ ? shift : $Self;
	my @a;
	open(my $fh, '<', $self->group_file());
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

	use Passwd::Unix qw(check_sanity reset encpass passwd_file shadow_file 
				group_file backup warnings del del_user uid gid gecos
				home shell passwd rename maxgid maxuid exists_user 
				exists_group user users users_from_shadow del_group 
				group groups);
	
	my $err = user( "example", encpass("my_secret"), $pu->maxuid + 1, 10,
					"My User", "/home/example", "/bin/bash" );
	passwd("example",encpass("newsecret"));
	foreach my $user (users()) {
		print "Username: $user\nFull Name: ", gecos($user), "\n\n";
	}
	my $uid = uid('example');
	del("example");

=head1 ABSTRACT

Passwd::Unix provides an abstract object-oriented and function interface to
standard Unix files, such as /etc/passwd, /etc/shadow, /etc/group. Additionaly
this module provides  environment to testing new software, without using
system critical files in /etc/dir.

=head1 DESCRIPTION

The Passwd::Unix module provides an abstract interface to /etc/passwd, 
/etc/shadow and /etc/group format files. It is inspired by 
Unix::PasswdFile module (this one does not handle /etc/shadow file, 
what is necessary in modern systems like Sun Solaris 10 or Linux).

=head1 SUBROUTINES/METHODS

=over 4

=item B<new( [ param0 => 1, param1 => 0... ] )>

Constructor. Possible parameters are:

=over 8

=item B<passwd> - path to passwd file; default C</etc/passwd>

=item B<shadow> - path to shadow file; default C</etc/shadow>

=item B<group> - path to group file; default C</etc/group>

=item B<backup> - boolean; if set to C<1>, backup will be made; default C<1>

=item B<warnings> - boolean; if set to C<1>, important warnings will be displayed; default C<0>

=back


=item B<check_sanity()>

This method check if environment is sane. I.e. if users in I<shadow> and
in I<passwd> are the same. This method is invoked in constructor.

=item B<del( USERNAME0, USERNAME1... )>

This method is an alias for C<del_user>. It's for transition only.

=item B<del_user( USERNAME0, USERNAME1... )>

This method will delete the list of users. It has no effect if the 
supplied users do not exist.

=item B<del_group( GROUPNAME0, GROUPNAME1... )>

This method will delete the list of groups. It has no effect if the 
supplied groups do not exist.

=item B<encpass( PASSWORD )>

This method will encrypt plain text into unix style MD5 password.

=item B<gecos( USERNAME [,GECOS] )>

Read or modify a user's GECOS string (typically their full name). 
Returns the result of operation (C<1> or C<undef>) if GECOS was specified. 
Otherwhise returns the GECOS.

=item B<gid( USERNAME [,GID] )>

Read or modify a user's GID. Returns the result of operation (TRUE or 
FALSE) if GID was specified otherwhise returns the GID.

=item B<home( USERNAME [,HOMEDIR] )>

Read or modify a user's home directory. Returns the result of operation 
(C<1> or C<undef>) if HOMEDIR was specified otherwhise returns the HOMEDIR.

=item B<maxuid( )>

This method returns the maximum UID in use by all users. 

=item B<maxgid( )>

This method returns the maximum GID in use by all groups. 

=item B<passwd( USERNAME [,PASSWD] )>

Read or modify a user's password. If you have a plaintext password, 
use the encpass method to encrypt it before passing it to this method. 
Returns the result of operation (C<1> or C<undef>) if PASSWD was specified. 
Otherwhise returns the PASSWD.

=item B<rename( OLDNAME, NEWNAME )>

This method changes the username for a user. If NEWNAME corresponds to 
an existing user, that user will be overwritten. It returns FALSE on 
failure and TRUE on success.

=item B<shell( USERNAME [,SHELL] )>

Read or modify a user's shell. Returns the result of operation (TRUE 
or FALSE) if SHELL was specified otherwhise returns the SHELL.

=item B<uid( USERNAME [,UID] )>

Read or modify a user's UID. Returns the result of operation (TRUE or 
FALSE) if UID was specified otherwhise returns the UID.

=item B<user( USERNAME [,PASSWD, UID, GID, GECOS, HOMEDIR, SHELL] )>

This method can add, modify, or return information about a user. 
Supplied with a single username parameter, it will return a six element 
list consisting of (PASSWORD, UID, GID, GECOS, HOMEDIR, SHELL), or 
undef if no such user exists. If you supply all seven parameters, 
the named user will be created or modified if it already exists.

=item B<group( GROUPNAME [,GID, ARRAYREF] )>

This method can add, modify, or return information about a group. 
Supplied with a single groupname parameter, it will return a two element 
list consisting of (GID, ARRAYREF), where ARRAYREF is a ref to array 
consisting names of users in this GROUP. It will return undef and ref to empty array (C<undef, [ ]>) if no such group 
exists. If you supply all three parameters, the named group will be 
created or modified if it already exists.

=item B<users()>

This method returns a list of all existing usernames. 

=item B<groups()>

This method returns a list of all existing groups. 

=item B<exists_user(USERNAME)>

This method checks if specified user exists. It returns TRUE or FALSE.

=item B<exists_group(GROUPNAME)>

This method checks if specified group exists. It returns TRUE or FALSE.

=item B<passwd_file([PATH])>

This method, if called with an argument, sets path to the I<passwd> file.
Otherwise returns the current PATH.

=item B<shadow_file([PATH])>

This method, if called with an argument, sets path to the I<shadow> file.
Otherwise returns the current PATH.

=item B<group_file([PATH])>

This method, if called with an argument, sets path to the I<group> file.
Otherwise returns the current PATH.

=item B<reset()>

This method sets paths to files I<passwd>, I<shadow>, I<group> to the
default values.

=back

=head1 DEPENDENCIES

=over 4

=item Struct::Compare

=item Crypt::PasswdMD5

=back

=head1 INCOMPATIBILITIES

None known.

=head1 BUGS AND LIMITATIONS

None. I hope. 

=head1 THANKS

=over 4

=item BIG THANKS to Lopes Victor for reporting some bugs and his exact sugesstions :-)

=item Thanks to Foudil BRÉTEL for some remarks, suggestions as well as supplying relevant patch!

=item BIG thanks to Artem Russakovskii for reporting a bug.

=back

=head1 AUTHOR

Strzelecki Lukasz <strzelec@rswsystems.com>

=head1 LICENCE AND COPYRIGHT

This program is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

See http://www.perl.com/perl/misc/Artistic.html
