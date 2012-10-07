#!/usr/bin/perl
# Database importer for rules. Written by Kost. Copyright (C) 2012. OISF

use strict;
use DBI qw(:sql_types);
use DBD::SQLite;
use Snort::Rule;
use Getopt::Long;

my @configfiles=("$ENV{HOME}/.suricatadb","/etc/suricatadb");
my %config;

# default values
$config{'verbose'}=0; # don't be too chatty by default
$config{'cache'}=1; # much faster if script caches actions and class types

# starting sid number for rules without sid, should be maximum number
# this value will be used for following query:
# select max(sid) from rules where sid>$config{'nosidvalue'}
$config{'nosidvalue'}=200000000; 

# default table names
$config{'tb-rules'}="rules";
$config{'tb-classtypes'}="classtypes";

foreach my $configfile (@configfiles) {
	if (-e $configfile) {
		open(CONFIG,"<$configfile") or next;
		while (<CONFIG>) {
		    chomp;                  # no newline
		    s/#.*//;                # no comments
		    s/^\s+//;               # no leading white
		    s/\s+$//;               # no trailing white
		    next unless length;     # anything left?
		    my ($var, $value) = split(/\s*=\s*/, $_, 2);
		    $config{$var} = $value;
		} 
		close(CONFIG);
	}
}
Getopt::Long::Configure ("bundling");

my $result = GetOptions (
	"a|activate" => \$config{'activate'},
	"c|cache!" => \$config{'cache'},
	"3|oldsqlite" => \$config{'oldsqlite'},
	"d|sqldb=s" => \$config{'sqldb'},
	"e|enablerule" => \$config{'enablerule'},
	"E|enableall" => \$config{'enableall'},
	"f|forceaction=s" => \$config{'forceaction'},
	"F|forceall=s" => \$config{'forceall'},
	"p|duplicate" => \$config{'duplicate'},
	"r|removerule" => \$config{'removerule'},
	"R|removedb" => \$config{'removedb'},
	"t|createtb" => \$config{'createtb'},
	"D|dropfirst" => \$config{'dropfirst'},
	"v|verbose+"  => \$config{'verbose'},
	"h|help" => \&help
);

# for caching purposes
my %cache;
my %classes;

# for statistics
my %stat;

# display help if database is not specified
help() if (not $config{'sqldb'});

print STDERR "[i] Using database: ".$config{'sqldb'}."\n" if ($config{'verbose'}>0);

my $dbh = DBI->connect("dbi:SQLite:dbname=$config{'sqldb'}","","") or die ("Cannot open database $config{'sqldb'}: $!");

if ($config{'cache'}) {
    $dbh->do("PRAGMA synchronous = OFF") or warn ("Cannot turn off synchronous writes, import will be slow");
}

# reset stat variables;
$stat{'files'}=0; $stat{'lines'}=0; $stat{'enabled'}=0; $stat{'disabled'}=0;
$stat{'rules'}=0; $stat{'mrules'}=0; $stat{'newclass'}=0; 
$stat{'rules-updated'}=0; $stat{'rules-inserted'}=0;

if ($config{'createtb'}) {
	print STDERR "[i] Creating tables\n" if ($config{'verbose'}>0);
	createtables();
}

# remove whole database if asked
if ($config{'removedb'}) {
	print STDERR "[i] Removing all rules from database\n" if ($config{'verbose'}>0);
	dbh->do("DELETE FROM $config{'tb-rules'}") or warn ("SQL query for removing rule database failed with $!");
} 

# process each file on command line
while (my $currfile = shift) {
	print STDERR "[i] Processing $currfile...\n" if ($config{'verbose'}>0);
	processfile($currfile);
	$stat{'files'}++;
}

# display statistics
print STDERR "[s] Statistics: $stat{'files'} files with $stat{'lines'} lines in total processed.\n";
print STDERR "[s] $stat{'rules-inserted'} new rules were inserted and $stat{'rules-updated'} were updated.\n";
print STDERR "[s] $stat{'rules'} rules processed and $stat{'mrules'} were multiline. $stat{'enabled'} were enabled and $stat{'disabled'} were disabled.\n";
print STDERR "[s] $stat{'newclass'} new classes created.\n";

# -- end of main --

# execute SQL query with single bind parameter
sub dosqlid {
	my($sqlq,$id) = @_;
	my $sthq = $dbh->prepare ($sqlq) or warn "Cannot prepare: $!";
	$sthq->bind_param(1, $id, SQL_INTEGER);
	$sthq->execute() or warn "cannot execute SQL: $sqlq with ".$id;
}

# find duplicate by rule string
sub finddupbyrule {
	my($rname) = @_;
	my $sqlq="select sid from $config{'tb-rules'} where sig=?";
	my $sthq = $dbh->prepare ($sqlq) or warn "Cannot prepare: $!";
	$sthq->bind_param(1, $rname, SQL_VARCHAR);
	$sthq->execute() or warn "cannot execute SQL: $sqlq with ".$rname;
	if (my @row = $sthq->fetchrow_array) {
		return $row[0];
	} else {
		return 0;
	}
}

# find free sid value (if rule doesn't have it)
sub findfreesid {
	if ($config{'cache'}) {
		return $cache{'cursidvalue'} if (exists $cache{'cursidvalue'}); 
	}
	my $sqlq="select max(sid) from $config{'tb-rules'} where sid>?";
	my $sthq = $dbh->prepare ($sqlq) or warn "Cannot prepare: $!";
	$sthq->bind_param(1, $config{'nosidvalue'}, SQL_INTEGER);
	$sthq->execute() or warn "cannot execute SQL: $sqlq with ".$config{'nosidvalue'};
	if (my @row = $sthq->fetchrow_array) {
		print STDERR "=> Value row: $row[0]\n";
		$cache{'cursidvalue'}=$row[0]+1 if ($config{'cache'});
		return $row[0];
	} else {
		print STDERR "=> Value config: $config{'nosidvalue'}\n";
		$cache{'cursidvalue'}=$config{'nosidvalue'}+1 if ($config{'cache'});
		return $config{'nosidvalue'};
	}
}

# find by sid value 
sub findbysid {
	my($sid) = @_;
	my $sqlq="select sig,defaction,defenabled,enabled,action,classtypes_cid from $config{'tb-rules'} where sid=?";
	my $sthq = $dbh->prepare ($sqlq) or warn "Cannot prepare: $!";
	$sthq->bind_param(1, $sid, SQL_INTEGER);
	$sthq->execute() or warn "cannot execute SQL: $sqlq with ".$sid;
	if (my $row = $sthq->fetchrow_hashref) {
		return $row;
	} 
	return undef;
}

# return class ID by giving classtype, if classtype is not here, create it 
sub getclass {
	my($sname) = @_;

	return (0) if ($sname eq '' or not defined($sname)); 

	if ($config{'cache'}) {
		if (exists $classes{$sname}) {
			return $classes{$sname};
		}
	}
	my $sqlq = "SELECT cid FROM $config{'tb-classtypes'} WHERE title=?";
	my $sthq = $dbh->prepare ($sqlq) or warn "Cannot prepare: $!";
	$sthq->execute($sname) or warn "cannot execute SQL: $sqlq with $sname";
	if (my @row = $sthq->fetchrow_array) {
		$classes{$sname}=$row[0] if ($config{'cache'});
		return $row[0];
	} else {
		$stat{'newclass'}++;
		my $sqli="INSERT INTO $config{'tb-classtypes'}(title) VALUES (?)";
		my $sthi = $dbh->prepare($sqli) or warn ("cannot prepare $sqli:".$dbh->errstr);
		$sthi->execute($sname) or warn ("cannot insert $sqli:".$dbh->errstr);
		my $sths = $dbh->prepare ($sqlq) or warn ("cannot prepare $sqlq:".$dbh->errstr);
		$sths->execute($sname) or warn ("cannot select after insert $sqlq:".$dbh->errstr);;
		if (my @srow = $sths->fetchrow_array) {
			$classes{$sname}=$srow[0] if ($config{'cache'});
			return $srow[0];
		} else {
			warn("Weird. Cannot get ID after INSERT in classes.");
		}
		
	}
	return (0);
}

# process rule file and import each rule
sub processfile {
	my($rfile) = @_;
	open (FILE,"<$rfile") or die ("cannot open rule file for reading: $!");
	my $strule;
	while (<FILE>) {
		my $enabled=1;
		$stat{'lines'}++;
		chomp;
		s/^\s+//;               # no leading white
		s/\s+$//;               # no trailing white

		# disabled rules are also interesting to import
		if (/^#\s*alert/ or /^#\s*drop/) {
			$enabled=0; 
			$stat{'disabled'}++;
			s/^#\s*//;
		} else {
			s/^#.*//;
		}

		next unless length;     # anything left?

		# multiline rule
		if (/\\$/) {
			$strule=$strule.$_."\n";
			$stat{'mrules'}++;
			next;
		} 
		$strule=$strule.$_;

		$stat{'enabled'}++ if ($enabled);
		my $rule = Snort::Rule->new(-parse => $strule);
		$stat{'rules'}++;
		# print $rule->string()."\n";

		my $action = $rule->action;
		my $sid = $rule->opt('sid');
		
		# handle case when rule does not have sid defined
		if (not defined($sid)) {
			$sid=findfreesid();
			print STDERR "Rule: '$strule' does not have sid, using next free sid: $sid\n";
		}
	
		my $sig = $strule;
		my $class=$rule->opt('classtype');
		$sig =~ s/^\Q$action\E\s+//;

		if ($config{'duplicate'}) {
			my $tsid=finddupbyrule($sig);
			if ($tsid) {
				print STDERR "[d] Found duplicate rule '$sid' in database\n";
			}
		}

		$strule='';	

		my $dbsig=undef;
		if ($config{'removerule'}) {
			dosqlid("DELETE FROM $config{'tb-rules'} WHERE sid=?",$sid);
		} else {
			$dbsig=findbysid($sid);
		}

		if (defined ($dbsig)) {
			my $sql="UPDATE $config{'tb-rules'} SET sig=?,enabled=?,action=?,defenabled=?,defaction=?,classtypes_cid=? WHERE sid=?";
			my $sth = $dbh->prepare($sql) or warn ("cannot prepare $sql: $!");
			$sth->bind_param(1, $sig, SQL_VARCHAR);
			if ($config{'enableall'}) {
				$sth->bind_param(2, 1, SQL_INTEGER);
			} else {
				$sth->bind_param(2, $dbsig->{'enabled'}, SQL_INTEGER);
			}
			if ($config{'forceall'}) {
				$sth->bind_param(3, $config{'forceall'}, SQL_VARCHAR);
			} else {
				$sth->bind_param(3, $dbsig->{'action'}, SQL_VARCHAR);
			}	
			$sth->bind_param(4, $enabled, SQL_INTEGER);
			$sth->bind_param(5, $action, SQL_VARCHAR);
			$sth->bind_param(6, getclass($class), SQL_INTEGER);
			$sth->bind_param(7, $sid, SQL_INTEGER);
			$sth->execute() or warn "Error updating rule with $sql and $sid:$sig";
			$stat{'rules-updated'}++;
			
		} else {
			my $sql="INSERT INTO $config{'tb-rules'}(sid,sig,defaction,defenabled,classtypes_cid,action,enabled) VALUES (?,?,?,?,?,?,?)";
			my $sth = $dbh->prepare($sql) or warn ("cannot prepare $sql: $!");
			$sth->bind_param(1, $sid, SQL_INTEGER);
			$sth->bind_param(2, $sig, SQL_VARCHAR);
			$sth->bind_param(3, $action, SQL_VARCHAR);
			$sth->bind_param(4, $enabled, SQL_INTEGER);
			$sth->bind_param(5, getclass($class), SQL_INTEGER);
			if ($config{'forceaction'}) {
				$sth->bind_param(6, $config{'forceaction'}, SQL_VARCHAR);
			} else {
				$sth->bind_param(6, $action, SQL_VARCHAR);
			}	
			if ($config{'enableall'} or $config{'enablerule'}) {
				$sth->bind_param(7, 1, SQL_INTEGER);
			} else {
				$sth->bind_param(7, $enabled, SQL_INTEGER);
			}
			$sth->execute() or warn "Error inserting rule with $sql and $sid:$sig";
			$stat{'rules-inserted'}++;
		}
	}
	close(FILE);
}

# display help and exit
sub help {
	print "Database importer for rules. Written by Kost. Distributed under Suricata License.\n\n";
	print "Usage: $0 [options] <rulefile> <rulefile> <rulefile> ...\n";
	print "\n";
	print " -a	automatically activate rules by their default action (usually alert)\n";
	print " -c	cache classes and actions (faster, enabled by default!)\n";
	print " -d <s>	Use database <s>\n";
	print " -e	enable by default all new rules imported\n";
	print " -E	enable by default all rules imported (new & already in database)\n";
	print " -f <s>	force action on all new rules imported\n";
	print " -F <s>	force action on all rules imported (new & already in database)\n";
	print " -i	incremental update (slower, but it does not delete whole rules table for specified source)\n";
	print " -p	print duplicate rules in database (not useful if updating existing ones)\n";
	print " -r	delete whole rule if already exists\n";
	print " -R	delete whole rule database\n";
	print " -s <s>	Use source alias <s> (usually custom, vrt, et, suricata, ...)\n";
	print " -t	create tables\n";
	print " -D	drop tables first when creating tables\n";
	print " -v	verbose (-vv will be more verbose)\n";
	print "\n";

	print "Example: $0 -s et -d /etc/suricata/rules/rules.sqlite web-attacks.rules\n";
	print "Example: $0 -s et -d /etc/suricata/rules/rules.sqlite rules/*rule\n";
	
	exit 0;
}

# create tables
sub createtables {
	my $ifnotexists="if not exists";
	my $ifexists="if exists";
	if ($config{'oldsqlite'}) {
		$ifexists="";
		$ifnotexists="";
	}
	
	if ($config{'dropfirst'}) {
		$dbh->do("DROP TABLES $ifexists $config{'tb-rules'}") or warn("cannot drop rules table: $!");
		$dbh->do("DROP TABLES $ifexists $config{'tb-classtypes'}") or warn("cannot drop classtypes table: $!");
	}

	my $crtactiontbl=<<END;
CREATE TABLE $ifnotexists $config{'tb-rules'} (
	sid integer PRIMARY KEY NOT NULL,
	sig text,
	defaction varchar(10),
	defenabled BOOL NOT NULL DEFAULT 0,
	enabled	BOOL NOT NULL DEFAULT 1,
	action varchar(10) NOT NULL,
	classtypes_cid integer
);
END
	$dbh->do($crtactiontbl) or warn("cannot create rules table: $!");

	my $crtclasstbl=<<END;
CREATE TABLE $ifnotexists $config{'tb-classtypes'} (
	cid integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	title varchar(255)
);
END
	$dbh->do($crtclasstbl) or warn("cannot create classtypes table: $!");
}
