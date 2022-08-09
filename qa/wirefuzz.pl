#!/usr/bin/perl -w
#Author:William Metcalf <william.metcalf@gmail.com>
#File:wirefuzz.pl

#Copyright (C) 2010-2015 Open Information Security Foundation

#You can copy, redistribute or modify this Program under the terms of
#the GNU General Public License version 2 as published by the Free
#Software Foundation.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#version 2 along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
#02110-1301, USA.

#This script is useful if you want to fuzz and or otherwise try to make suricata explode during decoding/proto parsing using saved pcaps.
#It is simply a reimplimentation of the technique described here, hence the name:
#http://wiki.wireshark.org/FuzzTesting
#
#Options for getting thre required perl modules:
#Ubuntu 9.10
#sudo apt-get install libdevel-gdb-perl libcapture-tiny-perl
#
#RedHatES/CentOS 5
#yum -y install cpanspec perl-Module-Build
#cpanspec --packager OISF -v -s --follow Capture::Tiny
#cpanspec --packager OISF -v -s --follow Devel::GDB
#rpmbuild --rebuild *.src.rpm
#rpm -ivh /usr/src/redhat/RPMS/noarch/perl-Devel-GDB*.rpm
#rpm -ivh /usr/src/redhat/RPMS/noarch/perl-Capture-Tiny*.rpm
#
#Fedora Core 12
#yum -y install perl-Capture-Tiny perl-Devel-GDB
#
#Other debian based versions, try the Ubunutu instructions if this doesn't work try the following.
#sudo apt-get install dh-make-perl
#mkdir fuzzmodules && cd fuzzmodules
#dh-make-perl --cpan Devel-GDB --build
#dh-make-perl --cpan Capture-Tiny --build
#sudo dpkg -i *.deb

#TODO: Figure out a better way to deal with signal handling.
#TODO: Try to determine flow/stream that caused segv by extracting from the bt and extract it from the pcap.
#TODO: E-mail notification on segv?
#TODO: Parse Valgrind output and alert on errors

use strict;
use warnings;
use Capture::Tiny 'capture';
use List::Util 'shuffle';
use Devel::GDB;
use File::Find;
use Getopt::Long qw(:config no_ignore_case);
use File::Basename;

#globals
my %config;
my @tmpfiles;
my @files;
my $suricatabin;
my $loopnum;
my $loopnum_per_file = 0;
my $rules;
my $rules_exclusive = 0;
my $logdir;
my $configfile;
my $editeratio;
my $valgrindopt;
my $shuffle;
my $useltsuri;
my $ltsuribin;
my $core_dump;
my $excluderegex;
my %excludefuzz;
my $timestamp;
my $keeplogs;
my $file_was_fuzzed = 0;

Getopt::Long::Configure("prefix_pattern=(-|--)");
GetOptions( \%config, qw(n=s N=s r=s c=s e=s v=s p=s l=s s=s S=s x=s k y z=s q h help) );

&parseopts();

#Parse the options
sub parseopts {

    #display help if asked
    if ( $config{h} || $config{help} ) {
        &printhelp();
    }

    #filemask of pcaps to read?
    if ( $config{r} ) {
        @tmpfiles = <$config{r}>;
        if(@tmpfiles eq 0){
            print "parseopts: Pcap filemask was invalid we couldn't find any matching files\n";
            exit(1);
        } else {
            #escapes for filenames
            foreach my $file (@tmpfiles) {
                $file =~ s/\(/\\(/g;
                $file =~ s/\)/\\)/g;
                $file =~ s/\&/\\&/g;
            }
        }
    }
    else {
        print "parseopts: Pcap filemask not specified or doesn't exist\n";
        &printhelp();
    }

    #filemask do we have a path to suricata bin?
    if ( $config{p} && -e $config{p} ) {
        $suricatabin = $config{p};

        #do wrapper script detection lt-suricata won't be created until first run but .libs/suricata should exist.
        if ( -T $suricatabin ) {
            open my $in, '<', $suricatabin or die "Can't read old file: $!";
            while (<$in>) {
                if ( $_ =~
                        m/suricata \- temporary wrapper script for \.libs\/suricata/
                   )
                {
                    print "parseopts: suricata bin file appears to be a wrapper script going to try to find the real bin for gdb.\n";
                    my $tmpdirname    = dirname $suricatabin;
                    my $tmpltsuriname = $tmpdirname . "/.libs/suricata";
                    if ( -e $tmpltsuriname && -B $tmpltsuriname ) {
                        $ltsuribin = $tmpltsuriname;
                        print "parseopts: telling gdb to use " . $ltsuribin . "\n";
                        $useltsuri = "yes";
                    }
                    last;
                }
            }
            close $in;
        }
        elsif ( -B $suricatabin ) {
            if ( ! $config{q} ) {
                print "parseopts: suricata bin file checks out\n";
            }
        }
        else {
            print "parseopts: suricata bin file is not a text or a bin exiting.\n";
            exit(1);
        }
    }
    else {
        print "parseopts: Path to suricata bin not provided or doesn't exist\n";
        &printhelp();
    }

    if ( $config{n} && $config{N} ) {
        print "ERROR: can't mix -n and -N\n";
        exit(1);
    }

    #number of times to loop
    if ( $config{n} ) {
        $loopnum = $config{n};
        $loopnum_per_file = 1;
        print "parseopts: looping through the pcaps " . $loopnum . " times or until we have an error\n";
    }
    else {
        $loopnum = "infinity";
    }

    if ( $config{N} ) {
        $loopnum = $config{N};
        print "parseopts: looping through the pcaps " . $loopnum . " times or until we have an error\n";
    }
    else {
        $loopnum = "infinity";
    }

    if ( $loopnum == "infinity") {
        print "parseopts: looping through the pcaps forever or until we have an error\n";
    }

    #rules file do we have a path and does it exist
    if ( $config{s} && -e $config{s} ) {
        $rules = $config{s};
        print "parseopts: telling suricata to use rules file " . $rules . "\n";
    }
    else {
        print("parseopts: rules file not specified or doesn't exist\n");
    }

    # exclusive rules file: do we have a path and does it exist
    if ( $config{S} && -e $config{S} ) {
        $rules = $config{S};
        $rules_exclusive = 1;
        print "parseopts: telling suricata to use rules file exclusively " . $rules . "\n";
    }
    else {
        print("parseopts: rules file not specified or doesn't exist\n");
    }

    #log dir does it exist
    if ( $config{l} && -e $config{l} ) {
        $logdir = $config{l} . "/";
        print "parseopts: using log dir " . $logdir . "\n";
    }
    else {
        $logdir = "./";
    }

    #config file do we have a path and does it exist
    if ( $config{c} && -e $config{c} ) {
        $configfile = $config{c};
        print "parseopts: telling suricata to use the config file " . $configfile . "\n";
    }
    else {
        print "parseopts: config file not specified or doesn't exist\n";
        &printhelp();
    }

    #% chance that a byte will be modified.
    if ( $config{e} ) {

        #valid range?
        my $tmperatio = $config{e} * 100;
        if ( $tmperatio <= 100 && $tmperatio >= 0 ) {
            $editeratio = $config{e};
            print "parseopts: using error ratio " . $editeratio . "\n";
        }
        else {
            print "parseopts: error ratio specified but outside of range. Valid range is 0.00-1.0\n";
            exit(1);
        }
    }
    else {
        print("parseopts: not going to fuzz pcap(s)\n");
    }

    #parse the valgrind opts
    if ( $config{v} ) {
        if ( $config{v} =~ /^(memcheck|drd|helgrind|callgrind)$/ ) {
            $valgrindopt = $config{v};
            print "parseopts: using valgrind opt " . $valgrindopt . "\n";
        }
        else {
            print "invalid valgrind opt " . $valgrindopt . "\n";
        }
    }

    #shuffle the array if we are starting multiple fuzzers at once.  GO-GO gadget shuffle
    if ( $config{y} ) {
        print "parseopts: going to shuffle the array\n";
        $shuffle = "yes";
    }

    #keep logs instead of removing them after each run
    if ( $config{k} ) {
        print "parseopts: going to keep logs instead of removing them\n";
        $keeplogs = "yes";
    }
    else {
        $keeplogs = "no";
    }

    #we want to process some files but not fuzz them add them to a hash and check it later
    if ( $config{z} ) {
        print "will process but not fuzz files that match regex of " . $config{z} . "\n";
        $excluderegex = $config{z};

        my $tmpfilepos = 0;
        while ($tmpfilepos <= $#tmpfiles) {
            if ($tmpfiles[$tmpfilepos] =~ m/$excluderegex/) {
                print "adding  " . $tmpfiles[$tmpfilepos] . " to fuzz_exclude_hash because it matches our regex\n";
                $excludefuzz{$tmpfiles[$tmpfilepos]} = 1;
            }
            $tmpfilepos++
        }
    }

    #maybe we want to exclude a file based on some regex so we can restart the fuzzer after an error
    #and not have to worry about hitting the same file.
    if ( $config{x} ) {
        print "excluding files that match regex of " . $config{x} . "\n";
        $excluderegex = $config{x};

        my $tmpfilepos = 0;
        while ($tmpfilepos <= $#tmpfiles) {
            if ($tmpfiles[$tmpfilepos] =~ m/$excluderegex/) {
                print "removing " . $tmpfiles[$tmpfilepos] . " because it matches our exclude regex\n";
                splice(@tmpfiles, $tmpfilepos, 1);
            }
            else {
                $tmpfilepos++
            }
        }
    }

    if ( ! $config{q} ) {
        print "******************Initialization Complete**********************\n";
    }
    return;

}

sub printhelp {
    print "
        -h or help <this output>
        -r=<filemask for pcaps to read>
        -n=<(optional) number of iterations or if not specified will run until error>
        -N=<(optional) number of iterations of all files in the test set>
        -s=<(optional) path to ids rules file will be passed as -s to suricata>
        -S=<(optional) path to ids rules file will be passed as -S to suricata>
        -e=<(optional) editcap error ratio to introduce if not specified will not fuzz. Valid range for this is 0.00 - 1.0>
        -p=<path to the suricata bin>
        -l=<(optional) log dir for output if not specified will use current directory.>
        -v=<(optional) (memcheck|drd|helgrind|callgrind) will run the command through one of the specified valgrind tools.>
        -x=<(optional) regex for excluding certain files incase something blows up but we want to continue fuzzing .>
        -z=<(optional) regex for excluding certain files from fuzzing but still process them note: the original files will be processed and not removed.>
        -y <shuffle the array, this is useful if running multiple instances of this script.>
        -k <will keep alert-debug.log fast.log http.log and stats.log instead of removing them at the end of each run.>
        Example usage:
        First thing to do is download and build suricata from git with -O0 so vars don't get optimized out. See the example below:
        git clone git://phalanx.openinfosecfoundation.org/oisf.git suricatafuzz1 && cd suricatafuzz1 && ./autogen.sh && CFLAGS=\"-g -O0\" ./configure && make

        Second thing to do is to edit suricata.yaml to fit your environment.

        Third go ahead and run the script.

        In the example below the script will loop forever until an error is encountered will behave in the following way.
        1.-r Process all pcaps in subdirectories of /home/somepath/pcaps/
        2.-s Tell suricata to use the rules file /home/somepath/current-all.rules
        3.-y Shuffle the array of pcaps this is useful if running multiple instances of this script.
        4.-c Tell suricata to use the suricata.yaml in the current dir.
        6.-e Tell editcap to introduce a 2% error ratio, i.e. there is a 2% chance that a byte will be fuzzed see http://wiki.wireshark.org/FuzzTesting for more info.
        7.-p Use src/suricata as our suricata bin file. The script will determine if the argument passed is a bin file or a txt wrapper and will adjust accordingly.

        /usr/bin/wirefuzz.pl -r=/home/somepath/pcaps/*/* -s=/home/somepath/current-all.rules -y -c=suricata.yaml -e=0.02 -p src/suricata

        If an error is encountered a file named <fuzzedfile>ERR.txt will be created in the log dir (current dir in this example) that will contain output from stderr,stdout, and gdb.

        Take a look at the opts make it work for you environment and from the OISF QA team thanks for helping us make our meerkat fuzzier! ;-)\n";
        exit;
}

my $logfile = $logdir . "wirefuzzlog.txt";
open( LOGFILE, ">>$logfile" )
|| die( print "error: Could not open logfile! $logfile\n" );

my $successcnt = 0;
while ( $successcnt < $loopnum ) {
    if ( defined $shuffle ) {
        @files = shuffle(@tmpfiles);
    }
    else {
        @files = @tmpfiles;
    }

    foreach my $file (@files) {
        my $file_was_fuzzed = 0;
        #split out the path from the filename
        my $filedir  = dirname $file;
        my $filename = basename $file;
        my ( $fuzzedfile, $editcapcmd, $editcapout, $editcaperr, $editcapexit,
                $editcap_sys_signal, $editcap_sys_coredump );
        my ( $fuzzedfiledir, $fuzzedfilename, $fullcmd, $out, $err, $exit,
                $suricata_sys_signal, $suricata_sys_coredump, $report);
        if ( ! $config{q} ) {
           print "Going to work with file: $file\n";
        }
        my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) =
            localtime(time);
        $timestamp = sprintf "%4d-%02d-%02d-%02d-%02d-%02d", $year + 1900,
           $mon + 1, $mday, $hour, $min, $sec;
        if ( defined $editeratio and !exists $excludefuzz{$file}) {
            $file_was_fuzzed = 1;
            $fuzzedfile = $logdir . $filename . "-fuzz-" . $timestamp;
            $editcapcmd =
                "editcap -E " . $editeratio . " " . $file . " " . $fuzzedfile;
            if ( ! $config{q} ) {
                print( "editcap: " . $editcapcmd . "\n" );
            }
            ( $editcapout, $editcaperr ) = capture {
                system $editcapcmd;
                $editcapexit          = $? >> 8;
                $editcap_sys_signal   = $? & 127;
                $editcap_sys_coredump = $? & 128;
            };
            if ( $editcapexit ne 0 ) {

                #this could still cause us to loop forever if all pcaps are bad but it's better than nothing.
                if ( @files < 2 ) {
                    print "editcap: had an error and this was our only pcap:" . $editcaperr . "\n";
                    exit(1);
                }
                else {
                    print "editcap: had an error going to the next pcap:" . $editcaperr . "\n";
                    next;
                }
            }
            elsif ( $editcap_sys_signal eq 2 ) {
                print "editcap: system() got a ctl+c we are bailing as well\n";
                exit(1);

            }
            elsif ( ! $config{q} ) {
                print("editcap: ran successfully\n");
                print
                    "******************Editcap Complete**********************\n";
            }
        }
        else {
            $fuzzedfile = $file;
        }

        #split out the path from the filename
        $fuzzedfiledir  = dirname $fuzzedfile;
        $fuzzedfilename = basename $fuzzedfile;

        $fullcmd = "ulimit -c unlimited; ";

        if ( defined $valgrindopt ) {
            if ( $valgrindopt eq "memcheck" ) {
                $fullcmd =
                    $fullcmd
                    . "valgrind -v --log-file="
                    . $logdir
                    . $fuzzedfilename
                    . $timestamp
                    . "-memcheck-vg.log ";
            }
            elsif ( $valgrindopt eq "drd" ) {
                $fullcmd =
                    $fullcmd
                    . "valgrind  --tool=drd --var-info=yes -v --log-file="
                    . $logdir
                    . $fuzzedfilename
                    . $timestamp
                    . "-drd-vg.log ";
            }
            elsif ( $valgrindopt eq "helgrind" ) {
                $fullcmd =
                    $fullcmd
                    . "valgrind  --tool=helgrind -v --log-file="
                    . $logdir
                    . $fuzzedfilename
                    . $timestamp
                    . "-helgrind-vg.log ";
            }
            elsif ( $valgrindopt eq "callgrind" ) {
                $fullcmd =
                    $fullcmd
                    . "valgrind  --tool=callgrind -v --callgrind-out-file="
                    . $logdir
                    . $fuzzedfilename
                    . $timestamp
                    . "-callgrind-vg.log ";
            }
        }

        $fullcmd =
            $fullcmd
            . $suricatabin . " -c "
            . $configfile . " -r "
            . $fuzzedfile . " -l "
            . $logdir;
        if ( defined $rules ) {
            if ($rules_exclusive == 1) {
                $fullcmd = $fullcmd . " -S " . $rules;
            } else {
                $fullcmd = $fullcmd . " -s " . $rules;
            }
        }
        if ( ! $config{q} ) {
            print "suricata: $fullcmd \n";
        }
        my $starttime = time();
        ( $out, $err ) = capture {
            system $fullcmd;
            $exit                  = $? >> 8;
            $suricata_sys_signal   = $? & 127;
            $suricata_sys_coredump = $? & 128;
        };

        my $stoptime  = time();
        my $timetotal = $stoptime - $starttime;
        print LOGFILE $fullcmd . ","
            . $timetotal . ","
            . $exit . ","
            . $suricata_sys_signal . ","
            . $suricata_sys_coredump . "\n";
        if ( ! $config{q} ) {
            print "suricata: exit value $exit\n";
        }

        if ( $exit ne 0 ) {
            my $knownerr = 0;

            #fuzzer generated some random link type we can't deal with
            if ( $err =~
                    /datalink type \d+ not \(yet\) supported in module PcapFile\./ )
            {
                print "suricata: we matched a known error going to the next file\n";
                $knownerr = 1;
            }
            elsif ( $err =~
                    /invalid interface capture length/ )
            {
                print "suricata: we matched a known error going to the next file\n";
                $knownerr = 1;
            }
            if ( $knownerr eq 1 ) {
                if ($loopnum_per_file == 1) {
                    $successcnt++;
                }
                print "suricata: we have run with success " . $successcnt . " times\n";
                if( $keeplogs eq "yes" ) {
                    &keep_logs($fuzzedfilename);
                    $report = $logdir . $fuzzedfilename . "-OUT.txt";
                    &generate_report($report, $fullcmd, $out, $err, $exit, "none");
                }
                &clean_logs($fuzzedfilename,$file_was_fuzzed);
            }
            else {
                print "suricata: $fullcmd \n";
                print "suricata: exit value $exit\n";
                my $report = $logdir . $fuzzedfilename . "-ERR.txt";

                &process_core_dump();
                if ($core_dump) {
                    print "core dump \n $core_dump";
                    system( "mv "
                            . $ENV{'PWD'}
                            . "/core* "
                            . $logdir
                            . $fuzzedfilename
                            . ".core" );
                    &generate_report($report, $fullcmd, $out, $err, $exit, $core_dump);
                }else{
                    &generate_report($report, $fullcmd, $out, $err, $exit, "none");
                }
                exit(1);
            }
        }
        elsif ( $suricata_sys_signal eq 2 ) {
            print "suricata: system() got a ctl+c we are bailing as well\n";
            if( $keeplogs eq "yes" ) {
                &keep_logs($fuzzedfilename);
            }
            &clean_logs($fuzzedfilename,$file_was_fuzzed);
            exit;
        }
        else {
            if ($loopnum_per_file == 1) {
                $successcnt++;
            }

            if ( ! $config{q} ) {
                print "suricata: we have run with success " . $successcnt . " times\n";
                print "******************Suricata Complete**********************\n";
            }
            if( $keeplogs eq "yes" ) {
                &keep_logs($fuzzedfilename);
                $report = $logdir . $fuzzedfilename . "-OUT.txt";
                &generate_report($report, $fullcmd, $out, $err, $exit, "none");
            }
            &clean_logs($fuzzedfilename,$file_was_fuzzed);
            if ( ! $config{q} ) {
                print "******************Next Pcap or Exit *******************\n";
            }
        }

        if ($successcnt >= $loopnum) {
            last;
        }
    }
    if ($loopnum_per_file == 0) {
        $successcnt++;
    }
    if ($successcnt >= $loopnum) {
        last;
    }
}

sub process_core_dump {
    my $gdbbin;
    my $gdb       = new Devel::GDB();
    my $coremask  = $ENV{'PWD'} . "/core*";
    my @coredumps = <${coremask}>;
    if (@coredumps eq 1 ) {
        my $corefile = $coredumps[0];
        print "gdb: core dump found $corefile processing with";
        if ( $useltsuri eq "yes" ) {
            $gdbbin = $ltsuribin;
        }
        else {
            $gdbbin = $suricatabin;
        }
        print " the following bin file" . $gdbbin . "\n";
        $core_dump .= join '',
            $gdb->get("file $gdbbin"), $gdb->get("core $corefile"),
            $gdb->get('info threads'), $gdb->get('thread apply all bt full');
        print "gdb: core dump \n $core_dump";

    }
    elsif ( @coredumps > 1 ) {
        print "gdb: multiple core dumps, please clear all core dumps and try the test again. We found:\n";
        foreach my $corefile (@coredumps) {
            print $corefile . "\n";
        }
    }
    else {
        print "gdb: no coredumps found returning.\n";
        print @coredumps;
        print " $#coredumps" . "\n";
    }
    print "******************GDB Complete**********************\n";
    return;
}

sub clean_logs {
    my $deleteme    = shift;
    my $file_was_fuzzed = shift;
    my $deletemerge = $logdir . $deleteme;
    my $rmcmd;
    if ( defined $editeratio and $file_was_fuzzed) {
        if ( unlink($deletemerge) == 1 ) {
            if ( ! $config{q} ) {
                print "clean_logs: " . $deletemerge . " deleted successfully.\n";
            }
        }
        else {
            print "clean_logs: error " . $deletemerge . " was not deleted. You may have to delete the file manually.\n";
        }
    }

    if ( defined $valgrindopt ) {
        #uncomment the following lines if you want to remove valgrind logs
        #$rmcmd = "rm -f " . $deletemerge . "*vg.log";
        #print( "running " . $rmcmd . "\n" );
        #system("$rmcmd");
    }

    foreach my $file (glob "$logdir/*.log $logdir/*.json") {
        #print $file . "\n";
        if (unlink($file) <= 0) {
            print "clean_logs: failed to delete log file $file\n";
        }
    }

    return;
}

sub keep_logs {
    my $saveme = shift;
    unless(defined($editeratio) || $loopnum eq '1'){
        my $saveme = $saveme . "-" . $timestamp;
    }
    my $savecmd;

    if (-e $logdir . "alert-debug.log"){
        $savecmd = "mv -f " . $logdir
        . "alert-debug.log "
        . $logdir
        . $saveme
        . "-alert-debug.log";
        system($savecmd);
    }
    if (-e $logdir . "fast.log"){
        $savecmd = "mv -f " . $logdir
        . "fast.log "
        . $logdir
        . $saveme
        . "-fast.log";
        system($savecmd);
    }
    if (-e $logdir . "http.log"){
        $savecmd = "mv -f " . $logdir
        . "http.log "
        . $logdir
        . $saveme
        . "-http.log";
        system($savecmd);
    }
    if (-e $logdir . "stats.log"){
        $savecmd = "mv -f " . $logdir
        . "stats.log "
        . $logdir
        . $saveme
        . "-stats.log";
        system($savecmd);
    }
    print "******************Log Move Complete**********************\n";
    return;
}

sub generate_report {
    my ($report, $fullcmd, $stdout, $stderr, $exit, $coredump) = ($_[0], $_[1], $_[2], $_[3], $_[4], $_[5]);

    open( REPORT, ">$report" ) || ( print "Could not open report file! $report\n" );
    print REPORT "COMMAND:$fullcmd\n";
    print REPORT "EXITVAL:$exit\n";
    print REPORT "STDERR:$stderr\n";
    print REPORT "STDOUT:$stdout\n";
    if($coredump ne "none"){
        print REPORT "COREDUMP:$coredump\n";
    }
    close(REPORT);
}
