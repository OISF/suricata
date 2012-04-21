# Copyright (C) 2012 Martin Holste
#
# You can copy, redistribute or modify this Program under the terms of
# the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# version 2 along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.
#


package Processor;
use Moose;
use Data::Dumper;
use Module::Pluggable search_path => qw(Processor), sub_name => 'processors';
use Module::Pluggable search_path => qw(Action), sub_name => 'actions';
use Log::Log4perl;
use JSON;

has 'conf' => (is => 'rw', isa => 'HashRef', required => 1);
has 'log' => (is => 'rw', isa => 'Object', required => 1);
has 'json' => (is => 'ro', isa => 'JSON', required => 1, default => sub { return JSON->new->pretty->allow_blessed });

sub BUILD {
	my $self = shift;

	foreach my $processor_plugin ($self->processors){
		next unless exists $self->conf->{processors}->{$processor_plugin};
		eval qq{require $processor_plugin};
		$self->log->info('Using processor plugin ' . $processor_plugin->description);
	}

	foreach my $action_plugin ($self->actions){
		next unless exists $self->conf->{actions}->{$action_plugin};
		eval qq{require $action_plugin};
		$self->log->info('Using action plugin ' . $action_plugin->description);
	}
}

sub process {
	my $self = shift;
	my $line = shift;
	#$self->log->debug('got line ' . $line);
	eval {
		my $data = $self->json->decode($line);
		$data->{processors} = {};
		if($data->{md5}){
			foreach my $processor_plugin ($self->processors){
				next unless exists $self->conf->{processors}->{$processor_plugin};
				my $processor = $processor_plugin->new(conf => $self->conf, log => $self->log, md5 => $data->{md5});
				$self->log->debug('processing with plugin ' . $processor->description);
				$data->{processors}->{ $processor->name } = $processor->process();
			}
		}
		#$self->log->debug('data: ' . Dumper($data));
		foreach my $action_plugin ($self->actions){
			next unless exists $self->conf->{actions}->{$action_plugin};
			my $action = $action_plugin->new(conf => $self->conf, log => $self->log, data => $data);
			$self->log->debug('performing action with plugin ' . $action->description);
			$action->perform();
		}
	};
	if ($@){
		$self->log->error('Error: ' . $@ . ', processing line: ' . $line);
	}
}

package main;
use strict;
use Getopt::Std;
use FindBin;
use Config::JSON;
use File::Tail;

# Include the directory this script is in
use lib $FindBin::Bin;

my %Opts;
getopts('c:', \%Opts);

my $conf_file = $Opts{c} ? $Opts{c} : '/etc/suricata/file_processor.conf';
my $Conf = {
	logdir => '/tmp',
	debug_level => 'TRACE',
	actions => {
		'Action::Log' => 1,
		'Action::Syslog' => 1,
	},
	processors => {
		'Processor::Anubis' => 1,
		'Processor::Malwr' => 1,
		'Processor::ThreatExpert' => 1,
	}
};
if (-f $conf_file){
	$Conf = Config::JSON->new( $conf_file );
	$Conf = $Conf->{config}; # native hash is 10x faster than using Config::JSON->get()
}

# Setup logger
my $logdir = $Conf->{logdir} ? $Conf->{logdir} : '/var/log/suricata';
my $debug_level = $Conf->{debug_level} ? $Conf->{debug_level} : 'TRACE';
my $l4pconf = qq(
	log4perl.category.App       = $debug_level, File, Screen
	log4perl.appender.File			 = Log::Log4perl::Appender::File
	log4perl.appender.File.filename  = $logdir/file_processor.log
	log4perl.appender.File.syswrite = 1
	log4perl.appender.File.recreate = 1
	log4perl.appender.File.layout = Log::Log4perl::Layout::PatternLayout
	log4perl.appender.File.layout.ConversionPattern = * %p [%d] %F (%L) %M %P %m%n
	log4perl.filter.ScreenLevel               = Log::Log4perl::Filter::LevelRange
	log4perl.filter.ScreenLevel.LevelMin  = $debug_level
	log4perl.filter.ScreenLevel.LevelMax  = ERROR
	log4perl.filter.ScreenLevel.AcceptOnMatch = true
	log4perl.appender.Screen         = Log::Log4perl::Appender::Screen
	log4perl.appender.Screen.Filter = ScreenLevel
	log4perl.appender.Screen.stderr  = 1
	log4perl.appender.Screen.layout = Log::Log4perl::Layout::PatternLayout
	log4perl.appender.Screen.layout.ConversionPattern = * %p [%d] %F (%L) %M %P %m%n
);
Log::Log4perl::init( \$l4pconf ) or die("Unable to init logger\n");
my $Log = Log::Log4perl::get_logger('App') or die("Unable to init logger\n");

my $processor = new Processor(conf => $Conf, log => $Log);

my $file = $Conf->{file} ? $Conf->{file} : '/var/log/suricata/files-json.log';
my $tail = new File::Tail(name => $file, maxinterval => 1);

while (my $line = $tail->read){
	$processor->process($line);
}

__END__
Example config file /etc/suricata/file_processor.conf
{
	"logdir": "/var/log/suricata",
	"debug_level": "INFO",
	"virustotal_apikey": "xxx"
	"actions": {
		"Action::Log": 1
	},
	"processors": {
		"Processor::Anubis": 1,
		"Processor::Malwr": 1,
		"Processor::ThreatExpert": 1,
		"Processor::VirusTotal": 1
	}
}
