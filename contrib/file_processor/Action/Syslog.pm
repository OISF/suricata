package Action::Syslog;
use Moose;
extends 'Processor';
use Sys::Syslog qw(:standard :macros);

our $Program = 'suricata_file';
our $Facility = LOG_LOCAL0;
has 'data' => (is => 'rw', isa => 'HashRef', required => 1);

sub name { 'syslog' }
sub description { 'Log to local syslog' }

sub perform {
	my $self = shift;
	openlog($Program, undef, $Facility);
	syslog(LOG_INFO, $self->json->encode($self->data));
	closelog;
}

1
