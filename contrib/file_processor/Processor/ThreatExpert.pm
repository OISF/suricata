package Processor::ThreatExpert;
use Moose;
extends 'Processor';
use Data::Dumper;
use LWP::UserAgent;

has 'md5' => (is => 'ro', isa => 'Str', required => 1);
has 'ua' => (is => 'rw', isa => 'LWP::UserAgent', required => 1, default => sub { return LWP::UserAgent->new(agent => 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:10.0.1) Gecko/20100101 Firefox/10.0.1'); });
has 'url_template' => (is => 'ro', isa => 'Str', required => 1, default => 'http://www.threatexpert.com/report.aspx?md5=%s');
sub name { 'ThreatExpert' }
sub description { 'Processor for threatexpert.com' }

sub process {
	my $self = shift;
	my $url = sprintf($self->url_template, $self->md5);
	$self->log->debug('Getting url ' . $url);
	my $response = $self->ua->get($url);
	#$self->log->debug(Dumper($response));
	if ($response->code eq 200){
		if ($response->decoded_content =~ /Search All Reports/){
			$self->log->debug('No result');
			return 0;
		}
		$self->log->info('Got result');
		return $url;
	}
	else {
		$self->log->debug('Communications failure: ' . Dumper($response));
		return 0;
	}
}

1