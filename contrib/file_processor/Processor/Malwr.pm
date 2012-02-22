package Processor::Malwr;
use Moose;
extends 'Processor';
use Data::Dumper;
use LWP::UserAgent;

has 'md5' => (is => 'ro', isa => 'Str', required => 1);
has 'ua' => (is => 'rw', isa => 'LWP::UserAgent', required => 1, default => sub { return LWP::UserAgent->new(agent => 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:10.0.1) Gecko/20100101 Firefox/10.0.1'); });
has 'url_template' => (is => 'ro', isa => 'Str', required => 1, default => 'http://malwr.com/analysis/%s/');
sub name { 'Malwr' }
sub description { 'Processor for Malwr.com' }

sub process {
	my $self = shift;
	my $url = sprintf($self->url_template, $self->md5);
	$self->log->debug('Getting url ' . $url);
	my $response = $self->ua->get($url);
	if ($response->code eq 200){
		if ($response->decoded_content =~ /Cannot find analysis with specified ID or MD5/){
			$self->log->debug('No result');
			return 0;
		}
		$self->log->info('Got malwr.com result');
		return $url;
	}
	else {
		$self->log->debug('Communications failure: ' . Dumper($response));
		return 0;
	}
}

1