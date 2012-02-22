package Processor::VirusTotal;
use Moose;
extends 'Processor';
use Data::Dumper;
use LWP::UserAgent;

has 'md5' => (is => 'ro', isa => 'Str', required => 1);
has 'ua' => (is => 'rw', isa => 'LWP::UserAgent', required => 1, default => sub { return LWP::UserAgent->new(agent => 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:10.0.1) Gecko/20100101 Firefox/10.0.1'); });
has 'url' => (is => 'ro', isa => 'Str', required => 1, default => 'https://www.virustotal.com/vtapi/v2/file/report');
sub name { 'VirusTotal' }
sub description { 'Processor for virustotal.com' }

sub process {
	my $self = shift;
	unless ($self->conf->{virustotal_apikey}){
		warn('No VirusTotal apikey configured in config file');
		return 0;
	}
	$self->log->debug('Getting url ' . $self->url);
	#$self->log->debug('md5: ' . $self->md5 . ', apikey: ' . $self->conf->{virustotal_apikey});
	my $response = $self->ua->post($self->url, { resource => $self->md5, apikey => $self->conf->{virustotal_apikey} });
	#$self->log->debug(Dumper($response));
	if ($response->code eq 200){
		my $data = $self->json->decode($response->decoded_content);
		$self->log->debug('data: ' . Dumper($data));
		if ($data->{positives}){
			return $data;
		}
		else {
			return 0;
		}
	}
	else {
		$self->log->debug('Communications failure: ' . Dumper($response));
		return 0;
	}
}

1