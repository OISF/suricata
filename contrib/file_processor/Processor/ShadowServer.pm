package Processor::ShadowServer;
use Moose;
extends 'Processor';
use Data::Dumper;
use LWP::UserAgent;
use JSON;

has 'md5' => (is => 'ro', isa => 'Str', required => 1);
has 'ua' => (is => 'rw', isa => 'LWP::UserAgent', required => 1, default => sub { return LWP::UserAgent->new(agent => 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:10.0.1) Gecko/20100101 Firefox/10.0.1'); });
has 'url_template' => (is => 'ro', isa => 'Str', required => 1, default => 'http://innocuous.shadowserver.org/api/?query=%s');
sub name { 'ShadowServer' }
sub description { 'Processor for shadowserver.com' }

sub process {
	my $self = shift;
	my $url = sprintf($self->url_template, $self->md5);
	$self->log->debug('Getting url ' . $url);
	my $response = $self->ua->get($url);
	if ($response->code eq 200){
		if ($response->decoded_content =~ /No match/){
			$self->log->debug('No result');
			return 0;
		}
		elsif ($response->decoded_content =~ /Whitelisted/){
			$self->log->info('Whitelisted');
			return 0;
		}
		$self->log->info('Got shadowserver.com result');
		my $ret;
		eval {
			my ($meta,$json) = split(/\n/, $response->decoded_content);
			my @meta_cols = qw(md5 sha1 first_date last_date type ssdeep);
			my %metas;
			@metas{@meta_cols} = split(/\,/, $meta);
			$ret = { meta => \%metas, results => decode_json($json) };
		};
		if ($@){
			$self->log->error($@);
			return 0;
		}
		return $ret;
	}
	else {
		$self->log->debug('Communications failure: ' . Dumper($response));
		return 0;
	}
}

1
