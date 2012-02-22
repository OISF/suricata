package Action::Log;
use Moose;
extends 'Processor';

has 'data' => (is => 'rw', isa => 'HashRef', required => 1);

sub name { 'log' }
sub description { 'Log to file' }

sub perform {
	my $self = shift;
	$self->log->info($self->json->encode($self->data));
}

1