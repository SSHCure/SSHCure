######################################################################
#
#  Cache.pm
#  Authors: Rick Hofstede <r.j.hofstede@utwente.nl>
#           Luuk Hendriks <luuk.hendriks@utwente.nl>
#  University of Twente, The Netherlands
#
#  LICENSE TERMS: 3-clause BSD license (outlined in license.html)
#
######################################################################
# vim: expandtab:tw=4:sw=4

package SSHCure::Cache;
use strict;
use warnings;

sub new {
    my ($class, $name, $max_entries) = @_;

    my $self = {};
    bless $self, $class;

    $self->{name} = $name;
    $self->{max_entries} = $max_entries;
    $self->{misses} = 0;

    my %data = ();
    $self->{data} = \%data;

    return $self;
}

sub clean {
    my $self = shift;
    my $cache_entry_count = scalar keys($self->{data});

    if ($cache_entry_count > $self->{max_entries}) {
        SSHCure::Utils::log_info(sprintf("Cleaning up cache '%s' (hit ratio: %.2f)...", $self->{name}, $self->get_hit_ratio()));
        my @keys_to_be_cleared = ();

        # Determine which elements must be removed from the cache
        foreach my $key (sort { $self->{data}{$a}{'hits'} <=> $self->{data}{$b}{'hits'} } keys($self->{data}) ) {
            push(@keys_to_be_cleared, $key) if (scalar @keys_to_be_cleared < $cache_entry_count - $self->{max_entries});
        }

        # Remove elements from the cache
        foreach my $key (@keys_to_be_cleared) {
            delete($self->{data}{$key});
        }

        # Reset hit and miss counters
        foreach my $key (keys($self->{data})) {
            $self->{data}{$key}{'hits'} = 0;
        }
        $self->{misses} = 0;

        SSHCure::Utils::log_info(sprintf("Removed %i elements from cache '%s'; new number of elements in cache: %i", scalar @keys_to_be_cleared, $self->{name}, scalar keys($self->{data})));
    } else {
        my $utilization = $cache_entry_count/$self->{max_entries};
        SSHCure::Utils::log_info(sprintf("No cleanup of cache '%s' needed (utilization: %.2f)...", $self->{name}, $utilization));
    }

    return;
}

sub get {
    my ($self, $key) = @_;

    # Check whether $key exists in cache
    if (exists $self->{data}{$key}) {
        $self->{data}{$key}{'hits'}++;
        return $self->{data}{$key}{'value'};
    } else {
        $self->{misses}++;
        return;
    }
}

sub set {
    my ($self, $key, $value) = @_;

    # If $key exists in cache, overwrite its value (and update hit counter)
    if (exists $self->{data}{$key}) {
        $self->{data}{$key}{'value'} = $value;
        $self->{data}{$key}{'hits'}++;
    } else {
        $self->{data}{$key}{'value'} = $value;
        $self->{data}{$key}{'hits'} = 1;
    }
}

sub get_hit_ratio {
    my $self = shift;
    my $hits = 0;
    foreach my $key (keys(%{$self->{data}})) {
        $hits += $self->{data}{$key}{'hits'};
    }

    return $hits / ($hits + $self->{misses});
}

1;
