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

    my %data = ();
    $self->{data} = \%data;

    return $self;
}

sub clean {
    my $self = shift;
    my $cache_entry_count = scalar keys($self->{data});

    if ($cache_entry_count > $self->{max_entries}) {
        SSHCure::Utils::log_info("Cleaning up cache '".$self->{name}."'...");
        my @keys_to_be_cleared = ();

        # Determine which elements must be removed from the cache
        foreach my $key (sort { $self->{data}{$a}{'hits'} <=> $self->{data}{$b}{'hits'} } keys($self->{data}) ) {
            push(@keys_to_be_cleared, $key) if (scalar @keys_to_be_cleared < $cache_entry_count - $self->{max_entries});
        }

        # Remove elements from the cache
        foreach my $key (@keys_to_be_cleared) {
            delete($self->{data}{$key});
        }

        SSHCure::Utils::log_info(sprintf("Removed %i elements from cache '%s'; new number of elements in cache: %i", scalar @keys_to_be_cleared, $self->{name}, scalar keys($self->{data})));
    } else {
        SSHCure::Utils::log_info("No cleanup of cache '".$self->{name}."' needed...");
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

    SSHCure::Utils::log_debug("Added element '$key' to cache '".$self->{name}."'; elements in cache: ".scalar keys($self->{data}));
}

1;
