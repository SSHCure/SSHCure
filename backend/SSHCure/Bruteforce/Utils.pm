######################################################################
#
#  Checks.pm
#  Authors: Luuk Hendriks
#           Rick Hofstede <r.j.hofstede@utwente.nl>
#  University of Twente, The Netherlands
#
#  LICENSE TERMS: 3-clause BSD license (outlined in license.html)
#
######################################################################
# vim: expandtab:tw=4:sw=4

package SSHCure::Bruteforce::Utils;
use strict;
use warnings;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw (
    get_histogram_stats
    get_histogram_end
    get_concurrent_connection_stats
);

# Determines the following values in the supplied histogram:
#   * Highest peak
#   * Highest peak frequency
#   * Highest peak share (overall, fraction)
#   * Highest key
sub get_histogram_stats {
    my $h = $_[0];
    my @sorted_keys_by_value_frequency = sort { $$h{$a} <=> $$h{$b} } keys (%$h);
    my $top_value = $sorted_keys_by_value_frequency[-1];
    
    my $highest_key = (sort {$a <=> $b} keys (%$h))[-1];

    my $total_values = 0;
    $total_values += $_ for (values %$h);
    
    my $top_value_fraction = $$h{$top_value} / $total_values;
    return ($top_value, $$h{$top_value}, $top_value_fraction, $highest_key);
}

# The get_histogram_end routine determines whether the last 'bins' of the histogram
# contain a peak. This is used to find possible network-wide blocks in a collection of flow records.
sub get_histogram_end {
    my ($h, $bin_count) = @_;
    my $total_item_count = 0;
    $total_item_count += $_ for (values %$h);

    my @sorted = sort keys %$h;

    my $last_bins_sum = 0;
    my $number_of_bins_to_check = $bin_count;
    $number_of_bins_to_check = scalar @sorted;
    my $timestamp_to_return = 0;
    foreach (0..$number_of_bins_to_check-1) {
        last if $sorted[-1 - $_] < $timestamp_to_return - 1;
        $last_bins_sum += $$h{$sorted[-1 - $_]};
        $timestamp_to_return = $sorted[-1 - $_];
    }
    
    my $percentage = $last_bins_sum/$total_item_count;
    return ($timestamp_to_return, $last_bins_sum, $percentage);
}

sub get_concurrent_connection_stats {
    my $conc_conns = $_[0];
    my $sum = 0;
    $sum += $_ for (values %$conc_conns);

    my $avg = $sum/(scalar keys %$conc_conns);
    my $max = (sort (values %$conc_conns))[-1];
    return ($avg, $max);
}

1;
