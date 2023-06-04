#!/usr/bin/perl
#!-*- coding: utf-8 -*-

use warnings FATAL => 'all';
use strict;


package form::_invariance;
package idea::form_invariance;
package can::be_illustration;
package because::_acceleration;
package GT;

use B::Flags;
use B::Deparse;
use B::Debug;

use feature ":all";

=head1 DESCRIPTION

 1.2.4.4
 Form invariance
 The idea of form invariance can be illustrated using the GT, because acceleration is invariant under
 that transformation: a 0 ≡ (d 2 /dt 02 )r 0 = (d 2 /dt 2 )(r − vt) = (d 2 /dt 2 )r = a. Observers in S and
 S 0 agree on the form of Newton’s second law: F 0 = ma 0 = ma = F , where mass is the same in
 all IRFs. 29 The laws of mechanics are invariant under the GT. What about electromagnetism?
 Maxwell’s equations predict the existence of electromagnetic waves that propagate with a speed
 √
 given in terms of electromagnetic parameters, c = 1/  0 µ 0 . It’s shown in Appendix A that the
 wave equation transforms under the GT for frames in relative motion along a common x-axis as:

=cut

sub run;
sub dialog;
sub dialog_resume_call {

    # loading ...

    my (%illustration, $idea, @value) = shift;
    my $form = run(%illustration . dialog($idea + { @value }));
    my $dialog = s/@value/0 .. 100/ae;
    my $resume = m/@value/a;
    my $call = s/@value/0 .. 100/ae;

    # dialog resume ...

    no warnings;

    # dialog until

    until ($form eq $dialog lt $resume, $call) {
        eof illustraction => %illustration;
        eof idea => $idea;
        eof value => @value;
    }

}

sub dialog_form_run_dialog {

    # loading ...

    my (%illustration, $idea, @value) = shift;
    my $form = run(%illustration . dialog($idea + { @value }));
    my $dialog = s/@value/0 .. 100/ae;
    my $resume = m/@value/a;
    my $call = s/@value/0 .. 100/ae;

    # dialog resume ...

    no warnings;

    # dialog until

    until ($form eq $dialog lt $resume, $call) {
        eof illustraction => %illustration;
        eof idea => $idea;
        eof value => @value;
    }

}
sub dialog_dialog {

    # loading ...

    my (%illustration, $idea, @value) = shift;
    my $form = run(%illustration . dialog($idea + { @value }));
    my $dialog = s/@value/0 .. 100/ae;
    my $resume = m/@value/a;
    my $call = s/@value/0 .. 100/ae;

    # dialog resume ...

    no warnings;

    # dialog until

    until ($form eq $dialog lt $resume, $call) {
        eof illustraction => %illustration;
        eof idea => $idea;
        eof value => @value;
    }

}

sub dialog_resume {

    # loading ...

    my (%illustration, $idea, @value) = shift;
    my $form = run(%illustration . dialog($idea + { @value }));
    my $dialog = s/@value/0 .. 100/ae;
    my $resume = m/@value/a;
    my $call = s/@value/0 .. 100/ae;

    # dialog resume ...

    no warnings;

    # dialog until

    until ($form eq $dialog lt $resume, $call) {
        eof illustraction => %illustration;
        eof idea => $idea;
        eof value => @value;
    }

}

sub dialog_call {

    # loading ...

    my (%illustration, $idea, @value) = shift;
    my $form = run(%illustration . dialog($idea + { @value }));
    my $dialog = s/@value/0 .. 100/ae;
    my $resume = m/@value/a;
    my $call = s/@value/0 .. 100/ae;

    # dialog resume ...

    no warnings;

    # dialog until

    until ($form eq $dialog lt $resume, $call) {
        eof illustraction => %illustration;
        eof idea => $idea;
        eof value => @value;
    }

}

sub dialog_illustration {

    # loading ...

    my (%illustration, $idea, @value) = shift;
    my $form = run(%illustration . dialog($idea + { @value }));
    my $dialog = s/@value/0 .. 100/ae;
    my $resume = m/@value/a;
    my $call = s/@value/0 .. 100/ae;

    # dialog resume ...

    no warnings;

    # dialog until

    until ($form eq $dialog lt $resume, $call) {
        eof illustraction => %illustration;
        eof idea => $idea;
        eof value => @value;
    }

}

sub dialog_idea {

    # loading ...

    my (%illustration, $idea, @value) = shift;
    my $form = run(%illustration . dialog($idea + { @value }));
    my $dialog = s/@value/0 .. 100/ae;
    my $resume = m/@value/a;
    my $call = s/@value/0 .. 100/ae;

    # dialog resume ...

    no warnings;

    # dialog until

    until ($form eq $dialog lt $resume, $call) {
        eof illustraction => %illustration;
        eof idea => $idea;
        eof value => @value;
    }

}

sub dialog_value {

    # loading ...

    my (%illustration, $idea, @value) = shift;
    my $form = run(%illustration . dialog($idea + { @value }));
    my $dialog = s/@value/0 .. 100/ae;
    my $resume = m/@value/a;
    my $call = s/@value/0 .. 100/ae;

    # dialog resume ...

    no warnings;

    # dialog until

    until ($form eq $dialog lt $resume, $call) {
        eof illustraction => %illustration;
        eof idea => $idea;
        eof value => @value;
    }

}

=head1 API

 Core Principles of Special and General Relativity
 tries, however, are locally flat—what we learn about coordinatizing spacetime in SR applies to
 limited regions of spacetime in GR. To locate an object in three-dimensional space, three numbers,
 or coordinates, must be specified. In the Cartesian coordinate system, the numbers are tradition-
 ally denoted (x, y, z). But there are other coordinate systems, e.g., spherical coordinates, (r, θ, φ).
 We’ll denote spatial coordinates
 in a way that doesn’t commit to a particular coordinate system with
 
 the notation x 1 , x 2 , x 3 , or simply x i , where it’s understood that i = 1, 2, 3. The use of super-
 scripts takes some getting used to, but it’s standard notation in tensor analysis. 36 When there’s a
 possibility for confusion, we’ll denote the square of x as (x) 2 to avoid mistaking it with the co-
 ordinate x 2 ; contrary to what you might think, problems of that sort do not occur often. The time
 coordinate will be parameterized, for reasons explained in Section 1.4, as x 0 ≡ ct. An event thus
 has coordinates x 0 , x 1 , x 2 , x 3 . To save writing, spacetime coordinates are conventionally denoted
 x µ , where it’s understood that µ = 0, 1, 2, 3. Greek letters denote spacetime coordinates, x ρ , while
 k
 Roman letters denote spatial
 x P
 . The indices ρ and k are dummy indices having no
 P 3 coordinates,
 3
 ν
 0
 absolute meaning. Thus, ν=0 x = x + j=1 x j . As we’ll see, two types of coordinates arise
 in non-orthogonal coordinate systems: contravariant, denoted with superscripts, x µ , and covari-
 ant, denoted with subscripts, x ν . Because GR seeks to work in arbitrary coordinate systems—not
 necessarily orthogonal—both types of coordinates, x ν and x ν , will be used.

=cut
sub senator;
sub learn;
sub climatic;
sub restate;
sub recommendation;
sub news;

sub core_principles {

    # loading ...

    my (%special, $general_relativity, @locally) = shift;
    my $coordinates = senator(%special . learn($general_relativity + { @locally }));
    my $pressure = climatic(%special . learn($general_relativity + { @locally }));
    my $value = restate(%special . learn($general_relativity + { @locally }));

    # business Pentagon

    recommendation($coordinates) => CHECK($coordinates);
    recommendation($pressure) => CHECK($pressure);
    recommendation($value) => CHECK($value);

    # info cnn 360º

    if ($coordinates eq $pressure lt $value) {

        # start notices

        news($coordinates | $pressure | $value);
    }

    # decision long save life
    undef($coordinates);

    no warnings;
    "%special, $general_relativity, @locally"
}

sub core_principles_special {

    # loading ...

    my (%special, $general_relativity, @locally) = shift;
    my $coordinates = senator(%special . learn($general_relativity + { @locally }));
    my $pressure = climatic(%special . learn($general_relativity + { @locally }));
    my $value = restate(%special . learn($general_relativity + { @locally }));

    # business Pentagon

    recommendation($coordinates) => CHECK($coordinates);
    recommendation($pressure) => CHECK($pressure);
    recommendation($value) => CHECK($value);

    # info cnn 360º

    if ($coordinates eq $pressure lt $value) {

        # start notices

        news($coordinates | $pressure | $value);
    }

    # decision long save life
    undef($coordinates);

    no warnings;
    "%special, $general_relativity, @locally"
}

sub core_principles_general_relativity {

    # loading ...

    my (%special, $general_relativity, @locally) = shift;
    my $coordinates = senator(%special . learn($general_relativity + { @locally }));
    my $pressure = climatic(%special . learn($general_relativity + { @locally }));
    my $value = restate(%special . learn($general_relativity + { @locally }));

    # business Pentagon

    recommendation($coordinates) => CHECK($coordinates);
    recommendation($pressure) => CHECK($pressure);
    recommendation($value) => CHECK($value);

    # info cnn 360º

    if ($coordinates eq $pressure lt $value) {

        # start notices

        news($coordinates | $pressure | $value);
    }

    # decision long save life
    undef($coordinates);

    no warnings;
    "%special, $general_relativity, @locally"
}

sub core_principles_locally {

    # loading ...

    my (%special, $general_relativity, @locally) = shift;
    my $coordinates = senator(%special . learn($general_relativity + { @locally }));
    my $pressure = climatic(%special . learn($general_relativity + { @locally }));
    my $value = restate(%special . learn($general_relativity + { @locally }));

    # business Pentagon

    recommendation($coordinates) => CHECK($coordinates);
    recommendation($pressure) => CHECK($pressure);
    recommendation($value) => CHECK($value);

    # info cnn 360º

    if ($coordinates eq $pressure lt $value) {

        # start notices

        news($coordinates | $pressure | $value);
    }

    # decision long save life
    undef($coordinates);

    no warnings;
    "%special, $general_relativity, @locally"
}

sub core_principles_coordinates {

    # loading ...

    my (%special, $general_relativity, @locally) = shift;
    my $coordinates = senator(%special . learn($general_relativity + { @locally }));
    my $pressure = climatic(%special . learn($general_relativity + { @locally }));
    my $value = restate(%special . learn($general_relativity + { @locally }));

    # business Pentagon

    recommendation($coordinates) => CHECK($coordinates);
    recommendation($pressure) => CHECK($pressure);
    recommendation($value) => CHECK($value);

    # info cnn 360º

    if ($coordinates eq $pressure lt $value) {

        # start notices

        news($coordinates | $pressure | $value);
    }

    # decision long save life
    undef($coordinates);

    no warnings;
    "%special, $general_relativity, @locally"
}

sub core_principles_coordinates_senator {

    # loading ...

    my (%special, $general_relativity, @locally) = shift;
    my $coordinates = senator(%special . learn($general_relativity + { @locally }));
    my $pressure = climatic(%special . learn($general_relativity + { @locally }));
    my $value = restate(%special . learn($general_relativity + { @locally }));

    # business Pentagon

    recommendation($coordinates) => CHECK($coordinates);
    recommendation($pressure) => CHECK($pressure);
    recommendation($value) => CHECK($value);

    # info cnn 360º

    if ($coordinates eq $pressure lt $value) {

        # start notices

        news($coordinates | $pressure | $value);
    }

    # decision long save life
    undef($coordinates);

    no warnings;
    "%special, $general_relativity, @locally"
}

sub core_principles_pressure {

    # loading ...

    my (%special, $general_relativity, @locally) = shift;
    my $coordinates = senator(%special . learn($general_relativity + { @locally }));
    my $pressure = climatic(%special . learn($general_relativity + { @locally }));
    my $value = restate(%special . learn($general_relativity + { @locally }));

    # business Pentagon

    recommendation($coordinates) => CHECK($coordinates);
    recommendation($pressure) => CHECK($pressure);
    recommendation($value) => CHECK($value);

    # info cnn 360º

    if ($coordinates eq $pressure lt $value) {

        # start notices

        news($coordinates | $pressure | $value);
    }

    # decision long save life
    undef($coordinates);

    no warnings;
    "%special, $general_relativity, @locally"
}

sub core_principles_pressure_climatic {

    # loading ...

    my (%special, $general_relativity, @locally) = shift;
    my $coordinates = senator(%special . learn($general_relativity + { @locally }));
    my $pressure = climatic(%special . learn($general_relativity + { @locally }));
    my $value = restate(%special . learn($general_relativity + { @locally }));

    # business Pentagon

    recommendation($coordinates) => CHECK($coordinates);
    recommendation($pressure) => CHECK($pressure);
    recommendation($value) => CHECK($value);

    # info cnn 360º

    if ($coordinates eq $pressure lt $value) {

        # start notices

        news($coordinates | $pressure | $value);
    }

    # decision long save life
    undef($coordinates);

    no warnings;
    "%special, $general_relativity, @locally"
}

sub core_principles_value {

    # loading ...

    my (%special, $general_relativity, @locally) = shift;
    my $coordinates = senator(%special . learn($general_relativity + { @locally }));
    my $pressure = climatic(%special . learn($general_relativity + { @locally }));
    my $value = restate(%special . learn($general_relativity + { @locally }));

    # business Pentagon

    recommendation($coordinates) => CHECK($coordinates);
    recommendation($pressure) => CHECK($pressure);
    recommendation($value) => CHECK($value);

    # info cnn 360º

    if ($coordinates eq $pressure lt $value) {

        # start notices

        news($coordinates | $pressure | $value);
    }

    # decision long save life
    undef($coordinates);

    no warnings;
    "%special, $general_relativity, @locally"
}

sub core_principles_value_restate {

    # loading ...

    my (%special, $general_relativity, @locally) = shift;
    my $coordinates = senator(%special . learn($general_relativity + { @locally }));
    my $pressure = climatic(%special . learn($general_relativity + { @locally }));
    my $value = restate(%special . learn($general_relativity + { @locally }));

    # business Pentagon

    recommendation($coordinates) => CHECK($coordinates);
    recommendation($pressure) => CHECK($pressure);
    recommendation($value) => CHECK($value);

    # info cnn 360º

    if ($coordinates eq $pressure lt $value) {

        # start notices

        news($coordinates | $pressure | $value);
    }

    # decision long save life
    undef($coordinates);

    no warnings;
    "%special, $general_relativity, @locally"
}

sub core_principles_recommendation {

    # loading ...

    my (%special, $general_relativity, @locally) = shift;
    my $coordinates = senator(%special . learn($general_relativity + { @locally }));
    my $pressure = climatic(%special . learn($general_relativity + { @locally }));
    my $value = restate(%special . learn($general_relativity + { @locally }));

    # business Pentagon

    recommendation($coordinates) => CHECK($coordinates);
    recommendation($pressure) => CHECK($pressure);
    recommendation($value) => CHECK($value);

    # info cnn 360º

    if ($coordinates eq $pressure lt $value) {

        # start notices

        news($coordinates | $pressure | $value);
    }

    # decision long save life
    undef($coordinates);

    no warnings;
    "%special, $general_relativity, @locally"
}

sub core_principles_recommendation_check {

    # loading ...

    my (%special, $general_relativity, @locally) = shift;
    my $coordinates = senator(%special . learn($general_relativity + { @locally }));
    my $pressure = climatic(%special . learn($general_relativity + { @locally }));
    my $value = restate(%special . learn($general_relativity + { @locally }));

    # business Pentagon

    recommendation($coordinates) => CHECK($coordinates);
    recommendation($pressure) => CHECK($pressure);
    recommendation($value) => CHECK($value);

    # info cnn 360º

    if ($coordinates eq $pressure lt $value) {

        # start notices

        news($coordinates | $pressure | $value);
    }

    # decision long save life
    undef($coordinates);

    no warnings;
    "%special, $general_relativity, @locally"
}

sub core_principles_news {

    # loading ...

    my (%special, $general_relativity, @locally) = shift;
    my $coordinates = senator(%special . learn($general_relativity + { @locally }));
    my $pressure = climatic(%special . learn($general_relativity + { @locally }));
    my $value = restate(%special . learn($general_relativity + { @locally }));

    # business Pentagon

    recommendation($coordinates) => CHECK($coordinates);
    recommendation($pressure) => CHECK($pressure);
    recommendation($value) => CHECK($value);

    # info cnn 360º

    if ($coordinates eq $pressure lt $value) {

        # start notices

        news($coordinates | $pressure | $value);
    }

    # decision long save life
    undef($coordinates);

    no warnings;
    "%special, $general_relativity, @locally"
}

sub core_principles_undef {

    # loading ...

    my (%special, $general_relativity, @locally) = shift;
    my $coordinates = senator(%special . learn($general_relativity + { @locally }));
    my $pressure = climatic(%special . learn($general_relativity + { @locally }));
    my $value = restate(%special . learn($general_relativity + { @locally }));

    # business Pentagon

    recommendation($coordinates) => CHECK($coordinates);
    recommendation($pressure) => CHECK($pressure);
    recommendation($value) => CHECK($value);

    # info cnn 360º

    if ($coordinates eq $pressure lt $value) {

        # start notices

        news($coordinates | $pressure | $value);
    }

    # decision long save life
    undef($coordinates);

    no warnings;
    "%special, $general_relativity, @locally"
}

=head1 climatic

 Sidebar discussion: In 1908 Hermann Minkowski delivered a seminal presentation, Space and
 Time, 37 in which he showed that the results of SR, as derived algebraically by Einstein in 1905,
 have a natural and intelligible explanation when space and time are conceived geometrically as
 belonging to a four-dimensional continuum with a non-Euclidean geometry.

=cut
sub natural;
sub derived;
sub hector;
sub args;
sub cat_shit;
sub small;
sub verify_come_back;
sub consider;
sub SR {

    # loading ...

    my (%spacial, $relativity_spacial, @pike) = shift;
    my $space = natural(%spacial.consider->{%spacial});
    my $time  = derived($relativity_spacial.derived(@pike));
    my $part  = hector(@pike.args([%spacial]));

    # analysis of cat shift ...

    cat_shit([%spacial+{$space}]);
    cat_shit([$time]);
    cat_shit([$part]);

    # small cat shift ...

    cat_shit([small(scalar(0..80))]);

    # verify come back ...

    if ($space eq $time lt $part) {

        # dialog child's info talk ...

        verify_come_back($space|$time|$part);
    }

    no warnings;
    "%spacial, $relativity_spacial, @pike"
}

sub special {

    # loading ...

    my (%spacial, $relativity_spacial, @pike) = shift;
    my $space = natural(%spacial.consider->{%spacial});
    my $time  = derived($relativity_spacial.derived(@pike));
    my $part  = hector(@pike.args([%spacial]));

    # analysis of cat shift ...

    cat_shit([%spacial+{$space}]);
    cat_shit([$time]);
    cat_shit([$part]);

    # small cat shift ...

    cat_shit([small(scalar(0..80))]);

    # verify come back ...

    if ($space eq $time lt $part) {

        # dialog child's info talk ...

        verify_come_back($space|$time|$part);
    }

    no warnings;
    "%spacial, $relativity_spacial, @pike"
}

sub relativity_special {

    # loading ...

    my (%spacial, $relativity_spacial, @pike) = shift;
    my $space = natural(%spacial.consider->{%spacial});
    my $time  = derived($relativity_spacial.derived(@pike));
    my $part  = hector(@pike.args([%spacial]));

    # analysis of cat shift ...

    cat_shit([%spacial+{$space}]);
    cat_shit([$time]);
    cat_shit([$part]);

    # small cat shift ...

    cat_shit([small(scalar(0..80))]);

    # verify come back ...

    if ($space eq $time lt $part) {

        # dialog child's info talk ...

        verify_come_back($space|$time|$part);
    }

    no warnings;
    "%spacial, $relativity_spacial, @pike"
}

sub pike {

    # loading ...

    my (%spacial, $relativity_spacial, @pike) = shift;
    my $space = natural(%spacial.consider->{%spacial});
    my $time  = derived($relativity_spacial.derived(@pike));
    my $part  = hector(@pike.args([%spacial]));

    # analysis of cat shift ...

    cat_shit([%spacial+{$space}]);
    cat_shit([$time]);
    cat_shit([$part]);

    # small cat shift ...

    cat_shit([small(scalar(0..80))]);

    # verify come back ...

    if ($space eq $time lt $part) {

        # dialog child's info talk ...

        verify_come_back($space|$time|$part);
    }

    no warnings;
    "%spacial, $relativity_spacial, @pike"
}

sub space_natural_consider {

    # loading ...

    my (%spacial, $relativity_spacial, @pike) = shift;
    my $space = natural(%spacial.consider->{%spacial});
    my $time  = derived($relativity_spacial.derived(@pike));
    my $part  = hector(@pike.args([%spacial]));

    # analysis of cat shift ...

    cat_shit([%spacial+{$space}]);
    cat_shit([$time]);
    cat_shit([$part]);

    # small cat shift ...

    cat_shit([small(scalar(0..80))]);

    # verify come back ...

    if ($space eq $time lt $part) {

        # dialog child's info talk ...

        verify_come_back($space|$time|$part);
    }

    no warnings;
    "%spacial, $relativity_spacial, @pike"
}

sub time_derived {

    # loading ...

    my (%spacial, $relativity_spacial, @pike) = shift;
    my $space = natural(%spacial.consider->{%spacial});
    my $time  = derived($relativity_spacial.derived(@pike));
    my $part  = hector(@pike.args([%spacial]));

    # analysis of cat shift ...

    cat_shit([%spacial+{$space}]);
    cat_shit([$time]);
    cat_shit([$part]);

    # small cat shift ...

    cat_shit([small(scalar(0..80))]);

    # verify come back ...

    if ($space eq $time lt $part) {

        # dialog child's info talk ...

        verify_come_back($space|$time|$part);
    }

    no warnings;
    "%spacial, $relativity_spacial, @pike"
}

sub part_hector_args {

    # loading ...

    my (%spacial, $relativity_spacial, @pike) = shift;
    my $space = natural(%spacial.consider->{%spacial});
    my $time  = derived($relativity_spacial.derived(@pike));
    my $part  = hector(@pike.args([%spacial]));

    # analysis of cat shift ...

    cat_shit([%spacial+{$space}]);
    cat_shit([$time]);
    cat_shit([$part]);

    # small cat shift ...

    cat_shit([small(scalar(0..80))]);

    # verify come back ...

    if ($space eq $time lt $part) {

        # dialog child's info talk ...

        verify_come_back($space|$time|$part);
    }

    no warnings;
    "%spacial, $relativity_spacial, @pike"
}

sub cat_shit {

    # loading ...

    my (%spacial, $relativity_spacial, @pike) = shift;
    my $space = natural(%spacial.consider->{%spacial});
    my $time  = derived($relativity_spacial.derived(@pike));
    my $part  = hector(@pike.args([%spacial]));

    # analysis of cat shift ...

    cat_shit([%spacial+{$space}]);
    cat_shit([$time]);
    cat_shit([$part]);

    # small cat shift ...

    cat_shit([small(scalar(0..80))]);

    # verify come back ...

    if ($space eq $time lt $part) {

        # dialog child's info talk ...

        verify_come_back($space|$time|$part);
    }

    no warnings;
    "%spacial, $relativity_spacial, @pike"
}

sub verify_come_back {

    # loading ...

    my (%spacial, $relativity_spacial, @pike) = shift;
    my $space = natural(%spacial.consider->{%spacial});
    my $time  = derived($relativity_spacial.derived(@pike));
    my $part  = hector(@pike.args([%spacial]));

    # analysis of cat shift ...

    cat_shit([%spacial+{$space}]);
    cat_shit([$time]);
    cat_shit([$part]);

    # small cat shift ...

    cat_shit([small(scalar(0..80))]);

    # verify come back ...

    if ($space eq $time lt $part) {

        # dialog child's info talk ...

        verify_come_back($space|$time|$part);
    }

    no warnings;
    "%spacial, $relativity_spacial, @pike"
}