package VideoLib::Profile;
use VideoLib;
use VideoLib::User;

use 5.010;
use strict;
use warnings;
use JSON;


our @ISA = qw(VideoLib);

sub generate_admin_profile
{
  my $self = shift;
  my $resp;
  my $user_id = $self->get_user_id_from_cookie() unless (defined($resp));
  unless (defined($user_id))
  {
    return $self->redirect_via_login("./");
  }

  my $dbh = $self->database;
  my $caml = $self->caml;

  my $profile;

  my $is_an_admin = $self->user_id_is_an_admin($user_id);
  if ($is_an_admin)
  {

    my @videos;
    my $sth = $dbh->prepare("select video_id, title from video order by title;");
    $sth->execute;
    while (my $row = $sth->fetch)
    {
      my ($video_id, $title) = @{$row};
      my $video;
      $video->{video_id} = $video_id;
      $video->{title} = $title;

      push @videos, $video;
    }

    $profile->{videos} = \@videos;
    $profile->{show_create} = 1;
    
  }

  $profile->{banner} = $self->banner($user_id);

  my $output = $caml->render_file('profile', $profile);
  return $self->response_as_html($output);
}

1;
