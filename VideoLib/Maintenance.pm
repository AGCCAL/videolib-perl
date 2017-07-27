package VideoLib::Maintenance;
use VideoLib;

use 5.010;
use strict;
use warnings;
use JSON;
use Data::Dumper;
use HTML::Entities;
use VideoLib::User;

use Text::Markdown 'markdown';

our @ISA = qw(VideoLib);


sub delete_video
{
  my $self = shift;
  my $video_id = shift;

  my $dbh = $self->database;
  my $sth = $dbh->prepare("select video_type, name from video where video_id = ?");
  $sth->bind_param(1,$video_id);
  $sth->execute;
  my $row = $sth->fetch;
  if (defined($row))
  {
    my ($video_type, $name) = @{$row};

    $sth = $dbh->prepare("delete from video where video_id = ?");
    $sth->bind_param(1,$video_id);
    $sth->execute;

    $sth = $dbh->prepare("delete from video_instance where video_id = ?");
    $sth->bind_param(1,$video_id);
    $sth->execute;
    
    $sth = $dbh->prepare("delete from video_instance_answer where video_id = ?");
    $sth->bind_param(1,$video_id);
    $sth->execute;

    $sth = $dbh->prepare("delete from video_group where video_id = ?");
    $sth->bind_param(1,$video_id);
    $sth->execute;

    if ($video_type == 1)
    {
      #regular video — delete the questions and dimensions

      $sth = $dbh->prepare("delete from video_dimension where video_id = ?");
      $sth->bind_param(1, $video_id);
      $sth->execute;

      $sth = $dbh->prepare("delete from question where video_id = ?;");
      $sth->bind_param(1,$video_id);
      $sth->execute;

      $sth = $dbh->prepare("delete from question_dimension where video_id = ?;");
      $sth->bind_param(1,$video_id);
      $sth->execute;
      
    }
    else
    {
      $sth = $dbh->prepare("select sub_video_id from combined_video where video_id = ? order by index_id;");
      $sth->bind_param(1,$video_id);
      $sth->execute;
      my @subs;
      my $index_id = 0;
      while (my $row = $sth->fetch)
      {
        my $sub_video_id = $row->[0];
        $self->duplicate_video($sub_video_id);
      }
      
      $sth = $dbh->prepare("delete from combined_video where video_id = ?;");
      $sth->bind_param(1,$video_id);
      $sth->execute;
      
    }
    return $name;
  }
  return undef;
}

sub create_video_new
{
  my $self = shift;
  my $resp;

  my $dbh = $self->database;
  my $caml = $self->caml;

  my $video;
  my $user_id = $self->get_user_id_from_cookie();

  $video->{banner} = $self->banner($user_id);

  my $output = $caml->render_file('create_video', $video);
  utf8::encode($output);
  return $self->response_as_html($output);

}

sub create_video
{
  my $self = shift;
  my $resp;

  my $dbh = $self->database;
  my $caml = $self->caml;

  # Ensure we're logged in as an admin
  my $user_id = $self->get_user_id_from_cookie() unless (defined($resp));
  unless ($self->user_id_is_an_admin($user_id))
  {
    $user_id = undef;
  }

  unless (defined($user_id))
  {
    return $self->redirect_via_login($self->request->uri);
  }


  # At this point, we're definitely an administrator.

  $resp = $self->test_params([qw(title vlength description transcript keywords url)]);

  unless (defined($resp))
  {
    my $video_id = $self->params->{"video_id"};

    unless(defined($video_id))
    {
      $video_id = $self->hex_token(2)."-".$self->hex_token(1)."-".$self->hex_token(1)."-".$self->hex_token(1)."-".$self->hex_token(3);
      my $title = $self->params->{"title"};
      my $length = $self->params->{"vlength"};
      my $description = $self->params->{"description"};
      my $transcript = $self->params->{"transcript"};
      my $keywords = $self->params->{"keywords"};
      my $url = $self->params->{"url"};

      utf8::upgrade($title);
      utf8::upgrade($length);
      utf8::upgrade($description);
      utf8::upgrade($transcript);
      utf8::upgrade($keywords);

      $title = $self->clean_input($title);
      $length = $self->clean_input($length);
      $description = $self->clean_input($description);
      $transcript = $self->clean_input($transcript);
      $keywords = $self->clean_input($keywords);

      my $sth = $dbh->prepare("insert into video values (?,?,?,?,?,?,?);");
      $sth->bind_param(1,$video_id);
      $sth->bind_param(2,$title);
      $sth->bind_param(3,$length);
      $sth->bind_param(4,$description);
      $sth->bind_param(5,$transcript);
      $sth->bind_param(6,$keywords);
      $sth->bind_param(7,$url);
      $sth->execute;

      return $self->update_video($video_id);
    }
  }
  
  return $self->create_video_new;
}


sub update_video
{
  my $self = shift;

  my $resp;

  my $dbh = $self->database;
  my $sth;
  my $caml = $self->caml;

  my $video;

  # Ensure we're logged in as an admin
  my $user_id = $self->get_user_id_from_cookie() unless (defined($resp));
  unless ($self->user_id_is_an_admin($user_id))
  {
    $user_id = undef;
  }

  unless (defined($user_id))
  {
    return $self->redirect_via_login($self->request->uri);
  }

  # at this point, we're logged in as an administrator


  # if we're called from create_video, we had the video_id passed as
  # an argument. Otherwise, we need to get it from the HTTP params.

  my $video_id = shift;
  unless(defined($video_id))
  {
    $video_id = $self->params->{"video_id"};
  }

  $video->{video_id} = $video_id;

  my $title = $self->params->{"title"};
  my $length = $self->params->{"vlength"};
  my $description = $self->params->{"description"};
  my $transcript = $self->params->{"transcript"};
  my $keywords = $self->params->{"keywords"};
  my $url = $self->params->{"url"};

  if ((defined($title)) &&
      (defined($length)) &&
      (defined($description)) &&
      (defined($transcript)) &&
      (defined($keywords)) &&
      (defined($url)))
  {
    utf8::upgrade($title);
    utf8::upgrade($length);
    utf8::upgrade($description);
    utf8::upgrade($transcript);
    utf8::upgrade($keywords);

    $title = $self->clean_input($title);
    $description = $self->clean_input($description);
    $length = $self->clean_input($length);
    $transcript = $self->clean_input($transcript);
    $keywords = $self->clean_input($keywords);

    $sth = $dbh->prepare("update video set title = ?, length = ?, description = ?, transcript = ?, keywords = ?, url = ? where video_id = ?");
    $sth->bind_param(1,$title);
    $sth->bind_param(2,$length);
    $sth->bind_param(3,$description);
    $sth->bind_param(4,$transcript);
    $sth->bind_param(5,$keywords);
    $sth->bind_param(6,$url);
    $sth->bind_param(7,$video_id);
    $sth->execute;

  }



  # Now pull all the latest values from the database.


  $sth = $dbh->prepare("select title, length, description, transcript, keywords, url from video where video_id = ?");
  $sth->bind_param(1,$video_id);
  $sth->execute;
  my $row = $sth->fetch;
  if ($row)
  {
    my $state;
    ($title, $length, $description, $transcript, $keywords, $url) = @{$row};

    #TODO: If state is "published", we need to kill this video and make a new one.

    utf8::decode($title);
    utf8::decode($length);
    utf8::decode($description);
    utf8::decode($transcript);
    utf8::decode($keywords);

    $video->{title} = $title;
    $video->{vlength} = $length;
    $video->{description} = $description;
    $video->{transcript} = $transcript;
    $video->{keywords} = $keywords;
    $video->{url} = $url;
  }

  $video->{banner} = $self->banner($user_id);

  my %hashy;
  my $output = $caml->render_file('update_video', $video);

  $hashy{"output"} = $output;

  return $self->success_response(%hashy);
}


sub modify_video
{
  my $self = shift;
  my $resp = $self->update_video;
  
  if ($resp->code == 200)
  {
    my $content = decode_json($resp->content);
    my $output = $content->{output};
    utf8::encode($output);
    my $video;
    my $user_id = $self->get_user_id_from_cookie();

    $video->{banner} = $self->banner($user_id);

    $video->{output} = $output;
    my $caml = $self->caml;
    $output = $caml->render_file('modify_video', $video);
    $resp = $self->response_as_html($output);
  }
  return $resp;
}
1;
