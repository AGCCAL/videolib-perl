package VideoLib::Search;
use VideoLib;

use 5.010;
use strict;
use warnings;
use JSON;
use Data::Dumper;
use HTML::Entities;
use Garden::User;

use Text::Markdown 'markdown';

our @ISA = qw(VideoLib);


sub perform_search
{
  my $self = shift;
  my $resp;
  my $banner;
  
  my $user_id = $self->get_user_id_from_cookie() unless (defined($resp));
  if ($self->user_id_is_an_admin($user_id))
  {
    $banner = $self->banner($user_id);
  }
  else
  {
    $user_id = undef;
    $banner = '<div class="banner"><img src="img/logo.png" class="logo" /></div>';
  }
  
  my $query = (defined($self->params)) ? $self->params->{"q"} : undef;
  my $dbh = $self->database;
  my $caml = $self->caml;
  my $search_results;
  my @results;

  if (defined($query))
  {
    my $sth = $dbh->prepare("select title, description, length, url from video where video match ?");
    $sth->bind_param(1,$query);
    $sth->execute;
    
    while (my $row = $sth->fetch)
    {
      my ($title, $description, $length, $url) = @{$row};
      my $result;
      $result->{title} = $title;
      $result->{vlength} = $length;
      $result->{description} = markdown($description);
      $result->{url} = $url;
      push @results, $result;
    }
    
    $search_results->{title} = "Search results — $query";
      
  }
  else
  {
    $query = "";
    $search_results->{title} = "Advanced Leadership Video Library";
  }
  
  $search_results->{query} = $query;
  $search_results->{results} = \@results;
  $search_results->{banner} = $banner;

  my $output = $caml->render_file('search_results', $search_results);
  utf8::encode($output);
  return $self->response_as_html($output);
  
 
 }

1;
