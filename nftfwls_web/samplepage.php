<!doctype html>
<html>
  <head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Blacklist output</title>
<link rel="stylesheet" href="samplepage.css">
</head>
<html>
<div class="main">	 
<h1>Blacklist</h1>	 
<?php
#
# PHP insert to display nftfwls on a web page
#
# include the css to make the table work
#
function display_nftfwls()
{
	$op = array();
	$cmd = '/usr/local/bin/nftfwls -w -p no';
	exec($cmd, $op);
	foreach ($op as $l) {
		echo($l."\n");
	}
}
#
#
# run the function
#
#
display_nftfwls();
?>
</div>  
</html>
  
  