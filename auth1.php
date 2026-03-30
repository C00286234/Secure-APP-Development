<?php
	include_once 'header.php';
	if (!isset($_SESSION['u_id'])) {
	header("Location: home.php");
	exit();
	} else {
		$user_id = $_SESSION['u_id']; 
		$user_uid = $_SESSION['u_uid'];
	}
?>
        <section class="main-container">
            <div class="main-wrapper">
                <h2>Auth page 1</h2>
				Only authenticated users should be able to see this Page(1).
            </div>
        </section>
	
<?php	
	echo "<br>";
	//Reflect user's name on the page
	if(isset($_SESSION['u_id'])) {
		$user_uid = $_SESSION['u_uid'];
		echo "You're logged in as " . cleanChars($user_uid);
	}

	// MITIGATION: XSS - RemoveXSS decodes obfuscated HTML entities to neutralize encoded XSS payloads
	// RemoveXSS loaded via header.php -> includes/removexss.inc.php
	function cleanChars($val)
	{
		return RemoveXSS($val);
	}
?>

<html>

<!-- https://hackersonlineclub.com/command-injection-cheatsheet/

Objectives
1. Obtain the directory structure on the server
2. obtain the network configuration of the server
3. Upload a file that will execuite on the server (.php file parhaps)
4. Run the file -->

<head>

</head>


<div class="header">

</div>

<div class="clearfix">
  <div class="column menu">

  </div>

  <div class="column content">
	<p></p>


  </div> 
  
  <div class="column content">
  <p><br>Enter your IP/host to ping.  
            <form method='get' action=''>
                <div class="form-group"> 
                    <label></label>
                    <input class="form-control" width="50%" placeholder="" name="target"></input> <br>
                    <div align="left"> <button class="btn btn-default" type="submit">Submit Button</button></div>
               </div> 
            </form>
	</p>

  <?php

	try {

		if (isset($_REQUEST['target'])) {
			$target = $_REQUEST['target'];

			// MITIGATION: Command Injection - Validate input is a valid IP or hostname
			// Only allow alphanumeric characters, dots, and hyphens (valid for IPs/hostnames)
			if($target){
				// Whitelist validation: only allow valid IP addresses or hostnames
				if (preg_match('/^[a-zA-Z0-9.\-]+$/', $target) &&
				    (filter_var($target, FILTER_VALIDATE_IP) ||
				     preg_match('/^[a-zA-Z0-9][a-zA-Z0-9.\-]{0,253}[a-zA-Z0-9]$/', $target))) {

					// Additional protection: use escapeshellarg to safely escape the argument
					$safeTarget = escapeshellarg($target);

					if (stristr(php_uname('s'), 'Windows NT')) {
						$cmd = shell_exec('ping ' . $safeTarget);
						echo '<pre>'.RemoveXSS($cmd).'</pre>';
					} else {
						$cmd = shell_exec('ping -c 3 ' . $safeTarget);
						echo '<pre>'.RemoveXSS($cmd).'</pre>';
					}
				} else {
					echo '<pre>Invalid target. Please enter a valid IP address or hostname.</pre>';
				}
			}
		}
	}
	catch(Exception $e) {
		echo '<BR> Pass your payload to a parameter called name on the URL (HTTP GET request) ';
		echo '<BR><p><b>Example:</b>    http://localhost/Lab/dt/dt.php?target=IPaddress </p>';
	}

	?>
	</div>
	
</div>

<div class="footer">
</div>

</body>
</html>



