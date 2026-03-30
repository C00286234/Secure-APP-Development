<?php
    session_start();
    require_once __DIR__ . '/includes/removexss.inc.php';

    // MITIGATION: Page Caching - Prevent browsers from caching authenticated pages
    // This ensures users cannot view cached pages after logout using back button
    header("Cache-Control: no-cache, no-store, must-revalidate, max-age=0");
    header("Cache-Control: post-check=0, pre-check=0", false);
    header("Pragma: no-cache");
    header("Expires: Sat, 01 Jan 2000 00:00:00 GMT");

    //include_once 'includes/dbh.inc.php';
    if(!isset($_SESSION['u_id'])) {
        $session = 0;
    } else {
        $session = 1;
    }

?>

<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Super Secure Site</title>
<link rel="stylesheet" href="css/style.css">
<script>
//Run the function on window.onload
    window.onload = function() {
    inactiveUser(); 
}
var inactiveUser = function () {
var timer;

//Relevant DOM Events in order to reset the time (whenever the user is deemed active)
window.onload = resetTimer;
document.onmousemove = resetTimer;
document.onkeypress = resetTimer;

//Only logout if the user is logged in
function logout() {
    var session='<?php echo $session;?>';
    if(session == 1) {
        location.href = './includes/logout.inc.php'
    } else {
        //No need to logout, they're not logged in
    }
}

function resetTimer() {
    clearTimeout(timer);
    timer = setTimeout(logout, 600000) //600000 10 minutes in milliseconds
}
};

window.addEventListener('pageshow', function (event) {
    var navEntries = window.performance.getEntriesByType('navigation');
    var isBackForward = event.persisted || (navEntries.length > 0 && navEntries[0].type === 'back_forward');

    if (isBackForward) {
        window.location.reload();
    }
});
</script>
</head>

<!--Keep the user logged in for 1 hour maximum-->
<meta http-equiv="refresh" content="3600;url=includes/logout.inc.php" />

<body>

<!--Navigation-->
<header>
<nav>
<div class="main-wrapper">
<ul class="nav-bar">
<li><a href="index.php">Home</a></li>
     
<?php
    if (!isset($_SESSION['u_id'])) {
        echo '<li><a href="register.php">Register</a></li>';
    }
    if (isset($_SESSION['u_uid'])) {
        $admin_status = $_SESSION['u_admin'];
        if (isset($_SESSION['u_id']) && $admin_status == 1) {
            echo '<li><a href="admin.php">Admin</a></li>';
            echo '<li><a href="auth1.php">Auth1</a></li>';
            echo '<li><a href="auth2.php?FileToView=yellow.txt">Auth2</a></li>';
            echo '<li><a href="change.php">Change Password</a></li>';
        } else if (isset($_SESSION['u_id'])) {
            echo '<li><a href="auth1.php">Auth1</a></li>';
            echo '<li><a href="auth2.php?FileToView=yellow.txt">Auth2</a></li>';
            echo '<li><a href="change.php">Change Password</a></li>';
        } 
    }
?>
</ul>

<div class="nav-login">
<?php
    if (isset($_SESSION['u_id'])) {
        echo '  <form class="" action="includes/logout.inc.php" method="POST">
        <button type="submit" name="submit"> Log out </button>
        </form>';
    } else {
        echo '  <form class="" action="includes/login.inc.php" method="POST">
        <input type="text" name="uid" value="" placeholder="Username">
        <input type="password" name="pwd" value="" placeholder="Password">
        <button type="submit" name="submit"> Login </button>
        </form>
        <a href="register.php"> Sign up </a>';
    }
?>

</div>
</div>
</nav>
</header>
