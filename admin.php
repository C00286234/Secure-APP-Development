<?php
      include_once 'header.php';
	  include_once 'includes/dbh.inc.php';

		// MITIGATION: Insufficient Session Management - Proper access control
		// Redirect unauthorized users and prevent direct page access
      if (!isset($_SESSION['u_id']) || $_SESSION['u_admin'] != 1) {
            // User is not logged in or not an admin - redirect to home
            header("Location: index.php");
            exit(); // Critical: must exit after redirect to prevent code execution
      } else {
            $user_id = $_SESSION['u_id'];
            $user_uid = $_SESSION['u_uid'];
      }
?>

      <section class="main-container">
            <div class="main-wrapper">
                  <h2>Login Events</h2>
                  <div class="admin-entry-count">
                        <?php
                              $entry_total_result = mysqli_query($conn, "SELECT count(event_id) AS num_rows FROM loginevents");
                              $row = mysqli_fetch_object($entry_total_result);
                              $total = $row->num_rows;
                        ?>
                        <p><i>Total entry count: <?php echo $total; ?></i></p>
                  </div>
                  <?php

                        $query = mysqli_query($conn, "SELECT * FROM loginevents");
                        while ($row = mysqli_fetch_array($query)) {
                              // MITIGATION: Persistent XSS - Sanitize all output from database
                              $id = htmlspecialchars($row['event_id'], ENT_QUOTES, 'UTF-8');
                              $ipAddr = htmlspecialchars($row['ip'], ENT_QUOTES, 'UTF-8');
                              $time = htmlspecialchars($row['timeStamp'], ENT_QUOTES, 'UTF-8');
                              $user_id = htmlspecialchars($row['user_id'], ENT_QUOTES, 'UTF-8');
                              $outcome = htmlspecialchars($row['outcome'], ENT_QUOTES, 'UTF-8');

                              echo "<div class='admin-content'>
                                          Entry ID: <b>$id</b>
                                          <br>
                                          <form class='admin-form' method='GET'>
                                                <label>IP Address: </label><input type='text' name='IP' value='$ipAddr' ><br>
                                                <label>Timestamp: </label><input type='text' name='timestamp' value='$time' ><br>
                                                <label>User ID: </label><input type='text' name='userid' value='$user_id' ><br>
                                                <label>Outcome: </label><input type='text' name='outcome' value='$outcome' >
                                          </form>
                                          <br>
                                    </div>";
                        }
                  ?>
            </div>
      </section>
      <?php
            include_once 'footer.php';
      ?>
