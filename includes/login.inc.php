<?php
// Start PHP script for login processing
require_once __DIR__ . '/removexss.inc.php';

// Detect client IP address from server variables
if(!empty($_SERVER['HTTP_CLIENT_IP'])) { // Check if client IP is available
    $ipAddr=$_SERVER['HTTP_CLIENT_IP']; // Use client IP
} elseif(!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) { // Check if forwarded IP exists
    $ipAddr=$_SERVER['HTTP_X_FORWARDED_FOR']; // Use forwarded IP
}
  else { // Fallback option
    $ipAddr=$_SERVER['REMOTE_ADDR']; // Use remote address
}

// Start session management
session_start();



// Check if login form was submitted
if (isset($_POST['submit'])) { // Check if form submit button was clicked

    // Include database connection file
    include 'dbh.inc.php';

    // Sanitize inputs from POST request
    $uid = $_POST['uid']; // Get username from form
    $pwd = $_POST['pwd']; // Get password from form
    $ipAddr = $ipAddr; // Assign IP address variable

    // Check for previous failed login attempts from this client IP
    $checkClient = "SELECT `failedLoginCount`, `timeStamp` FROM `failedLogins` WHERE `ip` = ?"; // SQL query to check existing records
    $stmt = $conn->prepare($checkClient); // Prepare statement to prevent SQL injection
    $stmt->bind_param("s", $ipAddr); // Bind the IP address parameter
    $stmt->execute(); // Execute the prepared statement
    $result = $stmt->get_result(); // Store the query results
    $time = date("Y-m-d H:i:s"); // Get current timestamp

    // Check if this is a new client or returning client
    // "Initialise" attempts recording their IP, timestamp and setup a failed login count, based off IP and attempted uid
    if ($result->num_rows == 0) { // If client IP is not in database (new client)

        // Insert new client record into database
        $addUser = "INSERT INTO `failedLogins` (`ip`, `timeStamp`, `failedLoginCount`, `lockOutCount`) VALUES (?, ?, '0', '0')"; // SQL insert query
        $stmt = $conn->prepare($addUser); // Prepare the insert statement
        $stmt->bind_param("ss", $ipAddr, $time); // Bind parameters

        // Check if insert was successful
        if(!$stmt->execute()) { // If execution fails
            die("Error: " . $stmt->error); // Show error and stop execution
        }

        // Process login for new client
        processLogin($conn,$uid,$pwd,$ipAddr);
        
        // Handle subsequent visits for existing clients
    } else { // Client IP already exists in database
        // Retrieve failed login count for this client
        $getCount = "SELECT `failedLoginCount` FROM `failedLogins` WHERE `ip` = ?"; // SQL query to get count
        $stmt = $conn->prepare($getCount); // Prepare statement
        $stmt->bind_param("s", $ipAddr); // Bind IP parameter
        $stmt->execute(); // Execute query
        $result = $stmt->get_result(); // Get results

        // Check if query executed successfully
            if (!$result) { // If query failed
                die("Error: " . $stmt->error); // Show error and exit
            } else { // Query succeeded
                // Assign count in variable so we can compare it for each failed login
                $failedLoginCount = ($result->fetch_row()[0]); // Get the count from first column

                // Check if failed login attempts exceed threshold
                if ($failedLoginCount >= 5) { // If 5 or more failed attempts
                    // Assuming theres 5 failed logins from this IP now check the timestamp to lock them out for 3 minutes
                    $checkTime = "SELECT `timeStamp` FROM `failedLogins` WHERE `ip` = ?"; // SQL query to get timestamp
                    $stmt = $conn->prepare($checkTime); // Prepare statement
                    $stmt->bind_param("s", $ipAddr); // Bind IP parameter
                    $stmt->execute(); // Execute query
                    $result = $stmt->get_result(); // Get results

                    // Check if query executed successfully
                    if(!$result) { // If query failed
                        die('Error: ' . $stmt->error); // Show error and exit
                    } else { // Query succeeded
                        $failedLoginTime = ($result->fetch_row()[0]); // Get the timestamp from first column
                    }

                    // Calculate time difference between current time and failed login time
                    $currTime = date("Y-m-d H:i:s"); // Get current timestamp
                    $timeDiff = abs(strtotime($currTime) - strtotime($failedLoginTime)); // Calculate difference in seconds
                    $_SESSION['timeLeft'] = 180 - $timeDiff; // Store remaining lockout time (3 minutes = 180 seconds)

                    // Check if lockout period is still active
                    if((int)$timeDiff <= 180) { // If within 3-minute lockout window
                        // Set lockout message for user
                        $_SESSION['lockedOut'] = "Due to multiple failed logins you're now locked out, please try again in 3 minutes"; // Store lockout message

                        // Store unsuccessful login attempt, uid, timestamp, IP in log format for viewing at admin.php
                        $time = date("Y-m-d H:i:s"); // Get current timestamp
                        $recordLogin = "INSERT INTO `loginEvents` (`ip`, `timeStamp`, `user_id`, `outcome`) VALUES (?, ?, ?, 'fail')"; // SQL insert query for failed login
                        $stmt = $conn->prepare($recordLogin); // Prepare statement
                        $stmt->bind_param("sss", $ipAddr, $time, cleanChars($uid)); // Bind parameters
                        $stmt->execute(); // Execute query

                        // Check if record insertion was successful
                        if(!$stmt->execute()) { // If execution fails
                            die("Errory: " . $stmt->error); // Show error and exit
                        }
                        // Redirect given lockout is currently enabled
                        header("location: ../index.php"); // Redirect to index page
                        exit(); // Critical: must exit after redirect to prevent code execution

                    } else { // Lockout period has expired

                        // Update lockOutCount
                        $updateLockOutCount = "UPDATE `failedLogins` SET `lockOutCount` = `lockOutCount` + 1 WHERE `ip` = ?"; // SQL update query
                        $stmt = $conn->prepare($updateLockOutCount); // Prepare statement
                        $stmt->bind_param("s", $ipAddr); // Bind IP parameter

                        // Check if update was successful
                        if(!$stmt->execute()) { // If execution fails
                            die("Errorz: " . $stmt->error); // Show error and exit
                        } else { // Update succeeded

                            // Otherwise update the lockout counter/timestamp
                            $currTime = date("Y-m-d H:i:s"); // Get current timestamp
                            $updateCount = "UPDATE `failedLogins` SET `failedLoginCount` = '0', `timeStamp` = ? WHERE `ip` = ?"; // SQL update query to reset counter
                            $stmt = $conn->prepare($updateCount); // Prepare statement
                            $stmt->bind_param("ss", $currTime, $ipAddr); // Bind parameters

                            // Check if reset was successful
                            if(!$stmt->execute()) { // If execution fails
                                die("Error: " . $stmt->error); // Show error and exit
                            }
                            
                            // Process login after resetting counters
                            processLogin($conn,$uid,$pwd,$ipAddr); // Call login function
                        }
                    }
                    
                } else { // Failed login count is below threshold
                    // Process login normally
                    processLogin($conn,$uid,$pwd,$ipAddr); // Call login function
                }
            }
    }
}

// Function to process the login request
function processLogin($conn, $uid, $pwd, $ipAddr) { // Parameters: database connection, username, password, IP address
    // Errors handlers
    // Check if inputs are empty
    if (empty($uid) || empty($pwd)) { // If either username or password is empty

        // Redirect to index with error message
        header("Location: ../index.php?login=empty"); // Send to login page with error indicator
        // Record failed login attempt
        failedLogin($uid,$ipAddr); // Call failed login function
        exit(); // Stop execution

    } else { // Inputs are not empty

        // Attempt to query database with try-catch for error handling
		try{ // Begin try block
		// MITIGATION: SQL Injection - Using prepared statements with parameterized queries
		// Fetch by uid only; password verified separately using password_verify
		$sql = "SELECT * FROM sapusers WHERE user_uid = ?"; // SQL query with placeholder
		$stmt = $conn->prepare($sql); // Prepare statement to prevent injection
		$stmt->bind_param("s", $uid); // Bind username parameter only
		$stmt->execute(); // Execute the prepared statement
		$result = $stmt->get_result(); // Retrieve query results

		} // End try block
		catch (Exception $e) { // Catch any exceptions thrown
			// Handle exception
			echo 'Caught exception: ',  $e->getMessage(), "\n"; // Display exception message
			// Record failed login with error message
			failedLogin($e->getMessage(),$ipAddr); // Call failed login with exception details
		}
		
        // Check if any user records were found
        if ($result->num_rows < 1) { // If no matching user found
            
            // Record failed login attempt
            failedLogin($uid,$ipAddr); // Call failed login function

        } else { // User record found

            // Fetch the user record as associative array
            if ($row = mysqli_fetch_assoc($result)) { // Retrieve first record from results
                // Check password validity
				
				// $pwd inputted from user
                $hashedPwdCheck = $row['user_pwd']; // Get hashed password from database

                // MITIGATION: Insecure Password Storage - Use password_verify to compare
                if (!password_verify($pwd, $hashedPwdCheck)){ // If password does not match hash

                    // Record failed login attempt
                    failedLogin($uid,$ipAddr); // Call failed login function

                } else{ // Passwords match - successful login
                    // MITIGATION: Session Fixation - Regenerate session ID on successful login
                    // This prevents attackers from using a pre-set session ID
                    session_regenerate_id(true); // Generate new session ID

                    // Initiate session variables with user information
                    $_SESSION['u_id'] = $row['user_id']; // Store user ID
                    $_SESSION['u_uid'] = $row['user_uid']; // Store username
                    $_SESSION['u_admin'] = $row['user_admin']; // Store admin flag (0 for non-admin users)

                    // Store successful login attempt in log
                    $time = date("Y-m-d H:i:s"); // Get current timestamp
                    $recordLogin = "INSERT INTO `loginEvents` (`ip`, `timeStamp`, `user_id`, `outcome`) VALUES (?, ?, ?, 'success')"; // SQL insert query for successful login
                    $stmt = $conn->prepare($recordLogin); // Prepare statement
                    $stmt->bind_param("sss", $ipAddr, $time, cleanChars($uid)); // Bind parameters

                    // Check if record insertion was successful
                    if(!$stmt->execute()) { // If execution fails
                        die("Errorx: " . $stmt->error); // Show error and exit
                    } else { // Log record inserted successfully
                        // Redirect to next authentication page
                        header("Location: ../auth1.php"); // Send to auth1 page
                        exit(); // Stop execution
                    }
                }
            }
        }
    }
} // End processLogin function 

// Function to handle failed login attempts
function failedLogin ($uid,$ipAddr) { // Parameters: username, IP address
    // Include database connection file
    include "dbh.inc.php"; // Load database connection
    // When login fails redirect to index and set the failedMsg variable so it can be displayed on index
    $_SESSION['failedMsg'] = "The username " . cleanChars($uid) . " and password could not be authenticated at this moment."; // Set error message in session
    
    // Store unsuccessful login attempt, uid, timestamp, IP in log format for viewing at admin.php
    $time = date("Y-m-d H:i:s"); // Get current timestamp
    $recordLogin = "INSERT INTO `loginEvents` (`ip`, `timeStamp`, `user_id`, `outcome`) VALUES (?, ?, ?, 'fail')"; // SQL insert query for failed login
    $stmt = $conn->prepare($recordLogin); // Prepare statement
    $stmt->bind_param("sss", $ipAddr, $time, cleanChars($uid)); // Bind parameters

    // Check if logging was successful
    if(!$stmt->execute()) { // If execution fails
        die("Error 1: " . $stmt->error); // Show error and exit
    } else { // Logging succeeded
        // Update failed login count for client
        $currTime = date("Y-m-d H:i:s"); // Get current timestamp
        $updateCount = "UPDATE `failedLogins` SET `failedLoginCount` = `failedLoginCount` + 1, `timeStamp` = ? WHERE `ip` = ?"; // SQL update query to increment failed count
        $stmt = $conn->prepare($updateCount); // Prepare statement
        $stmt->bind_param("ss", $currTime, $ipAddr); // Bind parameters

        // Check if update was successful
        if(!$stmt->execute()) { // If execution fails
            die("Error 2: " . $stmt->error); // Show error and exit
        } else { // Update succeeded
            // Redirect user to login page
            header("Location: ../index.php"); // Send to index page
            exit(); // Stop execution
        }
    }
    
} // End failedLogin function

// Function to sanitize output and prevent XSS attacks
// MITIGATION: XSS (Reflective & Persistent) - RemoveXSS decodes obfuscated HTML entities
// This strips encoded XSS payloads preventing script injection
// RemoveXSS loaded via require_once -> includes/removexss.inc.php
function cleanChars($val) // Parameter: value to sanitize
{ // Begin function body
    return RemoveXSS($val); // Return sanitized value
} // End cleanChars function