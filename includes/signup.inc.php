<?php

    if (isset($_POST['submit'])) {

        session_start();
        include_once 'dbh.inc.php';

        $uid = $_POST['uid'];
        $pwd = $_POST['pwd'];

        if(!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ipAddr=$_SERVER['HTTP_CLIENT_IP'];
        } elseif(!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ipAddr=$_SERVER['HTTP_X_FORWARDED_FOR'];
        }
          else {
            $ipAddr=$_SERVER['REMOTE_ADDR'];
        }

        // MITIGATION: Brute-Force Protection - Extended to registration
        // Check if user exists in failedLogins table, if not add them
        $checkClient = "SELECT `failedLoginCount`, `timeStamp` FROM `failedLogins` WHERE `ip` = ?";
        $stmt = $conn->prepare($checkClient);
        $stmt->bind_param("s", $ipAddr);
        $stmt->execute();
        $result = $stmt->get_result();
        $time = date("Y-m-d H:i:s");

        if ($result->num_rows == 0) {
            // New IP - add to tracking table
            $addUser = "INSERT INTO `failedLogins` (`ip`, `timeStamp`, `failedLoginCount`, `lockOutCount`) VALUES (?, ?, '0', '0')";
            $stmt = $conn->prepare($addUser);
            $stmt->bind_param("ss", $ipAddr, $time);
            $stmt->execute();
        }

        // Re-fetch to check current count
        $stmt = $conn->prepare($checkClient);
        $stmt->bind_param("s", $ipAddr);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();

        if ($row && $row['failedLoginCount'] >= 5) {
            // Check if lockout period has passed (3 minutes)
            $timeDiff = abs(strtotime($time) - strtotime($row['timeStamp']));
            if ($timeDiff <= 180) {
                $_SESSION['register'] = "Error: Too many attempts. Please wait " . (180 - $timeDiff) . " seconds.";
                header("Location: ../index.php");
                exit();
            } else {
                // Reset count after lockout period
                $resetCount = "UPDATE `failedLogins` SET `failedLoginCount` = '0', `timeStamp` = ? WHERE `ip` = ?";
                $stmt = $conn->prepare($resetCount);
                $stmt->bind_param("ss", $time, $ipAddr);
                $stmt->execute();
            }
        }

        // Increment attempt counter for each registration attempt
        $incrementCount = "UPDATE `failedLogins` SET `failedLoginCount` = `failedLoginCount` + 1, `timeStamp` = ? WHERE `ip` = ?";
        $stmt = $conn->prepare($incrementCount);
        $stmt->bind_param("ss", $time, $ipAddr);
        $stmt->execute();
        
        // Check for empty fields
        if (empty($uid) || empty($pwd)) {
            $_SESSION['register'] = "Cannot submit empty username or password.";
            header("Location: ../index.php");
            exit();

        } else {

            //Check to make sure only alphabetical characters are used for the username
            if (!preg_match("/^[a-zA-Z]*$/", $uid)) {

                $_SESSION['register'] = "Username must only contain alphabetic characters.";
                header("Location: ../index.php");
                exit();

            } else {
				
                    $sql = "SELECT * FROM `sapusers` WHERE `user_uid` = ?"; //$uid
                    $stmt = $conn->prepare($sql);
                    $stmt->bind_param("s", $uid);
                    $stmt->execute();
                    $result = $stmt->get_result();

					//If the user already exists, prevent them from signing up
                    if ($result->num_rows > 0) {

                        $_SESSION['register'] = "Error.";
                        header("Location: ../index.php");
                        exit();

                    } else {
                        $hashedPWD = $pwd;

                        $sql = "INSERT INTO `sapusers` (`user_uid`, `user_pwd`) VALUES (?, ?)"; 
                        $stmt = $conn->prepare($sql);
                        $stmt->bind_param("ss", $uid, $hashedPWD);
                        
                        if(!$stmt->execute()) {
                            echo "Error: " . $stmt->error;
                        }

                        // Reset brute-force counter on successful registration
                        $resetCount = "UPDATE `failedLogins` SET `failedLoginCount` = '0' WHERE `ip` = ?";
                        $stmt = $conn->prepare($resetCount);
                        $stmt->bind_param("s", $ipAddr);
                        $stmt->execute();

                        $_SESSION['register'] = "You've successfully registered as " . htmlspecialchars($uid, ENT_QUOTES, 'UTF-8') . ".";

                        header("Location: ../index.php");
                        exit();

                    }
                }   
        }
    }