<?php

//If user is not logged in or requesting to reset, redirect
include 'dbh.inc.php';
session_start();

if (!isset($_GET['reset'],$_SESSION['u_uid'])) {
    $_SESSION['resetError'] = "Error code 1";
    header("Location: ../index.php");
    exit();
} else {
    // MITIGATION: CSRF - Validate the CSRF token before processing
    $csrfToken = isset($_GET['csrf-token']) ? $_GET['csrf-token'] : '';

    if (empty($csrfToken) || !isset($_SESSION['csrf']) || !hash_equals($_SESSION['csrf'], $csrfToken)) {
        $_SESSION['resetError'] = "CSRF token validation failed. Please try again.";
        header("Location: ../change.php");
        exit();
    }

    // Regenerate CSRF token after successful validation to prevent reuse
    unset($_SESSION['csrf']);

    $oldpass = $_GET['old'];
    $newConfirm = $_GET['new_confirm'];
    $newpass = $_GET['new'];

    if (empty($oldpass || $newpass)) {
        $_SESSION['resetError'] = "Error code 2";
    } else {
        
        $uid = $_SESSION['u_uid'];

        $checkOld = "SELECT * FROM `sapusers` WHERE `user_uid` = ?"; //$uid
        $stmt = $conn->prepare($checkOld);
        $stmt->bind_param("s", $uid);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) { 

            $row = mysqli_fetch_assoc($result); 

			
            // MITIGATION: Verify old password against bcrypt hash (consistent with login flow)
            if (!password_verify($oldpass, $row['user_pwd'])) {
                $_SESSION['resetError'] = "Error code 4";
                header("Location: ../index.php");
                exit();
            } else {
                if ($newConfirm == $newpass) { //confirm they match

                    // MITIGATION: Hash new password with bcrypt before storing
                    $hashedNewPass = password_hash($newpass, PASSWORD_BCRYPT);
                    $changePass = "UPDATE `sapusers` SET `user_pwd` = ? WHERE `user_uid` = ?";
                    $stmt = $conn->prepare($changePass);
                    $stmt->bind_param("ss", $hashedNewPass, $uid);
                            
                    if(!$stmt->execute()) {
                        echo "Error: " . $stmt->error;
                    }

                    header("Location: ./logout.inc.php");
                    exit();
                } else {
                    $_SESSION['resetError'] = "Error code 5";
                    header("Location: ../index.php");
                    exit();
                }
            }
        } else {
            $_SESSION['resetError'] = "Error code 6"; 
            header("Location: ../index.php");
            exit();
        }
    }
}