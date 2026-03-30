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
                <h2>Auth page 2</h2>
				<?php
				// MITIGATION: Directory Traversal - Whitelist allowed files and validate path
				// Only allow specific files to be viewed, prevent path traversal sequences

				// Define whitelist of allowed files
				$allowedFiles = array('yellow.txt', 'Yellow.txt');

				// Get the requested file
				$ViewFile = isset($_GET['FileToView']) ? $_GET['FileToView'] : '';

				// Use basename to strip any directory traversal attempts
				$ViewFile = basename($ViewFile);

				// Check if file is in whitelist
				if (in_array($ViewFile, $allowedFiles)) {
					$fullPath = __DIR__ . '/' . $ViewFile;

					// Verify the file exists and is within the allowed directory
					$realPath = realpath($fullPath);
					$allowedDir = realpath(__DIR__);

					if ($realPath && strpos($realPath, $allowedDir) === 0 && file_exists($realPath)) {
						$FileData = file_get_contents($realPath);
						echo RemoveXSS($FileData);
					} else {
						echo "File not found.";
					}
				} else {
					echo "Access denied. File not in allowed list.";
				}

				// RemoveXSS loaded via header.php -> includes/removexss.inc.php
?>
            </div>
        </section>

<?php
	include_once 'footer.php';
?>