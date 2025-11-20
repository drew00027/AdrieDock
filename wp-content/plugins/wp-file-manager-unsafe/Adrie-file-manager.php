<?php
/*
Plugin Name: WP File Manager Unsafe
Description: Extremely insecure file upload plugin for testing.
Version: 1.0
Author: Adrie
*/

// Auto‑create uploads folder
$upload_dir = __DIR__ . '/uploads';
if (!is_dir($upload_dir)) {
    mkdir($upload_dir, 0777, true);
}

// Handle upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $target = $upload_dir . '/' . basename($_FILES['file']['name']);
    if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
        echo "<p>Uploaded to: $target</p>";
    } else {
        echo "<p>Upload failed.</p>";
    }
}

// Simple HTML form (always visible)
?>
<!DOCTYPE html>
<html>
<body>
<h2>Unsafe File Upload</h2>

<form method="POST" enctype="multipart/form-data">
    <input type="file" name="file">
    <button type="submit">Upload</button>
</form>

</body>
</html>
