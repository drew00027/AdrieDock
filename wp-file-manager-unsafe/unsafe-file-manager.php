<?php
/*
Plugin Name: Unsafe File Manager
Version: 2.6
*/

// Arbitrary file upload vulnerability for lab

if (isset($_FILES['file'])) {
    $target = __DIR__ . '/uploads/' . basename($_FILES['file']['name']);
    move_uploaded_file($_FILES['file']['tmp_name'], $target);
    echo "Uploaded to: " . $target;
    exit;
}
?>

<form method="POST" enctype="multipart/form-data">
  <input type="file" name="file">
  <button type="submit">Upload</button>
</form>
