<?php
session_start();

    session_destroy();

    $_SESSION = [];

    return header("Location: login.php");