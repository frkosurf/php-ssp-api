<html>
<head>
<title>Configuration Log</title>
<style>
    table {
        border: 1px solid #000;
    }
    td {
        border: 1px solid #000;
    }
    span.prodaccepted {
        color: #080;
    }
    span.testaccepted {
        color: #888;
    }
</style>
</head>
<body>

<?php

$jsonData = file_get_contents($argv[1]);
$data = json_decode($jsonData, TRUE);

foreach ($data as $set => $entities) {
    echo '<h1>' . $set . '</h1>';
    echo '<table style="border: 1px solid #000;">';
    echo "<tr><th>Entity ID</th><th>State</th><th>Messages</th></tr>";

    foreach ($entities as $k => $v) {
        echo "<tr><td>";
        echo $k;
        echo "</td><td>";
        echo '<span class="' . $v['state'] . '">' . $v['state'] . '</span>';
        echo "</td>";

        echo "<td>";
        echo "<ul>";
        foreach ($v['messages'] as $m) {
            echo '<li>' . $m['message'] . '</li>';
        }
        echo "</ul>";
        echo "</td></tr>";
    }

    echo "</table>";

    echo "<hr>";
}

?>

</body></html>
