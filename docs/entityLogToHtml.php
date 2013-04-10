<html>
<head>
<title>Configuration Log</title>
<style>
    body {
        font-family: sans-serif;
    }
    table {
        border: 1px solid #000;
        border-collapse: collapse;
    }
    td, th {
        border: 1px dotted #000;
    padding: 5px;
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
$sr = 'https://serviceregistry.surfconext.nl';

$jsonData = file_get_contents($argv[1]);
$data = json_decode($jsonData, TRUE);

echo '<h1>Entity Log</h1>';
echo '<ul>';

foreach (array_keys($data) as $set) {
    echo '<li><a href="#' . $set . '">' . $set . '</a></li>';
}
echo '</ul>';

foreach ($data as $set => $entities) {
    echo '<h2 id="' . $set . '">' . $set . '</h2>';
    echo '<table style="border: 1px solid #000;">';
    echo "<tr><th>Entity ID</th><th>State</th><th>Messages</th></tr>";

    foreach ($entities as $k => $v) {
        echo "<tr><td>";
        echo '<a target="_blank" href="' . $sr . '/simplesaml/module.php/janus/editentity.php?eid=' . $v['eid'] . '">' . $k . '</a>';
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
