<?php
include "WhoIsInfoAjaxApi.php";

error_reporting(E_ALL);
ini_set('display_errors', 1);


header('Content-Type: application/json');

$method = $_SERVER['REQUEST_METHOD'];
$domain = isset($_POST['domain']) ? $_POST['domain'] : '';

if ($method === 'POST' && !empty($domain)) {
    /*$apiKey = isset($_SERVER['HTTP_APIKEY']) ? $_SERVER['HTTP_APIKEY'] : null;
    if($apiKey != 'apikey'){
        echo json_encode(['error' => 'Invalid apikey.']);
        die();
    }else{
        $api = new WhoIsInfoAjaxApi();
        $response=$api->printJsonResponse($domain);
        json_encode($response);
        die();
    }*/

    $api = new WhoIsInfoAjaxApi();
    $response=$api->printJsonResponse($domain);
    json_encode($response);
    die();

} else {
    echo json_encode(['error' => 'Invalid request method or missing domain parameter']);
}
?>

