<?php
/**
 * OWASP TOP 10 ONLINE SCANNER
 * Router: proxies /api/* to FastAPI backend, serves frontend SPA for all other routes
 */

$requestUri = $_SERVER['REQUEST_URI'];
$requestPath = parse_url($requestUri, PHP_URL_PATH);

// ── API Proxy (/api/*) ──
if (strpos($requestPath, '/api') === 0) {
    $backendUrl = 'http://127.0.0.1:8000' . $requestUri;
    
    $ch = curl_init($backendUrl);
    
    // Forward method
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $_SERVER['REQUEST_METHOD']);
    
    // Forward request body
    $input = file_get_contents('php://input');
    if (!empty($input)) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $input);
    }
    
    // Forward headers
    $headers = [];
    foreach ($_SERVER as $key => $value) {
        if (strpos($key, 'HTTP_') === 0) {
            $headerName = str_replace('_', '-', substr($key, 5));
            // Skip host header
            if (strtoupper($headerName) === 'HOST') continue;
            $headers[] = "$headerName: $value";
        }
    }
    if (isset($_SERVER['CONTENT_TYPE'])) {
        $headers[] = "Content-Type: " . $_SERVER['CONTENT_TYPE'];
    }
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    
    // Capture response
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 300);
    
    // Forward cookies
    if (isset($_SERVER['HTTP_COOKIE'])) {
        curl_setopt($ch, CURLOPT_COOKIE, $_SERVER['HTTP_COOKIE']);
    }
    
    $response = curl_exec($ch);
    
    if (curl_errno($ch)) {
        http_response_code(502);
        header('Content-Type: application/json');
        echo json_encode(['detail' => 'Backend unreachable: ' . curl_error($ch)]);
        curl_close($ch);
        exit;
    }
    
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $responseHeaders = substr($response, 0, $headerSize);
    $responseBody = substr($response, $headerSize);
    curl_close($ch);
    
    // Set response code
    http_response_code($httpCode);
    
    // Forward response headers
    foreach (explode("\r\n", $responseHeaders) as $headerLine) {
        if (empty($headerLine)) continue;
        if (stripos($headerLine, 'HTTP/') === 0) continue;
        if (stripos($headerLine, 'transfer-encoding:') === 0) continue;
        header($headerLine, false);
    }
    
    echo $responseBody;
    exit;
}

// ── Static Assets (/assets/*) ──
if (strpos($requestPath, '/assets/') === 0) {
    $filePath = __DIR__ . '/frontend/dist' . $requestPath;
    if (file_exists($filePath)) {
        $ext = pathinfo($filePath, PATHINFO_EXTENSION);
        $mimeTypes = [
            'js' => 'application/javascript',
            'css' => 'text/css',
            'svg' => 'image/svg+xml',
            'png' => 'image/png',
            'jpg' => 'image/jpeg',
            'woff' => 'font/woff',
            'woff2' => 'font/woff2',
            'ttf' => 'font/ttf',
        ];
        header('Content-Type: ' . ($mimeTypes[$ext] ?? 'application/octet-stream'));
        header('Cache-Control: public, max-age=31536000, immutable');
        readfile($filePath);
        exit;
    }
}

// ── Favicon & root static files ──
$staticFile = __DIR__ . '/frontend/dist' . $requestPath;
if ($requestPath !== '/' && file_exists($staticFile) && is_file($staticFile)) {
    $ext = pathinfo($staticFile, PATHINFO_EXTENSION);
    $mimeTypes = ['svg' => 'image/svg+xml', 'ico' => 'image/x-icon', 'png' => 'image/png'];
    header('Content-Type: ' . ($mimeTypes[$ext] ?? 'application/octet-stream'));
    readfile($staticFile);
    exit;
}

// ── SPA Fallback: serve index.html ──
readfile(__DIR__ . '/frontend/dist/index.html');
