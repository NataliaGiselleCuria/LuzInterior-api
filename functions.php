<?php

require_once 'config.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use \Firebase\JWT\ExpiredException;
use \Firebase\JWT\SignatureInvalidException;

function generarToken($userId)
{
    $issuedAt = time();
    $expirationTime = $issuedAt + 3600;

    $payload = [
        'iat' => $issuedAt,         // Fecha de emisión
        'exp' => $expirationTime,   // Fecha de expiración
        'sub' => $userId            // ID del usuario
    ];

    return JWT::encode($payload, JWT_SECRET, JWT_ALGORITHM);
}

function enviarCorreo($destinatario, $asunto, $mensajeHtml)
{
    $mail = new PHPMailer(true);

    try {

        $mail->isSMTP();
        $mail->Host = MAIL_HOST; // Usar constante desde config.php
        $mail->SMTPAuth = true;
        $mail->Username = MAIL_USERNAME; // Usar constante desde config.php
        $mail->Password = MAIL_PASSWORD; // Usar constante desde config.php
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS; // Usar constante desde config.php
        $mail->Port = MAIL_PORT; // Usar constante desde config.php

        // Configuración del correo
        $mail->setFrom(MAIL_FROM, MAIL_FROM_NAME); // Usar constantes desde config.php
        $mail->addAddress($destinatario);
        $mail->isHTML(true);
        $mail->Subject = $asunto;
        $mail->Body = $mensajeHtml;

        $mail->send();
        return true;
    } catch (Exception $e) {

        error_log("Error al enviar correo: {$mail->ErrorInfo}");
        return false;
    }
}

function enviarRespuesta($data)
{
    global $dominiosPermitidos;

    if (isset($_SERVER['HTTP_ORIGIN']) && in_array($_SERVER['HTTP_ORIGIN'], $dominiosPermitidos)) {
        header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
        header("Access-Control-Allow-Credentials: true");
    }

    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

function verificarToken($token)
{
    try {
        // Intentar decodificar el token
        return JWT::decode($token, new Key(JWT_SECRET, JWT_ALGORITHM));
    } catch (ExpiredException $e) {
        // El token ha expirado
        return ['success' => false, 'message' => 'El token ha expirado'];
    } catch (SignatureInvalidException $e) {
        // La firma del token no es válida
        return ['success' => false, 'message' => 'Token con firma inválida'];
    } catch (Exception $e) {
        // Otros errores generales relacionados con la decodificación
        return ['success' => false, 'message' => 'Token inválido'];
    }
}

function obtenerDatos($con, $query, $errorMessage) {
    try {
        $sql = $con->prepare($query);
        $sql->execute();
        $resultado = $sql->fetchAll(PDO::FETCH_ASSOC);

        if ($resultado) {
            return ['success' => true, 'data' => $resultado];
        } else {
            throw new Exception($errorMessage);
        }
    } catch (Exception $e) {
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

function registerProduct($con, $data)
{
    try {
        $sql = $con->prepare("INSERT INTO products (id, name, category, price, description) VALUES (?, ?, ?, ?, ?)");
        $sql->execute([$data['id'], $data['name'], $data['category'], $data['price'], $data['description']]);

        if ($sql->rowCount() > 0) {
            return ['success' => true];
        } else {
            return ['success' => false, 'message' => 'No se pudo registrar el producto'];
        }
    } catch (PDOException $e) {
        if ($e->getCode() == 23000) {
            return ['success' => false, 'message' => 'Este producto ya está registrado'];
        } else {
            return ['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()];
        }
    }
}

