<?php

require_once 'config.php';
require_once 'vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use \Firebase\JWT\ExpiredException;
use \Firebase\JWT\SignatureInvalidException;
use PHPMailer\PHPMailer\SMTP;

function generateToken($userId)
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

function sendReply($data)
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

function verifyToken($token)
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

function getData($con, $sql, $params = [], $fetchAll = false) {
    try {
        $stmt = $con->prepare($sql);
        $stmt->execute($params);
        
        if ($fetchAll) {
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } else {
            return $stmt->fetch(PDO::FETCH_ASSOC);
        }

    } catch (PDOException $e) {
        return ['error' => 'Error en la consulta: ' . $e->getMessage()];
    }
}

function getDataCompany()
{
    try {
        $db = new DataBase();
        $con = $db->conectar();

        $sql = $con->prepare("SELECT `key`, `value` FROM company_info WHERE `key` IN ('email', 'tel', 'web')");
        $sql->execute();
        $result = $sql->fetchAll(PDO::FETCH_ASSOC);

        if ($result) {
            $data = [];
            foreach ($result as $row) {
                $data[$row['key']] = $row['value'];
            }

            return ['success' => true, 'data' => $data];
        } else {
            throw new Exception('No se encontraron datos para las claves email y teléfono.');
        }
    } catch (Exception $e) {
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

function registerProduct($con, $data)
{
    $config = HTMLPurifier_Config::createDefault();
    $config->set('HTML.Allowed', 'p,ul,ol,li,b,strong,i,em,br');
    $config->set('Core.EscapeInvalidTags', true);
    $purifier = new HTMLPurifier($config);

    // Sanitizar HTML
    $clean_html_description = $purifier->purify($data['description']);

    try {
        $sql = $con->prepare("INSERT INTO products (id, name, category, price, description, novelty) VALUES (?, ?, ?, ?, ?, ?)");
        $sql->execute([$data['id'], $data['name'], $data['category'], $data['price'], $clean_html_description, $data['novelty']]);

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

function generateEmailTemplate( $title, $content)
{
    $baseURL = "https://luz-interior.free.nf/API/src/assets";

   
    $companyInfo = getDataCompany();

    $email = htmlspecialchars($companyInfo['data']['email'], ENT_QUOTES, 'UTF-8');
    $tel = htmlspecialchars($companyInfo['data']['tel'], ENT_QUOTES, 'UTF-8');

    // Plantilla HTML
    $html = <<<HTML
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>$title</title>
        <style>
           
            p{
                font-size: 16px;            
            }

            body {
                background-color: #3a3a3a;
                padding: 20px;
                margin: 0;
            }
            
            .email-container {
                max-width: 600px;
                margin: 0 auto;
                background-color: #3a3a3a;
                border-radius: 8px;
                border: 5px solid  #3a3a3a;
                overflow: hidden;
            }

            .header{
                background: white;
                padding:0;
            }

            .header img {
                width: 100%;
                height: auto;
            }
            
            .content {
                padding: 10px 50px 50px;
                background-color: white;
                background-image: url('$baseURL/li_logo.png');
                background-size: 50%;
                background-position: left bottom;
                background-repeat: no-repeat;
                color: #3a3a3a;
            }
            .content a{
                color: #3a3a3a;
            }

            .footer {
                background-color: #3a3a3a;
                color: white;
                font-size: 14px;
                display: flex;
                padding: 0;
            }
            .footer a {
                color: white;
                text-decoration: none;
            }
            .footer p {
               margin: 0;
               font-size: 12px
            }
            .footer img {
                width: 20px;
                height: auto;
            }
            .footer-logo{
                justify-items: center;
            }
            .footer-logo img {
                height: 70px;
                width: auto;
            }
        </style>
    </head>
    <body>
        <div class="email-container">
            <table style="width: 100%; border-spacing: 0;">
                <thead>
                    <tr>
                        <td class="header">
                            <img src="$baseURL/banner-email.png" alt="Logo de Luz Interior" style="width: 100%;">
                        </td>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="content">
                            $content
                        </td>
                    </tr>
                </tbody>
                <tfoot>
                    <tr>
                        <td class="footer">
                            <table style="width: 100%; color: white; padding: 0px 20px;">
                                <tr>
                                    <td>
                                        <p>No responder este email.</p>
                                        <p>Contactarse a:</p>
                                        <div style="height: 25px; padding:10px 0px;">
                                            <a href="https://wa.me/$tel"> <img src="$baseURL/whatsapp.png" alt="WhatsApp" style="width: auto; height: 90%; margin: auto; padding: 0 5px;"></a>                                  
                                            <a href="mailto:$email"><img src="$baseURL/email.png" alt="Email" style="width: auto; height:80%; margin: auto; padding: 0 5px;"></a>
                                        </div>
                                    </td>
                                    <td style="text-align: center; padding:0;">
                                        <div class="footer-logo">
                                            <img src="$baseURL/pendant.png" alt="Lámpara colgante">
                                            <p style="font-size: 10px">© 2024 Luz Interior SRL</p>
                                        </div>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </tfoot>
            </table>
        </div>
    </body>
    </html>
    HTML;

    return $html;
}

function sendMail($destinatario, $asunto, $mensajeHtml, $altBody)
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
        $mail->CharSet = 'UTF-8';
        $mail->Subject = $asunto;
        $mail->Body = $mensajeHtml;
        $mail->AltBody = $altBody;
        // $mail->SMTPDebug = SMTP::DEBUG_LOWLEVEL;

        $mail->send();
        return true;
    } catch (Exception $e) {

        error_log("Error al enviar correo: {$mail->ErrorInfo}");
        return false;
    }
}


