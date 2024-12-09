<?php


ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

require_once 'database.php';
require_once 'config.php';
require_once 'vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

$db = new DataBase();
$con = $db->conectar();

$dominiosPermitidos = ["http://localhost:5173", "https://localhost:5173"];

if (isset($_SERVER['HTTP_ORIGIN']) && in_array($_SERVER['HTTP_ORIGIN'], $dominiosPermitidos)) {
    header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
    header("Access-Control-Allow-Credentials: true");
}

header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");
header("Access-Control-Allow-Methods: OPTIONS, GET, POST, PUT, DELETE");
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Max-Age: 1728000');
    header('Content-Length: 0');
    header('Content-Type: text/plain');
    die();
}

require 'vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

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
        $mail->Host = 'smtp.gmail.com'; // Cambiar por tu servidor SMTP
        $mail->SMTPAuth = true;
        $mail->Username = 'nataliagiselle.c@gmail.com'; // Tu email
        $mail->Password = 'zayd qnsz faib ryfy'; // Tu contraseña (usa claves de app si es Gmail)
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = 587;

        // Configuración del correo
        $mail->setFrom('nataliagiselle.c@gmail.com', 'LUZ INTERIOR');
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
        return JWT::decode($token, new Key(JWT_SECRET, JWT_ALGORITHM));
    } catch (Exception $e) {
        return null; // Token inválido o expirado
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

function uploadImagesProducts($con, $file, $priority, $productId)
{
    $allowedTypes = ['image/jpeg', 'image/png'];
    if (!in_array($file['type'], $allowedTypes)) {
        return ['success' => false, 'message' => 'Tipo de archivo no permitido'];
    }

    $targetDir = 'uploads/img-products/';
    $targetFile = $targetDir . basename($file['name']);

    if (move_uploaded_file($file['tmp_name'], $targetFile)) {
        try {
            $sql = $con->prepare("INSERT INTO products_images (product_id, img_url, priority) VALUES (?, ?, ?)");
            $sql->execute([$productId, $targetFile, $priority]);

            if ($sql->rowCount() > 0) {
                return ['success' => true];
            } else {
                return ['success' => false, 'message' => 'No se pudo guardar la imagen en la base de datos'];
            }
        } catch (PDOException $e) {
            return ['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()];
        }
    } else {
        return ['success' => false, 'message' => 'Error al subir la imagen'];
    }
}

if (isset($_GET['action'])) {
    $action = $_GET['action'];
    switch ($action) {
        case 'verify-token':
            $authHeader = getallheaders();

            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');

            $decoded = verificarToken($jwt);

            if ($decoded) {
                enviarRespuesta(['success' => true, 'message' => 'Token válido', 'data' => $decoded]);
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;

        case 'products':
            $sql = $con->prepare("
                    SELECT
                        products.*,
                         products_images.id_img,
                        products_images.img_url,
                        products_images.priority
                    FROM
                        products
                    LEFT JOIN
                        products_images
                    ON
                        products.id = products_images.product_id
                    ORDER BY
                        products.id, products_images.priority ASC
                ");

            $sql->execute();
            $resultado = $sql->fetchAll(PDO::FETCH_ASSOC);

            // Agrupar las imágenes por producto
            $productos = [];
            foreach ($resultado as $row) {
                $id_producto = $row['id'];
                if (!isset($productos[$id_producto])) {
                    // Agregar los datos del producto
                    $productos[$id_producto] = [
                        'id' => $row['id'],
                        'name' => $row['name'],
                        'category' => $row['category'],
                        'price' => $row['price'],
                        'description' => $row['description'],
                        'img_url' => [],
                    ];
                }

                // Agregar la imagen al arreglo del producto
                if ($row['img_url']) {
                    $productos[$id_producto]['img_url'][] = [
                        'id_img' => $row['id_img'],
                        'url' => $row['img_url'],
                        'priority' => $row['priority'],
                    ];
                }
            }

            // Convertir a un arreglo indexado
            $productos = array_values($productos);

            enviarRespuesta($productos);
            break;

        case 'users':
            $sql = $con->prepare("
                SELECT users.*, addresses.*
                FROM users
                LEFT JOIN addresses ON users.id = addresses.id_user
            ");
            $sql->execute();
            $resultado = $sql->fetchAll(PDO::FETCH_ASSOC);

            // Procesamos los datos para que cada usuario tenga un array de direcciones
            $usuarios = [];
            foreach ($resultado as $row) {

                if (!isset($usuarios[$row['id']])) {
                    $usuarios[$row['id']] = [
                        'id' => $row['id'],
                        'name' => $row['name'],
                        'email' => $row['email'],
                        'role' => $row['role'],
                        'addresses' => []
                    ];
                }

                if ($row['id_address']) {
                    $usuarios[$row['id']]['addresses'][] = [
                        'id' => $row['id_address'],
                        'name' => $row['name'],
                        'last_name' => $row['last_name'],
                        'company_name' => $row['company_name'],
                        'street' => $row['street'],
                        'street2' => $row['street2'],
                        'city' => $row['city'],
                        'province' => $row['province'],
                        'cp' => $row['cp'],
                        'tel' => $row['tel'],
                        'default_address' => $row['default_address']
                    ];
                }
            }

            enviarRespuesta(array_values($usuarios));
            break;

        case 'settings':
            $sql = $con->prepare("SELECT * FROM settings");
            $sql->execute();
            $resultado = $sql->fetchAll(PDO::FETCH_ASSOC);
            enviarRespuesta($resultado);
            echo $resultado;
            break;

        case 'shipping':
            $sql = $con->prepare("SELECT * FROM shipping");
            $sql->execute();
            $resultado = $sql->fetchAll(PDO::FETCH_ASSOC);
            enviarRespuesta($resultado);
            echo $resultado;
            break;

        case 'user-data':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents("php://input"), true);

                if (isset($data['email'])) {
                    $email = $data['email'];

                    $sql = $con->prepare("
                            SELECT users.*, addresses.*
                            FROM users
                            LEFT JOIN addresses ON users.id = addresses.id_user
                            WHERE users.email = :email
                        ");

                    $sql->bindParam(':email', $email, PDO::PARAM_INT);
                    $sql->execute();
                    $resultado = $sql->fetchAll(PDO::FETCH_ASSOC);

                    $usuario = null;
                    if (!empty($resultado)) {
                        $usuario = [
                            'id' => $resultado[0]['id'],
                            'name' => $resultado[0]['name'],
                            'email' => $resultado[0]['email'],
                            'password' => $resultado[0]['password'],
                            'cuit' => $resultado[0]['cuit'],
                            'tel' => $resultado[0]['tel'],
                            'addresses' => [],
                            'role' => $resultado[0]['role']
                        ];
                        foreach ($resultado as $row) {
                            if ($row['id_address']) {
                                $usuario['addresses'][] = [
                                    'id_address' => $row['id_address'],
                                    'street' => $row['street'],
                                    'street2' => $row['street2'],
                                    'city' => $row['city'],
                                    'province' => $row['province'],
                                    'cp' => $row['cp'],
                                    'name_address' => $row['name_address'],
                                    'last_name' => $row['last_name'],
                                    'company_name' => $row['company_name'],
                                    'tel_address' => $row['tel_address'],
                                    'default_address' => $row['default_address'],
                                ];
                            }
                        }
                    }
                    enviarRespuesta(['success' => true, 'user' => $usuario]);
                } else {
                    enviarRespuesta(['success' => false, 'message' => 'ID de usuario no encontrado en el token']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;

        case 'register-user':
            $data = json_decode(file_get_contents("php://input"), true);

            if (isset($data['name'], $data['cuit'], $data['email'], $data['tel'], $data['password'])) {
                $name = $data['name'];
                $cuit = $data['cuit'];
                $email = $data['email'];
                $tel = $data['tel'];
                $password = password_hash($data['password'], PASSWORD_BCRYPT);
                $approved = false;

                try {
                    $sql = $con->prepare("INSERT INTO users (name, cuit, email, password, approved) VALUES (?,?, ?, ?, ?)");
                    $sql->execute([$name, $cuit, $email, $password, $approved]);

                    if ($sql->rowCount() > 0) {
                        enviarRespuesta(['success' => true, 'message' => 'Usuario registrado exitosamente']);
                    } else {
                        enviarRespuesta(['success' => false, 'message' => 'No se pudo registrar el usuario']);
                    }
                } catch (PDOException $e) {
                    if ($e->getCode() == 23000) {
                        enviarRespuesta(['success' => false, 'message' => 'Este usuario ya está registrado']);
                    } else {
                        enviarRespuesta(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                    }
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Datos incompletos']);
            }
            break;

        case 'login':
            $data = json_decode(file_get_contents("php://input"), true);

            $email = $data['email'];
            $password = $data['password'];

            $sql = $con->prepare("SELECT id, password, approved, role FROM users WHERE email = ?");
            $sql->execute([$email]);

            if ($sql->rowCount() > 0) {
                $user = $sql->fetch(PDO::FETCH_ASSOC);
                $userId = $user['id'];
                $hashedPassword = $user['password'];
                $isApproved = $user['approved'];
                $role = $user['role'];

                if ($isApproved) {
                    if (password_verify($password, $hashedPassword)) {
                        $token = generarToken($userId);
                        enviarRespuesta([
                            'success' => true,
                            'message' => 'Inicio de sesión exitoso',
                            'token' => $token,
                            'role' => $role
                        ]);
                    } else {
                        enviarRespuesta(['success' => false, 'message' => 'Contraseña incorrecta']);
                    }
                } else {
                    enviarRespuesta(['success' => false, 'message' => 'El usuario no está aprobado']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'El usuario no existe']);
            }
            break;

        case 'recover':
            $data = json_decode(file_get_contents("php://input"), true);
            $email = $data['email'];

            $sql = $con->prepare("SELECT id FROM users WHERE email = ?");
            $sql->execute([$email]);

            if ($sql->rowCount() > 0) {
                $user = $sql->fetch(PDO::FETCH_ASSOC);

                // Generar token y guardarlo en la base de datos
                $token = password_hash(bin2hex(random_bytes(32)), PASSWORD_DEFAULT);
                $expiration = date("Y-m-d H:i:s", strtotime("+1 hour")); // 1 hora de validez

                $insertToken = $con->prepare("INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)");
                $insertToken->execute([$user['id'], $token, $expiration]);

                // Enviar correo con el enlace
                $url = "http://localhost:5173/restablecer-contraseña?token=$token";
                $mensaje = "
                        <h1>Recuperar Contraseña</h1>
                        <p>Haz clic en el enlace para restablecer tu contraseña:</p>
                        <a href='$url'>Restablecer Contraseña</a>
                    ";
                if (enviarCorreo($email, "Recuperar Contraseña", $mensaje)) {
                    enviarRespuesta(['success' => true, 'message' => 'Correo de recuperación enviado.']);
                } else {
                    enviarRespuesta(['success' => false, 'message' => 'No se pudo enviar el correo. Inténtalo más tarde.']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'El usuario no existe.']);
            }
            break;

        case 'reset-password':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents("php://input"), true);
                $token = $data['token'];
                $newPassword = $data['newPassword'];

                // Verificar token en la base de datos
                $sql = $con->prepare("SELECT user_id FROM password_resets WHERE token = ? AND expires_at > NOW()");
                $sql->execute([$token]);

                if ($sql->rowCount() > 0) {
                    $user = $sql->fetch(PDO::FETCH_ASSOC);

                    $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT);
                    $updatePassword = $con->prepare("UPDATE users SET password = ? WHERE id = ?");
                    $updatePassword->execute([$hashedPassword, $user['user_id']]);

                    // Eliminar el token usado
                    $deleteToken = $con->prepare("DELETE FROM password_resets WHERE token = ?");
                    $deleteToken->execute([$token]);

                    enviarRespuesta(['success' => true, 'message' => 'Contraseña restablecida correctamente.']);
                } else {
                    enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado.']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;

        case 'update-personal-user':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents('php://input'), true);

                if (isset($data['data']['name'], $data['data']['cuit'], $data['data']['tel'], $data['id'])) {
                    $name = $data['data']['name'];
                    $cuit = $data['data']['cuit'];
                    $tel = $data['data']['tel'];
                    $id = $data['id'];

                    try {
                        $sql = $con->prepare("UPDATE users SET name = :name, cuit = :cuit, tel = :tel WHERE id = :id");
                        $sql->execute([
                            ':name' => $name,
                            ':cuit' => $cuit,
                            ':tel' => $tel,
                            ':id' => $id,
                        ]);

                        if ($sql->rowCount() > 0) {
                            enviarRespuesta(['success' => true, 'message' => 'Información actualizada']);
                        } else {
                            enviarRespuesta(['success' => false, 'message' => 'No se pudo actualizar la información']);
                        }
                    } catch (PDOException $e) {
                        error_log('Database error: ' . $e->getMessage());
                        enviarRespuesta(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                    }
                } else {
                    enviarRespuesta(['status' => 'error', 'message' => 'Datos incompletos']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;

        case 'update-account-user':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents('php://input'), true);

                if (isset($data['data']['password'], $data['id'])) {
                    $password = password_hash($data['data']['password'], PASSWORD_BCRYPT);
                    $id = $data['id'];

                    try {
                        $sql = $con->prepare("UPDATE users SET password = :password WHERE id = :id");
                        $sql->execute([
                            ':password' => $password,
                            ':id' => $id,
                        ]);

                        if ($sql->rowCount() > 0) {
                            enviarRespuesta(['success' => true, 'message' => 'Información actualizada']);
                        } else {
                            enviarRespuesta(['success' => false, 'message' => 'No se pudo actualizar la información']);
                        }
                    } catch (PDOException $e) {

                        enviarRespuesta(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                    }
                } else {
                    enviarRespuesta(['status' => 'error', 'message' => 'Datos incompletos']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;

        case 'update-address-user':
        case 'add-address-user':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents('php://input'), true);

                if (isset(
                    $data['data']['street'],
                    $data['data']['city'],
                    $data['data']['province'],
                    $data['data']['name_address'],
                    $data['data']['last_name'],
                    $data['data']['cp'],
                    $data['data']['tel_address'],
                )) {
                    $userId = $data['id'];
                    $addressData = $data['data'];

                    try {
                        if ($action == 'add-address-user') {

                            if ($addressData['default_address']) {
                                $unsetDefaultSql = $con->prepare("UPDATE addresses SET default_address = 0 WHERE id_user = :id_user");
                                $unsetDefaultSql->execute([':id_user' => $userId]);
                            }

                            $sql = $con->prepare("INSERT INTO addresses (id_user, street, street2, city, province, company_name, name_address, last_name, cp, tel_address, default_address)
                                                        VALUES (:id_user, :street, :street2, :city, :province, :company_name, :name_address, :last_name, :cp, :tel_address, :default_address)");
                            $sql->execute([
                                ':id_user' => $userId,
                                ':street' => $addressData['street'],
                                ':street2' => $addressData['street2'],
                                ':city' => $addressData['city'],
                                ':province' => $addressData['province'],
                                ':company_name' => $addressData['company_name'],
                                ':name_address' => $addressData['name_address'],
                                ':last_name' => $addressData['last_name'],
                                ':cp' => $addressData['cp'],
                                ':tel_address' => $addressData['tel_address'],
                                ':default_address' => $addressData['default_address']
                            ]);

                            if ($sql->rowCount() > 0) {
                                enviarRespuesta(['success' => true, 'message' => 'Dirección agregada']);
                            } else {
                                enviarRespuesta(['success' => false, 'message' => 'No se pudo agregar la dirección']);
                            }
                        } elseif ($action == 'update-address-user') {

                            if ($addressData['default_address']) {
                                $unsetDefaultSql = $con->prepare("UPDATE addresses SET default_address = 0 WHERE id_user = :id_user");
                                $unsetDefaultSql->execute([':id_user' => $userId]);
                            }

                            $addressId = $addressData['id_address'];
                            $sql = $con->prepare("UPDATE addresses SET
                                                        street = :street,
                                                        street2 = :street2,
                                                        city = :city,
                                                        province = :province,
                                                        name_address = :name_address,
                                                        last_name = :last_name,
                                                        company_name = :company_name,
                                                        cp = :cp,
                                                        tel_address = :tel_address,
                                                        default_address = :default_address
                                                        WHERE id_address = :id_address AND id_user = :id_user");
                            $sql->execute([
                                ':street' => $addressData['street'],
                                ':street2' => $addressData['street2'],
                                ':city' => $addressData['city'],
                                ':province' => $addressData['province'],
                                ':name_address' => $addressData['name_address'],
                                ':last_name' => $addressData['last_name'],
                                ':company_name' => $addressData['company_name'],
                                ':cp' => $addressData['cp'],
                                ':tel_address' => $addressData['tel_address'],
                                ':default_address' => $addressData['default_address'],
                                ':id_address' => $addressId,
                                ':id_user' => $userId
                            ]);

                            if ($sql->rowCount() > 0) {
                                enviarRespuesta(['success' => true, 'message' => 'Dirección actualizada']);
                            } else {
                                enviarRespuesta(['success' => false, 'message' => 'No se pudo actualizar la dirección']);
                            }
                        }
                    } catch (PDOException $e) {
                        enviarRespuesta(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                    }
                } else {
                    enviarRespuesta(['status' => 'error', 'message' => 'Datos incompletos']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;
        case 'delete-address-user':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents('php://input'), true);

                if (isset($data['data'])) {
                    $id_address = $data['data'];

                    try {
                        $sqlCheckDefault = $con->prepare("SELECT default_address, id_user FROM addresses WHERE id_address = :id_address");
                        $sqlCheckDefault->execute([':id_address' => $id_address]);
                        $addressInfo = $sqlCheckDefault->fetch(PDO::FETCH_ASSOC);

                        if ($addressInfo) {
                            $isDefault = $addressInfo['default_address'];
                            $userId = $addressInfo['id_user'];

                            $sql = $con->prepare("DELETE FROM addresses WHERE id_address = :id_address");
                            $sql->execute([':id_address' => $id_address]);

                            if ($sql->rowCount() > 0) {
                                if ($isDefault) {
                                    $sqlSetNewDefault = $con->prepare("UPDATE addresses
                                                                    SET default_address = 1
                                                                    WHERE id_user = :id_user
                                                                    LIMIT 1");
                                    $sqlSetNewDefault->execute([':id_user' => $userId]);
                                }

                                enviarRespuesta(['success' => true, 'message' => 'Dirección eliminada']);
                            } else {
                                enviarRespuesta(['success' => false, 'message' => 'No se pudo eliminar la dirección']);
                            }
                        } else {
                            enviarRespuesta(['success' => false, 'message' => 'Dirección no encontrada']);
                        }
                    } catch (PDOException $e) {
                        enviarRespuesta(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                    }
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;
        case 'save-order':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents("php://input"), true);

                if (isset(
                    $data['data']['user']['id'],
                    $data['data']['products'],
                    $data['data']['total_price'],
                    $data['data']['address']['id_address'],
                    $data['data']['shipping']['id'],
                    $data['data']['state'],
                    $data['data']['date']
                )) {

                    $id_user = $data['data']['user']['id'];
                    $products = $data['data']['products'];
                    $total_price = $data['data']['total_price'];
                    $shipping_address = $data['data']['address']['id_address'];
                    $shipping_type = $data['data']['shipping']['id'];
                    $state = $data['data']['state'];
                    $date = date('Y-m-d H:i:s', strtotime($data['data']['date']));

                    try {
                        $sql = $con->prepare("INSERT INTO orders (id_user, total_price, shipping_address, shipping_type, state, date)
                                                VALUES (?, ?, ?, ?, ?, ?)");
                        $sql->execute([$id_user, $total_price, $shipping_address, $shipping_type, $state, $date]);

                        $order_id = $con->lastInsertId();

                        $product_sql = $con->prepare("INSERT INTO order_products (order_id, product_id, quantity) VALUES (?, ?, ?)");
                        foreach ($products as $product) {
                            $product_id = $product['product']['id'];
                            $quantity = $product['quantity'];
                            $product_sql->execute([$order_id, $product_id, $quantity]);
                        }

                        enviarRespuesta(['success' => true, 'message' => 'Orden registrada exitosamente']);
                    } catch (PDOException $e) {
                        enviarRespuesta(['success' => false, 'message' => 'Error al registrar la orden: ' . $e->getMessage()]);
                    }
                } else {
                    enviarRespuesta(['success' => false, 'message' => 'Datos incompletos']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;
        case 'register-product':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents("php://input"), true);

                if (isset(
                    $data['id'],
                    $data['name'],
                    $data['price'],
                    $data['category'],
                    $data['description']
                )) {
                    $id = $data['id'];
                    $name = $data['name'];
                    $price = $data['price'];
                    $category = $data['category'];
                    $description = $data['description'];

                    $result = registerProduct($con, $data);
                    enviarRespuesta($result);
                } else {
                    enviarRespuesta(['success' => false, 'message' => 'Datos incompletos']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;
        case 'update-product':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);


            if ($decoded) {
                $data = json_decode(file_get_contents("php://input"), true);

                if (isset(
                    $data['productId'],
                    $data['data']['id'],
                    $data['data']['name'],
                    $data['data']['category'],
                    $data['data']['description'],
                    $data['data']['price']
                )) {
                    $id = $data['productId'];
                    $new_id = $data['data']['id'];
                    $new_name = $data['data']['name'];
                    $new_category = $data['data']['category'];
                    $new_description = $data['data']['description'];
                    $new_price = $data['data']['price'];

                    $stmt = $con->prepare("SELECT COUNT(*) FROM products WHERE id = :id");
                    $stmt->execute([':id' => $id]);
                    if ($stmt->fetchColumn() == 0) {
                        enviarRespuesta(['success' => false, 'message' => 'El producto no existe']);
                        exit;
                    }

                    try {
                        $sql = $con->prepare("UPDATE products SET id=:new_id, name=:new_name, category=:new_category, description=:new_description, price=:new_price WHERE id = :id");
                        $sql->execute([
                            ':new_id' => $new_id,
                            ':new_name' => $new_name,
                            ':new_category' => $new_category,
                            ':new_description' => $new_description,
                            ':new_price' => $new_price,
                            ':id' => $id
                        ]);

                        if ($sql->rowCount() > 0) {
                            enviarRespuesta(['success' => true, 'message' => 'Información actualizada']);
                        } else {
                            enviarRespuesta(['success' => false, 'message' => 'No se pudo actualizar la información']);
                        }
                    } catch (PDOException $e) {

                        enviarRespuesta(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                    }
                } else {
                    enviarRespuesta(['success' => false, 'message' => 'Datos incompletos']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;

        case 'delete-product':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents("php://input"), true);

                if (isset($data['productId'])) {
                    $id = $data['productId'];

                    $sql = $con->prepare("DELETE FROM products WHERE id = :id");
                    $sql->execute([':id' => $id]);

                    if ($sql->rowCount() > 0) {
                        enviarRespuesta(['success' => true, 'message' => 'Producto eliminado exitosamente']);
                    } else {
                        enviarRespuesta(['success' => false, 'message' => 'No se pudo eliminar el producto']);
                    }
                } else {
                    enviarRespuesta(['success' => false, 'message' => 'Datos incompletos']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;

        case 'upload-images-products':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                if (isset($_POST['productId'])) {
                    $productId = $_POST['productId'];
                    $updatedImages = [];
                    $deletedImages = $_POST['deletedImages'] ?? [];

                    if (!empty($_POST['deletedImages'])) {
                        foreach ($_POST['deletedImages'] as $imageId) {
                            $deleteQuery = "DELETE FROM products_images WHERE id_img = ?";
                            $sql = $con->prepare($deleteQuery);
                            $sql->execute([$imageId]);
                        }
                    }

                    foreach ($_POST as $key => $value) {
                        if (strpos($key, 'existingImageId') === 0) {
                            $imageId = $value;
                            $priorityKey = str_replace('existingImageId', 'priority', $key);
                            $priority = $_POST[$priorityKey] ?? null;

                            if ($priority !== null) {
                                $sql = $con->prepare("UPDATE products_images SET priority = ? WHERE id_img = ? AND product_id = ?");
                                $sql->execute([$priority, $imageId, $productId]);
                                $updatedImages[] = $imageId;
                            }
                        }
                    }

                    // Procesar nuevas imágenes
                    foreach ($_FILES as $key => $file) {
                        if (strpos($key, 'image') === 0) {
                            $priorityKey = str_replace('image', 'priority', $key);
                            $priority = $_POST[$priorityKey] ?? null;

                            if ($priority !== null && $file['error'] === UPLOAD_ERR_OK) {
                                $filePath = '/uploads/' . basename($file['name']);
                                if (move_uploaded_file($file['tmp_name'], __DIR__ . $filePath)) {
                                    // Insertar la nueva imagen en la base de datos
                                    $sql = $con->prepare("INSERT INTO products_images (product_id, img_url, priority) VALUES (?, ?, ?)");
                                    $sql->execute([$productId, $filePath, $priority]);
                                    $updatedImages[] = $con->lastInsertId();
                                }
                            }
                        }
                    }

                    echo json_encode(['success' => true, 'updatedImages' => $updatedImages]);
                } else {
                    echo json_encode(['success' => false, 'message' => 'Faltan datos necesarios.']);
                }
            } else {
                echo json_encode(['success' => false, 'message' => 'Token inválido.']);
            }
            break;

        case 'register-prod-and-img':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                if (isset(
                    $_POST['id'],
                    $_POST['name'],
                    $_POST['price'],
                    $_POST['category'],
                    $_POST['description'],
                )) {
                    $data = [
                        'id' => $_POST['id'],
                        'name' => $_POST['name'],
                        'price' => $_POST['price'],
                        'category' => $_POST['category'],
                        'description' => $_POST['description'],
                    ];

                    $productId = $_POST['id'];

                    // Iniciar una transacción
                    $con->beginTransaction();

                    $result = registerProduct($con, $data);
                    if (!$result['success']) {
                        $con->rollBack();
                        enviarRespuesta($result);
                        break;
                    }

                    // Procesar todas las imágenes enviadas
                    $imageUploadSuccess = true;
                    foreach ($_FILES as $key => $file) {
                        if (strpos($key, 'image') === 0) {
                            $index = str_replace('image', '', $key);
                            $priorityKey = 'priority' . $index;

                            if (!isset($_POST[$priorityKey])) {
                                $imageUploadSuccess = false;
                                break;
                            }

                            $priority = $_POST[$priorityKey];
                            $result = uploadImagesProducts($con, $file, $priority, $productId);

                            if (!$result['success']) {
                                $imageUploadSuccess = false;
                                break;
                            }
                        }
                    }

                    if (!$imageUploadSuccess) {
                        $con->rollBack();
                        enviarRespuesta(['success' => false, 'message' => 'Error al subir imágenes']);
                        break;
                    }

                    // Confirmar la transacción
                    $con->commit();
                    enviarRespuesta(['success' => true, 'message' => 'Producto e imagen registrados correctamente']);
                } else {
                    enviarRespuesta(['success' => false, 'message' => 'Datos incompletos']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;

        default:
            enviarRespuesta(['error' => 'acción no válida']);
            break;
    }
} else {
    enviarRespuesta(['error' => 'acción no válida']);
}
