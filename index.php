<?php
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);
// error_reporting(E_ALL & ~E_WARNING & ~E_NOTICE); // Oculta advertencias y avisos
// ini_set('display_errors', 0); // No muestra errores en la salida

require_once 'database.php';
require_once 'config.php';
require_once 'vendor/autoload.php';
require_once 'functions.php';

$db = new DataBase();
$con = $db->conectar();

$dominiosPermitidos = ["http://192.168.0.237:5173", "https://192.168.0.237:5173", "http://localhost:5173", "https://luz-interior.free.nf/"];

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

if (!function_exists('getallheaders')) {
    function getallheaders()
    {
        $headers = [];
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $headerName = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))));
                $headers[$headerName] = $value;
            }
        }
        return $headers;
    }
}

if (isset($_GET['action'])) {
    $action = $_GET['action'];
    switch ($action) {
        case 'verify-token':
            try {
                // Obtener los datos enviados en el cuerpo de la solicitud
                $data = json_decode(file_get_contents('php://input'), true);

                if (!isset($data['token']) || empty($data['token'])) {
                    throw new Exception("Token ausente");
                }

                $jwt = $data['token']; // Obtener el token del cuerpo de la solicitud

                $decoded = (array) verifyToken($jwt);

                if ($decoded && !isset($decoded['success'])) {
                    sendReply(['success' => true, 'message' => 'Token válido', 'data' => $decoded]);
                } else {
                    throw new Exception("Token inválido o expirado");
                }
            } catch (Exception $e) {
                sendReply(['success' => false, 'message' => $e->getMessage()]);
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
            $result = $sql->fetchAll(PDO::FETCH_ASSOC);

            // Agrupar las imágenes por producto
            $productos = [];
            foreach ($result as $row) {
                $id_producto = $row['id'];
                if (!isset($productos[$id_producto])) {
                    // Agregar los datos del producto
                    $productos[$id_producto] = [
                        'id' => $row['id'],
                        'name' => $row['name'],
                        'category' => $row['category'],
                        'price' => $row['price'],
                        'description' => $row['description'],
                        'novelty' => $row['novelty'],
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

            sendReply($productos);
            break;

        case 'users':
            $sql = $con->prepare("
                SELECT users.*, addresses.*
                FROM users
                LEFT JOIN addresses ON users.id = addresses.id_user
            ");
            $sql->execute();
            $result = $sql->fetchAll(PDO::FETCH_ASSOC);

            $usuarios = [];
            foreach ($result as $row) {

                if (!isset($usuarios[$row['id']])) {
                    $usuarios[$row['id']] = [
                        'id' => $row['id'],
                        'name' => $row['name'],
                        'email' => $row['email'],
                        'cuit' => $row['cuit'],
                        'approved' => $row['approved'],
                        'role' => $row['role'],
                        'register_date' => $row['register_date'],
                        'new' => $row['new'],
                        'addresses' => []
                    ];
                }

                if ($row['id_address']) {
                    $usuarios[$row['id']]['addresses'][] = [
                        'id_address' => $row['id_address'],
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

            $usuariosArray = array_values($usuarios);

            sendReply($usuariosArray);
            break;
        case 'orders':
            $sql = $con->prepare("
                SELECT orders.*, order_products.*
                FROM orders
                LEFT JOIN order_products ON orders.id_order = order_products.order_id
            ");
            $sql->execute();
            $result = $sql->fetchAll(PDO::FETCH_ASSOC);

            $ordenes = [];
            foreach ($result as $row) {

                if (!isset($ordenes[$row['id_order']])) {
                    $ordenes[$row['id_order']] = [
                        'id_order' => $row['id_order'],
                        'id_user' => $row['id_user'],
                        'date' => $row['date'],
                        'total_price' => $row['total_price'],
                        'shipping_address' => $row['shipping_address'],
                        'shipping_type' => $row['shipping_type'],
                        'state' => $row['state'],
                        'new' => $row['new'],
                        'products' => []
                    ];
                }

                if ($row['order_id']) {
                    $ordenes[$row['order_id']]['products'][] = [
                        'id' => $row['id'],
                        'product_id' => $row['product_id'],
                        'quantity' => $row['quantity']
                    ];
                }
            }

            sendReply(array_values($ordenes));
            break;
        case 'company-info':
            $sql = $con->prepare("SELECT * FROM company_info");
            $sql->execute();
            $result = $sql->fetchAll(PDO::FETCH_ASSOC);
            sendReply($result);
            echo $result;
            break;
        case 'social':
            $sql = $con->prepare("SELECT * FROM social_networks");
            $sql->execute();
            $result = $sql->fetchAll(PDO::FETCH_ASSOC);
            sendReply($result);
            echo $result;
            break;
        case 'shipping':
            $sql = $con->prepare("SELECT * FROM shipping");
            $sql->execute();
            $result = $sql->fetchAll(PDO::FETCH_ASSOC);
            sendReply($result);
            echo $result;
            break;
        case 'gallery':
            $sql = $con->prepare("SELECT * FROM gallery_images");
            $sql->execute();
            $result = $sql->fetchAll(PDO::FETCH_ASSOC);
            sendReply($result);
            echo $result;
            break;
        case 'banner-desktop':
            $sql = $con->prepare("SELECT * FROM banner_images_desktop");
            $sql->execute();
            $result = $sql->fetchAll(PDO::FETCH_ASSOC);
            sendReply($result);
            echo $result;
            break;
        case 'banner-mobile':
            $sql = $con->prepare("SELECT * FROM banner_images_mobile");
            $sql->execute();
            $result = $sql->fetchAll(PDO::FETCH_ASSOC);
            sendReply($result);
            echo $result;
            break;
        case 'list-price':
            $sql = $con->prepare("SELECT * FROM list_price");
            $sql->execute();
            $result = $sql->fetchAll(PDO::FETCH_ASSOC);
            sendReply($result);
            echo $result;
            break;
        case 'frequently-asked-questions':
            $sql = $con->prepare("SELECT * FROM frequently_asked_questions");
            $sql->execute();
            $result = $sql->fetchAll(PDO::FETCH_ASSOC);
            sendReply($result);
            echo $result;
            break;
        case 'get-list-price':
            $uploadDirectory = 'uploads/list_price/'; // Carpeta de subida
            $files = glob($uploadDirectory . '*'); // Obtener todos los archivos en la carpeta

            if (!empty($files)) {
                $fileName = basename($files[0]); // Tomar el primer archivo
                $fileUrl = $uploadDirectory . $fileName; // Crear la URL relativa del archivo

                echo json_encode([
                    'success' => true,
                    'fileUrl' => $fileUrl // Ruta completa para acceder al archivo
                ]);
            } else {
                echo json_encode([
                    'success' => false,
                    'message' => 'No hay archivos disponibles.'
                ]);
            }
            break;
        case 'user-data':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null; // Verifica si el token existe

            if ($jwt) {
                $decoded = verifyToken($jwt);

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
                        $result = $sql->fetchAll(PDO::FETCH_ASSOC);

                        $usuario = null;
                        if (!empty($result)) {
                            $usuario = [
                                'id' => $result[0]['id'],
                                'name' => $result[0]['name'],
                                'email' => $result[0]['email'],
                                'password' => $result[0]['password'],
                                'cuit' => $result[0]['cuit'],
                                'tel' => $result[0]['tel'],
                                'addresses' => [],
                                'role' => $result[0]['role']
                            ];
                            foreach ($result as $row) {
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
                        sendReply(['success' => true, 'user' => $usuario]);
                    } else {
                        sendReply(['success' => false, 'message' => 'ID de usuario no encontrado en el token']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido o expirado']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;

        case 'register-user': // Acciones de usuario
            $data = json_decode(file_get_contents("php://input"), true);

            if (isset($data['data']['name'], $data['data']['cuit'], $data['data']['email'], $data['data']['tel'], $data['data']['password'])) {
                $name = $data['data']['name'];
                $cuit = $data['data']['cuit'];
                $email = $data['data']['email'];
                $tel = $data['data']['tel'];
                $password = $data['data']['password'];

                if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                    sendReply(['success' => false, 'message' => 'El email no tiene un formato válido']);
                    break;
                }

                $passwordHashed = password_hash($password, PASSWORD_BCRYPT);
                $approved = false;
                $register_date = date('Y-m-d H:i:s');

                try {
                    $sql = $con->prepare("INSERT INTO users (name, cuit, email, password, approved, register_date) VALUES (?, ?, ?, ?, ?, ?)");
                    $sql->execute([$name, $cuit, $email, $passwordHashed, $approved, $register_date]);

                    if ($sql->rowCount() > 0) {

                        $companyInfo = getDataCompany();

                        //email cliente
                        $title = 'Correo de registro.';
                        $contentClient = "
                            <p>Hola $name,</p>
                            <h1>Gracias por registrarte en Luz Interior.</h1>
                            <p>Tu cuenta ha sido creada exitosamente, pero antes de que puedas iniciar sesión, es necesario que validemos y aprobemos tus datos.</p>
                            <p><strong>Recibirás un correo de confirmación una vez que tu cuenta haya sido aprobada.</strong></p>
                            <p>Gracias por tu paciencia y por elegirnos.</p>
                            <p>Saludos,<br>El equipo de Luz Interior.</p>
                        ";
                        $altBodyClient = 'Gracias por registrarte en Luz Interior. Recibirás un correo de confirmación una vez que tu cuenta haya sido aprobada.';
                        $emailTemplateClient = generateEmailTemplate($title, $contentClient);
                        $sendMailClient = sendMail($email, "Registro Luz Interior", $emailTemplateClient, $altBodyClient);

                        //email empresa
                        $contentCompany = "
                            <h1>Nuevo usuario registrado.</h1>
                            <p>El usuario <strong>$name</strong> se ha registrado y espera aprobación de cuenta.</p>
                            <p><u><a href='" . $companyInfo['data']['web'] . "mayoristas'>Inicia sesión para tomar acción sobre la cuenta del usuario desde el panel de administrador.</a></u></p>
                            <p>$name te está esperando.</p>
                            <p>Saludos,<br>El equipo de Luz Interior.</p>
                        ";
                        $altBodyCompany = 'Nuevo usuario registrado. Tome acción sobre la cuenta del nuevo usuario en el panel de administador.';
                        $emailTemplateCompany = generateEmailTemplate($title, $contentCompany);
                        $sendMailCompany = sendMail($companyInfo['data']['email'], "Nuevo registro Luz Interior", $emailTemplateCompany, $altBodyCompany);

                        if ($sendMailClient) {
                            sendReply(['success' => true, 'message' => 'Usuario registrado y correo enviado exitosamente.']);
                        } else {
                            sendReply(['success' => false, 'message' => 'Usuario registrado, pero no se pudo enviar el correo.']);
                        }
                    } else {
                        sendReply(['success' => false, 'message' => 'No se pudo registrar el usuario']);
                    }
                } catch (PDOException $e) {
                    if ($e->getCode() == 23000) {
                        sendReply(['success' => false, 'message' => 'Este usuario ya está registrado']);
                    } else {
                        sendReply(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                    }
                }
            } else {
                sendReply(['success' => false, 'message' => 'Datos incompletos']);
            }
            break;

        case 'login':
            $data = json_decode(file_get_contents("php://input"), true);

            $email = $data['email'];
            $password = $data['password'];

            if (empty($email) || empty($password)) {
                sendReply(['success' => false, 'message' => 'Email y contraseña son requeridos']);
                exit;
            }

            $sql = $con->prepare("SELECT id, password, approved, role FROM users WHERE email = ?");
            $sql->execute([$email]);

            if (!$sql) {
                sendReply(['success' => false, 'message' => 'Error al consultar la base de datos']);
                exit;
            }

            if ($sql->rowCount() > 0) {
                $user = $sql->fetch(PDO::FETCH_ASSOC);
                $userId = $user['id'];
                $hashedPassword = $user['password'];
                $isApproved = $user['approved'];
                $role = $user['role'];

                if ($isApproved) {
                    if (password_verify($password, $hashedPassword)) {
                        $token = generateToken($userId);
                        sendReply([
                            'success' => true,
                            'message' => 'Inicio de sesión exitoso',
                            'token' => $token,
                            'role' => $role
                        ]);
                    } else {
                        sendReply(['success' => false, 'message' => 'Contraseña incorrecta']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'El usuario no está aprobado']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'El usuario no existe']);
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
                $title = 'Correo recuperación de contraseña.';
                $url = "http://localhost:5173/restablecer_contrasenia?token=$token";

                $contentClient = "
                    <h1>Recuperación de contraseña.</h1>
                    <p>Hemos recibido una solicitud para restablecer tu contraseña.</p>
                    <p>Si no realizaste esta solicitud, ignora este correo. De lo contrario, puedes restablecer tu contraseña haciendo clic en el siguiente enlace:</p>
                    <u><a href='$url'>Restablecer Contraseña</a></u>
                    <p>Si tienes preguntas o necesitas ayuda, no dudes en contactarnos.</p>
                    <p>Saludos,<br>El equipo de Luz Interior.</p>
                ";
                $altBodyClient = 'Recuperación de contraseña. Ingrese al enlace enviado para restablecer la contraseña.';
                $emailTemplateClient = generateEmailTemplate($title, $contentClient);
                $sendMailClient = sendMail($email, "Recuperación de contraseña", $emailTemplateClient, $altBodyClient);

                if ($sendMailClient) {
                    sendReply(['success' => true, 'message' => 'Correo de recuperación enviado.']);
                } else {
                    sendReply(['success' => false, 'message' => 'No se pudo enviar el correo. Inténtalo más tarde.']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'El usuario no existe.']);
            }
            break;

        case 'reset-password':
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

                sendReply(['success' => true, 'message' => 'Contraseña restablecida correctamente.']);
            } else {
                sendReply(['success' => false, 'message' => 'Token inválido o expirado.']);
            }
            break;

        case 'update-personal-user':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

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
                                sendReply(['success' => true, 'message' => 'Información actualizada']);
                            } else {
                                sendReply(['success' => false, 'message' => 'No se pudo actualizar la información']);
                            }
                        } catch (PDOException $e) {
                            error_log('Database error: ' . $e->getMessage());
                            sendReply(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                        }
                    } else {
                        sendReply(['status' => 'error', 'message' => 'Datos incompletos']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido o expirado']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;

        case 'update-account-user':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

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
                                sendReply(['success' => true, 'message' => 'Información actualizada']);
                            } else {
                                sendReply(['success' => false, 'message' => 'No se pudo actualizar la información']);
                            }
                        } catch (PDOException $e) {

                            sendReply(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                        }
                    } else {
                        sendReply(['status' => 'error', 'message' => 'Datos incompletos']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido o expirado']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;

        case 'update-address-user':
        case 'add-address-user':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

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
                                    sendReply(['success' => true, 'message' => 'Dirección agregada']);
                                } else {
                                    sendReply(['success' => false, 'message' => 'No se pudo agregar la dirección']);
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
                                    sendReply(['success' => true, 'message' => 'Dirección actualizada']);
                                } else {
                                    sendReply(['success' => false, 'message' => 'No se pudo actualizar la dirección']);
                                }
                            }
                        } catch (PDOException $e) {
                            sendReply(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                        }
                    } else {
                        sendReply(['status' => 'error', 'message' => 'Datos incompletos']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido o expirado']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;
        case 'delete-address-user':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    if (isset($data['id'])) {

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

                                    sendReply(['success' => true, 'message' => 'Dirección eliminada']);
                                } else {
                                    sendReply(['success' => false, 'message' => 'No se pudo eliminar la dirección']);
                                }
                            } else {
                                sendReply(['success' => false, 'message' => 'Dirección no encontrada']);
                            }
                        } catch (PDOException $e) {
                            sendReply(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                        }
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido o expirado']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;
        case 'save-order':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    $data = json_decode(file_get_contents("php://input"), true);

                    if (isset(
                        $data['data']['user']['id'],
                        $data['data']['products'],
                        $data['data']['total_price'],
                        $data['data']['address']['id_address'],
                        $data['data']['shipping']['id_shipping'],
                        $data['data']['state'],
                        $data['data']['date']
                    )) {
                        $id_user = $data['data']['user']['id'];
                        $products = $data['data']['products'];
                        $total_price = $data['data']['total_price'];
                        $shipping_address = $data['data']['address']['id_address'];
                        $shipping_type = $data['data']['shipping']['id_shipping'];
                        $state = $data['data']['state'];
                        $date = date('Y-m-d H:i:s', strtotime($data['data']['date']));

                        try {
                            $sql = $con->prepare("INSERT INTO orders (id_user, total_price, shipping_address, shipping_type, state, date)
                                                VALUES (?, ?, ?, ?, ?, ?)");
                            $sql->execute([$id_user, $total_price, $shipping_address, $shipping_type, $state, $date]);

                            $order_id = $con->lastInsertId();

                            $product_sql = $con->prepare("INSERT INTO order_products (order_id, product_id, quantity) VALUES (?, ?, ?)");

                            $companyInfo = getDataCompany();

                            $user_sql = "SELECT name, email FROM users WHERE id = :id";
                            $user_params = [':id' => $id_user];
                            $result_user = getData($con, $user_sql, $user_params);

                            $address_sql = "SELECT street, street2, city, province, cp FROM addresses WHERE id_address = :id";
                            $address_params = [':id' => $shipping_address];
                            $result_user_address = getData($con, $address_sql, $address_params);

                            $shipping_sql = "SELECT description FROM shipping WHERE id_shipping = :id";
                            $shipping_params = [':id' => $shipping_type];
                            $result_shipping = getData($con, $shipping_sql, $shipping_params);

                            $name = $result_user['name'];
                            $email = $result_user['email'];
                            $street = $result_user_address['street'];
                            $street2 = $result_user_address['street2'];
                            $city = $result_user_address['city'];
                            $province = $result_user_address['province'];
                            $cp = $result_user_address['cp'];
                            $shipping =  $result_shipping['description'];

                            foreach ($products as $product) {
                                $product_id = $product['product']['id'];
                                $quantity = $product['quantity'];
                                $product_sql->execute([$order_id, $product_id, $quantity]);
                            }

                            // Enviar correo cliente
                            $title = 'Correo recepción de nuevo pedido.';
                            $contentClient = "
                            <p>Hola $name</p>
                            <h1>Tu orden de pedido fue ingresada con éxito.</h1>
                            <h2>Orden n° $order_id</h2>
                            <p>Hemos recibido tu orden y está siendo procesada.</p>
                            <p>Nos comunicaremos a la brevedad para finalizar el proceso.</p>
                            <h4>Detalles del pedido</h4>
                            <ul>
                                <li><strong>Total:</strong>$ $total_price</li>
                                <li><strong>Dirección de envío:</strong> $street, $street2, $city, $province, cp: $cp</li>
                                <li><strong>Tipo de envío:</strong> $shipping</li>
                                <li><strong>Fecha del pedido:</strong> $date</li>
                            </ul>

                            <h4>Productos:</h4>
                            <ul>";

                            foreach ($products as $product) {
                                $product_name = $product['product']['id'];
                                $quantity = $product['quantity'];
                                $contentClient .= "<li>$product_name - Cantidad: $quantity</li>";
                            }

                            $contentClient .= "</ul>
        
                                <p>Si tienes preguntas o necesitas ayuda, no dudes en contactarnos.</p>
                                <p>Saludos,<br>El equipo de Luz Interior.</p>
                            ";
                            $altBodyClient = 'Tu orden de pedido fue ingresada con éxito.';
                            $emailTemplateClient = generateEmailTemplate($title, $contentClient);
                            $sendMailClient = sendMail($email, "Recibimos tu orden de pedido.", $emailTemplateClient, $altBodyClient);

                            //email empresa
                            $contentCompany = "
                            <h1>Nueva orden de pedido.</h1>
                            <h2>Orden n° $order_id</h2>
                            <p><strong>$name</strong> acaba de realizar una nueva orden de pedido.</p>
                            <p><u><a href='" . $companyInfo['data']['web'] . "mayoristas'>Inicia sesión para ver la orden completa desde el panel de administrador.</a></u></p>
                            <h4>Detalles del pedido</h4>
                            <ul>
                                <li><strong>Total:</strong>$ $total_price</li>
                                <li><strong>Dirección de envío:</strong> $street, $street2, $city, $province, cp: $cp</li>
                                <li><strong>Tipo de envío:</strong> $shipping</li>
                                <li><strong>Fecha del pedido:</strong> $date</li>
                            </ul>

                            <h4>Productos:</h4>
                            <ul>";

                            foreach ($products as $product) {
                                $product_name = $product['product']['id'];
                                $quantity = $product['quantity'];
                                $contentCompany .= "<li>$product_name - Cantidad: $quantity</li>";
                            }

                            $contentCompany .= "</ul>
                            <p>Saludos,<br>El equipo de Luz Interior.</p>
                            ";

                            $altBodyCompany = 'Nueva orden de pedido. Puedes ver la orden completa desde el panel de administador.';
                            $emailTemplateCompany = generateEmailTemplate($title, $contentCompany);
                            $sendMailCompany = sendMail($companyInfo['data']['email'], "Nueva orden de pedido", $emailTemplateCompany, $altBodyCompany);

                            if ($sendMailClient) {
                                sendReply(['success' => true, 'message' => 'Correo de recepcion de orden enviado.']);
                            } else {
                                sendReply(['success' => false, 'message' => 'No se pudo enviar el correo. Inténtalo más tarde.']);
                            }

                            sendReply(['success' => true, 'message' => 'Orden registrada exitosamente']);
                        } catch (PDOException $e) {
                            sendReply(['success' => false, 'message' => 'Error al registrar la orden: ' . $e->getMessage()]);
                        }
                    } else {
                        sendReply(['success' => false, 'message' => 'Datos incompletos']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido o expirado']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;
        case 'register-prod-and-img': // Acciones de administrador  -productos
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $_POST['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    if (isset(
                        $_POST['id'],
                        $_POST['name'],
                        $_POST['price'],
                        $_POST['category'],
                        $_POST['description'],
                        $_POST['novelty']
                    )) {
                        $data = [
                            'id' => $_POST['id'],
                            'name' => $_POST['name'],
                            'price' => $_POST['price'],
                            'category' => $_POST['category'],
                            'description' => $_POST['description'],
                            'novelty' =>   $_POST['novelty']
                        ];

                        $productId = $_POST['id'];

                        // Iniciar una transacción
                        $con->beginTransaction();

                        $result = registerProduct($con, $data);
                        if (!$result['success']) {
                            $con->rollBack();
                            sendReply($result);
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
                                $filePath = '/uploads/products/' . basename($file['name']);
                                if (move_uploaded_file($file['tmp_name'], __DIR__ . $filePath)) {
                                    // Insertar la nueva imagen en la base de datos
                                    $sql = $con->prepare("INSERT INTO products_images (product_id, img_url, priority) VALUES (?, ?, ?)");
                                    $sql->execute([$productId, $filePath, $priority]);
                                    $updatedImages[] = $con->lastInsertId();
                                }
                            }
                        }

                        if (!$imageUploadSuccess) {
                            $con->rollBack();
                            sendReply(['success' => false, 'message' => 'Error al subir imágenes']);
                            break;
                        }

                        // Confirmar la transacción
                        $con->commit();
                        sendReply(['success' => true, 'message' => 'Producto e imagen registrados correctamente']);
                    } else {
                        sendReply(['success' => false, 'message' => 'Datos incompletos']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido o expirado']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;
        case 'register-product':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    $data = json_decode(file_get_contents("php://input"), true);

                    if (isset(
                        $data['id'],
                        $data['name'],
                        $data['price'],
                        $data['category'],
                        $data['description'],
                        $data['novelty']
                    )) {
                        $id = $data['id'];
                        $name = $data['name'];
                        $price = $data['price'];
                        $category = $data['category'];
                        $description = $data['description'];
                        $novelty =  $data['novelty'];

                        $result = registerProduct($con, $data);
                        sendReply($result);
                    } else {
                        sendReply(['success' => false, 'message' => 'Datos incompletos']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido o expirado']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;
        case 'update-product':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    $data = json_decode(file_get_contents("php://input"), true);

                    if (isset(
                        $data['productId'],
                        $data['data']['id'],
                        $data['data']['name'],
                        $data['data']['category'],
                        $data['data']['description'],
                        $data['data']['price'],
                        $data['data']['novelty']
                    )) {
                        $id = $data['productId'];
                        $new_id = $data['data']['id'];
                        $new_name = $data['data']['name'];
                        $new_category = $data['data']['category'];
                        $new_description = $data['data']['description'];
                        $new_price = $data['data']['price'];
                        $new_novelty =  $data['data']['novelty'];

                        $stmt = $con->prepare("SELECT COUNT(*) FROM products WHERE id = :id");
                        $stmt->execute([':id' => $id]);
                        if ($stmt->fetchColumn() == 0) {
                            sendReply(['success' => false, 'message' => 'El producto no existe']);
                            exit;
                        }

                        try {
                            $sql = $con->prepare("UPDATE products SET id=:new_id, name=:new_name, category=:new_category, description=:new_description, price=:new_price, novelty=:new_novelty WHERE id = :id");
                            $sql->execute([
                                ':new_id' => $new_id,
                                ':new_name' => $new_name,
                                ':new_category' => $new_category,
                                ':new_description' => $new_description,
                                ':new_price' => $new_price,
                                ':new_novelty' => $new_novelty,
                                ':id' => $id
                            ]);

                            if ($sql->rowCount() > 0) {
                                sendReply(['success' => true, 'message' => 'Información actualizada']);
                            } else {
                                sendReply(['success' => false, 'message' => 'No se pudo actualizar la información']);
                            }
                        } catch (PDOException $e) {

                            sendReply(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                        }
                    } else {
                        sendReply(['success' => false, 'message' => 'Datos incompletos']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido o expirado']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;

        case 'delete-product':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    $data = json_decode(file_get_contents("php://input"), true);

                    if (isset($data['productId'])) {
                        $id = $data['productId'];

                        $sql = $con->prepare("DELETE FROM products WHERE id = :id");
                        $sql->execute([':id' => $id]);

                        if ($sql->rowCount() > 0) {
                            sendReply(['success' => true, 'message' => 'Producto eliminado exitosamente']);
                        } else {
                            sendReply(['success' => false, 'message' => 'No se pudo eliminar el producto']);
                        }
                    } else {
                        sendReply(['success' => false, 'message' => 'Datos incompletos']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido o expirado']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;
        case 'update-price': // - precios de productos en lista
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    $data = json_decode(file_get_contents("php://input"), true);

                    if (isset($data['percentage'])) {
                        $percentage = $data['percentage'];
                        $productIds = $data['productIds'] ?? [];

                        $factor = 1 + ($percentage / 100);

                        if (empty($productIds)) {
                            $sql = $con->prepare("UPDATE products SET price = price * :factor");
                            $sql->execute([':factor' => $factor]);
                        } else {
                            $placeholders = [];
                            $params = [':factor' => $factor];

                            foreach ($productIds as $index => $id) {
                                $paramName = ":id$index";
                                $placeholders[] = $paramName;
                                $params[$paramName] = $id;
                            }

                            $placeholdersString = implode(',', $placeholders);
                            $sql = $con->prepare("UPDATE products SET price = price * :factor WHERE id IN ($placeholdersString)");
                            $sql->execute($params);
                        }

                        if ($sql->rowCount() > 0) {
                            sendReply(['success' => true, 'message' => 'Precios actualizados exitosamente']);
                        } else {
                            sendReply(['success' => false, 'message' => 'No se pudo actualizar la lista de precios']);
                        }
                    } else {
                        sendReply(['success' => false, 'message' => 'Datos incompletos']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido o expirado']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;
        case 'update-list-price': // - lista de precios
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt =  $_POST['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    if (!empty($_FILES['list_price']['tmp_name'])) {
                        $fileTmpName = $_FILES['list_price']['tmp_name'];
                        $fileName = basename($_FILES['list_price']['name']);
                        $fileName = str_replace(' ', '_', $fileName);

                        $uploadDirectory = 'uploads/list_price/';
                        $uploadDate = date("Y-m-d H:i:s");

                        $files = glob($uploadDirectory . '*');
                        foreach ($files as $file) {
                            if (is_file($file)) {
                                unlink($file);
                            }
                        }
                        // Validar que el archivo sea PDF
                        if (pathinfo($fileName, PATHINFO_EXTENSION) !== 'pdf') {
                            sendReply(['success' => false, 'message' => 'El archivo debe ser un PDF']);
                            exit;
                        }

                        $uniqueFileName = uniqid() . '-' . $fileName;
                        $uploadPath = $uploadDirectory . $uniqueFileName;

                        if (move_uploaded_file($fileTmpName, $uploadPath)) {
                            try {
                                $sql1 = $con->prepare("TRUNCATE TABLE `luzinterior`.`list_price`");
                                $sql1->execute();
                                // Guardar la ruta del archivo en la base de datos
                                $sql = $con->prepare("INSERT INTO list_price (list_price, date) VALUES (:list_price, :upload_date)");
                                $sql->execute([
                                    ':list_price' => $uploadPath,
                                    ':upload_date' => $uploadDate,
                                ]);

                                if ($sql->rowCount() > 0) {
                                    sendReply(['success' => true, 'message' => 'Archivo subido y ruta guardada exitosamente']);
                                } else {
                                    sendReply(['success' => false, 'message' => 'No se pudo guardar la ruta en la base de datos']);
                                }
                            } catch (PDOException $e) {
                                sendReply(['success' => false, 'message' => 'Error al guardar la ruta en la base de datos']);
                            }
                        } else {
                            sendReply(['success' => false, 'message' => 'Error al mover el archivo a la carpeta de uploads']);
                        }
                    } else {
                        sendReply(['success' => false, 'message' => 'No se recibió un archivo para subir']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido o expirado']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;
        case 'delete-list-price':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    try {
                        $sql = $con->prepare("SELECT list_price FROM list_price LIMIT 1");
                        $sql->execute();
                        $result = $sql->fetch(PDO::FETCH_ASSOC);

                        if ($result) {
                            $filePath = $result['list_price'];

                            // Eliminar el archivo físico si existe
                            if (file_exists($filePath)) {
                                unlink($filePath);
                            }

                            $sqlDelete = $con->prepare("TRUNCATE TABLE `luzinterior`.`list_price`");
                            $sqlDelete->execute();

                            sendReply(['success' => true, 'message' => 'Lista de precios eliminada correctamente']);
                        } else {
                            sendReply(['success' => false, 'message' => 'No se encontró ninguna lista de precios para eliminar']);
                        }
                    } catch (PDOException $e) {
                        sendReply(['success' => false, 'message' => 'Error al eliminar la lista de precios']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido o expirado']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;

        case 'upload-images-products':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $_POST['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);
                if ($decoded) {
                    if (isset($_POST['productId'])) {
                        $productId = $_POST['productId'];
                        $updatedImages = [];
                        $deletedImages = $_POST['deletedImages'] ?? [];

                        // Eliminar imágenes seleccionadas de la base de datos y del sistema de archivos
                        if (!empty($deletedImages)) {
                            foreach ($deletedImages as $imageId) {
                                // Obtener la URL de la imagen antes de eliminarla
                                $getImageQuery = "SELECT img_url FROM products_images WHERE id_img = ?";
                                $stmtGetImage = $con->prepare($getImageQuery);
                                $stmtGetImage->execute([$imageId]);
                                $image = $stmtGetImage->fetch(PDO::FETCH_ASSOC);

                                if ($image) {
                                    $filePath = __DIR__ . $image['img_url'];
                                    if (is_file($filePath)) {
                                        unlink($filePath); // Eliminar el archivo físico
                                    }
                                }

                                // Eliminar el registro de la base de datos
                                $deleteQuery = "DELETE FROM products_images WHERE id_img = ?";
                                $stmtDelete = $con->prepare($deleteQuery);
                                $stmtDelete->execute([$imageId]);
                            }
                        }

                        // Actualizar prioridades de las imágenes existentes
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
                                    $filePath = '/uploads/products/' . basename($file['name']);
                                    if (move_uploaded_file($file['tmp_name'], __DIR__ . $filePath)) {
                                        // Insertar la nueva imagen en la base de datos
                                        $sql = $con->prepare("INSERT INTO products_images (product_id, img_url, priority) VALUES (?, ?, ?)");
                                        $sql->execute([$productId, $filePath, $priority]);
                                        $updatedImages[] = $con->lastInsertId();
                                    }
                                }
                            }
                        }
                        sendReply(['success' => true, 'updatedImages' => $updatedImages]);
                    } else {
                        sendReply(['success' => false, 'message' => 'Faltan datos necesarios.']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido.']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;
        case 'add-frequently-asked-questions':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    $data = json_decode(file_get_contents("php://input"), true);

                    if (isset($data['data']['question'], $data['data']['answer'])) {
                        $question = $data['data']['question'];
                        $answer = $data['data']['answer'];

                        try {
                            $sql = $con->prepare("INSERT INTO frequently_asked_questions (question, answer) VALUES (?,?)");
                            $sql->execute([$question, $answer]);

                            if ($sql->rowCount() > 0) {
                                sendReply(['success' => true, 'message' => 'Información actualizada']);
                            } else {
                                sendReply(['success' => false, 'message' => 'No se pudo actualizar la información']);
                            }
                        } catch (PDOException $e) {
                            error_log('Database error: ' . $e->getMessage());
                            sendReply(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                        }
                    } else {
                        sendReply(['status' => 'error', 'message' => 'Datos incompletos']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido.']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;
        case 'update-frequently-asked-questions':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    $data = json_decode(file_get_contents("php://input"), true);

                    if (isset($data['data']['id'], $data['data']['question'], $data['data']['answer'])) {
                        $id = $data['data']['id'];
                        $question = $data['data']['question'];
                        $answer = $data['data']['answer'];

                        try {
                            $sql = $con->prepare("UPDATE frequently_asked_questions SET question = :question, answer = :answer WHERE id = :id");
                            $sql->execute([
                                ':id' => $id,
                                ':question' => $question,
                                ':answer' => $answer,
                            ]);

                            if ($sql->rowCount() > 0) {
                                sendReply(['success' => true, 'message' => 'Información actualizada']);
                            } else {
                                sendReply(['success' => false, 'message' => 'No se pudo actualizar la información']);
                            }
                        } catch (PDOException $e) {
                            error_log('Database error: ' . $e->getMessage());
                            sendReply(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                        }
                    } else {
                        sendReply(['status' => 'error', 'message' => 'Datos incompletos']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido.']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;
        case 'delete-frequently-asked-questions':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    $data = json_decode(file_get_contents("php://input"), true);

                    if (isset($data['id'], $data['question'], $data['answer'])) {
                        $id = $data['id'];

                        try {
                            $sql = $con->prepare("DELETE FROM frequently_asked_questions WHERE id = :id");
                            $sql->execute([
                                ':id' => $id,
                            ]);

                            if ($sql->rowCount() > 0) {
                                sendReply(['success' => true, 'message' => 'Información actualizada']);
                            } else {
                                sendReply(['success' => false, 'message' => 'No se pudo actualizar la información']);
                            }
                        } catch (PDOException $e) {
                            error_log('Database error: ' . $e->getMessage());
                            sendReply(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                        }
                    } else {
                        sendReply(['status' => 'error', 'message' => 'Datos incompletos']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido.']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;
        case 'change-approved': // -usuarios
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    $data = json_decode(file_get_contents("php://input"), true);

                    if (isset($data['id'])) {
                        $id = $data['id'];

                        $user_sql = "SELECT * FROM users WHERE id = :id";
                        $user_id_params = [':id' => $id];
                        $result_user = getData($con, $user_sql, $user_id_params);

                        $name = $result_user['name'];
                        $email = $result_user['email'];

                        $sql = $con->prepare("UPDATE users SET approved = NOT approved, new = 0 WHERE id = :id");
                        $sql->execute([':id' => $id]);

                        if ($sql->rowCount() > 0) {
                            $companyInfo = getDataCompany();

                            //email cliente
                            $title = 'Correo de aprobación de cuenta.';
                            $contentClient = "
                            <p>Hola $name,</p>
                            <h1>Bienvenido a Luz Interior.</h1>
                            <p>Tu cuenta ha sido verificada.</p>
                            <p>Ya puedes <u><a href='" . $companyInfo['data']['web'] . "mayoristas'><strong>iniciar sesión</strong></a></u> para acceder a la lista de precios mayoristas y realizar ordenes de compra.</p>
                            <p>Gracias por tu paciencia y por elegirnos.</p>
                            <p>Saludos,<br>El equipo de Luz Interior.</p>
                        ";
                            $altBodyClient = 'Bienvenido a Luz Interior. Tu cuenta ha sido verificada y ya puedes acceder al sitio.';
                            $emailTemplateClient = generateEmailTemplate($title, $contentClient);
                            $sendMailClient = sendMail($email, "Bienvenido! Tu cuenta ha sido verificada.", $emailTemplateClient, $altBodyClient);

                            if ($sendMailClient) {
                                sendReply(['success' => true, 'message' => 'Correo de aprobación de cuenta enviado.']);
                            } else {
                                sendReply(['success' => false, 'message' => 'No se pudo enviar el correo. Inténtalo más tarde.']);
                            }

                            sendReply(['success' => true, 'message' => 'Estado de aprovación del usuario modificado exitosamente']);
                        } else {
                            sendReply(['success' => false, 'message' => 'No se pudo modificar el estado de aprovación del usuario']);
                        }
                    } else {
                        sendReply(['status' => 'error', 'message' => 'Datos incompletos']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido.']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;
        case 'change-role':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    $data = json_decode(file_get_contents("php://input"), true);

                    if (isset($data['id'])) {
                        $id = $data['id'];

                        $sql = $con->prepare("
                        UPDATE users
                        SET role = CASE
                            WHEN role = 'user' THEN 'admin'
                            ELSE 'user'
                        END,
                        new = 0
                        WHERE id = :id
                    ");
                        $sql->execute([':id' => $id]);

                        if ($sql->rowCount() > 0) {
                            sendReply(['success' => true, 'message' => 'Estado de aprovación del usuario modificado exitosamente']);
                        } else {
                            sendReply(['success' => false, 'message' => 'No se pudo modificar el estado de aprovación del usuario']);
                        }
                    } else {
                        sendReply(['status' => 'error', 'message' => 'Datos incompletos']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido.']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;

        case 'delete-user':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    $data = json_decode(file_get_contents("php://input"), true);

                    if (isset($data['id'])) {
                        $id = $data['id'];

                        try {
                            $sql = $con->prepare("DELETE FROM users WHERE id = :id");
                            $sql->execute([':id' => $id]);

                            if ($sql->rowCount() > 0) {
                                sendReply(['success' => true, 'message' => 'El usuario se eliminó exitosamente']);
                            } else {
                                sendReply(['success' => false, 'message' => 'No se pudo eliminar el usuario']);
                            }
                        } catch (PDOException $e) {
                            if ($e->getCode() == 23000) {
                                sendReply(['success' => false, 'message' => 'No se puede eliminar el usuario porque tiene una orden asociada. Si desea eliminar este usuario, elimine previamente las ordenes asociadas.']);
                            } else {
                                sendReply(['success' => false, 'message' => 'Error al eliminar el usuario: ' . $e->getMessage()]);
                            }
                        }
                    } else {
                        sendReply(['status' => 'error', 'message' => 'Datos incompletos']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido.']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;
        case 'update-state-order': // -ordenes
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    $data = json_decode(file_get_contents("php://input"), true);

                    if (isset($data['orderId'], $data['newState'])) {
                        $id_order = $data['orderId'];
                        $state = $data['newState'];

                        $sql = $con->prepare("UPDATE orders SET state = :state WHERE id_order = :id_order");
                        $sql->execute([
                            ':id_order' => $id_order,
                            ':state' => $state
                        ]);

                        if ($sql->rowCount() > 0) {

                            $user_id_sql = "SELECT * FROM orders WHERE id_order = :id";
                            $user_id_params = [':id' => $id_order];
                            $result_user_id = getData($con, $user_id_sql, $user_id_params);

                            $id_user = $result_user_id['id_user'];
                            $date = $result_user_id['date'];
                            $total_price = $result_user_id['total_price'];

                            $user_sql = "SELECT name, email FROM users WHERE id = :id";
                            $user_params = [':id' => $id_user];
                            $result_user = getData($con, $user_sql, $user_params);

                            $name = $result_user['name'];
                            $email = $result_user['email'];

                            $products_sql = "SELECT product_id, quantity FROM order_products WHERE order_id = :id";
                            $products_params = [':id' => $id_order];
                            $result_products = getData($con, $products_sql, $products_params, true);

                            $state_message = "";

                            switch ($state) {
                                case 'En proceso':
                                    $state_message = "
                                <p>Tu pedido está siendo preparado.</p>
                                <p> Te notificaremos cuando esté listo para el siguiente paso.</p>";
                                    break;
                                case 'Entregado':
                                    $state_message = "
                                <p>Tu pedido ha sido entregado con éxito.</p>
                                <p> ¡Esperamos que lo disfrutes!</p>";
                                    break;
                                case 'Cancelado':
                                    $state_message = "
                                <p>Tu pedido ha sido cancelado.</p>
                                <p>Si tienes alguna consulta o necesitas más información, no dudes en contactarnos.</p>";
                                    break;
                            }
                            // Enviar correo cliente
                            $title = 'Correo actualización de estado de la orden de pedido.';
                            $contentClient = "
                             <p>Hola $name</p>
                             <h1>Tu orden n° $id_order tiene un nuevo estado: $state</h1>
                             <h2>Orden n° $id_order</h2>
                                $state_message
                             <h4>Detalles del pedido</h4>
                             <ul>
                                 <li><strong>Total:</strong>$ $total_price</li>
                                 <li><strong>Fecha del pedido:</strong> $date</li>
                             </ul>
                             <h4>Productos:</h4>
                             <ul>";

                            foreach ($result_products as $product) {
                                $product_name = $product['product_id'];
                                $quantity = $product['quantity'];
                                $contentClient .= "<li>$product_name - Cantidad: $quantity</li>";
                            }

                            $contentClient .= "</ul>
                                 <p>Saludos,<br>El equipo de Luz Interior.</p>
                             ";
                            $altBodyClient = 'El estado de tu pedido fue actualizado.';
                            $emailTemplateClient = generateEmailTemplate($title, $contentClient);
                            $sendMailClient = sendMail($email, "Nuevo estado de pedido: $state.", $emailTemplateClient, $altBodyClient);

                            if ($sendMailClient) {
                                sendReply(['success' => true, 'message' => 'Correo de actualización de estado de orden enviado.']);
                            } else {
                                sendReply(['success' => false, 'message' => 'No se pudo enviar el correo. Inténtalo más tarde.']);
                            }

                            sendReply(['success' => true, 'message' => 'El estado de la orden se actualizó exitosamente']);
                        } else {
                            sendReply(['success' => false, 'message' => 'No se pudo actualizar el estado de la orden']);
                        }
                    } else {
                        sendReply(['status' => 'error', 'message' => 'Datos incompletos']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido.']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;
        case 'update-new':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    $data = json_decode(file_get_contents("php://input"), true);

                    if (isset($data['orderId'])) {
                        $orderId = $data['orderId'];

                        $sql = $con->prepare("UPDATE orders SET new = 0 WHERE id_order = :orderId");
                        $sql->execute([':orderId' => $orderId]);

                        if ($sql->rowCount() > 0) {
                            sendReply(['success' => true, 'message' => 'Orden actualizada exitosamente']);
                        } else {
                            sendReply(['success' => false, 'message' => 'No se pudo actualizar la orden']);
                        }
                    } else {
                        sendReply(['status' => 'error', 'message' => 'Datos incompletos']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido.']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;

        case 'delete-order':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);
                if ($decoded) {
                    $data = json_decode(file_get_contents("php://input"), true);

                    if (isset($data['orderId'])) {
                        $id_order = $data['orderId'];

                        $sql = $con->prepare("DELETE FROM orders WHERE id_order = :id_order");
                        $sql->execute([
                            ':id_order' => $id_order,
                        ]);

                        if ($sql->rowCount() > 0) {
                            sendReply(['success' => true, 'message' => 'La orden se eliminó exitosamente']);
                        } else {
                            sendReply(['success' => false, 'message' => 'No se pudo eliminar la orden']);
                        }
                    } else {
                        sendReply(['status' => 'error', 'message' => 'Datos incompletos']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido.']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }

            break;
        case 'add-gallery': // -galería
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $_POST['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    // Verificar si el archivo fue enviado correctamente
                    if (!empty($_FILES['image']['tmp_name']) && isset($_POST['priority'])) {
                        $image = $_FILES['image'];
                        $priority = intval($_POST['priority']);

                        // Validar tipo de archivo
                        $allowedTypes = ['image/jpeg', 'image/png'];
                        if (!in_array($image['type'], $allowedTypes)) {
                            echo json_encode([
                                'success' => false,
                                'message' => 'Tipo de archivo no permitido.',
                            ]);
                            break;
                        }

                        // Crear directorio si no existe
                        $targetDir = './uploads/img-gallery/';

                        // Generar un nombre único para el archivo
                        $fileName = uniqid() . "_" . basename($image['name']);
                        $targetFile = $targetDir . $fileName;

                        if (move_uploaded_file($image['tmp_name'], $targetFile)) {
                            // Insertar datos en la base de datos
                            $sql = $con->prepare("INSERT INTO gallery_images (img_url, priority) VALUES (?, ?)");
                            if ($sql->execute([$targetFile, $priority])) {
                                echo json_encode([
                                    'success' => true,
                                    'message' => 'Imagen añadida exitosamente.',
                                ]);
                            } else {
                                echo json_encode([
                                    'success' => false,
                                    'message' => 'Error al guardar la imagen en la base de datos.',
                                ]);
                            }
                        } else {
                            echo json_encode([
                                'success' => false,
                                'message' => 'Error al mover el archivo subido.',
                            ]);
                        }
                    } else {
                        echo json_encode([
                            'success' => false,
                            'message' => 'Archivo o prioridad no enviados.',
                        ]);
                    }
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }

            break;
        case 'update-gallery':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    $payload = json_decode(file_get_contents('php://input'), true);
                    $updatedImages = $payload['payload']['images'] ?? [];


                    try {
                        $con->beginTransaction();

                        if (!empty($updatedImages)) {
                            $imageIds = array_map(function ($img) {
                                return $img['id'];
                            }, $updatedImages);

                            // Obtener registros actuales en la base de datos
                            $sqlSelect = "SELECT id, img_url FROM gallery_images";
                            $stmtSelect = $con->prepare($sqlSelect);
                            $stmtSelect->execute();
                            $existingImages = $stmtSelect->fetchAll(PDO::FETCH_ASSOC);

                            // Identificar las imágenes que deben ser eliminadas
                            $imagesToDelete = array_filter($existingImages, function ($img) use ($imageIds) {
                                return !in_array($img['id'], $imageIds);
                            });

                            // Eliminar los archivos correspondientes
                            foreach ($imagesToDelete as $image) {
                                $filePath = $image['img_url'];
                                if (is_file($filePath)) {
                                    unlink($filePath);
                                }
                            }

                            $placeholders = rtrim(str_repeat('?, ', count($imageIds)), ', ');
                            $sqlDelete = "DELETE FROM gallery_images WHERE id NOT IN ($placeholders)";
                            $stmtDelete = $con->prepare($sqlDelete);
                            $stmtDelete->execute($imageIds);

                            foreach ($updatedImages as $index => $image) {
                                $sqlUpdate = "UPDATE gallery_images SET priority = ? WHERE id = ?";
                                $stmtUpdate = $con->prepare($sqlUpdate);
                                $stmtUpdate->execute([($index + 1), $image['id']]);
                            }
                        } else {
                            $sqlDeleteAll = "DELETE FROM gallery_images";
                            $con->exec($sqlDeleteAll);

                            $targetDir = './uploads/img-gallery/';
                            $files = glob($targetDir . '*');
                            foreach ($files as $file) {
                                if (is_file($file)) {
                                    unlink($file);
                                }
                            }
                        }
                        $con->commit();
                        sendReply(['success' => true, 'message' => 'Galería actualizada correctamente']);
                    } catch (PDOException $e) {
                        $con->rollBack();
                        echo json_encode(['success' => false, 'message' => $e->getMessage()]);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'No images provided.']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }

            break;
        case 'add-banner':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $_POST['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    if (!empty($_FILES['image']['tmp_name']) && isset($_POST['priority']) && isset($_POST['type'])) {
                        $image = $_FILES['image'];
                        $priority = intval($_POST['priority']);
                        $type = $_POST['type']; // 'desktop' o 'mobile'
                        $link = isset($_POST['link']) ? trim($_POST['link']) : null;

                        $allowedTypes = ['image/jpeg', 'image/png'];
                        if (!in_array($image['type'], $allowedTypes)) {
                            echo json_encode([
                                'success' => false,
                                'message' => 'Tipo de archivo no permitido.',
                            ]);
                            break;
                        }

                        if ($type === 'desktop') {
                            $targetDir = './uploads/img-banner/desktop/';
                            $tableName = 'banner_images_desktop';
                        } elseif ($type === 'mobile') {
                            $targetDir = './uploads/img-banner/mobile/';
                            $tableName = 'banner_images_mobile';
                        } else {
                            echo json_encode([
                                'success' => false,
                                'message' => 'Tipo de banner inválido.',
                            ]);
                            break;
                        }

                        if (!is_dir($targetDir)) {
                            mkdir($targetDir, 0777, true);
                        }

                        $fileName = uniqid() . "_" . basename($image['name']);
                        $targetFile = $targetDir . $fileName;

                        if (move_uploaded_file($image['tmp_name'], $targetFile)) {
                            // Insertar datos en la base de datos
                            $sql = $con->prepare("INSERT INTO $tableName (img_url, priority, link) VALUES (?, ?, ?)");
                            if ($sql->execute([$targetFile, $priority, $link])) {
                                echo json_encode([
                                    'success' => true,
                                    'message' => 'Imagen añadida exitosamente.',
                                ]);
                            } else {
                                echo json_encode([
                                    'success' => false,
                                    'message' => 'Error al guardar la imagen en la base de datos.',
                                ]);
                            }
                        } else {
                            echo json_encode([
                                'success' => false,
                                'message' => 'Error al mover el archivo subido.',
                            ]);
                        }
                    } else {
                        echo json_encode([
                            'success' => false,
                            'message' => 'Archivo, prioridad o tipo de banner no enviados.',
                        ]);
                    }
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;
        case 'update-banner-desktop':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    $payload = json_decode(file_get_contents('php://input'), true);
                    $updatedImages = $payload['payload']['images'] ?? [];

                    try {
                        $con->beginTransaction();

                        if (!empty($updatedImages)) {
                            $imageIds = array_map(function ($img) {
                                return $img['id'];
                            }, $updatedImages);

                            // Obtener registros actuales en la base de datos
                            $sqlSelect = "SELECT id, img_url FROM banner_images_desktop";
                            $stmtSelect = $con->prepare($sqlSelect);
                            $stmtSelect->execute();
                            $existingImages = $stmtSelect->fetchAll(PDO::FETCH_ASSOC);

                            // Identificar las imágenes que deben ser eliminadas
                            $imagesToDelete = array_filter($existingImages, function ($img) use ($imageIds) {
                                return !in_array($img['id'], $imageIds);
                            });

                            // Eliminar los archivos correspondientes
                            foreach ($imagesToDelete as $image) {
                                $filePath = $image['img_url'];
                                if (is_file($filePath)) {
                                    unlink($filePath);
                                }
                            }

                            $placeholders = rtrim(str_repeat('?, ', count($imageIds)), ', ');
                            $sqlDelete = "DELETE FROM banner_images_desktop WHERE id NOT IN ($placeholders)";
                            $stmtDelete = $con->prepare($sqlDelete);
                            $stmtDelete->execute($imageIds);

                            foreach ($updatedImages as $index => $image) {
                                $sqlUpdate = "UPDATE banner_images_desktop SET priority = ? , link = ? WHERE id = ?";
                                $stmtUpdate = $con->prepare($sqlUpdate);
                                $stmtUpdate->execute([($index + 1), $image['link'], $image['id']]);
                            }
                        } else {
                            $sqlDeleteAll = "DELETE FROM banner_images_desktop";
                            $con->exec($sqlDeleteAll);

                            $targetDir = '/uploads/img-banner/desktop/';
                            $files = glob($targetDir . '*');
                            foreach ($files as $file) {
                                if (is_file($file)) {
                                    unlink($file);
                                }
                            }
                        }
                        $con->commit();
                        sendReply(['success' => true, 'message' => 'Banner actualizado correctamente']);
                    } catch (PDOException $e) {
                        $con->rollBack();
                        echo json_encode(['success' => false, 'message' => $e->getMessage()]);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'No images provided.']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }



        case 'update-banner-mobile':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    $payload = json_decode(file_get_contents('php://input'), true);
                    $updatedImages = $payload['payload']['images'] ?? [];


                    try {
                        $con->beginTransaction();

                        if (!empty($updatedImages)) {
                            $imageIds = array_map(function ($img) {
                                return $img['id'];
                            }, $updatedImages);

                            // Obtener registros actuales en la base de datos
                            $sqlSelect = "SELECT id, img_url FROM banner_images_mobile";
                            $stmtSelect = $con->prepare($sqlSelect);
                            $stmtSelect->execute();
                            $existingImages = $stmtSelect->fetchAll(PDO::FETCH_ASSOC);

                            // Identificar las imágenes que deben ser eliminadas
                            $imagesToDelete = array_filter($existingImages, function ($img) use ($imageIds) {
                                return !in_array($img['id'], $imageIds);
                            });

                            // Eliminar los archivos correspondientes
                            foreach ($imagesToDelete as $image) {
                                $filePath = $image['img_url'];
                                if (is_file($filePath)) {
                                    unlink($filePath);
                                }
                            }

                            $placeholders = rtrim(str_repeat('?, ', count($imageIds)), ', ');
                            $sqlDelete = "DELETE FROM banner_images_mobile WHERE id NOT IN ($placeholders)";
                            $stmtDelete = $con->prepare($sqlDelete);
                            $stmtDelete->execute($imageIds);

                            foreach ($updatedImages as $index => $image) {
                                $sqlUpdate = "UPDATE banner_images_mobile SET priority = ? WHERE id = ?";
                                $stmtUpdate = $con->prepare($sqlUpdate);
                                $stmtUpdate->execute([($index + 1), $image['id']]);
                            }
                        } else {
                            $sqlDeleteAll = "DELETE FROM banner_images_mobile";
                            $con->exec($sqlDeleteAll);

                            $targetDir = '/uploads/img-banner/mobile/';
                            $files = glob($targetDir . '*');
                            foreach ($files as $file) {
                                if (is_file($file)) {
                                    unlink($file);
                                }
                            }
                        }
                        $con->commit();
                        sendReply(['success' => true, 'message' => 'Banner actualizado correctamente']);
                    } catch (PDOException $e) {
                        $con->rollBack();
                        echo json_encode(['success' => false, 'message' => $e->getMessage()]);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'No images provided.']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }

            break;
        case 'update_companyInfo': // -cuenta
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    $data = json_decode(file_get_contents('php://input'), true);

                    if (isset($data['data']['email'], $data['data']['store_address'], $data['data']['tel'])) {
                        try {
                            // Preparar la consulta
                            $sql = "UPDATE company_info SET value = ? WHERE `key` = ?";
                            $stmt = $con->prepare($sql);

                            // Ejecutar una consulta para cada par key-value
                            foreach ($data['data'] as $key => $value) {
                                if (is_array($value)) {
                                    $value = json_encode($value);
                                }
                                $stmt->execute([$value, $key]);
                            }

                            sendReply(['success' => true, 'message' => 'Información actualizada']);
                        } catch (PDOException $e) {
                            error_log('Database error: ' . $e->getMessage());
                            sendReply(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                        }
                    } else {
                        sendReply(['success' => false, 'message' => 'Datos incompletos']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido o expirado']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;
        case 'update_social':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $_POST['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    if ($_SERVER['REQUEST_METHOD'] === 'POST') {

                        if (isset($_FILES['img_social']) && isset($_POST['id']) && isset($_POST['social_url'])) {
                            // Obtener la información del formulario
                            $id = $_POST['id'];
                            $social_url = $_POST['social_url'];
                            $img_social = $_FILES['img_social'];

                            // Verificar si el archivo se subió correctamente
                            if ($img_social['error'] === UPLOAD_ERR_OK) {
                                // Directorio donde guardarás la imagen
                                $filePath = '/uploads/social/' . basename($img_social['name']); // Corregir el uso de variable

                                // Mover el archivo a su ubicación final
                                if (move_uploaded_file($img_social['tmp_name'], __DIR__ . $filePath)) {
                                    // Verificar si el registro ya existe en la base de datos
                                    $sqlCheck = "SELECT * FROM social_networks WHERE id = :id";
                                    $stmtCheck = $con->prepare($sqlCheck);
                                    $stmtCheck->execute([':id' => $id]);
                                    $existingRecord = $stmtCheck->fetch();

                                    if ($existingRecord) {
                                        // Si el registro existe, actualizarlo
                                        $sqlUpdate = "UPDATE social_networks SET img_social = :img_social, url = :social_url WHERE id = :id";
                                        $stmtUpdate = $con->prepare($sqlUpdate);
                                        $stmtUpdate->execute([
                                            ':img_social' => $filePath, // Usar la ruta definida en $filePath
                                            ':social_url' => $social_url,
                                            ':id' => $id
                                        ]);
                                        sendReply(['success' => true, 'message' => 'Red social actualizada correctamente']);
                                    } else {
                                        // Si el registro no existe, insertarlo
                                        $sqlInsert = "INSERT INTO social_networks (id, img_social, url) VALUES (:id, :img_social, :social_url)";
                                        $stmtInsert = $con->prepare($sqlInsert);
                                        $stmtInsert->execute([
                                            ':id' => $id,
                                            ':img_social' => $filePath,
                                            ':social_url' => $social_url
                                        ]);
                                        sendReply(['success' => true, 'message' => 'Red social agregada correctamente']);
                                    }
                                } else {
                                    sendReply(['success' => false, 'message' => 'Error al subir el archivo']);
                                }
                            } else {
                                sendReply(['success' => false, 'message' => 'Error en la subida del archivo']);
                            }
                        } else {
                            sendReply(['success' => false, 'message' => 'Datos incompletos']);
                        }
                    }
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;
        case 'delete-social':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);
                if ($decoded) {
                    $data = json_decode(file_get_contents("php://input"), true);

                    if (isset($data['id'])) {
                        $id = $data['id'];

                        $sql = $con->prepare("DELETE FROM social_networks WHERE id = :id");
                        $sql->execute([
                            ':id' => $id,
                        ]);

                        if ($sql->rowCount() > 0) {
                            sendReply(['success' => true, 'message' => 'La red social se eliminó exitosamente']);
                        } else {
                            sendReply(['success' => false, 'message' => 'No se eliminar la red social']);
                        }
                    }
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;
        case 'update-shipping':
            $data = json_decode(file_get_contents("php://input"), true);
            $jwt = $data['token'] ?? null;

            if ($jwt) {
                $decoded = verifyToken($jwt);

                if ($decoded) {
                    $data = json_decode(file_get_contents("php://input"), true);

                    if (!isset($data['updatedShipping']) || !is_array($data['updatedShipping'])) {
                        sendReply(['success' => false, 'message' => 'Datos inválidos']);
                        break;
                    }

                    $updates = $data['updatedShipping'];
                    $anyUpdateFailed = false;

                    foreach ($updates as $update) {
                        if (isset($update['id_shipping'], $update['description'], $update['price'])) {
                            $id_shipping = $update['id_shipping'];
                            $description = $update['description'];
                            $price = $update['price'];

                            try {
                                $sql = $con->prepare("UPDATE shipping SET description = :description, price = :price  WHERE id_shipping = :id_shipping");

                                $sql->execute([
                                    ':id_shipping' => $id_shipping,
                                    ':description' => $description,
                                    ':price' => $price,
                                ]);

                                if (!$sql) {
                                    $anyUpdateFailed = true;
                                }
                            } catch (PDOException $e) {
                                $anyUpdateFailed = true;
                                error_log("Error en la actualización de envío: " . $e->getMessage());
                            }
                        } else {
                            $anyUpdateFailed = true;
                        }
                    }

                    if (!$anyUpdateFailed) {
                        sendReply(['success' => true, 'message' => 'La información de envío se actualizó exitosamente']);
                    } else {
                        sendReply(['success' => false, 'message' => 'No se pudo actualizar toda la información']);
                    }
                } else {
                    sendReply(['success' => false, 'message' => 'Token inválido']);
                }
            } else {
                sendReply(['success' => false, 'message' => 'Token no encontrado']);
            }
            break;

        default:
            sendReply(['success' => false, 'error' => 'acción no válida']);
            break;
    }
} else {
    sendReply(['error' => 'Acción no válida']);
}
